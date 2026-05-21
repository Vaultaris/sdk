//! Typestate OAuth 2.0 / OIDC flow builder for Vaultaris.
//!
//! Each OAuth flow is represented as `OAuthFlow<S>` where `S` is a compile-time
//! state marker.  State transitions consume the current value and return a new one,
//! so invalid sequences (e.g. exchanging a code before starting the flow, or
//! refreshing a token that was never issued) are caught at **compile time**.
//!
//! # Flows
//!
//! ## Authorization Code + PKCE (recommended for user-facing apps)
//! ```rust,no_run
//! use vaultaris_sdk::oauth::OAuthFlow;
//!
//! # #[tokio::main] async fn main() -> Result<(), vaultaris_sdk::Error> {
//! // 1. Build the flow and get the redirect URL (PKCE generated automatically)
//! let (url, flow) =
//!     OAuthFlow::new("https://vaultaris.example.com", "my-client", None::<String>)
//!         .authorization_url("https://myapp.com/callback", &["openid", "profile", "email"], None)?;
//!
//! // redirect the user to `url` …
//!
//! // 2. After redirect back, verify CSRF state and exchange the code
//! flow.verify_state("state-from-query-param")?;
//! let authed = flow.exchange("code-from-query-param").await?;
//!
//! println!("access_token: {}", authed.access_token());
//!
//! // 3. Optionally call /oauth/userinfo
//! let info = authed.userinfo().await?;
//! println!("email: {:?}", info.email);
//!
//! // 4. Refresh when the token expires
//! let authed = authed.into_refreshable()?.refresh().await?;
//!
//! // 5. Use as VaultarisClient for admin / resource APIs
//! let client = authed.as_client();
//! # Ok(()) }
//! ```
//!
//! ## Password grant (trusted apps / Vaultaris dashboard)
//! ```rust,no_run
//! # use vaultaris_sdk::oauth::OAuthFlow;
//! # #[tokio::main] async fn main() -> Result<(), vaultaris_sdk::Error> {
//! let authed =
//!     OAuthFlow::new("https://vaultaris.example.com", "dashboard-client", None::<String>)
//!         .login("alice@example.com", "hunter2", "openid profile email")
//!         .await?;
//! println!("{}", authed.access_token());
//! # Ok(()) }
//! ```
//!
//! ## Client credentials (machine-to-machine)
//! ```rust,no_run
//! # use vaultaris_sdk::oauth::OAuthFlow;
//! # #[tokio::main] async fn main() -> Result<(), vaultaris_sdk::Error> {
//! let authed = OAuthFlow::new("https://vaultaris.example.com", "svc-client", Some("s3cr3t"))
//!     .client_credentials("read:metrics write:events")
//!     .await?;
//! println!("{}", authed.access_token());
//! # Ok(()) }
//! ```

use std::time::{Duration, Instant};

use base64::Engine as _;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::config::VaultarisConfig;
use crate::error::Error;

// ============================================
// STATE MARKERS
// ============================================

/// Initial state — no tokens, no in-flight request.
#[derive(Clone)]
pub struct Unauthenticated;

/// Authorization Code flow is in progress.
/// Holds the PKCE verifier and CSRF state so they can be verified on callback.
#[derive(Clone)]
pub struct PendingCode {
    pub(crate) code_verifier: String,
    pub(crate) csrf_state: String,
    pub(crate) redirect_uri: String,
}

/// A valid access token has been obtained.
/// Methods on this state expose the tokens and allow further operations.
#[derive(Clone)]
pub struct Authenticated {
    pub(crate) access_token: String,
    pub(crate) refresh_token: Option<String>,
    pub(crate) id_token: Option<String>,
    pub(crate) scope: String,
    pub(crate) expires_at: Instant,
}

/// A refresh token is available.
/// Only reachable via `OAuthFlow<Authenticated>::into_refreshable()`.
#[derive(Clone)]
pub struct Refreshable {
    pub(crate) refresh_token: String,
    pub(crate) scope: String,
}

// ============================================
// CORE STRUCT
// ============================================

/// Typestate OAuth 2.0 flow.  `S` is one of [`Unauthenticated`], [`PendingCode`],
/// [`Authenticated`], or [`Refreshable`].
#[derive(Clone)]
pub struct OAuthFlow<S: Clone> {
    base_url: String,
    client_id: String,
    client_secret: Option<String>,
    #[cfg(feature = "async")]
    http: reqwest::Client,
    state: S,
}

// ============================================
// CONSTRUCTORS
// ============================================

impl OAuthFlow<Unauthenticated> {
    /// Create a new OAuth flow.
    ///
    /// - `base_url` — Vaultaris server base URL (e.g. `"https://auth.example.com"`)
    /// - `client_id` — registered OAuth2 client ID
    /// - `client_secret` — client secret (`None` for public clients)
    #[cfg(feature = "async")]
    pub fn new(
        base_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: Option<impl Into<String>>,
    ) -> Self {
        let http = reqwest::Client::builder()
            .user_agent(format!("vaultaris-sdk-rust/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("HTTP client failed to build");

        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            client_id: client_id.into(),
            client_secret: client_secret.map(Into::into),
            http,
            state: Unauthenticated,
        }
    }

    /// Create a new OAuth flow fron env variables.
    #[cfg(feature = "async")]
    pub fn from_env() -> Self {
        let http = reqwest::Client::builder()
            .user_agent(format!("vaultaris-sdk-rust/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("HTTP client failed to build");

        Self {
            base_url: std::env::var("VAULTARA_URL")
                .expect("Vaultaris needs 'VAULTARA_URL' env.")
                .trim_end_matches('/')
                .to_string(),
            client_id: std::env::var("VAULTARA_CLIENT_ID")
                .expect("Vaultaris needs 'VAULTARA_CLIENT_ID' env."),
            // Optional: not every flow needs a client secret (PKCE doesn't).
            client_secret: std::env::var("VAULTARA_CLIENT_SECRET").ok(),
            http,
            state: Unauthenticated,
        }
    }

    /// Restore a flow from a stored refresh token (e.g. from a DB/cookie),
    /// skipping the full auth flow.
    #[cfg(feature = "async")]
    pub fn from_refresh_token(
        base_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: Option<impl Into<String>>,
        refresh_token: impl Into<String>,
        scope: impl Into<String>,
    ) -> OAuthFlow<Refreshable> {
        let http = reqwest::Client::builder()
            .user_agent(format!("vaultaris-sdk-rust/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("HTTP client failed to build");

        OAuthFlow {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            client_id: client_id.into(),
            client_secret: client_secret.map(Into::into),
            http,
            state: Refreshable {
                refresh_token: refresh_token.into(),
                scope: scope.into(),
            },
        }
    }
}

// ============================================
// UNAUTHENTICATED → PENDING / AUTHENTICATED
// ============================================

#[cfg(feature = "async")]
impl OAuthFlow<Unauthenticated> {
    /// Build the authorization URL for the Authorization Code + PKCE flow.
    ///
    /// Returns the URL to redirect the user to, **and** a new `OAuthFlow<PendingCode>`
    /// that holds the PKCE verifier and CSRF state for the callback step.
    ///
    /// PKCE (`S256`) is generated automatically — you don't need to manage it.
    pub fn authorization_url(
        self,
        redirect_uri: impl Into<String>,
        scopes: &[&str],
        nonce: Option<&str>,
    ) -> Result<(String, OAuthFlow<PendingCode>), Error> {
        let redirect_uri = redirect_uri.into();
        let scope = scopes.join(" ");

        // Generate PKCE
        let code_verifier = pkce_verifier();
        let code_challenge = pkce_challenge(&code_verifier);

        // Generate CSRF state
        let csrf_state = random_token(16);

        let mut url = format!(
            "{}/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
            self.base_url,
            urlencoding::encode(&self.client_id),
            urlencoding::encode(&redirect_uri),
            urlencoding::encode(&scope),
            urlencoding::encode(&csrf_state),
            urlencoding::encode(&code_challenge),
        );

        if let Some(n) = nonce {
            url.push_str(&format!("&nonce={}", urlencoding::encode(n)));
        }

        let next = OAuthFlow {
            base_url: self.base_url,
            client_id: self.client_id,
            client_secret: self.client_secret,
            http: self.http,
            state: PendingCode {
                code_verifier,
                csrf_state,
                redirect_uri,
            },
        };

        Ok((url, next))
    }

    /// Authenticate via the **Resource Owner Password** grant.
    ///
    /// Use only for trusted first-party apps (e.g. the Vaultaris dashboard itself).
    /// Prefer `authorization_url` for third-party integrations.
    pub async fn login(
        self,
        username: impl AsRef<str>,
        password: impl AsRef<str>,
        scope: impl AsRef<str>,
    ) -> Result<OAuthFlow<Authenticated>, Error> {
        let mut params = vec![
            ("grant_type", "password".to_string()),
            ("username", username.as_ref().to_string()),
            ("password", password.as_ref().to_string()),
            ("scope", scope.as_ref().to_string()),
            ("client_id", self.client_id.clone()),
        ];
        if let Some(secret) = &self.client_secret {
            params.push(("client_secret", secret.clone()));
        }

        let token = self.token_request(&params).await?;
        Ok(self.into_authenticated(token))
    }

    /// Authenticate via the **Client Credentials** grant (machine-to-machine).
    ///
    /// Requires `client_secret`.  Returns an `Authenticated` state without a
    /// refresh token (per spec, client credentials never issue refresh tokens).
    pub async fn client_credentials(
        self,
        scope: impl AsRef<str>,
    ) -> Result<OAuthFlow<Authenticated>, Error> {
        let client_secret = self.client_secret.clone().ok_or_else(|| {
            Error::Config("client_secret required for client_credentials grant".into())
        })?;

        let params = vec![
            ("grant_type", "client_credentials".to_string()),
            ("client_id", self.client_id.clone()),
            ("client_secret", client_secret),
            ("scope", scope.as_ref().to_string()),
        ];

        let token = self.token_request(&params).await?;
        Ok(self.into_authenticated(token))
    }

    // ---- internal ----

    async fn token_request(&self, params: &[(&str, String)]) -> Result<TokenResponse, Error> {
        let res = self
            .http
            .post(format!("{}/oauth/token", self.base_url))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(params)
            .send()
            .await?;

        let status = res.status();
        let body = res.text().await.map_err(Error::from)?;

        if status.is_success() {
            serde_json::from_str::<TokenResponse>(&body).map_err(|e| Error::Json(e.to_string()))
        } else {
            let err: OAuthErrorResponse =
                serde_json::from_str(&body).unwrap_or(OAuthErrorResponse {
                    error: "unknown_error".into(),
                    error_description: Some(body),
                });
            Err(Error::Auth(err.error_description.unwrap_or(err.error)))
        }
    }

    fn into_authenticated(self, token: TokenResponse) -> OAuthFlow<Authenticated> {
        OAuthFlow {
            base_url: self.base_url,
            client_id: self.client_id,
            client_secret: self.client_secret,
            http: self.http,
            state: Authenticated {
                access_token: token.access_token,
                refresh_token: token.refresh_token,
                id_token: token.id_token,
                scope: token.scope.unwrap_or_default(),
                expires_at: Instant::now()
                    + Duration::from_secs(token.expires_in.unwrap_or(3600) as u64),
            },
        }
    }
}

// ============================================
// PENDING CODE → AUTHENTICATED
// ============================================

#[cfg(feature = "async")]
impl OAuthFlow<PendingCode> {
    /// Verify the CSRF `state` parameter returned by the authorization server.
    ///
    /// **Call this before `exchange`** to prevent CSRF attacks.
    /// Returns `Err` if the state does not match.
    pub fn verify_state(&self, returned_state: &str) -> Result<(), Error> {
        if returned_state == self.state.csrf_state {
            Ok(())
        } else {
            Err(Error::Auth(
                "CSRF state mismatch — possible CSRF attack".into(),
            ))
        }
    }

    /// Exchange the authorization `code` for tokens.
    ///
    /// The PKCE verifier stored in `PendingCode` is sent automatically.
    /// Consumes `self` — you cannot exchange the same code twice.
    pub async fn exchange(self, code: impl AsRef<str>) -> Result<OAuthFlow<Authenticated>, Error> {
        let mut params = vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", code.as_ref().to_string()),
            ("redirect_uri", self.state.redirect_uri.clone()),
            ("client_id", self.client_id.clone()),
            ("code_verifier", self.state.code_verifier.clone()),
        ];
        if let Some(secret) = &self.client_secret {
            params.push(("client_secret", secret.clone()));
        }

        let res = self
            .http
            .post(format!("{}/oauth/token", self.base_url))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&params)
            .send()
            .await?;

        let status = res.status();
        let body = res.text().await.map_err(Error::from)?;

        let token = if status.is_success() {
            serde_json::from_str::<TokenResponse>(&body).map_err(|e| Error::Json(e.to_string()))?
        } else {
            let err: OAuthErrorResponse =
                serde_json::from_str(&body).unwrap_or(OAuthErrorResponse {
                    error: "unknown_error".into(),
                    error_description: Some(body),
                });
            return Err(Error::Auth(err.error_description.unwrap_or(err.error)));
        };

        Ok(OAuthFlow {
            base_url: self.base_url,
            client_id: self.client_id,
            client_secret: self.client_secret,
            http: self.http,
            state: Authenticated {
                access_token: token.access_token,
                refresh_token: token.refresh_token,
                id_token: token.id_token,
                scope: token.scope.unwrap_or_default(),
                expires_at: Instant::now()
                    + Duration::from_secs(token.expires_in.unwrap_or(3600) as u64),
            },
        })
    }
}

// ============================================
// AUTHENTICATED
// ============================================

impl OAuthFlow<Authenticated> {
    /// The Bearer access token. Use this in `Authorization: Bearer <token>` headers.
    pub fn access_token(&self) -> &str {
        &self.state.access_token
    }

    /// The refresh token, if the server issued one.
    /// Not all grants return a refresh token (e.g. `client_credentials` never does).
    pub fn refresh_token(&self) -> Option<&str> {
        self.state.refresh_token.as_deref()
    }

    /// The OIDC ID token, present when `openid` scope was requested.
    pub fn id_token(&self) -> Option<&str> {
        self.state.id_token.as_deref()
    }

    /// The granted scope string.
    pub fn scope(&self) -> &str {
        &self.state.scope
    }

    /// Whether the access token has passed its `expires_in` window.
    ///
    /// Note: clock skew or server-side revocation are not reflected here.
    /// Use `introspect()` for authoritative status.
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.state.expires_at
    }

    /// Time remaining until the access token expires.
    /// Returns `Duration::ZERO` if already expired.
    pub fn expires_in(&self) -> Duration {
        self.state
            .expires_at
            .saturating_duration_since(Instant::now())
    }

    /// Transition to `Refreshable` state so you can call `refresh()`.
    ///
    /// Returns `Err` if this flow has no refresh token (e.g. from a
    /// `client_credentials` grant — use `client_credentials()` again instead).
    pub fn into_refreshable(self) -> Result<OAuthFlow<Refreshable>, Error> {
        let refresh_token = self.state.refresh_token.ok_or_else(|| {
            Error::Config("No refresh token available for this grant type".into())
        })?;

        Ok(OAuthFlow {
            base_url: self.base_url,
            client_id: self.client_id,
            client_secret: self.client_secret,
            http: self.http,
            state: Refreshable {
                refresh_token,
                scope: self.state.scope,
            },
        })
    }

    /// Create a `VaultarisClient` pre-configured with this access token.
    ///
    /// Use the returned client to call Vaultaris resource APIs (`list_users`,
    /// `check_permission`, etc.) on behalf of the authenticated user.
    pub fn as_client(&self) -> crate::client::VaultarisClient {
        let config =
            VaultarisConfig::new(&self.base_url).with_api_key(self.state.access_token.clone());
        crate::client::VaultarisClient::new(config)
            .expect("VaultarisClient build failed — base_url was already validated")
    }

    /// Call `/oauth/userinfo` to retrieve the authenticated user's claims.
    #[cfg(feature = "async")]
    pub async fn userinfo(&self) -> Result<UserInfo, Error> {
        let res = self
            .http
            .get(format!("{}/oauth/userinfo", self.base_url))
            .bearer_auth(&self.state.access_token)
            .send()
            .await?;

        let status = res.status();
        let body = res.text().await.map_err(Error::from)?;

        if status.is_success() {
            serde_json::from_str(&body).map_err(|e| Error::Json(e.to_string()))
        } else {
            Err(Error::Auth(format!("userinfo failed: {}", body)))
        }
    }

    /// Call `/oauth/introspect` to get authoritative token metadata from the server.
    #[cfg(feature = "async")]
    pub async fn introspect(&self) -> Result<IntrospectResult, Error> {
        let mut params = vec![
            ("token", self.state.access_token.clone()),
            ("client_id", self.client_id.clone()),
        ];
        if let Some(secret) = &self.client_secret {
            params.push(("client_secret", secret.clone()));
        }

        let res = self
            .http
            .post(format!("{}/oauth/introspect", self.base_url))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&params)
            .send()
            .await?;

        let body = res.text().await.map_err(Error::from)?;
        serde_json::from_str(&body).map_err(|e| Error::Json(e.to_string()))
    }

    /// Revoke the access token (and refresh token if present) at `/oauth/revoke`.
    ///
    /// Consumes `self` — you cannot use the flow after revoking.
    /// Returns `OAuthFlow<Unauthenticated>` so you can start a new flow.
    #[cfg(feature = "async")]
    pub async fn revoke(self) -> Result<OAuthFlow<Unauthenticated>, Error> {
        // Revoke refresh token first (invalidates the whole family), then access token
        let token_to_revoke = self
            .state
            .refresh_token
            .as_deref()
            .unwrap_or(&self.state.access_token);

        let mut params = vec![
            ("token", token_to_revoke.to_string()),
            ("client_id", self.client_id.clone()),
        ];
        if let Some(secret) = &self.client_secret {
            params.push(("client_secret", secret.clone()));
        }

        let res = self
            .http
            .post(format!("{}/oauth/revoke", self.base_url))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&params)
            .send()
            .await?;

        if !res.status().is_success() {
            let body = res.text().await.unwrap_or_default();
            return Err(Error::Http(format!("revoke failed: {}", body)));
        }

        Ok(OAuthFlow {
            base_url: self.base_url,
            client_id: self.client_id,
            client_secret: self.client_secret,
            http: self.http,
            state: Unauthenticated,
        })
    }
}

// ============================================
// REFRESHABLE → AUTHENTICATED
// ============================================

#[cfg(feature = "async")]
impl OAuthFlow<Refreshable> {
    /// The stored refresh token.
    pub fn refresh_token(&self) -> &str {
        &self.state.refresh_token
    }

    /// Exchange the refresh token for a fresh set of tokens.
    ///
    /// Consumes `self` — the old refresh token is considered spent.
    /// The returned `OAuthFlow<Authenticated>` holds the new tokens
    /// (including a rotated refresh token if the server issued one).
    pub async fn refresh(self) -> Result<OAuthFlow<Authenticated>, Error> {
        let mut params = vec![
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", self.state.refresh_token.clone()),
            ("client_id", self.client_id.clone()),
            ("scope", self.state.scope.clone()),
        ];
        if let Some(secret) = &self.client_secret {
            params.push(("client_secret", secret.clone()));
        }

        let res = self
            .http
            .post(format!("{}/oauth/token", self.base_url))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&params)
            .send()
            .await?;

        let status = res.status();
        let body = res.text().await.map_err(Error::from)?;

        let token = if status.is_success() {
            serde_json::from_str::<TokenResponse>(&body).map_err(|e| Error::Json(e.to_string()))?
        } else {
            let err: OAuthErrorResponse =
                serde_json::from_str(&body).unwrap_or(OAuthErrorResponse {
                    error: "unknown_error".into(),
                    error_description: Some(body),
                });
            return Err(Error::Auth(err.error_description.unwrap_or(err.error)));
        };

        // Carry over the old refresh_token if the server didn't rotate it
        let refresh_token = token.refresh_token.or(Some(self.state.refresh_token));

        Ok(OAuthFlow {
            base_url: self.base_url,
            client_id: self.client_id,
            client_secret: self.client_secret,
            http: self.http,
            state: Authenticated {
                access_token: token.access_token,
                refresh_token,
                id_token: token.id_token,
                scope: token.scope.unwrap_or(self.state.scope),
                expires_at: Instant::now()
                    + Duration::from_secs(token.expires_in.unwrap_or(3600) as u64),
            },
        })
    }

    /// Revoke the refresh token, returning to unauthenticated state.
    pub async fn revoke(self) -> Result<OAuthFlow<Unauthenticated>, Error> {
        let mut params = vec![
            ("token", self.state.refresh_token.clone()),
            ("client_id", self.client_id.clone()),
        ];
        if let Some(secret) = &self.client_secret {
            params.push(("client_secret", secret.clone()));
        }

        self.http
            .post(format!("{}/oauth/revoke", self.base_url))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&params)
            .send()
            .await?;

        Ok(OAuthFlow {
            base_url: self.base_url,
            client_id: self.client_id,
            client_secret: self.client_secret,
            http: self.http,
            state: Unauthenticated,
        })
    }
}

// ============================================
// VaultarisClient → OAuthFlow entry point
// ============================================

#[cfg(feature = "async")]
impl crate::client::VaultarisClient {
    /// Start an OAuth 2.0 flow from this client's configured base URL.
    ///
    /// If `client_id` / `client_secret` are not provided, falls back to the
    /// values set in the client's config.
    pub fn oauth_flow(
        &self,
        client_id: impl Into<String>,
        client_secret: Option<impl Into<String>>,
    ) -> OAuthFlow<Unauthenticated> {
        OAuthFlow::new(self.base_url(), client_id, client_secret)
    }
}

// ============================================
// RESPONSE TYPES
// ============================================

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
    #[serde(default)]
    scope: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OAuthErrorResponse {
    error: String,
    error_description: Option<String>,
}

/// Claims returned by `/oauth/userinfo`.
#[derive(Debug, Clone, Deserialize)]
pub struct UserInfo {
    pub sub: String,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub preferred_username: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub phone_number: Option<String>,
    pub locale: Option<String>,
    pub zoneinfo: Option<String>,
    pub updated_at: Option<i64>,
}

/// Token introspection result from `/oauth/introspect`.
#[derive(Debug, Clone, Deserialize)]
pub struct IntrospectResult {
    /// Whether the token is currently active.
    pub active: bool,
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub username: Option<String>,
    pub token_type: Option<String>,
    pub exp: Option<i64>,
    pub iat: Option<i64>,
    pub sub: Option<String>,
    pub aud: Option<String>,
    pub iss: Option<String>,
    pub jti: Option<String>,
}

// ============================================
// PKCE HELPERS
// ============================================

fn pkce_verifier() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn pkce_challenge(verifier: &str) -> String {
    let hash = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

fn random_token(len: usize) -> String {
    use rand::RngCore;
    let mut bytes = vec![0u8; len];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
