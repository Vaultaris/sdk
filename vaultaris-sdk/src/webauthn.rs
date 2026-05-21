//! Typestate WebAuthn / Passkeys / FIDO2 flow builders for Vaultaris.
//!
//! Both registration and authentication are modelled as two-step flows where
//! **state transitions are enforced at compile time**.  An attempt to call
//! `complete()` before `begin()`, or to reuse a spent challenge, is a
//! **compile error**, not a runtime panic.
//!
//! # Registration (adding a new passkey)
//!
//! ```rust,no_run
//! use vaultaris_sdk::webauthn::RegistrationFlow;
//! use vaultaris_sdk::types::AttestationResponse;
//!
//! # #[tokio::main] async fn main() -> Result<(), vaultaris_sdk::Error> {
//! // 1. Begin — server generates a challenge and returns creation options
//! let flow = RegistrationFlow::new("https://auth.example.com", "user-bearer-token")
//!     .with_device_name("MacBook Touch ID");
//! let pending = flow.begin().await?;
//!
//! // 2. Pass `pending.options()` to the browser:
//! //    let cred = await navigator.credentials.create({ publicKey: pending.options() });
//!
//! // 3. Complete — verify attestation and store the credential
//! let attestation = AttestationResponse::new(
//!     "cred-id-from-browser",
//!     "clientDataJSON-base64url",
//!     "attestationObject-base64url",
//! )
//! .with_transports(vec!["internal".to_string()])
//! .with_device_name("MacBook Touch ID");
//!
//! let done = pending.complete(attestation).await?;
//! println!("Registered credential: {}", done.credential().credential_id_base64);
//! # Ok(()) }
//! ```
//!
//! # Authentication (verifying a passkey)
//!
//! ```rust,no_run
//! use vaultaris_sdk::webauthn::AuthenticationFlow;
//! use vaultaris_sdk::types::AssertionResponse;
//!
//! # #[tokio::main] async fn main() -> Result<(), vaultaris_sdk::Error> {
//! // 1. Begin — server generates a challenge listing the user's credentials
//! let flow = AuthenticationFlow::new("https://auth.example.com", "user-bearer-token");
//! let pending = flow.begin().await?;
//!
//! // 2. Pass `pending.options()` to the browser:
//! //    let assertion = await navigator.credentials.get({ publicKey: pending.options() });
//!
//! // 3. Complete — server verifies signature and updates sign counter
//! let assertion = AssertionResponse::new(
//!     "cred-id-from-browser",
//!     "clientDataJSON-base64url",
//!     "authenticatorData-base64url",
//!     "signature-base64url",
//! );
//!
//! let done = pending.complete(assertion).await?;
//! println!("Authenticated with: {}", done.credential().credential_id_base64);
//! # Ok(()) }
//! ```
//!
//! # Entry points from `VaultarisClient`
//!
//! ```rust,no_run
//! use vaultaris_sdk::{VaultarisClient, VaultarisConfig};
//!
//! # #[tokio::main] async fn main() -> Result<(), vaultaris_sdk::Error> {
//! let client = VaultarisClient::new(
//!     VaultarisConfig::new("https://auth.example.com").with_api_key("bearer-token"),
//! )?;
//!
//! // Each flow needs the user's bearer token (the API key on the client is for
//! // admin/server credentials; per-user passkey flows authenticate separately).
//! let reg_flow = client.webauthn_registration("user-bearer-token");
//! let auth_flow = client.webauthn_authentication("user-bearer-token");
//! # Ok(()) }
//! ```

use uuid::Uuid;

use crate::error::Error;
use crate::types::{
    AssertionResponse, AttestationResponse, AuthenticationBeginResponse, CreationOptions,
    RegistrationBeginResponse, RequestOptions, WebAuthnCredential,
};

// ============================================
// STATE MARKERS — REGISTRATION
// ============================================

/// Initial state for a registration flow.
#[derive(Clone)]
pub struct RegistrationIdle {
    pub(crate) device_name: Option<String>,
}

/// A registration challenge has been issued.
/// Holds the challenge ID and creation options ready to pass to the browser.
#[derive(Clone)]
pub struct RegistrationPending {
    pub(crate) challenge_id: Uuid,
    pub(crate) options: CreationOptions,
    pub(crate) device_name: Option<String>,
}

/// Registration completed — the server has stored the credential.
#[derive(Clone)]
pub struct RegistrationComplete {
    pub(crate) credential: WebAuthnCredential,
}

// ============================================
// STATE MARKERS — AUTHENTICATION
// ============================================

/// Initial state for an authentication flow.
#[derive(Clone)]
pub struct AuthenticationIdle;

/// An authentication challenge has been issued.
/// Holds the challenge ID and request options ready to pass to the browser.
#[derive(Clone)]
pub struct AuthenticationPending {
    pub(crate) challenge_id: Uuid,
    pub(crate) options: RequestOptions,
}

/// Authentication completed — the server has verified the signature.
#[derive(Clone)]
pub struct AuthenticationComplete {
    pub(crate) credential: WebAuthnCredential,
}

// ============================================
// REGISTRATION FLOW
// ============================================

/// Typestate registration flow.
///
/// Transitions:  `RegistrationIdle` → `RegistrationPending` → `RegistrationComplete`
#[derive(Clone)]
pub struct RegistrationFlow<S: Clone> {
    base_url: String,
    access_token: String,
    #[cfg(feature = "async")]
    http: reqwest::Client,
    state: S,
}

impl RegistrationFlow<RegistrationIdle> {
    /// Create a new registration flow.
    ///
    /// - `base_url` — Vaultaris server base URL
    /// - `access_token` — Bearer token of the **authenticated user** who is adding the passkey
    #[cfg(feature = "async")]
    pub fn new(base_url: impl Into<String>, access_token: impl Into<String>) -> Self {
        let http = reqwest::Client::builder()
            .user_agent(format!("vaultaris-sdk-rust/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("HTTP client build failed");

        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            access_token: access_token.into(),
            http,
            state: RegistrationIdle { device_name: None },
        }
    }

    /// Attach a human-readable label for the device being registered
    /// (e.g. `"MacBook Touch ID"`, `"YubiKey 5C"`).
    ///
    /// The label is stored on the server and shown in the credentials list.
    pub fn with_device_name(mut self, name: impl Into<String>) -> Self {
        self.state.device_name = Some(name.into());
        self
    }

    /// Call `POST /api/v1/mfa/webauthn/register/begin`.
    ///
    /// Returns a `RegistrationFlow<RegistrationPending>` whose `.options()` method
    /// yields the `CreationOptions` to pass to the browser's
    /// `navigator.credentials.create({ publicKey: options })`.
    #[cfg(feature = "async")]
    pub async fn begin(self) -> Result<RegistrationFlow<RegistrationPending>, Error> {
        let resp = self
            .http
            .post(format!(
                "{}/api/v1/mfa/webauthn/register/begin",
                self.base_url
            ))
            .bearer_auth(&self.access_token)
            .json(&serde_json::json!({}))
            .send()
            .await?;

        let status = resp.status();
        let body = resp.text().await.map_err(Error::from)?;

        if !status.is_success() {
            return Err(parse_api_error(status, &body));
        }

        let begin: RegistrationBeginResponse =
            serde_json::from_str(&body).map_err(|e| Error::Json(e.to_string()))?;

        Ok(RegistrationFlow {
            base_url: self.base_url,
            access_token: self.access_token,
            http: self.http,
            state: RegistrationPending {
                challenge_id: begin.challenge_id,
                options: begin.options,
                device_name: self.state.device_name,
            },
        })
    }
}

impl RegistrationFlow<RegistrationPending> {
    /// Creation options to pass to the browser.
    ///
    /// ```javascript
    /// const cred = await navigator.credentials.create({ publicKey: sdkOptions });
    /// ```
    ///
    /// The challenge embedded in these options is already stored on the server and
    /// will be verified when you call `complete()`.
    pub fn options(&self) -> &CreationOptions {
        &self.state.options
    }

    /// The challenge UUID — included in the `complete()` request automatically.
    /// You do **not** need to store this yourself.
    pub fn challenge_id(&self) -> Uuid {
        self.state.challenge_id
    }

    /// Call `POST /api/v1/mfa/webauthn/register/complete`.
    ///
    /// Pass the `AttestationResponse` built from the browser's `PublicKeyCredential`.
    /// The server verifies the attestation, checks the challenge, and stores the key.
    ///
    /// Consumes `self` — you cannot complete the same challenge twice.
    #[cfg(feature = "async")]
    pub async fn complete(
        self,
        attestation: AttestationResponse,
    ) -> Result<RegistrationFlow<RegistrationComplete>, Error> {
        let body = serde_json::json!({
            "challenge_id": self.state.challenge_id,
            "device_name": attestation.device_name.or(self.state.device_name),
            "id": attestation.id,
            "response": {
                "clientDataJSON": attestation.client_data_json,
                "attestationObject": attestation.attestation_object,
                "transports": attestation.transports,
            }
        });

        let resp = self
            .http
            .post(format!(
                "{}/api/v1/mfa/webauthn/register/complete",
                self.base_url
            ))
            .bearer_auth(&self.access_token)
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        let text = resp.text().await.map_err(Error::from)?;

        if !status.is_success() {
            return Err(parse_api_error(status, &text));
        }

        let credential = parse_credential_response(&text)?;

        Ok(RegistrationFlow {
            base_url: self.base_url,
            access_token: self.access_token,
            http: self.http,
            state: RegistrationComplete { credential },
        })
    }
}

impl RegistrationFlow<RegistrationComplete> {
    /// The credential that was stored on the server.
    pub fn credential(&self) -> &WebAuthnCredential {
        &self.state.credential
    }

    /// Consume the flow and return the credential.
    pub fn into_credential(self) -> WebAuthnCredential {
        self.state.credential
    }
}

// ============================================
// AUTHENTICATION FLOW
// ============================================

/// Typestate authentication flow.
///
/// Transitions: `AuthenticationIdle` → `AuthenticationPending` → `AuthenticationComplete`
#[derive(Clone)]
pub struct AuthenticationFlow<S: Clone> {
    base_url: String,
    access_token: String,
    #[cfg(feature = "async")]
    http: reqwest::Client,
    state: S,
}

impl AuthenticationFlow<AuthenticationIdle> {
    /// Create a new authentication flow.
    ///
    /// - `base_url` — Vaultaris server base URL
    /// - `access_token` — Bearer token of the user to authenticate
    #[cfg(feature = "async")]
    pub fn new(base_url: impl Into<String>, access_token: impl Into<String>) -> Self {
        let http = reqwest::Client::builder()
            .user_agent(format!("vaultaris-sdk-rust/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("HTTP client build failed");

        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            access_token: access_token.into(),
            http,
            state: AuthenticationIdle,
        }
    }

    /// Call `POST /api/v1/mfa/webauthn/authenticate/begin`.
    ///
    /// Returns a `AuthenticationFlow<AuthenticationPending>` whose `.options()` yields
    /// the `RequestOptions` to pass to `navigator.credentials.get({ publicKey: options })`.
    ///
    /// Returns `Err` if the user has no registered WebAuthn credentials.
    #[cfg(feature = "async")]
    pub async fn begin(self) -> Result<AuthenticationFlow<AuthenticationPending>, Error> {
        let resp = self
            .http
            .post(format!(
                "{}/api/v1/mfa/webauthn/authenticate/begin",
                self.base_url
            ))
            .bearer_auth(&self.access_token)
            .json(&serde_json::json!({}))
            .send()
            .await?;

        let status = resp.status();
        let body = resp.text().await.map_err(Error::from)?;

        if !status.is_success() {
            return Err(parse_api_error(status, &body));
        }

        let begin: AuthenticationBeginResponse =
            serde_json::from_str(&body).map_err(|e| Error::Json(e.to_string()))?;

        Ok(AuthenticationFlow {
            base_url: self.base_url,
            access_token: self.access_token,
            http: self.http,
            state: AuthenticationPending {
                challenge_id: begin.challenge_id,
                options: begin.options,
            },
        })
    }
}

impl AuthenticationFlow<AuthenticationPending> {
    /// Request options to pass to the browser.
    ///
    /// ```javascript
    /// const assertion = await navigator.credentials.get({ publicKey: sdkOptions });
    /// ```
    pub fn options(&self) -> &RequestOptions {
        &self.state.options
    }

    /// The challenge UUID — sent automatically in `complete()`.
    pub fn challenge_id(&self) -> Uuid {
        self.state.challenge_id
    }

    /// Call `POST /api/v1/mfa/webauthn/authenticate/complete`.
    ///
    /// Pass the `AssertionResponse` built from the browser's assertion.
    /// The server verifies the signature, updates the sign counter, and returns the credential.
    ///
    /// Consumes `self` — a challenge cannot be reused.
    #[cfg(feature = "async")]
    pub async fn complete(
        self,
        assertion: AssertionResponse,
    ) -> Result<AuthenticationFlow<AuthenticationComplete>, Error> {
        let body = serde_json::json!({
            "challenge_id": self.state.challenge_id,
            "id": assertion.id,
            "response": {
                "clientDataJSON": assertion.client_data_json,
                "authenticatorData": assertion.authenticator_data,
                "signature": assertion.signature,
                "userHandle": assertion.user_handle,
            }
        });

        let resp = self
            .http
            .post(format!(
                "{}/api/v1/mfa/webauthn/authenticate/complete",
                self.base_url
            ))
            .bearer_auth(&self.access_token)
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        let text = resp.text().await.map_err(Error::from)?;

        if !status.is_success() {
            return Err(parse_api_error(status, &text));
        }

        let credential = parse_credential_response(&text)?;

        Ok(AuthenticationFlow {
            base_url: self.base_url,
            access_token: self.access_token,
            http: self.http,
            state: AuthenticationComplete { credential },
        })
    }
}

impl AuthenticationFlow<AuthenticationComplete> {
    /// The credential that was used for this authentication.
    pub fn credential(&self) -> &WebAuthnCredential {
        &self.state.credential
    }

    /// Consume the flow and return the credential.
    pub fn into_credential(self) -> WebAuthnCredential {
        self.state.credential
    }
}

// ============================================
// VaultarisClient entry points
// ============================================

#[cfg(feature = "async")]
impl crate::client::VaultarisClient {
    /// Start a WebAuthn **registration** flow for the user identified by `access_token`.
    ///
    /// The client's configured base URL is reused automatically.
    /// Chain `.with_device_name()` before calling `.begin()`.
    ///
    /// ```rust,no_run
    /// # use vaultaris_sdk::{VaultarisClient, VaultarisConfig};
    /// # use vaultaris_sdk::types::AttestationResponse;
    /// # #[tokio::main] async fn main() -> Result<(), vaultaris_sdk::Error> {
    /// # let client = VaultarisClient::new(VaultarisConfig::new("http://localhost:8080").with_api_key("tok"))?;
    /// let pending = client
    ///     .webauthn_registration("user-bearer-token")
    ///     .with_device_name("YubiKey 5C")
    ///     .begin()
    ///     .await?;
    ///
    /// // pass pending.options() to the browser …
    ///
    /// let done = pending
    ///     .complete(AttestationResponse::new("id", "cdj", "ao"))
    ///     .await?;
    /// println!("{:?}", done.credential());
    /// # Ok(()) }
    /// ```
    pub fn webauthn_registration(
        &self,
        access_token: impl Into<String>,
    ) -> RegistrationFlow<RegistrationIdle> {
        RegistrationFlow::new(self.base_url(), access_token)
    }

    /// Start a WebAuthn **authentication** flow for the user identified by `access_token`.
    ///
    /// ```rust,no_run
    /// # use vaultaris_sdk::{VaultarisClient, VaultarisConfig};
    /// # use vaultaris_sdk::types::AssertionResponse;
    /// # #[tokio::main] async fn main() -> Result<(), vaultaris_sdk::Error> {
    /// # let client = VaultarisClient::new(VaultarisConfig::new("http://localhost:8080").with_api_key("tok"))?;
    /// let pending = client.webauthn_authentication("user-bearer-token").begin().await?;
    ///
    /// // pass pending.options() to the browser …
    ///
    /// let done = pending
    ///     .complete(AssertionResponse::new("id", "cdj", "authData", "sig"))
    ///     .await?;
    /// println!("{:?}", done.credential());
    /// # Ok(()) }
    /// ```
    pub fn webauthn_authentication(
        &self,
        access_token: impl Into<String>,
    ) -> AuthenticationFlow<AuthenticationIdle> {
        AuthenticationFlow::new(self.base_url(), access_token)
    }
}

// ============================================
// INTERNAL HELPERS
// ============================================

/// Parse an API error body into an SDK `Error`.
fn parse_api_error(status: reqwest::StatusCode, body: &str) -> Error {
    #[derive(serde::Deserialize)]
    struct ApiErr {
        message: Option<String>,
        error: Option<String>,
    }

    let msg = serde_json::from_str::<ApiErr>(body)
        .ok()
        .and_then(|e| e.message.or(e.error))
        .unwrap_or_else(|| body.to_string());

    match status.as_u16() {
        400 => Error::Auth(msg),
        401 => Error::Auth(format!("Unauthorized: {}", msg)),
        403 => Error::PermissionDenied(msg),
        404 => Error::NotFound(msg),
        429 => Error::RateLimited,
        _ => Error::Server(format!("HTTP {}: {}", status, msg)),
    }
}

/// Extract `WebAuthnCredential` from an `{ success, data: { ... } }` envelope
/// or a direct JSON object.
fn parse_credential_response(body: &str) -> Result<WebAuthnCredential, Error> {
    #[derive(serde::Deserialize)]
    struct Envelope {
        data: WebAuthnCredential,
    }

    if let Ok(env) = serde_json::from_str::<Envelope>(body) {
        return Ok(env.data);
    }
    serde_json::from_str::<WebAuthnCredential>(body).map_err(|e| Error::Json(e.to_string()))
}
