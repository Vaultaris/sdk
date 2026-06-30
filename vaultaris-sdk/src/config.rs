//! SDK configuration.
//!
//! `VaultarisConfig` is the immutable settings object the client is built
//! from. Construct it with [`VaultarisConfig::new`] then chain the
//! `with_*` methods, or load from env with [`VaultarisConfigBuilder`].

use crate::error::{Error, Result};

/// Authentication scheme used on the wire.
///
/// Defaults to `ApiKey` — matches the server's
/// `Authorization: ApiKey <token>` / `X-Api-Key` extractor. `Bearer` is kept
/// as an opt-in for OAuth-issued access tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthScheme {
    /// `Authorization: ApiKey <token>` — Vaultaris API keys (default).
    #[default]
    ApiKey,
    /// `Authorization: Bearer <token>` — OAuth-issued access tokens.
    Bearer,
}

impl AuthScheme {
    fn header_prefix(self) -> &'static str {
        match self {
            Self::ApiKey => "ApiKey",
            Self::Bearer => "Bearer",
        }
    }
}

/// Configuration for [`crate::VaultarisClient`].
#[derive(Clone)]
pub struct VaultarisConfig {
    /// Base URL of the Vaultaris server (no trailing slash).
    pub base_url: String,
    /// Bearer/ApiKey token presented to the server.
    pub api_key: Option<String>,
    /// OAuth2 client_id for client-credentials flow.
    pub client_id: Option<String>,
    /// OAuth2 client_secret for client-credentials flow.
    pub client_secret: Option<String>,
    /// Default tenant ID — currently informational only; resource calls
    /// take their tenant_id explicitly.
    pub tenant_id: Option<String>,
    /// Per-request timeout.
    pub timeout: std::time::Duration,
    /// Whether to verify TLS certificates.
    pub verify_tls: bool,
    /// User-Agent override.
    pub user_agent: Option<String>,
    /// Wire auth scheme. Defaults to `ApiKey`. DPoP forces `DPoP` regardless.
    pub auth_scheme: AuthScheme,
    /// DPoP signer. When `Some`, every request gets a fresh proof and the
    /// auth scheme is `DPoP` per RFC 9449 §7.1.
    #[cfg(feature = "dpop")]
    pub dpop_signer: Option<std::sync::Arc<dyn crate::dpop::DpopSigner>>,
    /// Optional device fingerprint sent via `X-Device-Fingerprint`.
    pub device_fingerprint: Option<String>,
}

impl std::fmt::Debug for VaultarisConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("VaultarisConfig");
        s.field("base_url", &self.base_url)
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("tenant_id", &self.tenant_id)
            .field("timeout", &self.timeout)
            .field("verify_tls", &self.verify_tls)
            .field("user_agent", &self.user_agent)
            .field("auth_scheme", &self.auth_scheme);
        #[cfg(feature = "dpop")]
        s.field(
            "dpop_signer",
            &self.dpop_signer.as_ref().map(|s| s.jkt().to_string()),
        );
        s.finish()
    }
}

impl Default for VaultarisConfig {
    fn default() -> Self {
        Self {
            base_url: "http://localhost:8080".to_string(),
            api_key: None,
            client_id: None,
            client_secret: None,
            tenant_id: None,
            timeout: std::time::Duration::from_secs(30),
            verify_tls: true,
            user_agent: None,
            auth_scheme: AuthScheme::default(),
            #[cfg(feature = "dpop")]
            dpop_signer: None,
            device_fingerprint: None,
        }
    }
}

impl VaultarisConfig {
    /// Construct a fresh config with a base URL. All other fields default.
    #[must_use]
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            ..Self::default()
        }
    }

    /// Enable DPoP using the default in-memory ES256 signer.
    #[cfg(feature = "dpop")]
    #[must_use]
    pub fn with_dpop_key(self, key: crate::dpop::DpopKey) -> Self {
        self.with_dpop_signer(std::sync::Arc::new(key))
    }

    /// Enable DPoP with a custom signer — HSM, cloud KMS, TPM, etc.
    #[cfg(feature = "dpop")]
    #[must_use]
    pub fn with_dpop_signer(mut self, signer: std::sync::Arc<dyn crate::dpop::DpopSigner>) -> Self {
        self.dpop_signer = Some(signer);
        self
    }

    /// Set the API key (or OAuth access token).
    #[must_use]
    pub fn with_api_key(mut self, api_key: impl Into<String>) -> Self {
        self.api_key = Some(api_key.into());
        self
    }

    /// Set OAuth2 client credentials (used by the `oauth` module's
    /// client-credentials flow).
    #[must_use]
    pub fn with_client_credentials(
        mut self,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        self.client_id = Some(client_id.into());
        self.client_secret = Some(client_secret.into());
        self
    }

    /// Set the default tenant ID (informational; not auto-applied).
    #[must_use]
    pub fn with_tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Override the per-request timeout. Defaults to 30s.
    #[must_use]
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Disable TLS verification — never use in production.
    #[must_use]
    pub fn without_tls_verify(mut self) -> Self {
        self.verify_tls = false;
        self
    }

    /// Override the User-Agent.
    #[must_use]
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// Force a specific wire auth scheme. Defaults to `ApiKey`. Pass
    /// `AuthScheme::Bearer` when carrying an OAuth access token rather than
    /// a Vaultaris API key.
    #[must_use]
    pub fn with_auth_scheme(mut self, scheme: AuthScheme) -> Self {
        self.auth_scheme = scheme;
        self
    }

    /// Attach a pre-computed device fingerprint.
    #[must_use]
    pub fn with_device_fingerprint(mut self, fingerprint: impl Into<String>) -> Self {
        self.device_fingerprint = Some(fingerprint.into());
        self
    }

    /// Auto-compute the device fingerprint from local machine signals.
    #[must_use]
    pub fn with_auto_fingerprint(self) -> Self {
        self.with_device_fingerprint(crate::fingerprint::compute_fingerprint())
    }

    /// Validate the configuration before building a client.
    ///
    /// # Errors
    /// Returns `Error::Config` for an empty `base_url`, or
    /// `Error::InvalidUrl` if it cannot be parsed.
    pub fn validate(&self) -> Result<()> {
        if self.base_url.is_empty() {
            return Err(Error::Config("Base URL is required".to_string()));
        }
        url::Url::parse(&self.base_url)?;
        Ok(())
    }

    /// Build the wire `Authorization` header value (None if no key).
    ///
    /// `DPoP` is selected when a signer is configured (RFC 9449 §7.1);
    /// otherwise `auth_scheme` decides.
    #[must_use]
    pub fn auth_header(&self) -> Option<String> {
        let token = self.api_key.as_ref()?;
        #[cfg(feature = "dpop")]
        if self.dpop_signer.is_some() {
            return Some(format!("DPoP {token}"));
        }
        Some(format!("{} {token}", self.auth_scheme.header_prefix()))
    }

    /// When DPoP is configured, return the freshly-signed proof JWT.
    #[cfg(feature = "dpop")]
    pub async fn dpop_proof(&self, method: &str, url: &str) -> Option<Result<String>> {
        let signer = self.dpop_signer.as_ref()?;
        Some(
            crate::dpop::sign_proof_with(signer.as_ref(), method, url, self.api_key.as_deref())
                .await,
        )
    }

    /// Join `path` (must start with `/`) onto `base_url`.
    #[must_use]
    pub fn build_url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

/// Builder that loads config from environment variables.
///
/// Recognised vars (all `VAULTARIS_*`):
/// - `VAULTARIS_URL` — base URL
/// - `VAULTARIS_API_KEY` — API key
/// - `VAULTARIS_CLIENT_ID` / `VAULTARIS_CLIENT_SECRET` — OAuth client credentials
/// - `VAULTARIS_TENANT_ID` — default tenant
/// - `VAULTARIS_TIMEOUT` — per-request timeout in seconds
/// - `VAULTARIS_VERIFY_TLS` — `"false"` disables TLS verification
/// - `VAULTARIS_AUTH_SCHEME` — `"apikey"` (default) or `"bearer"`
#[derive(Default)]
pub struct VaultarisConfigBuilder {
    config: VaultarisConfig,
}

impl VaultarisConfigBuilder {
    /// Construct an empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Read every recognised `VAULTARIS_*` variable from the process env.
    #[must_use]
    pub fn from_env(mut self) -> Self {
        if let Ok(url) = std::env::var("VAULTARIS_URL") {
            self.config.base_url = url.trim_end_matches('/').to_string();
        }
        if let Ok(key) = std::env::var("VAULTARIS_API_KEY") {
            self.config.api_key = Some(key);
        }
        if let Ok(client_id) = std::env::var("VAULTARIS_CLIENT_ID") {
            self.config.client_id = Some(client_id);
        }
        if let Ok(secret) = std::env::var("VAULTARIS_CLIENT_SECRET") {
            self.config.client_secret = Some(secret);
        }
        if let Ok(tenant) = std::env::var("VAULTARIS_TENANT_ID") {
            self.config.tenant_id = Some(tenant);
        }
        if let Ok(timeout) = std::env::var("VAULTARIS_TIMEOUT")
            && let Ok(secs) = timeout.parse::<u64>()
        {
            self.config.timeout = std::time::Duration::from_secs(secs);
        }
        if let Ok(verify) = std::env::var("VAULTARIS_VERIFY_TLS") {
            self.config.verify_tls = !verify.eq_ignore_ascii_case("false");
        }
        if let Ok(scheme) = std::env::var("VAULTARIS_AUTH_SCHEME") {
            self.config.auth_scheme = match scheme.to_ascii_lowercase().as_str() {
                "bearer" => AuthScheme::Bearer,
                _ => AuthScheme::ApiKey,
            };
        }
        self
    }

    /// Finalise into a validated [`VaultarisConfig`].
    ///
    /// # Errors
    /// See [`VaultarisConfig::validate`].
    pub fn build(self) -> Result<VaultarisConfig> {
        self.config.validate()?;
        Ok(self.config)
    }
}
