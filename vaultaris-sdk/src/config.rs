//! SDK configuration

use crate::Error;

/// Configuration for the Vaultaris client
#[derive(Clone)]
pub struct VaultarisConfig {
    /// Base URL of the Vaultaris server
    pub base_url: String,
    /// API key for authentication
    pub api_key: Option<String>,
    /// Client ID for OAuth2 client credentials flow
    pub client_id: Option<String>,
    /// Client secret for OAuth2 client credentials flow
    pub client_secret: Option<String>,
    /// Default tenant ID
    pub tenant_id: Option<String>,
    /// Request timeout in seconds
    pub timeout_seconds: u64,
    /// Whether to verify TLS certificates
    pub verify_tls: bool,
    /// Custom user agent string
    pub user_agent: Option<String>,
    /// Optional DPoP signer. When present, the client attaches a fresh
    /// DPoP proof to every outgoing request and switches the Authorization
    /// scheme from `Bearer` to `DPoP`. The default in-process backend is
    /// [`crate::dpop::DpopKey`]; HSM / KMS / Secure-Enclave deployments
    /// can plug in any implementation of [`crate::dpop::DpopSigner`].
    #[cfg(feature = "dpop")]
    pub dpop_signer: Option<std::sync::Arc<dyn crate::dpop::DpopSigner>>,
    /// Device fingerprint sent via `X-Device-Fingerprint` header. When
    /// `None`, no fingerprint header is sent. Set to `Some(fp)` to send
    /// a pre-computed fingerprint, or call [`Self::with_auto_fingerprint`]
    /// to auto-compute from machine signals.
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
            .field("timeout_seconds", &self.timeout_seconds)
            .field("verify_tls", &self.verify_tls)
            .field("user_agent", &self.user_agent);
        #[cfg(feature = "dpop")]
        s.field(
            "dpop_signer",
            &self.dpop_signer.as_ref().map(|s| s.jkt().to_string()),
        );
        s.finish()
    }
}

impl VaultarisConfig {
    /// Create a new configuration with the base URL
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            api_key: None,
            client_id: None,
            client_secret: None,
            tenant_id: None,
            timeout_seconds: 30,
            verify_tls: true,
            user_agent: None,
            #[cfg(feature = "dpop")]
            dpop_signer: None,
            device_fingerprint: None,
        }
    }

    /// Enable DPoP using the default in-memory ES256 signer. Convenience
    /// wrapper around [`Self::with_dpop_signer`].
    #[cfg(feature = "dpop")]
    pub fn with_dpop_key(self, key: crate::dpop::DpopKey) -> Self {
        self.with_dpop_signer(std::sync::Arc::new(key))
    }

    /// Enable DPoP with a custom signer — typically an HSM, cloud KMS,
    /// TPM or platform keystore where the private key never enters the
    /// process. Anything implementing [`crate::dpop::DpopSigner`] works.
    #[cfg(feature = "dpop")]
    pub fn with_dpop_signer(
        mut self,
        signer: std::sync::Arc<dyn crate::dpop::DpopSigner>,
    ) -> Self {
        self.dpop_signer = Some(signer);
        self
    }

    /// Set the API key for authentication
    pub fn with_api_key(mut self, api_key: impl Into<String>) -> Self {
        self.api_key = Some(api_key.into());
        self
    }

    /// Set OAuth2 client credentials
    pub fn with_client_credentials(
        mut self,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        self.client_id = Some(client_id.into());
        self.client_secret = Some(client_secret.into());
        self
    }

    /// Set the default tenant ID
    pub fn with_tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Set request timeout
    pub fn with_timeout(mut self, seconds: u64) -> Self {
        self.timeout_seconds = seconds;
        self
    }

    /// Disable TLS verification (not recommended for production)
    pub fn without_tls_verify(mut self) -> Self {
        self.verify_tls = false;
        self
    }

    /// Set custom user agent
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// Set a pre-computed device fingerprint.
    pub fn with_device_fingerprint(mut self, fingerprint: impl Into<String>) -> Self {
        self.device_fingerprint = Some(fingerprint.into());
        self
    }

    /// Auto-compute the device fingerprint from machine signals (OS,
    /// architecture, hostname hash). Equivalent to calling
    /// [`with_device_fingerprint`] with [`crate::fingerprint::compute_fingerprint()`].
    pub fn with_auto_fingerprint(self) -> Self {
        self.with_device_fingerprint(crate::fingerprint::compute_fingerprint())
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), Error> {
        if self.base_url.is_empty() {
            return Err(Error::Config("Base URL is required".to_string()));
        }

        // Parse URL to validate format
        url::Url::parse(&self.base_url)?;

        Ok(())
    }

    /// Get authorization header value. When DPoP is configured, the scheme
    /// switches from `Bearer` to `DPoP` per RFC 9449 §7.1.
    pub fn auth_header(&self) -> Option<String> {
        let token = self.api_key.as_ref()?;
        #[cfg(feature = "dpop")]
        if self.dpop_signer.is_some() {
            return Some(format!("DPoP {}", token));
        }
        Some(format!("Bearer {}", token))
    }

    /// When DPoP is configured, returns the freshly signed proof JWT for
    /// the given request — `None` otherwise. Used internally by the
    /// transport to inject the `DPoP` header.
    #[cfg(feature = "dpop")]
    pub async fn dpop_proof(
        &self,
        method: &str,
        url: &str,
    ) -> Option<Result<String, Error>> {
        let signer = self.dpop_signer.as_ref()?;
        Some(
            crate::dpop::sign_proof_with(signer.as_ref(), method, url, self.api_key.as_deref())
                .await,
        )
    }

    /// Build the URL for an endpoint
    pub fn build_url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

impl Default for VaultarisConfig {
    fn default() -> Self {
        Self::new("http://localhost:8080")
    }
}

/// Builder for creating configuration from environment variables
pub struct VaultarisConfigBuilder {
    config: VaultarisConfig,
}

impl VaultarisConfigBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            config: VaultarisConfig::default(),
        }
    }

    /// Load configuration from environment variables
    ///
    /// Looks for:
    /// - `VAULTARA_URL`: Base URL
    /// - `VAULTARA_API_KEY`: API key
    /// - `VAULTARA_CLIENT_ID`: OAuth2 client ID
    /// - `VAULTARA_CLIENT_SECRET`: OAuth2 client secret
    /// - `VAULTARA_TENANT_ID`: Default tenant ID
    /// - `VAULTARA_TIMEOUT`: Request timeout in seconds
    /// - `VAULTARA_VERIFY_TLS`: Whether to verify TLS (true/false)
    pub fn from_env(mut self) -> Self {
        if let Ok(url) = std::env::var("VAULTARA_URL") {
            self.config.base_url = url.trim_end_matches('/').to_string();
        }

        if let Ok(key) = std::env::var("VAULTARA_API_KEY") {
            self.config.api_key = Some(key);
        }

        if let Ok(client_id) = std::env::var("VAULTARA_CLIENT_ID") {
            self.config.client_id = Some(client_id);
        }

        if let Ok(secret) = std::env::var("VAULTARA_CLIENT_SECRET") {
            self.config.client_secret = Some(secret);
        }

        if let Ok(tenant) = std::env::var("VAULTARA_TENANT_ID") {
            self.config.tenant_id = Some(tenant);
        }

        if let Ok(timeout) = std::env::var("VAULTARA_TIMEOUT")
            && let Ok(secs) = timeout.parse()
        {
            self.config.timeout_seconds = secs;
        }

        if let Ok(verify) = std::env::var("VAULTARA_VERIFY_TLS") {
            self.config.verify_tls = verify.to_lowercase() != "false";
        }

        self
    }

    /// Build the configuration
    pub fn build(self) -> Result<VaultarisConfig, Error> {
        self.config.validate()?;
        Ok(self.config)
    }
}

impl Default for VaultarisConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}
