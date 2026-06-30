//! Vaultaris HTTP client — module root.
//!
//! [`VaultarisClient`] owns the `reqwest::Client`, the per-request auth
//! pipeline, and the response envelope handling. Resource methods (users,
//! roles, tenants, …) live in `client/<resource>.rs`, each adding its own
//! `impl VaultarisClient` block beside the type.
//
// Every resource method may return either a transport error
// (`Error::Transport`) or a typed API error (`Error::Api`/`Error::RateLimited`).
// Repeating that on every method's `# Errors` block would be noise, so the
// pedantic lint is silenced module-wide here.
#![allow(clippy::missing_errors_doc)]

#[cfg(feature = "async")]
mod transport;

mod api_keys;
mod applications;
mod audit;
mod auth;
mod devices;
mod groups;
mod identity_providers;
mod integration;
mod keys;
mod mfa;
mod oauth_clients;
mod oauth_tokens;
mod permissions;
mod policies;
mod roles;
mod sessions;
mod setup;
mod statistics;
mod templates;
mod tenants;
mod users;

use crate::config::VaultarisConfig;
use crate::error::{Error, Result};

/// Vaultaris SDK client.
///
/// Build it from a [`VaultarisConfig`] via [`TryFrom`]:
///
/// ```rust,no_run
/// use vaultaris_sdk::{VaultarisClient, VaultarisConfig};
///
/// # fn main() -> Result<(), vaultaris_sdk::Error> {
/// let config = VaultarisConfig::new("https://auth.example.com")
///     .with_api_key("vk_live_...");
/// let client = VaultarisClient::try_from(config)?;
/// # Ok(()) }
/// ```
#[derive(Clone)]
pub struct VaultarisClient {
    pub(crate) config: VaultarisConfig,
    #[cfg(feature = "async")]
    pub(crate) http: reqwest::Client,
}

#[cfg(feature = "async")]
impl TryFrom<VaultarisConfig> for VaultarisClient {
    type Error = Error;

    fn try_from(config: VaultarisConfig) -> Result<Self> {
        config.validate()?;

        let ua = config
            .user_agent
            .clone()
            .unwrap_or_else(|| format!("vaultaris-sdk-rust/{}", env!("CARGO_PKG_VERSION")));

        let mut builder = reqwest::Client::builder()
            .timeout(config.timeout)
            .user_agent(ua);
        if !config.verify_tls {
            builder = builder.danger_accept_invalid_certs(true);
        }
        let http = builder.build()?;

        Ok(Self { config, http })
    }
}

impl VaultarisClient {
    /// Construct a client by reading every `VAULTARIS_*` env variable.
    ///
    /// # Errors
    /// Same conditions as [`TryFrom<VaultarisConfig>`].
    #[cfg(feature = "async")]
    pub fn from_env() -> Result<Self> {
        let config = crate::config::VaultarisConfigBuilder::new()
            .from_env()
            .build()?;
        Self::try_from(config)
    }

    /// Base URL the client is pointed at.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.config.base_url
    }

    /// Default tenant ID, if one was configured.
    #[must_use]
    pub fn tenant_id(&self) -> Option<&str> {
        self.config.tenant_id.as_deref()
    }

    /// Borrow the underlying configuration. Useful for the OAuth flow
    /// builder which needs to derive a new client from this one.
    #[must_use]
    pub fn config(&self) -> &VaultarisConfig {
        &self.config
    }
}

impl std::fmt::Debug for VaultarisClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultarisClient")
            .field("base_url", &self.config.base_url)
            .field("has_api_key", &self.config.api_key.is_some())
            .finish()
    }
}
