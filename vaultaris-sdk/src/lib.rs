//! Vaultaris SDK — client library for integrating with Vaultaris IAM.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use vaultaris_sdk::{VaultarisClient, VaultarisConfig};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), vaultaris_sdk::Error> {
//! let config = VaultarisConfig::new("https://auth.example.com")
//!     .with_api_key("vk_live_...");
//! let client = VaultarisClient::try_from(config)?;
//!
//! let validation = client.validate_token("user-token").await?;
//! if validation.valid {
//!     println!("user: {}", validation.username.unwrap_or_default());
//! }
//! # Ok(()) }
//! ```
//!
//! # Auth schemes
//!
//! The SDK speaks two schemes on the wire, selected by [`config::AuthScheme`]:
//!
//! - `ApiKey` (default) — `Authorization: ApiKey <token>`, matching the
//!   server's API-key extractor.
//! - `Bearer` — for OAuth-issued access tokens.
//!
//! With the `dpop` feature and a configured signer, every request also
//! carries a freshly-signed DPoP proof (RFC 9449).
//!
//! # Environment variables
//!
//! [`VaultarisClient::from_env`] reads:
//!
//! - `VAULTARIS_URL` — base URL
//! - `VAULTARIS_API_KEY` — API key or token
//! - `VAULTARIS_CLIENT_ID` / `VAULTARIS_CLIENT_SECRET` — OAuth client credentials
//! - `VAULTARIS_TENANT_ID` — default tenant
//! - `VAULTARIS_TIMEOUT` — per-request timeout (seconds)
//! - `VAULTARIS_VERIFY_TLS` — `"false"` to disable
//! - `VAULTARIS_AUTH_SCHEME` — `"apikey"` (default) or `"bearer"`

pub mod client;
pub mod config;
#[cfg(feature = "dpop")]
pub mod dpop;
pub mod error;
pub mod fingerprint;
pub mod oauth;
pub mod types;
pub mod webauthn;
pub mod workflows;

#[cfg(feature = "python")]
pub mod python;

pub use client::VaultarisClient;
pub use config::{AuthScheme, VaultarisConfig, VaultarisConfigBuilder};
#[cfg(feature = "dpop")]
pub use dpop::{DpopKey, DpopPublicJwk, DpopSigner};
pub use error::{ApiErrorKind, Error, Result};
pub use types::*;
