//! Vaultaris SDK - Client library for integrating with Vaultaris IAM
//!
//! This library provides a simple and ergonomic way to integrate your applications
//! with Vaultaris Identity and Access Management platform.
//!
//! # Features
//!
//! - **Token validation**: Validate access tokens issued by Vaultaris
//! - **Permission checking**: Check if users have specific permissions
//! - **Session management**: Validate and manage user sessions
//! - **User information**: Retrieve user details and attributes
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use vaultaris_sdk::{VaultarisClient, VaultarisConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), vaultaris_sdk::Error> {
//!     // Create a client
//!     let config = VaultarisConfig::new("http://localhost:8080")
//!         .with_api_key("your-api-key");
//!     let client = VaultarisClient::new(config)?;
//!
//!     // Validate a token
//!     let validation = client.validate_token("user-token").await?;
//!     if validation.valid {
//!         println!("User: {}", validation.username.unwrap_or_default());
//!     }
//!
//!     // Check permissions
//!     let allowed = client
//!         .check_permission("tenant-id", "user-id", "orders", "create")
//!         .await?;
//!     if allowed {
//!         println!("User can create orders!");
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! # Middleware Integration
//!
//! The SDK can be used as middleware in web frameworks:
//!
//! ```rust,ignore
//! use vaultaris_sdk::middleware::VaultarisAuth;
//!
//! // Axum example
//! let app = Router::new()
//!     .route("/protected", get(protected_handler))
//!     .layer(VaultarisAuth::new(client));
//! ```

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
pub use config::VaultarisConfig;
#[cfg(feature = "dpop")]
pub use dpop::{DpopKey, DpopPublicJwk, DpopSigner};
pub use error::Error;
pub use types::*;

/// Result type alias for Vaultaris SDK operations
pub type Result<T> = std::result::Result<T, Error>;
