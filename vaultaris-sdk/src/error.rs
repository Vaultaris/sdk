//! SDK Error types

use thiserror::Error;

/// Error type for Vaultaris SDK operations
#[derive(Debug, Error)]
pub enum Error {
    /// HTTP request failed
    #[error("HTTP request failed: {0}")]
    Http(String),

    /// Failed to parse JSON response
    #[error("JSON parsing failed: {0}")]
    Json(String),

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    Config(String),

    /// Authentication failed
    #[error("Authentication failed: {0}")]
    Auth(String),

    /// Permission denied
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Resource not found
    #[error("Resource not found: {0}")]
    NotFound(String),

    /// Rate limit exceeded
    #[error("Rate limit exceeded")]
    RateLimited,

    /// Server error
    #[error("Server error: {0}")]
    Server(String),

    /// Network error
    #[error("Network error: {0}")]
    Network(String),

    /// Token validation failed
    #[error("Token validation failed: {0}")]
    TokenInvalid(String),

    /// Token expired
    #[error("Token expired")]
    TokenExpired,

    /// Invalid URL
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),
}

#[cfg(feature = "async")]
impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            Error::Network("Request timed out".to_string())
        } else if err.is_connect() {
            Error::Network("Failed to connect".to_string())
        } else if err.is_status() {
            match err.status() {
                Some(status) if status.as_u16() == 401 => Error::Auth("Unauthorized".to_string()),
                Some(status) if status.as_u16() == 403 => {
                    Error::PermissionDenied("Forbidden".to_string())
                }
                Some(status) if status.as_u16() == 404 => Error::NotFound("Not found".to_string()),
                Some(status) if status.as_u16() == 429 => Error::RateLimited,
                Some(status) if status.as_u16() >= 500 => {
                    Error::Server(format!("Server error: {}", status))
                }
                _ => Error::Http(err.to_string()),
            }
        } else {
            Error::Http(err.to_string())
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Json(err.to_string())
    }
}

impl From<url::ParseError> for Error {
    fn from(err: url::ParseError) -> Self {
        Error::InvalidUrl(err.to_string())
    }
}
