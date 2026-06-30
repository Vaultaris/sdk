//! SDK error types.
//!
//! Errors are typed per failure domain; callers can match on the variant
//! to react to specific conditions (rate limiting, auth, validation, …)
//! without parsing strings.

use thiserror::Error;

/// Result alias used throughout the SDK.
pub type Result<T> = std::result::Result<T, Error>;

/// Top-level SDK error.
///
/// `Api`/`Transport`/`Codec` cover the three layers a request can fail at:
/// the remote returned an HTTP error, the wire failed before it could, or the
/// payload could not be (de)serialised. `Config` and `InvalidArgument` are
/// caller-side mistakes — the SDK never produces them from the network.
#[derive(Debug, Error)]
pub enum Error {
    /// Remote returned a non-success HTTP status. `status` is the response
    /// code; `message` is the server-supplied body (when present).
    #[error("Vaultaris API error: HTTP {status}: {message}")]
    Api {
        status: u16,
        kind: ApiErrorKind,
        message: String,
    },

    /// Rate limit hit. Separated from `Api` because most callers retry
    /// with backoff rather than surfacing the failure.
    #[error("rate limit exceeded")]
    RateLimited,

    /// Transport-layer failure (connect refused, TLS handshake, timeout).
    #[cfg(feature = "async")]
    #[error("HTTP transport error: {0}")]
    Transport(#[from] reqwest::Error),

    /// JSON encode/decode failed.
    #[error("JSON codec error: {0}")]
    Codec(#[from] serde_json::Error),

    /// Configuration is malformed (empty base URL, unparseable URL, …).
    #[error("invalid configuration: {0}")]
    Config(String),

    /// Caller passed an argument the SDK refuses (e.g. malformed UUID).
    #[error("invalid argument `{name}`: {reason}")]
    InvalidArgument { name: &'static str, reason: String },

    /// URL parsing failed.
    #[error("invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),

    /// DPoP proof signing failed.
    #[cfg(feature = "dpop")]
    #[error("DPoP signing failed: {0}")]
    Dpop(String),

    /// Workflow helper rejected a permission check (caller-side, not a
    /// server response).
    #[error("permission denied: user {user_id} lacks {resource}:{action} on tenant {tenant_id}")]
    PermissionDenied {
        tenant_id: uuid::Uuid,
        user_id: uuid::Uuid,
        resource: String,
        action: String,
    },

    /// Workflow helper considered a token invalid (missing claims or
    /// `valid: false` response).
    #[error("token invalid: {0}")]
    TokenInvalid(String),
}

/// Classification of an API failure derived from the response status.
///
/// Lets callers match on the *meaning* of an HTTP error without copying the
/// status table around.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiErrorKind {
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    UnprocessableEntity,
    BadRequest,
    Server,
    Other,
}

impl ApiErrorKind {
    #[must_use]
    pub fn from_status(status: u16) -> Self {
        match status {
            400 => Self::BadRequest,
            401 => Self::Unauthorized,
            403 => Self::Forbidden,
            404 => Self::NotFound,
            409 => Self::Conflict,
            422 => Self::UnprocessableEntity,
            500..=599 => Self::Server,
            _ => Self::Other,
        }
    }
}

impl Error {
    /// Build an `Api` variant from a status code and body.
    #[must_use]
    pub fn from_response(status: u16, body: String) -> Self {
        if status == 429 {
            return Self::RateLimited;
        }
        Self::Api {
            status,
            kind: ApiErrorKind::from_status(status),
            message: body,
        }
    }

    /// Build an invalid-argument error.
    pub fn invalid_argument(name: &'static str, reason: impl Into<String>) -> Self {
        Self::InvalidArgument {
            name,
            reason: reason.into(),
        }
    }

    /// Shorthand: is the error a 401?
    #[must_use]
    pub fn is_unauthorized(&self) -> bool {
        matches!(
            self,
            Self::Api {
                kind: ApiErrorKind::Unauthorized,
                ..
            }
        )
    }

    /// Shorthand: is the error a 404?
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        matches!(
            self,
            Self::Api {
                kind: ApiErrorKind::NotFound,
                ..
            }
        )
    }
}
