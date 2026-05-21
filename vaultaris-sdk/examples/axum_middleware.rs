//! Axum middleware / extractor example
//!
//! Scenario: A REST API that protects routes using Vaultaris for both
//! token validation and permission checks. The VaultarisClient lives in
//! Axum shared state and is called from a custom extractor.
//!
//! Run with:
//!   VAULTARA_URL=http://localhost:8080 VAULTARA_API_KEY=your-key \
//!   cargo run --example axum_middleware
//!
//! Then test:
//!   curl -H "Authorization: Bearer <token>" http://localhost:3000/protected
//!   curl -H "Authorization: Bearer <token>" http://localhost:3000/admin

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{FromRef, FromRequestParts, State},
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::json;
use vaultaris_sdk::{Error as VaultarisError, TokenValidation, VaultarisClient};

// ────────────────────────────────────────────────────────────────────────────
// Shared application state
// ────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    vaultaris: Arc<VaultarisClient>,
    tenant_id: String,
}

// ────────────────────────────────────────────────────────────────────────────
// Custom extractor: ValidatedUser
//
// Validates the Bearer token from the Authorization header.
// Handlers that take this extractor will receive a 401 automatically if the
// token is missing or invalid.
// ────────────────────────────────────────────────────────────────────────────

struct ValidatedUser(TokenValidation);

impl<S> FromRequestParts<S> for ValidatedUser
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);

        let token = parts
            .headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({ "error": "Missing Authorization header" })),
                )
                    .into_response()
            })?;

        let validation = app_state
            .vaultaris
            .validate_token(token)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": e.to_string() })),
                )
                    .into_response()
            })?;

        if !validation.valid {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": validation.error.unwrap_or_else(|| "invalid token".into())
                })),
            )
                .into_response());
        }

        Ok(ValidatedUser(validation))
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Handlers
// ────────────────────────────────────────────────────────────────────────────

/// Open endpoint — no auth required
async fn public_handler() -> impl IntoResponse {
    Json(json!({ "message": "This endpoint is public" }))
}

/// Protected endpoint — requires a valid token
async fn protected_handler(ValidatedUser(user): ValidatedUser) -> impl IntoResponse {
    Json(json!({
        "message": "You are authenticated",
        "username": user.username,
        "roles": user.roles,
    }))
}

/// Admin endpoint — requires a valid token AND the users:manage permission
async fn admin_handler(
    State(state): State<AppState>,
    ValidatedUser(user): ValidatedUser,
) -> Response {
    let user_id = match user.user_id {
        Some(id) => id.to_string(),
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "token missing user_id" })),
            )
                .into_response();
        }
    };

    match state
        .vaultaris
        .require_permission(&state.tenant_id, &user_id, "users", "manage")
        .await
    {
        Ok(()) => Json(json!({
            "message": "Welcome, admin!",
            "user_id": user_id,
        }))
        .into_response(),

        Err(VaultarisError::PermissionDenied(_)) => (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Insufficient permissions" })),
        )
            .into_response(),

        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Main
// ────────────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let vaultaris = VaultarisClient::from_env()?;
    let tenant_id = std::env::var("EXAMPLE_TENANT_ID")
        .unwrap_or_else(|_| "00000000-0000-0000-0000-000000000001".into());

    let state = AppState {
        vaultaris: Arc::new(vaultaris),
        tenant_id,
    };

    let app = Router::new()
        .route("/public", get(public_handler))
        .route("/protected", get(protected_handler))
        .route("/admin", get(admin_handler))
        .with_state(state);

    let addr = "0.0.0.0:3000";
    println!("Listening on http://{}", addr);
    println!("  GET /public      - no auth required");
    println!("  GET /protected   - valid token required");
    println!("  GET /admin       - valid token + users:manage required");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
