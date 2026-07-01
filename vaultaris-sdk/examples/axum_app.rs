//! End-to-end Axum service backed by Vaultaris.
//!
//! Demonstrates:
//! - A custom extractor (`AuthenticatedUser`) that validates the incoming
//!   `Authorization` token through Vaultaris and resolves
//!   `(tenant_id, user_id)` once per request.
//! - A typed extractor wrapper (`RequirePermission<R, A>`) that uses
//!   const-generic resource/action pairs to declare a per-handler
//!   permission requirement at the type level.
//! - Three real routes — `/me`, `/orders` (read), and `/orders` (delete) —
//!   wired through a shared `AppState` holding the `VaultarisClient`.
//!
//! Run with:
//!   VAULTARIS_URL=http://localhost:8080 VAULTARIS_API_KEY=your-key \
//!   cargo run --example axum_app

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{FromRef, FromRequestParts},
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
    routing::{delete, get},
};
use serde_json::json;
use uuid::Uuid;
use vaultaris_sdk::{ApiErrorKind, Error as VaultarisError, VaultarisClient};

// ── Shared state ────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    vaultaris: Arc<VaultarisClient>,
}

// ── Extractor: authenticated principal ──────────────────────────────────

/// Resolved identity for the current request.
#[derive(Clone, Debug)]
struct AuthenticatedUser {
    tenant_id: Uuid,
    user_id: Uuid,
    username: String,
    roles: Vec<String>,
}

impl<S> FromRequestParts<S> for AuthenticatedUser
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
            .and_then(|v| {
                v.strip_prefix("Bearer ")
                    .or_else(|| v.strip_prefix("ApiKey "))
            })
            .ok_or_else(|| unauthorized("Missing Authorization header"))?;

        let validation = app_state
            .vaultaris
            .validate_token(token)
            .await
            .map_err(|e| internal_error(format!("token validation: {e}")))?;

        if !validation.valid {
            return Err(unauthorized(
                validation.error.as_deref().unwrap_or("invalid token"),
            ));
        }

        Ok(AuthenticatedUser {
            tenant_id: validation
                .tenant_id
                .ok_or_else(|| unauthorized("token missing tenant_id"))?,
            user_id: validation
                .user_id
                .ok_or_else(|| unauthorized("token missing user_id"))?,
            username: validation.username.unwrap_or_default(),
            roles: validation.roles,
        })
    }
}

// ── Extractor: permission guard ─────────────────────────────────────────

/// Declares the `(resource, action)` pair a route requires. Implement on
/// a marker type to attach the requirement at the type level.
trait PermissionSpec {
    const RESOURCE: &'static str;
    const ACTION: &'static str;
}

/// Generic guard. Used in a handler signature as
/// `guard: RequirePermission<OrdersRead>` — the type is the requirement.
struct RequirePermission<P: PermissionSpec> {
    user: AuthenticatedUser,
    _marker: std::marker::PhantomData<P>,
}

impl<P: PermissionSpec> RequirePermission<P> {
    fn user(&self) -> &AuthenticatedUser {
        &self.user
    }
}

impl<S, P> FromRequestParts<S> for RequirePermission<P>
where
    AppState: FromRef<S>,
    S: Send + Sync,
    P: PermissionSpec + Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        let user = AuthenticatedUser::from_request_parts(parts, state).await?;

        match app_state
            .vaultaris
            .require_permission(user.tenant_id, user.user_id, P::RESOURCE, P::ACTION)
            .await
        {
            Ok(()) => Ok(Self {
                user,
                _marker: std::marker::PhantomData,
            }),
            Err(VaultarisError::PermissionDenied { .. }) => Err(forbidden(format!(
                "missing permission {}:{}",
                P::RESOURCE,
                P::ACTION
            ))),
            Err(VaultarisError::Api {
                kind: ApiErrorKind::Forbidden,
                message,
                ..
            }) => Err(forbidden(message)),
            Err(e) => Err(internal_error(format!("permission check: {e}"))),
        }
    }
}

// Concrete requirement markers — one per `(resource, action)` pair.
struct OrdersRead;
impl PermissionSpec for OrdersRead {
    const RESOURCE: &'static str = "orders";
    const ACTION: &'static str = "read";
}

struct OrdersDelete;
impl PermissionSpec for OrdersDelete {
    const RESOURCE: &'static str = "orders";
    const ACTION: &'static str = "delete";
}

// ── Handlers ───────────────────────────────────────────────────────────

async fn me(user: AuthenticatedUser) -> impl IntoResponse {
    Json(json!({
        "tenant_id": user.tenant_id,
        "user_id": user.user_id,
        "username": user.username,
        "roles": user.roles,
    }))
}

async fn list_orders(guard: RequirePermission<OrdersRead>) -> impl IntoResponse {
    Json(json!({
        "orders": ["ORD-001", "ORD-002"],
        "served_to": guard.user().username,
    }))
}

async fn delete_order(guard: RequirePermission<OrdersDelete>) -> impl IntoResponse {
    Json(json!({
        "deleted_by": guard.user().username,
        "user_id": guard.user().user_id,
    }))
}

async fn public_health() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

// ── Boot ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let vaultaris = Arc::new(VaultarisClient::from_env()?);
    let state = AppState { vaultaris };

    let app = Router::new()
        .route("/health", get(public_health))
        .route("/me", get(me))
        .route("/orders", get(list_orders))
        .route("/orders/{id}", delete(delete_order))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    println!("Listening on http://0.0.0.0:3000");
    println!("  GET    /health         (public)");
    println!("  GET    /me             (any valid token)");
    println!("  GET    /orders         (token + orders:read)");
    println!("  DELETE /orders/{{id}}    (token + orders:delete)");

    axum::serve(listener, app).await?;
    Ok(())
}

// ── Error helpers ──────────────────────────────────────────────────────

fn unauthorized(msg: impl Into<String>) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": msg.into() })),
    )
        .into_response()
}
fn forbidden(msg: impl Into<String>) -> Response {
    (StatusCode::FORBIDDEN, Json(json!({ "error": msg.into() }))).into_response()
}
fn internal_error(msg: impl Into<String>) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": msg.into() })),
    )
        .into_response()
}
