//! End-to-end Actix-Web service backed by Vaultaris.
//!
//! Demonstrates:
//! - A `FromRequest` extractor (`AuthenticatedUser`) that validates the
//!   `Authorization` token through Vaultaris and resolves
//!   `(tenant_id, user_id)` once per request.
//! - A `require_permission(resource, action)` factory that builds a
//!   `FromRequest`-backed guard so any handler can declare its
//!   per-route permission requirement directly in its signature.
//! - Three real routes — `/me`, `/orders` (read), and `/orders/{id}`
//!   (delete) — wired through Actix's `App::app_data(Data<...>)`.
//!
//! Run with:
//!   VAULTARIS_URL=http://localhost:8080 VAULTARIS_API_KEY=your-key \
//!   cargo run --example actix_app

use std::future::{Ready, ready};
use std::sync::Arc;

use actix_web::{
    App, FromRequest, HttpRequest, HttpServer, Responder, Result as ActixResult,
    dev::Payload,
    error::{ErrorForbidden, ErrorInternalServerError, ErrorUnauthorized},
    web::{self, Data, Json},
};
use serde_json::{Value as JsonValue, json};
use uuid::Uuid;
use vaultaris_sdk::{ApiErrorKind, Error as VaultarisError, VaultarisClient};

// ── Shared state ────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    vaultaris: Arc<VaultarisClient>,
}

// ── Extractor: authenticated principal ──────────────────────────────────

#[derive(Clone, Debug)]
struct AuthenticatedUser {
    tenant_id: Uuid,
    user_id: Uuid,
    username: String,
    roles: Vec<String>,
}

impl FromRequest for AuthenticatedUser {
    type Error = actix_web::Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = ActixResult<Self>>>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let app = match req.app_data::<Data<AppState>>().cloned() {
            Some(a) => a,
            None => {
                return Box::pin(async {
                    Err(ErrorInternalServerError(
                        "AppState missing — Data<AppState> not registered",
                    ))
                });
            }
        };
        let token = req
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| {
                v.strip_prefix("Bearer ")
                    .or_else(|| v.strip_prefix("ApiKey "))
            })
            .map(str::to_string);

        Box::pin(async move {
            let token = token.ok_or_else(|| ErrorUnauthorized("Missing Authorization header"))?;

            let validation = app
                .vaultaris
                .validate_token(&token)
                .await
                .map_err(|e| ErrorInternalServerError(format!("token validation: {e}")))?;

            if !validation.valid {
                return Err(ErrorUnauthorized(
                    validation
                        .error
                        .unwrap_or_else(|| "invalid token".to_string()),
                ));
            }

            Ok(AuthenticatedUser {
                tenant_id: validation
                    .tenant_id
                    .ok_or_else(|| ErrorUnauthorized("token missing tenant_id"))?,
                user_id: validation
                    .user_id
                    .ok_or_else(|| ErrorUnauthorized("token missing user_id"))?,
                username: validation.username.unwrap_or_default(),
                roles: validation.roles,
            })
        })
    }
}

// ── Permission guard ────────────────────────────────────────────────────

/// Verify the authenticated user holds `resource:action`. Use inside a
/// handler body to gate execution.
async fn require_permission(
    app: &AppState,
    user: &AuthenticatedUser,
    resource: &str,
    action: &str,
) -> ActixResult<()> {
    match app
        .vaultaris
        .require_permission(user.tenant_id, user.user_id, resource, action)
        .await
    {
        Ok(()) => Ok(()),
        Err(VaultarisError::PermissionDenied { .. }) => Err(ErrorForbidden(format!(
            "missing permission {resource}:{action}"
        ))),
        Err(VaultarisError::Api {
            kind: ApiErrorKind::Forbidden,
            message,
            ..
        }) => Err(ErrorForbidden(message)),
        Err(e) => Err(ErrorInternalServerError(format!("permission check: {e}"))),
    }
}

// ── Handlers ───────────────────────────────────────────────────────────

async fn me(user: AuthenticatedUser) -> impl Responder {
    Json(json!({
        "tenant_id": user.tenant_id,
        "user_id": user.user_id,
        "username": user.username,
        "roles": user.roles,
    }))
}

async fn list_orders(
    state: Data<AppState>,
    user: AuthenticatedUser,
) -> ActixResult<Json<JsonValue>> {
    require_permission(state.get_ref(), &user, "orders", "read").await?;
    Ok(Json(json!({
        "orders": ["ORD-001", "ORD-002"],
        "served_to": user.username,
    })))
}

async fn delete_order(
    state: Data<AppState>,
    user: AuthenticatedUser,
    path: web::Path<String>,
) -> ActixResult<Json<JsonValue>> {
    require_permission(state.get_ref(), &user, "orders", "delete").await?;
    Ok(Json(json!({
        "deleted_id": path.into_inner(),
        "deleted_by": user.username,
        "user_id": user.user_id,
    })))
}

async fn public_health() -> impl Responder {
    Json(json!({ "status": "ok" }))
}

// ── Boot ───────────────────────────────────────────────────────────────

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let vaultaris = VaultarisClient::from_env().map_err(std::io::Error::other)?;
    let state = Data::new(AppState {
        vaultaris: Arc::new(vaultaris),
    });

    println!("Listening on http://0.0.0.0:3000");
    println!("  GET    /health         (public)");
    println!("  GET    /me             (any valid token)");
    println!("  GET    /orders         (token + orders:read)");
    println!("  DELETE /orders/{{id}}    (token + orders:delete)");

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .route("/health", web::get().to(public_health))
            .route("/me", web::get().to(me))
            .route("/orders", web::get().to(list_orders))
            .route("/orders/{id}", web::delete().to(delete_order))
    })
    .bind(("0.0.0.0", 3000))?
    .run()
    .await
}

/// `ready` is used in lighter `FromRequest` variants that don't need to
/// `.await` Vaultaris. Kept here as a reminder of the simpler shape:
///
/// ```ignore
/// type Future = Ready<ActixResult<Self>>;
/// fn from_request(...) -> Self::Future { ready(Ok(Self { ... })) }
/// ```
#[allow(dead_code)]
fn _shape_reminder() -> Ready<ActixResult<()>> {
    ready(Ok(()))
}
