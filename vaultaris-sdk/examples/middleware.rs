//! Middleware integration example for Axum
//!
//! This example shows how to use Vaultaris SDK as authentication middleware in Axum.
//!
//! Run with: `cargo run --example middleware`

// Examples illustrate API surface — `AuthenticatedUser` carries fields a real
// app would read (email, permissions) and `require_permission` shows how to
// build a per-route guard. They aren't wired into `main` here so the example
// stays focused on the auth middleware itself.
#![allow(dead_code, unused_imports, unused_variables)]

use axum::{
    Extension, Json, Router,
    body::Body,
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::json;
use std::sync::Arc;
use vaultaris_sdk::{TokenValidation, VaultarisClient, VaultarisConfig};

/// Shared application state
#[derive(Clone)]
struct AppState {
    vaultaris: Arc<VaultarisClient>,
}

/// User context extracted from token
#[derive(Clone, Debug)]
struct AuthenticatedUser {
    user_id: String,
    tenant_id: String,
    username: String,
    email: String,
    roles: Vec<String>,
    permissions: Vec<String>,
}

/// Authentication middleware
async fn auth_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract token from Authorization header
    let token = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let token = match token {
        Some(t) => t,
        None => return Err(StatusCode::UNAUTHORIZED),
    };

    // Validate token with Vaultaris
    let validation = state.vaultaris.validate_token(token).await.map_err(|e| {
        eprintln!("Token validation error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if !validation.valid {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Create user context and attach to request extensions
    let user = AuthenticatedUser {
        user_id: validation
            .user_id
            .map(|u| u.to_string())
            .unwrap_or_default(),
        tenant_id: validation
            .tenant_id
            .map(|u| u.to_string())
            .unwrap_or_default(),
        username: validation.username.unwrap_or_default(),
        email: validation.email.unwrap_or_default(),
        roles: validation.roles,
        permissions: validation.permissions,
    };

    // Store user in request extensions
    let mut request = request;
    request.extensions_mut().insert(user);

    Ok(next.run(request).await)
}

/// Permission checking middleware
async fn require_permission(
    resource: &'static str,
    action: &'static str,
) -> impl Fn(
    State<AppState>,
    Request<Body>,
    Next,
) -> Box<dyn std::future::Future<Output = Result<Response, StatusCode>>> {
    move |State(state): State<AppState>, request: Request<Body>, next: Next| {
        let resource = resource;
        let action = action;
        Box::new(async move {
            // Get user from request extensions
            let user = request
                .extensions()
                .get::<AuthenticatedUser>()
                .ok_or(StatusCode::UNAUTHORIZED)?;

            // Check permission
            let has_permission = state
                .vaultaris
                .check_permission(&user.tenant_id, &user.user_id, resource, action)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            if !has_permission {
                return Err(StatusCode::FORBIDDEN);
            }

            Ok(next.run(request).await)
        })
    }
}

/// Protected endpoint that requires authentication
async fn protected_handler(
    Extension(user): Extension<AuthenticatedUser>,
    request: Request<axum::body::Body>,
) -> impl IntoResponse {
    Json(json!({
        "message": format!("Hello, {}!", user.username),
        "user_id": user.user_id,
        "roles": user.roles,
    }))
}

/// Admin-only endpoint
async fn admin_handler() -> impl IntoResponse {
    Json(json!({
        "message": "Welcome to the admin area!",
        "access": "admin"
    }))
}

/// Public endpoint (no authentication required)
async fn public_handler() -> impl IntoResponse {
    Json(json!({
        "message": "This is a public endpoint",
        "authenticated": false
    }))
}

/// Health check endpoint
async fn health_handler() -> impl IntoResponse {
    Json(json!({
        "status": "healthy"
    }))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize Vaultaris client
    let config = VaultarisConfig::new("http://localhost:8080")
        .with_tenant("00000000-0000-0000-0000-000000000001");

    let vaultaris = Arc::new(VaultarisClient::new(config)?);

    let state = AppState { vaultaris };

    // Build router
    let app = Router::new()
        // Public routes (no auth required)
        .route("/", get(public_handler))
        .route("/health", get(health_handler))
        // Protected routes (auth required)
        .route(
            "/api/me",
            get(protected_handler).layer(middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            )),
        )
        // Admin routes (auth + permission required)
        .route(
            "/api/admin",
            get(admin_handler).layer(middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            )), // Note: In production, you'd add permission checking here too
        )
        .with_state(state);

    println!("Server running on http://localhost:3000");
    println!("\nEndpoints:");
    println!("  GET / - Public");
    println!("  GET /health - Health check");
    println!("  GET /api/me - Protected (requires token)");
    println!("  GET /api/admin - Admin only");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}
