//! Basic SDK walkthrough — token validation, permission checks, user info,
//! session validation.
//!
//! Run with: `cargo run --example basic`

use std::time::Duration;

use uuid::Uuid;
use vaultaris_sdk::{PermissionToCheck, VaultarisClient, VaultarisConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = VaultarisConfig::new("http://localhost:8080")
        .with_api_key("your-api-key")
        .with_tenant("your-tenant-id")
        .with_timeout(Duration::from_secs(30));

    let client = VaultarisClient::try_from(config)?;
    // Or: let client = VaultarisClient::from_env()?;

    println!("=== Token Validation ===");
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
    let result = client.validate_token(token).await?;
    if result.valid {
        println!("OK   user: {}", result.username.unwrap_or_default());
        println!("     email: {}", result.email.unwrap_or_default());
        println!("     roles: {:?}", result.roles);
        println!("     scopes: {:?}", result.scopes);
    } else {
        println!("FAIL {}", result.error.unwrap_or_default());
    }

    // Validation with required scopes and permissions
    let result = client
        .validate_token_with(
            token,
            Some(vec!["read:users".to_string()]),
            Some(vec!["users:read".to_string()]),
        )
        .await?;
    if !result.valid {
        println!("Token missing required scopes/permissions");
    }

    if client.is_token_valid(token).await {
        println!("Token still valid");
    }

    println!("\n=== Permission Checking ===");
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000000")?;
    let user_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000")?;

    let can_create = client
        .check_permission(tenant_id, user_id, "orders", "create")
        .await?;
    println!("Can create orders: {can_create}");

    let context = serde_json::json!({ "department": "sales", "order_value": 1500 });
    let check = client
        .check_permission_detailed(tenant_id, user_id, "orders", "create", Some(context))
        .await?;
    println!("Allowed: {}", check.allowed);
    if let Some(reason) = check.reason {
        println!("Reason: {reason}");
    }

    let checks = vec![
        PermissionToCheck::new("orders", "read"),
        PermissionToCheck::new("orders", "create"),
        PermissionToCheck::new("orders", "delete"),
        PermissionToCheck::new("users", "read"),
    ];
    let results = client
        .batch_check_permissions(tenant_id, user_id, checks)
        .await?;
    println!("\nBatch results:");
    for r in results.results {
        let marker = if r.allowed { "OK" } else { "X " };
        println!("  {marker} {}:{}", r.resource, r.action);
    }

    let permissions = &[("orders", "read"), ("orders", "create")];
    if client
        .has_any_permission(tenant_id, user_id, permissions)
        .await?
    {
        println!("User has at least one of the permissions");
    }
    if client
        .has_all_permissions(tenant_id, user_id, permissions)
        .await?
    {
        println!("User has all of the permissions");
    }

    println!("\n=== User Info ===");
    let user = client.integration_user(tenant_id, user_id).await?;
    println!("User: {} ({})", user.username, user.email);
    println!("Roles:");
    for role in &user.roles {
        println!("  - {}", role.name);
    }
    println!("Groups:");
    for group in &user.groups {
        println!("  - {} ({})", group.name, group.path);
    }

    println!("\n=== Session Validation ===");
    let session_token = "your-session-token";
    let session = client.validate_session(session_token).await?;
    if session.valid {
        println!("Session valid");
        if let Some(info) = session.session {
            println!("  user_id: {}", info.user_id);
            println!("  mfa: {}", info.mfa_verified);
            println!("  expires: {}", info.expires_at);
        }
    } else {
        println!("Session invalid: {}", session.error.unwrap_or_default());
    }

    Ok(())
}
