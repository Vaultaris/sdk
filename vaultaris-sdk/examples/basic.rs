//! Basic usage example for Vaultaris SDK
//!
//! This example demonstrates the basic usage of the Vaultaris SDK.
//!
//! Run with: `cargo run --example basic`

use vaultaris_sdk::{VaultarisClient, VaultarisConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configuration from code
    let config = VaultarisConfig::new("http://localhost:8080")
        .with_api_key("your-api-key")
        .with_tenant("your-tenant-id")
        .with_timeout(30);

    let client = VaultarisClient::new(config)?;

    // Alternatively, create from environment variables
    // let client = VaultarisClient::from_env()?;

    // ========================================
    // Token Validation
    // ========================================

    println!("=== Token Validation ===");

    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."; // Your JWT token

    // Simple validation
    let result = client.validate_token(token).await?;
    if result.valid {
        println!("✅ Token is valid!");
        println!("   User: {}", result.username.unwrap_or_default());
        println!("   Email: {}", result.email.unwrap_or_default());
        println!("   Roles: {:?}", result.roles);
        println!("   Scopes: {:?}", result.scopes);
    } else {
        println!("❌ Token is invalid: {}", result.error.unwrap_or_default());
    }

    // Validation with required scopes and permissions
    let result = client
        .validate_token_with_requirements(
            token,
            Some(vec!["read:users".to_string()]),
            Some(vec!["users:read".to_string()]),
        )
        .await?;

    if !result.valid {
        println!("Token missing required scopes/permissions!");
    }

    // Quick boolean check
    if client.is_token_valid(token).await {
        println!("Token is valid!");
    }

    // ========================================
    // Permission Checking
    // ========================================

    println!("\n=== Permission Checking ===");

    let tenant_id = "your-tenant-id";
    let user_id = "550e8400-e29b-41d4-a716-446655440000";

    // Simple permission check
    let can_create = client
        .check_permission(tenant_id, user_id, "orders", "create")
        .await?;
    println!("Can create orders: {}", can_create);

    // Detailed permission check with ABAC context
    let context = serde_json::json!({
        "department": "sales",
        "order_value": 1500
    });

    let check = client
        .check_permission_detailed(tenant_id, user_id, "orders", "create", Some(context))
        .await?;

    println!("Permission allowed: {}", check.allowed);
    if let Some(reason) = check.reason {
        println!("Reason: {}", reason);
    }

    // Batch permission check
    use vaultaris_sdk::PermissionToCheck;
    let checks = vec![
        PermissionToCheck::new("orders", "read"),
        PermissionToCheck::new("orders", "create"),
        PermissionToCheck::new("orders", "delete"),
        PermissionToCheck::new("users", "read"),
    ];

    let results = client
        .batch_check_permissions(tenant_id, user_id, checks)
        .await?;

    println!("\nBatch permission results:");
    for result in results.results {
        let emoji = if result.allowed { "✅" } else { "❌" };
        println!("  {} {}:{}", emoji, result.resource, result.action);
    }

    // Convenience methods
    let permissions = &[("orders", "read"), ("orders", "create")];

    if client
        .has_any_permission(tenant_id, user_id, permissions)
        .await?
    {
        println!("User has at least one of the permissions!");
    }

    if client
        .has_all_permissions(tenant_id, user_id, permissions)
        .await?
    {
        println!("User has ALL of the permissions!");
    }

    // ========================================
    // User Information
    // ========================================

    println!("\n=== User Information ===");

    let user = client.get_user(tenant_id, user_id).await?;
    println!("User: {} ({})", user.username, user.email);
    println!(
        "Name: {} {}",
        user.first_name.unwrap_or_default(),
        user.last_name.unwrap_or_default()
    );
    println!("Roles:");
    for role in &user.roles {
        println!("  - {}", role.name);
    }
    println!("Groups:");
    for group in &user.groups {
        println!("  - {} ({})", group.name, group.path);
    }

    // ========================================
    // Session Validation
    // ========================================

    println!("\n=== Session Validation ===");

    let session_token = "your-session-token";
    let session = client.validate_session(session_token).await?;

    if session.valid {
        println!("✅ Session is valid!");
        if let Some(info) = session.session {
            println!("   User ID: {}", info.user_id);
            println!("   MFA Verified: {}", info.mfa_verified);
            println!("   Expires: {}", info.expires_at);
        }
    } else {
        println!(
            "❌ Session is invalid: {}",
            session.error.unwrap_or_default()
        );
    }

    Ok(())
}
