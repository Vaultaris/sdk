//! RBAC bootstrap — define roles + permissions, then verify access.
//!
//! Run with:
//!   VAULTARIS_URL=http://localhost:8080 VAULTARIS_API_KEY=your-key \
//!   EXAMPLE_TENANT_ID=<uuid> EXAMPLE_USER_ID=<uuid> \
//!   cargo run --example rbac_setup

use uuid::Uuid;
use vaultaris_sdk::{
    VaultarisClient,
    types::PermissionToCheck,
    workflows::{PermissionDefinition, RoleDefinition},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = VaultarisClient::from_env()?;

    let tenant_id = Uuid::parse_str(
        &std::env::var("EXAMPLE_TENANT_ID")
            .unwrap_or_else(|_| "00000000-0000-0000-0000-000000000001".into()),
    )?;
    let user_id = Uuid::parse_str(
        &std::env::var("EXAMPLE_USER_ID")
            .unwrap_or_else(|_| "00000000-0000-0000-0000-000000000002".into()),
    )?;

    let roles = vec![
        RoleDefinition::new("viewer", "Viewer").with_permissions(vec![
            PermissionDefinition::new("documents", "read"),
            PermissionDefinition::new("reports", "read"),
        ]),
        RoleDefinition::new("editor", "Editor").with_permissions(vec![
            PermissionDefinition::new("documents", "read"),
            PermissionDefinition::new("documents", "write"),
            PermissionDefinition::new("reports", "read"),
        ]),
        RoleDefinition::new("manager", "Manager").with_permissions(vec![
            PermissionDefinition::new("documents", "read"),
            PermissionDefinition::new("documents", "write"),
            PermissionDefinition::new("documents", "delete"),
            PermissionDefinition::new("reports", "read"),
            PermissionDefinition::new("reports", "delete"),
            PermissionDefinition::new("users", "read"),
            PermissionDefinition::new("users", "write"),
        ]),
        RoleDefinition::new("admin", "Administrator").with_permissions(vec![
            PermissionDefinition::new("documents", "read"),
            PermissionDefinition::new("documents", "write"),
            PermissionDefinition::new("documents", "delete"),
            PermissionDefinition::new("reports", "read"),
            PermissionDefinition::new("reports", "write"),
            PermissionDefinition::new("reports", "delete"),
            PermissionDefinition::new("users", "read"),
            PermissionDefinition::new("users", "write"),
            PermissionDefinition::new("users", "delete"),
        ]),
    ];

    println!("Setting up RBAC roles...");
    let role_ids = client.setup_rbac(tenant_id, &roles).await?;
    for (role, id) in roles.iter().zip(role_ids.iter()) {
        println!(
            "  Created '{}' ({} permissions) → {}",
            role.display_name,
            role.permissions.len(),
            id
        );
    }

    println!("\nBatch-checking permissions for user {user_id}...");
    let checks = vec![
        PermissionToCheck::new("documents", "read"),
        PermissionToCheck::new("documents", "delete"),
        PermissionToCheck::new("reports", "write"),
        PermissionToCheck::new("users", "delete"),
    ];
    let batch = client
        .batch_check_permissions(tenant_id, user_id, checks)
        .await?;
    for r in &batch.results {
        let icon = if r.allowed { "OK" } else { "X " };
        println!("  {icon} {}:{}", r.resource, r.action);
    }

    let has_any_admin = client
        .has_any_permission(
            tenant_id,
            user_id,
            &[("users", "write"), ("users", "delete")],
        )
        .await?;
    println!("\nHas any admin-level user permission: {has_any_admin}");

    let has_all_read = client
        .has_all_permissions(
            tenant_id,
            user_id,
            &[("documents", "read"), ("reports", "read")],
        )
        .await?;
    println!("Has all read permissions: {has_all_read}");

    println!("\nAll roles in tenant:");
    let all_roles = client.collect_roles(tenant_id).await?;
    for r in &all_roles {
        println!(
            "  - {} ({})",
            r.display_name.as_deref().unwrap_or(&r.name),
            r.id
        );
    }

    Ok(())
}
