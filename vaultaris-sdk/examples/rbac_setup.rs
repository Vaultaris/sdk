//! RBAC setup example
//!
//! Scenario: A document management system with granular permissions.
//! Demonstrates how to:
//!   - Define a permission matrix (resources × actions)
//!   - Bootstrap RBAC roles in a single call
//!   - Batch-check whether a user has a set of permissions
//!   - List all roles using the pagination helper
//!
//! Run with:
//!   VAULTARA_URL=http://localhost:8080 VAULTARA_API_KEY=your-key \
//!   EXAMPLE_TENANT_ID=<uuid> EXAMPLE_USER_ID=<uuid> \
//!   cargo run --example rbac_setup

use vaultaris_sdk::{
    VaultarisClient,
    types::PermissionToCheck,
    workflows::{PermissionDefinition, RoleDefinition},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = VaultarisClient::from_env()?;

    let tenant_id = std::env::var("EXAMPLE_TENANT_ID")
        .unwrap_or_else(|_| "00000000-0000-0000-0000-000000000001".into());
    let user_id = std::env::var("EXAMPLE_USER_ID")
        .unwrap_or_else(|_| "00000000-0000-0000-0000-000000000002".into());

    // --- Define the permission matrix ---
    //
    // Resources: documents, reports, users
    // Actions:   read, write, delete
    //
    // Roles:
    //   viewer  → can read documents and reports
    //   editor  → viewer + write documents
    //   manager → editor + manage users, delete documents/reports
    //   admin   → full access

    let roles = vec![
        RoleDefinition {
            name: "viewer".into(),
            display_name: "Viewer".into(),
            permissions: vec![
                PermissionDefinition::new("documents", "read"),
                PermissionDefinition::new("reports", "read"),
            ],
        },
        RoleDefinition {
            name: "editor".into(),
            display_name: "Editor".into(),
            permissions: vec![
                PermissionDefinition::new("documents", "read"),
                PermissionDefinition::new("documents", "write"),
                PermissionDefinition::new("reports", "read"),
            ],
        },
        RoleDefinition {
            name: "manager".into(),
            display_name: "Manager".into(),
            permissions: vec![
                PermissionDefinition::new("documents", "read"),
                PermissionDefinition::new("documents", "write"),
                PermissionDefinition::new("documents", "delete"),
                PermissionDefinition::new("reports", "read"),
                PermissionDefinition::new("reports", "delete"),
                PermissionDefinition::new("users", "read"),
                PermissionDefinition::new("users", "write"),
            ],
        },
        RoleDefinition {
            name: "admin".into(),
            display_name: "Administrator".into(),
            permissions: vec![
                PermissionDefinition::new("documents", "read"),
                PermissionDefinition::new("documents", "write"),
                PermissionDefinition::new("documents", "delete"),
                PermissionDefinition::new("reports", "read"),
                PermissionDefinition::new("reports", "write"),
                PermissionDefinition::new("reports", "delete"),
                PermissionDefinition::new("users", "read"),
                PermissionDefinition::new("users", "write"),
                PermissionDefinition::new("users", "delete"),
            ],
        },
    ];

    println!("Setting up RBAC roles...");
    let role_ids = client.setup_rbac(&tenant_id, &roles).await?;

    for (role, id) in roles.iter().zip(role_ids.iter()) {
        println!(
            "  Created role '{}' with {} permissions → {}",
            role.display_name,
            role.permissions.len(),
            id
        );
    }

    // --- Batch permission check for a user ---
    println!("\nBatch-checking permissions for user {}...", user_id);
    let checks = vec![
        PermissionToCheck::new("documents", "read"),
        PermissionToCheck::new("documents", "delete"),
        PermissionToCheck::new("reports", "write"),
        PermissionToCheck::new("users", "delete"),
    ];

    let batch = client
        .batch_check_permissions(&tenant_id, &user_id, checks)
        .await?;

    for result in &batch.results {
        let icon = if result.allowed { "✓" } else { "✗" };
        println!(
            "  {} {}:{} — {}",
            icon,
            result.resource,
            result.action,
            if result.allowed { "allowed" } else { "denied" }
        );
    }

    // --- Check any / all helpers ---
    let has_any_admin = client
        .has_any_permission(
            &tenant_id,
            &user_id,
            &[("users", "write"), ("users", "delete")],
        )
        .await?;
    println!("\nHas any admin-level user permission: {}", has_any_admin);

    let has_all_read = client
        .has_all_permissions(
            &tenant_id,
            &user_id,
            &[("documents", "read"), ("reports", "read")],
        )
        .await?;
    println!("Has all read permissions: {}", has_all_read);

    // --- List all roles via pagination helper ---
    println!("\nAll roles in tenant:");
    let all_roles = client.collect_roles(&tenant_id).await?;
    for r in &all_roles {
        println!(
            "  - {} ({})",
            r.display_name.as_deref().unwrap_or(&r.name),
            r.id
        );
    }

    Ok(())
}
