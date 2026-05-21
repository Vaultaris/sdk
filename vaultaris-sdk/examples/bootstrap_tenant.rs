//! Tenant bootstrap example
//!
//! Scenario: A SaaS application onboarding a new customer organization.
//! On sign-up, the app needs to:
//!   1. Ensure Vaultaris itself is initialized (first-time setup).
//!   2. Create the customer's tenant.
//!   3. Create an admin user for that tenant.
//!   4. Set up the initial RBAC roles (admin, editor, viewer).
//!   5. Assign the admin role to the admin user.
//!
//! All of this is done with two high-level workflow calls.
//!
//! Run with:
//!   VAULTARA_URL=http://localhost:8080 VAULTARA_API_KEY=your-key \
//!   cargo run --example bootstrap_tenant

use vaultaris_sdk::workflows::{BootstrapTenantRequest, PermissionDefinition, RoleDefinition};
use vaultaris_sdk::{VaultarisClient, types::SetupRequest};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = VaultarisClient::from_env()?;

    // Step 1: Ensure Vaultaris is initialized.
    // safe to call on every startup — it's a no-op when already configured.
    let setup_ran = client
        .setup_if_needed(SetupRequest {
            admin_username: "superadmin".into(),
            admin_email: "superadmin@vaultaris.internal".into(),
            admin_password: "SuperSecret123!".into(),
            tenant_name: Some("System".into()),
            tenant_slug: Some("system".into()),
        })
        .await?;

    if setup_ran {
        println!("Vaultaris initialized for the first time.");
    } else {
        println!("Vaultaris already initialized.");
    }

    // Step 2: Bootstrap a new customer tenant in one call.
    // This creates the tenant, admin user, and RBAC roles atomically.
    println!("Bootstrapping tenant for Acme Corp...");

    let result = client
        .bootstrap_tenant(BootstrapTenantRequest {
            tenant_name: "Acme Corp".into(),
            tenant_slug: "acme-corp".into(),
            admin_email: "admin@acme.com".into(),
            admin_username: "acme_admin".into(),
            admin_password: "Acme$ecret1!".into(),
            initial_roles: vec![
                // The first role is automatically assigned to the admin user
                RoleDefinition {
                    name: "admin".into(),
                    display_name: "Administrator".into(),
                    permissions: vec![
                        PermissionDefinition::new("users", "read"),
                        PermissionDefinition::new("users", "write"),
                        PermissionDefinition::new("users", "delete"),
                        PermissionDefinition::new("settings", "read"),
                        PermissionDefinition::new("settings", "write"),
                    ],
                },
                RoleDefinition {
                    name: "editor".into(),
                    display_name: "Editor".into(),
                    permissions: vec![
                        PermissionDefinition::new("content", "read"),
                        PermissionDefinition::new("content", "write"),
                        PermissionDefinition::new("users", "read"),
                    ],
                },
                RoleDefinition {
                    name: "viewer".into(),
                    display_name: "Viewer".into(),
                    permissions: vec![
                        PermissionDefinition::new("content", "read"),
                        PermissionDefinition::new("users", "read"),
                    ],
                },
            ],
        })
        .await?;

    println!(
        "Tenant created:    {} ({})",
        result.tenant.name, result.tenant.id
    );
    println!(
        "Admin user:        {} ({})",
        result.admin_user.username, result.admin_user.id
    );
    println!("Roles created:     {} role(s)", result.role_ids.len());
    for (i, id) in result.role_ids.iter().enumerate() {
        println!("  [{}] {}", i, id);
    }

    Ok(())
}
