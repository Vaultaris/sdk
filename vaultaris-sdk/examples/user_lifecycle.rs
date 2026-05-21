//! User lifecycle management example
//!
//! Scenario: An HR system managing employee accounts.
//! Demonstrates how to:
//!   - Create users with roles in one call (provision_user)
//!   - Fetch full user details
//!   - Reassign roles (e.g. promotion)
//!   - Suspend and delete users on offboarding
//!   - Collect all users across pages
//!
//! Run with:
//!   VAULTARA_URL=http://localhost:8080 VAULTARA_API_KEY=your-key \
//!   EXAMPLE_TENANT_ID=<uuid> EXAMPLE_ROLE_ID=<uuid> \
//!   cargo run --example user_lifecycle

use vaultaris_sdk::{
    VaultarisClient,
    types::{CreateUserRequest, UpdateUserRequest},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = VaultarisClient::from_env()?;

    let tenant_id = std::env::var("EXAMPLE_TENANT_ID")
        .unwrap_or_else(|_| "00000000-0000-0000-0000-000000000001".into());
    let role_id = std::env::var("EXAMPLE_ROLE_ID")
        .unwrap_or_else(|_| "00000000-0000-0000-0000-000000000002".into());
    let manager_role_id = std::env::var("EXAMPLE_MANAGER_ROLE_ID")
        .unwrap_or_else(|_| "00000000-0000-0000-0000-000000000003".into());

    // --- Onboarding: create a new employee and assign their starting role ---
    println!("Onboarding new employee...");
    let user = client
        .provision_user(
            &tenant_id,
            &CreateUserRequest {
                username: "jane.smith".into(),
                email: "jane.smith@company.com".into(),
                password: Some("TempPass123!".into()),
                first_name: Some("Jane".into()),
                last_name: Some("Smith".into()),
                status: Some("active".into()),
                ..Default::default()
            },
            &[&role_id],
        )
        .await?;

    println!("  Created: {} ({})", user.username, user.id);

    // --- Fetch detailed user info ---
    let user_id = user.id.to_string();
    println!("Fetching user details...");
    let user_detail = client.get_user_by_id(&tenant_id, &user_id).await?;
    println!(
        "  {} {} — status: {}",
        user_detail.first_name.as_deref().unwrap_or(""),
        user_detail.last_name.as_deref().unwrap_or(""),
        user_detail.status
    );

    // --- Promotion: add a manager role ---
    println!("Promoting to manager...");
    client
        .assign_role_to_user(&tenant_id, &user_id, &manager_role_id)
        .await?;
    println!("  Manager role assigned.");

    // --- View current roles ---
    let roles = client.get_user_roles(&tenant_id, &user_id).await?;
    println!("Current roles:");
    for r in &roles {
        println!("  - {} ({})", r.name, r.id);
    }

    // --- Update profile ---
    println!("Updating display name...");
    client
        .update_user(
            &tenant_id,
            &user_id,
            &UpdateUserRequest {
                display_name: Some("Jane Smith (Manager)".into()),
                ..Default::default()
            },
        )
        .await?;
    println!("  Display name updated.");

    // --- Offboarding: suspend first, then delete ---
    println!("Offboarding: suspending account...");
    client
        .update_user(
            &tenant_id,
            &user_id,
            &UpdateUserRequest {
                status: Some("inactive".into()),
                ..Default::default()
            },
        )
        .await?;
    println!("  Account suspended.");

    // Revoke all active sessions
    client.revoke_user_sessions(&tenant_id, &user_id).await?;
    println!("  Sessions revoked.");

    // Hard delete (optional — soft-deletes are the default on the server)
    client.delete_user(&tenant_id, &user_id).await?;
    println!("  User deleted.");

    // --- List all users (demonstrates pagination helper) ---
    println!("Collecting all users in tenant...");
    let all_users = client.collect_users(&tenant_id).await?;
    println!("  Total users: {}", all_users.len());

    Ok(())
}
