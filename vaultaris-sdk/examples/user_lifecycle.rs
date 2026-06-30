//! User lifecycle — onboarding, role changes, offboarding.
//!
//! Run with:
//!   VAULTARIS_URL=http://localhost:8080 VAULTARIS_API_KEY=your-key \
//!   EXAMPLE_TENANT_ID=<uuid> EXAMPLE_ROLE_ID=<uuid> \
//!   cargo run --example user_lifecycle

use uuid::Uuid;
use vaultaris_sdk::{
    VaultarisClient,
    types::{CreateUserRequest, UpdateUserRequest},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = VaultarisClient::from_env()?;

    let tenant_id = Uuid::parse_str(
        &std::env::var("EXAMPLE_TENANT_ID")
            .unwrap_or_else(|_| "00000000-0000-0000-0000-000000000001".into()),
    )?;
    let role_id = Uuid::parse_str(
        &std::env::var("EXAMPLE_ROLE_ID")
            .unwrap_or_else(|_| "00000000-0000-0000-0000-000000000002".into()),
    )?;
    let manager_role_id = Uuid::parse_str(
        &std::env::var("EXAMPLE_MANAGER_ROLE_ID")
            .unwrap_or_else(|_| "00000000-0000-0000-0000-000000000003".into()),
    )?;

    println!("Onboarding new employee...");
    let user = client
        .provision_user(
            tenant_id,
            &CreateUserRequest {
                username: "jane.smith".into(),
                email: "jane.smith@company.com".into(),
                password: Some("TempPass123!".into()),
                first_name: Some("Jane".into()),
                last_name: Some("Smith".into()),
                status: Some("active".into()),
                ..Default::default()
            },
            &[role_id],
        )
        .await?;
    println!("  Created: {} ({})", user.username, user.id);

    println!("Fetching user details...");
    let user_detail = client.get_user(tenant_id, user.id).await?;
    println!(
        "  {} {} — status: {}",
        user_detail.first_name.as_deref().unwrap_or(""),
        user_detail.last_name.as_deref().unwrap_or(""),
        user_detail.status
    );

    println!("Promoting to manager...");
    client
        .assign_role_to_user(tenant_id, user.id, manager_role_id)
        .await?;

    let roles = client.user_roles(tenant_id, user.id).await?;
    println!("Current roles:");
    for r in &roles {
        println!("  - {} ({})", r.name, r.id);
    }

    println!("Updating display name...");
    client
        .update_user(
            tenant_id,
            user.id,
            &UpdateUserRequest {
                display_name: Some("Jane Smith (Manager)".into()),
                ..Default::default()
            },
        )
        .await?;

    println!("Offboarding: suspending account...");
    client
        .update_user(
            tenant_id,
            user.id,
            &UpdateUserRequest {
                status: Some("inactive".into()),
                ..Default::default()
            },
        )
        .await?;
    client.revoke_user_sessions(tenant_id, user.id).await?;
    client.delete_user(tenant_id, user.id).await?;
    println!("  User deleted.");

    println!("Collecting all users in tenant...");
    let all_users = client.collect_users(tenant_id).await?;
    println!("  Total users: {}", all_users.len());

    Ok(())
}
