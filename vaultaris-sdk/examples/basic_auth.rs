//! Basic authentication example
//!
//! Scenario: A web API backend that validates every incoming request.
//! The bearer token is extracted from the Authorization header,
//! validated against Vaultaris, and then a permission is checked.
//!
//! Run with:
//!   VAULTARA_URL=http://localhost:8080 VAULTARA_API_KEY=your-key \
//!   cargo run --example basic_auth

use vaultaris_sdk::{Error, VaultarisClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Build the client from environment variables:
    //   VAULTARA_URL       - base URL of your Vaultaris instance
    //   VAULTARA_API_KEY   - service API key
    //   VAULTARA_TENANT_ID - default tenant (optional)
    let client = VaultarisClient::from_env()?;

    // --- Simulated incoming request data ---
    let incoming_token =
        std::env::var("EXAMPLE_TOKEN").unwrap_or_else(|_| "eyJhbGciOiJIUzI1NiJ9.example".into());
    let tenant_id = std::env::var("EXAMPLE_TENANT_ID")
        .unwrap_or_else(|_| "00000000-0000-0000-0000-000000000001".into());

    // 1. Validate the token
    println!("Validating token...");
    match client.validate_token(&incoming_token).await {
        Ok(v) if v.valid => {
            println!(
                "  Valid! User: {} | Roles: {:?}",
                v.username.as_deref().unwrap_or("unknown"),
                v.roles
            );

            let user_id = v.user_id.map(|id| id.to_string()).unwrap_or_default();

            // 2. Check a specific permission
            println!("Checking orders:read permission...");
            let allowed = client
                .check_permission(&tenant_id, &user_id, "orders", "read")
                .await?;

            if allowed {
                println!("  Granted. Proceeding with request.");
            } else {
                println!("  Denied. User lacks orders:read.");
            }

            // 3. Use require_permission for a guard-style check
            println!("Requiring orders:delete permission (will error if denied)...");
            match client
                .require_permission(&tenant_id, &user_id, "orders", "delete")
                .await
            {
                Ok(()) => println!("  Granted."),
                Err(Error::PermissionDenied(msg)) => println!("  Denied: {}", msg),
                Err(e) => return Err(e.into()),
            }

            // 4. Validate token AND check permission in one call
            println!("Checking token + permission together...");
            match client
                .check_token_permission(&incoming_token, "reports", "read")
                .await
            {
                Ok(()) => println!("  Token valid and permission granted."),
                Err(Error::PermissionDenied(msg)) => println!("  Permission denied: {}", msg),
                Err(Error::TokenInvalid(msg)) => println!("  Token invalid: {}", msg),
                Err(e) => return Err(e.into()),
            }
        }
        Ok(v) => {
            println!(
                "  Invalid token: {}",
                v.error.as_deref().unwrap_or("unknown reason")
            );
        }
        Err(Error::Auth(msg)) => println!("  Auth error: {}", msg),
        Err(e) => return Err(e.into()),
    }

    Ok(())
}
