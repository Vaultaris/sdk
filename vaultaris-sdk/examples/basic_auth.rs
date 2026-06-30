//! Basic authentication example — validate incoming token, then check a
//! permission, using the API-key-authenticated SDK client.
//!
//! Run with:
//!   VAULTARIS_URL=http://localhost:8080 VAULTARIS_API_KEY=your-key \
//!   cargo run --example basic_auth

use uuid::Uuid;
use vaultaris_sdk::{ApiErrorKind, Error, VaultarisClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Build the client from environment variables:
    //   VAULTARIS_URL       - base URL of your Vaultaris instance
    //   VAULTARIS_API_KEY   - service API key
    //   VAULTARIS_TENANT_ID - default tenant (optional)
    let client = VaultarisClient::from_env()?;

    let incoming_token =
        std::env::var("EXAMPLE_TOKEN").unwrap_or_else(|_| "eyJhbGciOiJIUzI1NiJ9.example".into());
    let tenant_id = Uuid::parse_str(
        &std::env::var("EXAMPLE_TENANT_ID")
            .unwrap_or_else(|_| "00000000-0000-0000-0000-000000000001".into()),
    )?;

    println!("Validating token...");
    match client.validate_token(&incoming_token).await {
        Ok(v) if v.valid => {
            println!(
                "  Valid! user={} roles={:?}",
                v.username.as_deref().unwrap_or("unknown"),
                v.roles
            );
            let user_id = v.user_id.ok_or("token response is missing user_id")?;

            println!("Checking orders:read...");
            let allowed = client
                .check_permission(tenant_id, user_id, "orders", "read")
                .await?;
            println!("  {}", if allowed { "Granted" } else { "Denied" });

            println!("Requiring orders:delete...");
            match client
                .require_permission(tenant_id, user_id, "orders", "delete")
                .await
            {
                Ok(()) => println!("  Granted"),
                Err(Error::PermissionDenied {
                    resource, action, ..
                }) => println!("  Denied: missing {resource}:{action}"),
                Err(e) => return Err(e.into()),
            }

            println!("Token + permission (combined)...");
            match client
                .check_token_permission(&incoming_token, "reports", "read")
                .await
            {
                Ok(()) => println!("  Token valid and permission granted"),
                Err(Error::PermissionDenied { .. }) => println!("  Permission denied"),
                Err(Error::TokenInvalid(msg)) => println!("  Token invalid: {msg}"),
                Err(e) => return Err(e.into()),
            }
        }
        Ok(v) => println!(
            "  Invalid: {}",
            v.error.as_deref().unwrap_or("unknown reason")
        ),
        Err(Error::Api {
            kind: ApiErrorKind::Unauthorized,
            message,
            ..
        }) => println!("  Auth error: {message}"),
        Err(e) => return Err(e.into()),
    }

    Ok(())
}
