//! Demonstrates the WebAuthn / Passkeys / FIDO2 typestate flow.
//!
//! This example shows two equivalent approaches:
//!  1. Typestate flow builders (`RegistrationFlow`, `AuthenticationFlow`)
//!  2. Flat `VaultarisClient` methods
//!
//! In a real application the "browser step" is performed by
//! `navigator.credentials.create()` / `navigator.credentials.get()` in
//! JavaScript.  Here we just print the options as a placeholder.

use vaultaris_sdk::types::{AssertionResponse, AttestationResponse};
use vaultaris_sdk::webauthn::{AuthenticationFlow, RegistrationFlow};
use vaultaris_sdk::{VaultarisClient, VaultarisConfig};

/// Bearer token of an already-authenticated user.
const USER_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
/// Vaultaris server base URL.
const BASE_URL: &str = "http://localhost:8080";

#[tokio::main]
async fn main() -> Result<(), vaultaris_sdk::Error> {
    // =========================================================
    // APPROACH 1: typestate flow builders (recommended)
    // =========================================================

    println!("=== Registration via typestate flow ===");

    // --- Step 1: begin ---
    let pending_reg = RegistrationFlow::new(BASE_URL, USER_TOKEN)
        .with_device_name("MacBook Touch ID")
        .begin()
        .await?;

    println!("Challenge ID : {}", pending_reg.challenge_id());
    println!("RP ID        : {}", pending_reg.options().rp.id);
    println!("User         : {}", pending_reg.options().user.display_name);

    // --- Browser step (pseudo-code) ---
    // let cred = navigator.credentials.create({ publicKey: pending_reg.options() });
    // let credential_id        = cred.id;
    // let client_data_json     = base64url(cred.response.clientDataJSON);
    // let attestation_object   = base64url(cred.response.attestationObject);
    // let transports           = cred.response.getTransports();

    // --- Step 2: complete (uses values that the browser would provide) ---
    let attestation = AttestationResponse::new(
        "AAAAAAAAAAAAAAAAAAAAAA",                     // credential_id (base64url)
        "eyJ0eXBlIjoiY3JlYXRlIn0",                    // clientDataJSON (base64url)
        "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVi...", // attestationObject (base64url)
    )
    .with_transports(vec!["internal".to_string()])
    .with_device_name("MacBook Touch ID");

    // In a real app this would succeed; here it will fail signature verification
    // because we're using placeholder base64url strings.
    match pending_reg.complete(attestation).await {
        Ok(done) => println!("Registered: {:?}", done.credential().credential_id_base64),
        Err(e) => println!("(expected in demo — real browser data required): {e}"),
    }

    println!();
    println!("=== Authentication via typestate flow ===");

    // --- Step 1: begin ---
    let pending_auth = AuthenticationFlow::new(BASE_URL, USER_TOKEN).begin().await;

    match pending_auth {
        Ok(pending) => {
            println!("Challenge ID  : {}", pending.challenge_id());
            println!(
                "Allow creds   : {}",
                pending.options().allow_credentials.len()
            );

            // --- Browser step (pseudo-code) ---
            // let assertion = navigator.credentials.get({ publicKey: pending.options() });

            let assertion = AssertionResponse::new(
                "AAAAAAAAAAAAAAAAAAAAAA",                      // credential_id
                "eyJ0eXBlIjoiZ2V0In0",                         // clientDataJSON (base64url)
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // authenticatorData
                "MEUCIQD...",                                  // signature (base64url)
            );

            match pending.complete(assertion).await {
                Ok(done) => println!("Authenticated: {:?}", done.credential().id),
                Err(e) => println!("(expected in demo): {e}"),
            }
        }
        Err(e) => println!("No credentials registered yet (expected): {e}"),
    }

    // =========================================================
    // APPROACH 2: flat VaultarisClient methods
    // =========================================================

    println!();
    println!("=== Flat client API ===");

    let client = VaultarisClient::new(VaultarisConfig::new(BASE_URL).with_api_key(USER_TOKEN))?;

    // List existing credentials
    match client.get_webauthn_credentials().await {
        Ok(creds) => println!("Registered credentials: {}", creds.len()),
        Err(e) => println!("(expected without server): {e}"),
    }

    // Begin registration (returns challenge + options)
    match client.begin_webauthn_registration().await {
        Ok(r) => println!("Begin reg challenge_id: {}", r.challenge_id),
        Err(e) => println!("(expected without server): {e}"),
    }

    // Begin authentication (returns challenge + allowCredentials)
    match client.begin_webauthn_authentication().await {
        Ok(r) => println!("Begin auth challenge_id: {}", r.challenge_id),
        Err(e) => println!("(expected without server): {e}"),
    }

    Ok(())
}
