# Vaultaris SDK

Rust client library for integrating applications with the Vaultaris IAM platform.

## Features

- **API-key auth (default)** — matches the server's `Authorization: ApiKey` extractor.
- **OAuth/Bearer auth** — opt-in for OAuth-issued access tokens.
- **DPoP (RFC 9449)** — sender-constrained tokens, every request signed with ES256.
- **Tenants, users, roles, permissions, groups, OAuth clients, sessions, ABAC policies, audit, identity providers, MFA (TOTP + WebAuthn), API keys, applications, statistics** — full coverage of the v1 API.
- **Typestate OAuth flows** — auth-code + PKCE, password, client-credentials, refresh.
- **High-level workflows** — `setup_if_needed`, `provision_user`, `bootstrap_tenant`, `setup_rbac`.

## Installation

```toml
[dependencies]
vaultaris-sdk = "0.1"
tokio = { version = "1", features = ["full"] }
```

## Quick start

```rust
use vaultaris_sdk::{VaultarisClient, VaultarisConfig};

#[tokio::main]
async fn main() -> Result<(), vaultaris_sdk::Error> {
    let config = VaultarisConfig::new("https://auth.example.com")
        .with_api_key("vk_live_...");
    let client = VaultarisClient::try_from(config)?;

    let v = client.validate_token("user-token").await?;
    if v.valid {
        println!("user: {}", v.username.unwrap_or_default());
    }

    Ok(())
}
```

## Auth schemes

```rust
use vaultaris_sdk::{AuthScheme, VaultarisConfig};

// Default — Vaultaris API keys
VaultarisConfig::new("https://auth.example.com")
    .with_api_key("vk_live_...");

// OAuth access token — opt-in
VaultarisConfig::new("https://auth.example.com")
    .with_api_key("eyJ...")
    .with_auth_scheme(AuthScheme::Bearer);
```

With the `dpop` feature and a configured signer, the scheme is forced to `DPoP` per RFC 9449 §7.1.

## Environment variables

`VaultarisClient::from_env()` reads:

| Variable | Purpose |
|---|---|
| `VAULTARIS_URL` | Base URL |
| `VAULTARIS_API_KEY` | API key or token |
| `VAULTARIS_CLIENT_ID` / `VAULTARIS_CLIENT_SECRET` | OAuth client credentials |
| `VAULTARIS_TENANT_ID` | Default tenant (informational) |
| `VAULTARIS_TIMEOUT` | Per-request timeout (seconds) |
| `VAULTARIS_VERIFY_TLS` | `"false"` to disable TLS verification |
| `VAULTARIS_AUTH_SCHEME` | `"apikey"` (default) or `"bearer"` |

## Endpoint coverage

| Resource | Methods |
|---|---|
| Tenants | `list_tenants`, `create_tenant`, `get_tenant`, `update_tenant`, `delete_tenant` |
| Users | `list_users`, `create_user`, `get_user`, `update_user`, `delete_user`, `restore_user`, `user_roles`, `assign_role_to_user`, `remove_role_from_user`, `user_groups`, `assign_group_to_user`, `remove_group_from_user` |
| Roles | `list_roles`, `create_role`, `get_role`, `update_role`, `delete_role`, `restore_role`, `role_permissions`, `assign_permission_to_role`, `remove_permission_from_role` |
| Permissions | `list_permissions`, `create_permission`, `get_permission`, `update_permission`, `delete_permission`, `restore_permission` |
| Groups | `list_groups`, `create_group`, `get_group`, `update_group`, `delete_group`, `restore_group`, `group_members`, `group_roles`, `assign_role_to_group`, `remove_role_from_group` |
| OAuth clients | `list_clients`, `create_client`, `get_client`, `update_client`, `delete_client`, `regenerate_client_secret` |
| Applications | `list_applications`, `create_application`, `get_application`, `update_application`, `delete_application`, link/unlink (oauth-clients, roles, groups, permissions, policies), members |
| Sessions | `list_sessions`, `revoke_session`, `user_sessions`, `revoke_user_sessions` |
| Policies (ABAC) | `list_policies`, `create_policy`, `get_policy`, `update_policy`, `delete_policy`, `evaluate_policies`, `check_user_access` |
| Audit | `list_audit_logs`, `get_audit_log` |
| Identity providers | `list_identity_providers`, `create_identity_provider`, `get_identity_provider`, `update_identity_provider`, `delete_identity_provider` |
| JWT keys | `list_keys`, `rotate_keys` |
| MFA | TOTP setup/verify/disable, WebAuthn registration + authentication, credentials |
| Devices | `list_devices`, `revoke_device`, `trust_device`, `device_sessions` |
| Templates | `export_template`, `import_template` |
| Statistics | `tenant_overview`, `auth_stats`, `session_stats`, `security_stats`, `dashboard_summary` |
| API keys | `list_api_keys`, `create_api_key`, `get_api_key`, `update_api_key`, `delete_api_key`, `revoke_api_key`, app/group-scoped variants, self-service (`current_api_key`, `authorize_api_key`) |
| Auth | password reset, email verification |
| OAuth tokens | `token_client_credentials`, `token_password`, `token_refresh` |
| Integration | `validate_token`, `check_permission`, `batch_check_permissions`, `integration_user`, `validate_session` |

See `examples/` for full walkthroughs.

## OAuth flows (typestate)

```rust
use vaultaris_sdk::oauth::OAuthFlow;

// Client credentials (machine-to-machine)
let authed = OAuthFlow::new("https://auth.example.com", "svc-client", Some("s3cr3t"))
    .client_credentials("read:metrics write:events")
    .await?;
println!("{}", authed.access_token());
```

The typestate ensures invalid transitions (refreshing a `client_credentials` token, exchanging a code twice, etc.) are **compile errors**, not runtime panics.

## DPoP

Enable the `dpop` feature (on by default) and pass a `DpopKey`:

```rust
use vaultaris_sdk::{DpopKey, VaultarisClient, VaultarisConfig};

let key = DpopKey::generate();
let config = VaultarisConfig::new("https://auth.example.com")
    .with_api_key("eyJ...")
    .with_dpop_key(key);
let client = VaultarisClient::try_from(config)?;
```

For HSM/KMS/TPM-backed keys, implement [`DpopSigner`] and pass it via `with_dpop_signer`.

## License

MIT OR Apache-2.0
