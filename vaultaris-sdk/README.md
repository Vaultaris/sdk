# Vaultaris SDK

Rust client library for integrating applications with Vaultaris IAM platform.

## Overview

The Vaultaris SDK provides a simple, type-safe way to integrate your applications with Vaultaris Identity and Access Management. It supports token validation, permission checking, session management, and user information retrieval.

## Features

- ✅ **Token Validation** - Validate access tokens and get user information
- ✅ **Permission Checking** - Check single or batch permissions
- ✅ **Session Management** - Validate and manage user sessions
- ✅ **User Information** - Retrieve user details and attributes
- ✅ **Async/Await** - Built on Tokio for async operations
- ✅ **Python Bindings** - Use from Python via PyO3

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
vaultaris-sdk = "0.1"
tokio = { version = "1", features = ["full"] }
```

For Python bindings:

```bash
pip install vaultaris-sdk
```

## Quick Start

### Rust

```rust
use vaultaris_sdk::{VaultarisClient, VaultarisConfig};

#[tokio::main]
async fn main() -> Result<(), vaultaris_sdk::Error> {
    // Create configuration
    let config = VaultarisConfig::new("http://localhost:8080")
        .with_api_key("your-api-key");

    // Create client
    let client = VaultarisClient::new(config)?;

    // Validate a token
    let validation = client.validate_token("user-access-token").await?;
    if validation.valid {
        println!("User: {}", validation.username.unwrap_or_default());
        println!("Roles: {:?}", validation.roles);
    }

    // Check a permission
    let allowed = client
        .check_permission("tenant-id", "user-id", "orders", "create")
        .await?;
    
    if allowed {
        println!("User can create orders!");
    }

    Ok(())
}
```

### Python

```python
from vaultaris_sdk import VaultarisClient

# Create client
client = VaultarisClient(
    base_url="http://localhost:8080",
    api_key="your-api-key"
)

# Validate token
result = client.validate_token("user-token")
if result.valid:
    print(f"User: {result.username}")
    print(f"Roles: {result.roles}")

# Check permission
allowed = client.check_permission(
    tenant_id="tenant-id",
    user_id="user-id", 
    resource="orders",
    action="create"
)

if allowed:
    print("Permission granted!")
```

## API Reference

### VaultarisConfig

```rust
// Create configuration
let config = VaultarisConfig::new("http://localhost:8080")
    .with_api_key("your-api-key")        // API key authentication
    .with_timeout(Duration::from_secs(30)); // Request timeout
```

### VaultarisClient

#### validate_token

Validates an access token and returns user information.

```rust
let validation = client.validate_token("token").await?;
// validation.valid: bool
// validation.user_id: Option<String>
// validation.username: Option<String>
// validation.email: Option<String>
// validation.roles: Vec<String>
// validation.expires_at: Option<DateTime>
// validation.error: Option<String>
```

#### check_permission

Checks if a user has permission to perform an action.

```rust
let allowed = client
    .check_permission("tenant-id", "user-id", "resource", "action")
    .await?;
```

#### check_permissions

Batch check multiple permissions.

```rust
let permissions = vec![
    ("orders", "read"),
    ("orders", "create"),
    ("users", "delete"),
];

let results = client
    .check_permissions("tenant-id", "user-id", permissions)
    .await?;

// results.all_allowed: bool
// results.results: Vec<PermissionResult>
```

#### validate_session

Validates a session token.

```rust
let session = client.validate_session("session-token").await?;
// session.valid: bool
// session.user_id: Option<String>
// session.expires_at: Option<DateTime>
```

#### get_user

Gets detailed user information.

```rust
let user = client.get_user("tenant-id", "user-id").await?;
// user.id: String
// user.username: String
// user.email: Option<String>
// user.roles: Vec<String>
// user.groups: Vec<String>
// user.metadata: HashMap<String, Value>
```

## Middleware Integration

### Axum Example

```rust
use axum::{
    extract::State,
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::get,
    Router,
};
use vaultaris_sdk::VaultarisClient;

async fn auth_middleware<B>(
    State(client): State<VaultarisClient>,
    request: Request<B>,
    next: Next<B>,
) -> Result<Response, StatusCode> {
    let token = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let validation = client
        .validate_token(token)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    if !validation.valid {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(next.run(request).await)
}

#[tokio::main]
async fn main() {
    let client = VaultarisClient::new(
        VaultarisConfig::new("http://localhost:8080")
    ).unwrap();

    let app = Router::new()
        .route("/protected", get(protected_handler))
        .layer(middleware::from_fn_with_state(client.clone(), auth_middleware))
        .with_state(client);

    // Start server...
}

async fn protected_handler() -> &'static str {
    "Protected content"
}
```

## Examples

See the `examples/` directory for more examples:

- **basic.rs** - Basic usage examples
- **middleware.rs** - Web framework middleware integration
- **python_usage.py** - Python SDK usage

## Error Handling

```rust
use vaultaris_sdk::Error;

match client.validate_token("token").await {
    Ok(validation) => {
        // Handle success
    }
    Err(Error::NetworkError(e)) => {
        // Network/connection error
    }
    Err(Error::Unauthorized) => {
        // Invalid API key
    }
    Err(Error::NotFound) => {
        // Resource not found
    }
    Err(Error::ServerError(msg)) => {
        // Server-side error
    }
    Err(e) => {
        // Other errors
    }
}
```

## License

MIT OR Apache-2.0
