//! Vaultaris client implementation for Node.js

use napi::bindgen_prelude::*;
use napi_derive::napi;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use serde::Serialize;
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::time::Duration;

use crate::dpop::DpopKey;
use crate::*;

const DPOP_HEADER: HeaderName = HeaderName::from_static("dpop");

/// Vaultaris client for Node.js
#[napi]
pub struct VaultarisClient {
    client: reqwest::Client,
    base_url: String,
    api_key: Option<String>,
    /// Optional ES256 keypair used to attach a DPoP proof to every request.
    /// When set, the Authorization scheme switches from `Bearer` to `DPoP`.
    dpop_key: Option<DpopKey>,
    device_fingerprint: Option<String>,
}

#[napi]
impl VaultarisClient {
    /// Create a new Vaultaris client. Pass `dpopKey` as the second
    /// argument to transparently issue and consume sender-constrained
    /// tokens — every outgoing request will then carry a freshly-signed
    /// DPoP proof and the Authorization scheme switches from `Bearer` to
    /// `DPoP`.
    ///
    /// ```js
    /// const key = DpopKey.generate();
    /// const client = new VaultarisClient(
    ///   { baseUrl: 'https://auth.example.com', apiKey: 'eyJ...' },
    ///   key,
    /// );
    /// ```
    #[napi(constructor)]
    pub fn new(config: VaultarisConfig, dpop_key: Option<&DpopKey>) -> Result<Self> {
        let timeout = config.timeout_ms.unwrap_or(30000) as u64;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(timeout))
            .build()
            .map_err(|e| Error::from_reason(format!("Failed to create HTTP client: {}", e)))?;

        let device_fingerprint = match config.device_fingerprint.as_deref() {
            Some("auto") => Some(vaultaris_sdk::fingerprint::compute_fingerprint()),
            Some(fp) => Some(fp.to_string()),
            None => None,
        };

        Ok(Self {
            client,
            base_url: config.base_url.trim_end_matches('/').to_string(),
            api_key: config.api_key,
            dpop_key: dpop_key.cloned(),
            device_fingerprint,
        })
    }

    // ============================================
    // INTERNAL HELPERS
    // ============================================

    /// Build the per-request header map: Content-Type, Authorization, and
    /// (when DPoP is configured) a fresh DPoP proof bound to this exact
    /// `method` + `url`. Centralising this here means every HTTP method
    /// pays a single line of plumbing and the rest of the file stays
    /// unaware of the binding.
    fn auth_headers(&self, method: &str, url: &str) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        if let Some(api_key) = &self.api_key {
            let scheme = if self.dpop_key.is_some() { "DPoP" } else { "Bearer" };
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("{} {}", scheme, api_key))
                    .map_err(|e| Error::from_reason(e.to_string()))?,
            );
        }

        if let Some(key) = &self.dpop_key {
            let proof = key
                .inner
                .sign_proof(method, url, self.api_key.as_deref())
                .map_err(|e| Error::from_reason(format!("DPoP signing failed: {}", e)))?;
            headers.insert(
                DPOP_HEADER.clone(),
                HeaderValue::from_str(&proof).map_err(|e| Error::from_reason(e.to_string()))?,
            );
        }

        if let Some(fp) = &self.device_fingerprint {
            headers.insert(
                HeaderName::from_static("x-device-fingerprint"),
                HeaderValue::from_str(fp).map_err(|e| Error::from_reason(e.to_string()))?,
            );
        }

        Ok(headers)
    }

    // ============================================
    // INTEGRATION ENDPOINTS
    // ============================================

    /// Validate an access token
    #[napi]
    pub async fn validate_token(&self, token: String) -> Result<TokenValidation> {
        let url = format!("{}/api/v1/integration/validate", self.base_url);

        #[derive(Serialize)]
        struct ValidateRequest {
            token: String,
        }

        let response = self
            .client
            .post(&url)
            .headers(self.auth_headers("POST", &url)?)
            .json(&ValidateRequest { token })
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Ok(TokenValidation {
                valid: false,
                user_id: None,
                username: None,
                email: None,
                tenant_id: None,
                expires_at: None,
                scopes: vec![],
                roles: vec![],
                error: Some(format!("HTTP {}", response.status())),
            });
        }

        response
            .json::<TokenValidation>()
            .await
            .map_err(|e| Error::from_reason(format!("Failed to parse response: {}", e)))
    }

    /// Check a single permission
    #[napi]
    pub async fn check_permission(
        &self,
        tenant_id: String,
        user_id: String,
        resource: String,
        action: String,
    ) -> Result<PermissionCheck> {
        let url = format!(
            "{}/api/v1/tenants/{}/integration/check-permission",
            self.base_url, tenant_id
        );

        #[derive(Serialize)]
        struct CheckRequest {
            user_id: String,
            resource: String,
            action: String,
        }

        let response = self
            .client
            .post(&url)
            .headers(self.auth_headers("POST", &url)?)
            .json(&CheckRequest {
                user_id,
                resource,
                action,
            })
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Ok(PermissionCheck {
                allowed: false,
                reason: Some(format!("HTTP {}", response.status())),
                policy: None,
            });
        }

        response
            .json::<PermissionCheck>()
            .await
            .map_err(|e| Error::from_reason(format!("Failed to parse response: {}", e)))
    }

    /// Check multiple permissions
    #[napi]
    pub async fn check_permissions(
        &self,
        tenant_id: String,
        user_id: String,
        permissions: Vec<HashMap<String, String>>,
    ) -> Result<BatchPermissionResponse> {
        let url = format!(
            "{}/api/v1/tenants/{}/integration/check-permissions",
            self.base_url, tenant_id
        );

        #[derive(Serialize)]
        struct PermItem {
            resource: String,
            action: String,
        }

        #[derive(Serialize)]
        struct BatchRequest {
            user_id: String,
            checks: Vec<PermItem>,
        }

        let checks: Vec<PermItem> = permissions
            .into_iter()
            .filter_map(|p| {
                Some(PermItem {
                    resource: p.get("resource")?.clone(),
                    action: p.get("action")?.clone(),
                })
            })
            .collect();

        let response = self
            .client
            .post(&url)
            .headers(self.auth_headers("POST", &url)?)
            .json(&BatchRequest { user_id, checks })
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Ok(BatchPermissionResponse {
                results: vec![],
                all_allowed: false,
            });
        }

        response
            .json::<BatchPermissionResponse>()
            .await
            .map_err(|e| Error::from_reason(format!("Failed to parse response: {}", e)))
    }

    /// Get user information
    #[napi]
    pub async fn get_user(&self, tenant_id: String, user_id: String) -> Result<UserInfo> {
        let url = format!(
            "{}/api/v1/tenants/{}/integration/users/{}",
            self.base_url, tenant_id, user_id
        );

        let response = self
            .client
            .get(&url)
            .headers(self.auth_headers("GET", &url)?)
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        response
            .json::<UserInfo>()
            .await
            .map_err(|e| Error::from_reason(format!("Failed to parse response: {}", e)))
    }

    /// Validate a session
    #[napi]
    pub async fn validate_session(&self, token: String) -> Result<SessionValidation> {
        let url = format!("{}/api/v1/integration/session/validate", self.base_url);

        let response = self
            .client
            .get(&url)
            .query(&[("token", &token)])
            .headers(self.auth_headers("GET", &url)?)
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Ok(SessionValidation {
                valid: false,
                session_id: None,
                user_id: None,
                username: None,
                tenant_id: None,
                expires_at: None,
                error: Some(format!("HTTP {}", response.status())),
            });
        }

        response
            .json::<SessionValidation>()
            .await
            .map_err(|e| Error::from_reason(format!("Failed to parse response: {}", e)))
    }

    // ============================================
    // TENANT MANAGEMENT
    // ============================================

    /// List tenants
    #[napi]
    pub async fn list_tenants(&self, page: i64, per_page: i64) -> Result<JsonValue> {
        let url = format!("{}/api/v1/tenants", self.base_url);

        let response = self
            .client
            .get(&url)
            .query(&[
                ("page", page.to_string()),
                ("per_page", per_page.to_string()),
            ])
            .headers(self.auth_headers("GET", &url)?)
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        let result: JsonValue = response
            .json()
            .await
            .map_err(|e| Error::from_reason(format!("Failed to parse response: {}", e)))?;
        Ok(result)
    }

    /// Create tenant
    #[napi]
    pub async fn create_tenant(&self, name: String, slug: String) -> Result<Tenant> {
        let url = format!("{}/api/v1/tenants", self.base_url);

        #[derive(Serialize)]
        struct CreateRequest {
            name: String,
            slug: String,
        }

        let response = self
            .client
            .post(&url)
            .headers(self.auth_headers("POST", &url)?)
            .json(&CreateRequest { name, slug })
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        response
            .json::<Tenant>()
            .await
            .map_err(|e| Error::from_reason(format!("Failed to parse response: {}", e)))
    }

    /// Get tenant
    #[napi]
    pub async fn get_tenant(&self, tenant_id: String) -> Result<Tenant> {
        let url = format!("{}/api/v1/tenants/{}", self.base_url, tenant_id);

        let response = self
            .client
            .get(&url)
            .headers(self.auth_headers("GET", &url)?)
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        response
            .json::<Tenant>()
            .await
            .map_err(|e| Error::from_reason(format!("Failed to parse response: {}", e)))
    }

    /// Delete tenant
    #[napi]
    pub async fn delete_tenant(&self, tenant_id: String) -> Result<()> {
        let url = format!("{}/api/v1/tenants/{}", self.base_url, tenant_id);

        let response = self
            .client
            .delete(&url)
            .headers(self.auth_headers("DELETE", &url)?)
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        Ok(())
    }

    // ============================================
    // USER MANAGEMENT
    // ============================================

    /// List users
    #[napi]
    pub async fn list_users(
        &self,
        tenant_id: String,
        page: i64,
        per_page: i64,
    ) -> Result<serde_json::Value> {
        let url = format!("{}/api/v1/tenants/{}/users", self.base_url, tenant_id);

        let response = self
            .client
            .get(&url)
            .query(&[
                ("page", page.to_string()),
                ("per_page", per_page.to_string()),
            ])
            .headers(self.auth_headers("GET", &url)?)
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        response
            .json::<serde_json::Value>()
            .await
            .map_err(|e| Error::from_reason(format!("Failed to parse response: {}", e)))
    }

    /// Create user
    #[napi]
    pub async fn create_user(&self, tenant_id: String, input: CreateUserInput) -> Result<User> {
        let url = format!("{}/api/v1/tenants/{}/users", self.base_url, tenant_id);

        let response = self
            .client
            .post(&url)
            .headers(self.auth_headers("POST", &url)?)
            .json(&input)
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        response
            .json::<User>()
            .await
            .map_err(|e| Error::from_reason(format!("Failed to parse response: {}", e)))
    }

    /// Get user by ID
    #[napi]
    pub async fn get_user_by_id(&self, tenant_id: String, user_id: String) -> Result<User> {
        let url = format!(
            "{}/api/v1/tenants/{}/users/{}",
            self.base_url, tenant_id, user_id
        );

        let response = self
            .client
            .get(&url)
            .headers(self.auth_headers("GET", &url)?)
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        response
            .json::<User>()
            .await
            .map_err(|e| Error::from_reason(format!("Failed to parse response: {}", e)))
    }

    /// Delete user
    #[napi]
    pub async fn delete_user(&self, tenant_id: String, user_id: String) -> Result<()> {
        let url = format!(
            "{}/api/v1/tenants/{}/users/{}",
            self.base_url, tenant_id, user_id
        );

        let response = self
            .client
            .delete(&url)
            .headers(self.auth_headers("DELETE", &url)?)
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        Ok(())
    }

    /// Get user roles
    #[napi]
    pub async fn get_user_roles(&self, tenant_id: String, user_id: String) -> Result<Vec<Role>> {
        let url = format!(
            "{}/api/v1/tenants/{}/users/{}/roles",
            self.base_url, tenant_id, user_id
        );

        let response = self
            .client
            .get(&url)
            .headers(self.auth_headers("GET", &url)?)
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        response
            .json::<Vec<Role>>()
            .await
            .map_err(|e| Error::from_reason(format!("Failed to parse response: {}", e)))
    }

    /// Assign role to user
    #[napi]
    pub async fn assign_role_to_user(
        &self,
        tenant_id: String,
        user_id: String,
        role_id: String,
    ) -> Result<()> {
        let url = format!(
            "{}/api/v1/tenants/{}/users/{}/roles",
            self.base_url, tenant_id, user_id
        );

        #[derive(Serialize)]
        struct AssignRequest {
            role_id: String,
        }

        let response = self
            .client
            .post(&url)
            .headers(self.auth_headers("POST", &url)?)
            .json(&AssignRequest { role_id })
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        Ok(())
    }

    // ============================================
    // ROLE MANAGEMENT
    // ============================================

    /// List roles
    #[napi]
    pub async fn list_roles(
        &self,
        tenant_id: String,
        page: i64,
        per_page: i64,
    ) -> Result<serde_json::Value> {
        let url = format!("{}/api/v1/tenants/{}/roles", self.base_url, tenant_id);

        let response = self
            .client
            .get(&url)
            .query(&[
                ("page", page.to_string()),
                ("per_page", per_page.to_string()),
            ])
            .headers(self.auth_headers("GET", &url)?)
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        response
            .json::<serde_json::Value>()
            .await
            .map_err(|e| Error::from_reason(format!("Failed to parse response: {}", e)))
    }

    /// Create role
    #[napi]
    pub async fn create_role(&self, tenant_id: String, input: CreateRoleInput) -> Result<Role> {
        let url = format!("{}/api/v1/tenants/{}/roles", self.base_url, tenant_id);

        let response = self
            .client
            .post(&url)
            .headers(self.auth_headers("POST", &url)?)
            .json(&input)
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        response
            .json::<Role>()
            .await
            .map_err(|e| Error::from_reason(format!("Failed to parse response: {}", e)))
    }

    /// Get role
    #[napi]
    pub async fn get_role(&self, tenant_id: String, role_id: String) -> Result<Role> {
        let url = format!(
            "{}/api/v1/tenants/{}/roles/{}",
            self.base_url, tenant_id, role_id
        );

        let response = self
            .client
            .get(&url)
            .headers(self.auth_headers("GET", &url)?)
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        response
            .json::<Role>()
            .await
            .map_err(|e| Error::from_reason(format!("Failed to parse response: {}", e)))
    }

    /// Delete role
    #[napi]
    pub async fn delete_role(&self, tenant_id: String, role_id: String) -> Result<()> {
        let url = format!(
            "{}/api/v1/tenants/{}/roles/{}",
            self.base_url, tenant_id, role_id
        );

        let response = self
            .client
            .delete(&url)
            .headers(self.auth_headers("DELETE", &url)?)
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        Ok(())
    }

    // ============================================
    // PERMISSION MANAGEMENT
    // ============================================

    /// List permissions
    #[napi]
    pub async fn list_permissions(
        &self,
        tenant_id: String,
        page: i64,
        per_page: i64,
    ) -> Result<serde_json::Value> {
        let url = format!("{}/api/v1/tenants/{}/permissions", self.base_url, tenant_id);

        let response = self
            .client
            .get(&url)
            .query(&[
                ("page", page.to_string()),
                ("per_page", per_page.to_string()),
            ])
            .headers(self.auth_headers("GET", &url)?)
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        response
            .json::<serde_json::Value>()
            .await
            .map_err(|e| Error::from_reason(format!("Failed to parse response: {}", e)))
    }

    /// Create permission
    #[napi]
    pub async fn create_permission(
        &self,
        tenant_id: String,
        input: CreatePermissionInput,
    ) -> Result<Permission> {
        let url = format!("{}/api/v1/tenants/{}/permissions", self.base_url, tenant_id);

        let response = self
            .client
            .post(&url)
            .headers(self.auth_headers("POST", &url)?)
            .json(&input)
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        response
            .json::<Permission>()
            .await
            .map_err(|e| Error::from_reason(format!("Failed to parse response: {}", e)))
    }

    /// Delete permission
    #[napi]
    pub async fn delete_permission(&self, tenant_id: String, permission_id: String) -> Result<()> {
        let url = format!(
            "{}/api/v1/tenants/{}/permissions/{}",
            self.base_url, tenant_id, permission_id
        );

        let response = self
            .client
            .delete(&url)
            .headers(self.auth_headers("DELETE", &url)?)
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        Ok(())
    }

    // ============================================
    // GROUP MANAGEMENT
    // ============================================

    /// List groups
    #[napi]
    pub async fn list_groups(
        &self,
        tenant_id: String,
        page: i64,
        per_page: i64,
    ) -> Result<serde_json::Value> {
        let url = format!("{}/api/v1/tenants/{}/groups", self.base_url, tenant_id);

        let response = self
            .client
            .get(&url)
            .query(&[
                ("page", page.to_string()),
                ("per_page", per_page.to_string()),
            ])
            .headers(self.auth_headers("GET", &url)?)
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        response
            .json::<serde_json::Value>()
            .await
            .map_err(|e| Error::from_reason(format!("Failed to parse response: {}", e)))
    }

    /// Create group
    #[napi]
    pub async fn create_group(&self, tenant_id: String, input: CreateGroupInput) -> Result<Group> {
        let url = format!("{}/api/v1/tenants/{}/groups", self.base_url, tenant_id);

        let response = self
            .client
            .post(&url)
            .headers(self.auth_headers("POST", &url)?)
            .json(&input)
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        response
            .json::<Group>()
            .await
            .map_err(|e| Error::from_reason(format!("Failed to parse response: {}", e)))
    }

    /// Get group
    #[napi]
    pub async fn get_group(&self, tenant_id: String, group_id: String) -> Result<Group> {
        let url = format!(
            "{}/api/v1/tenants/{}/groups/{}",
            self.base_url, tenant_id, group_id
        );

        let response = self
            .client
            .get(&url)
            .headers(self.auth_headers("GET", &url)?)
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        response
            .json::<Group>()
            .await
            .map_err(|e| Error::from_reason(format!("Failed to parse response: {}", e)))
    }

    /// Delete group
    #[napi]
    pub async fn delete_group(&self, tenant_id: String, group_id: String) -> Result<()> {
        let url = format!(
            "{}/api/v1/tenants/{}/groups/{}",
            self.base_url, tenant_id, group_id
        );

        let response = self
            .client
            .delete(&url)
            .headers(self.auth_headers("DELETE", &url)?)
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        Ok(())
    }

    // ============================================
    // OAUTH CLIENT MANAGEMENT
    // ============================================

    /// List clients
    #[napi]
    pub async fn list_clients(
        &self,
        tenant_id: String,
        page: i64,
        per_page: i64,
    ) -> Result<serde_json::Value> {
        let url = format!("{}/api/v1/tenants/{}/clients", self.base_url, tenant_id);

        let response = self
            .client
            .get(&url)
            .query(&[
                ("page", page.to_string()),
                ("per_page", per_page.to_string()),
            ])
            .headers(self.auth_headers("GET", &url)?)
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        response
            .json::<serde_json::Value>()
            .await
            .map_err(|e| Error::from_reason(format!("Failed to parse response: {}", e)))
    }

    /// Create client
    #[napi]
    pub async fn create_client(
        &self,
        tenant_id: String,
        input: CreateClientInput,
    ) -> Result<ClientWithSecret> {
        let url = format!("{}/api/v1/tenants/{}/clients", self.base_url, tenant_id);

        let response = self
            .client
            .post(&url)
            .headers(self.auth_headers("POST", &url)?)
            .json(&input)
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        response
            .json::<ClientWithSecret>()
            .await
            .map_err(|e| Error::from_reason(format!("Failed to parse response: {}", e)))
    }

    /// Get client
    #[napi]
    pub async fn get_client(&self, tenant_id: String, client_id: String) -> Result<OAuthClient> {
        let url = format!(
            "{}/api/v1/tenants/{}/clients/{}",
            self.base_url, tenant_id, client_id
        );

        let response = self
            .client
            .get(&url)
            .headers(self.auth_headers("GET", &url)?)
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        response
            .json::<OAuthClient>()
            .await
            .map_err(|e| Error::from_reason(format!("Failed to parse response: {}", e)))
    }

    /// Delete client
    #[napi]
    pub async fn delete_client(&self, tenant_id: String, client_id: String) -> Result<()> {
        let url = format!(
            "{}/api/v1/tenants/{}/clients/{}",
            self.base_url, tenant_id, client_id
        );

        let response = self
            .client
            .delete(&url)
            .headers(self.auth_headers("DELETE", &url)?)
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        Ok(())
    }

    // ============================================
    // SESSION MANAGEMENT
    // ============================================

    /// List sessions
    #[napi]
    pub async fn list_sessions(
        &self,
        tenant_id: String,
        page: i64,
        per_page: i64,
    ) -> Result<serde_json::Value> {
        let url = format!("{}/api/v1/tenants/{}/sessions", self.base_url, tenant_id);

        let response = self
            .client
            .get(&url)
            .query(&[
                ("page", page.to_string()),
                ("per_page", per_page.to_string()),
            ])
            .headers(self.auth_headers("GET", &url)?)
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        response
            .json::<serde_json::Value>()
            .await
            .map_err(|e| Error::from_reason(format!("Failed to parse response: {}", e)))
    }

    /// Revoke session
    #[napi]
    pub async fn revoke_session(&self, tenant_id: String, session_id: String) -> Result<()> {
        let url = format!(
            "{}/api/v1/tenants/{}/sessions/{}",
            self.base_url, tenant_id, session_id
        );

        let response = self
            .client
            .delete(&url)
            .headers(self.auth_headers("DELETE", &url)?)
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        Ok(())
    }

    // ============================================
    // AUDIT LOGS
    // ============================================

    /// List audit logs
    #[napi]
    pub async fn list_audit_logs(
        &self,
        tenant_id: String,
        page: i64,
        per_page: i64,
    ) -> Result<serde_json::Value> {
        let url = format!("{}/api/v1/tenants/{}/audit-logs", self.base_url, tenant_id);

        let response = self
            .client
            .get(&url)
            .query(&[
                ("page", page.to_string()),
                ("per_page", per_page.to_string()),
            ])
            .headers(self.auth_headers("GET", &url)?)
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        response
            .json::<serde_json::Value>()
            .await
            .map_err(|e| Error::from_reason(format!("Failed to parse response: {}", e)))
    }

    // ============================================
    // STATISTICS
    // ============================================

    /// Get tenant overview
    #[napi]
    pub async fn get_tenant_overview(&self, tenant_id: String) -> Result<TenantOverview> {
        let url = format!(
            "{}/api/v1/tenants/{}/stats/overview",
            self.base_url, tenant_id
        );

        let response = self
            .client
            .get(&url)
            .headers(self.auth_headers("GET", &url)?)
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        response
            .json::<TenantOverview>()
            .await
            .map_err(|e| Error::from_reason(format!("Failed to parse response: {}", e)))
    }

    /// Get authentication stats
    #[napi]
    pub async fn get_auth_stats(&self, tenant_id: String) -> Result<AuthenticationStats> {
        let url = format!("{}/api/v1/tenants/{}/stats/auth", self.base_url, tenant_id);

        let response = self
            .client
            .get(&url)
            .headers(self.auth_headers("GET", &url)?)
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        response
            .json::<AuthenticationStats>()
            .await
            .map_err(|e| Error::from_reason(format!("Failed to parse response: {}", e)))
    }

    /// Get session stats
    #[napi]
    pub async fn get_session_stats(&self, tenant_id: String) -> Result<SessionStats> {
        let url = format!(
            "{}/api/v1/tenants/{}/stats/sessions",
            self.base_url, tenant_id
        );

        let response = self
            .client
            .get(&url)
            .headers(self.auth_headers("GET", &url)?)
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        response
            .json::<SessionStats>()
            .await
            .map_err(|e| Error::from_reason(format!("Failed to parse response: {}", e)))
    }

    /// Get security stats
    #[napi]
    pub async fn get_security_stats(&self, tenant_id: String) -> Result<SecurityStats> {
        let url = format!(
            "{}/api/v1/tenants/{}/stats/security",
            self.base_url, tenant_id
        );

        let response = self
            .client
            .get(&url)
            .headers(self.auth_headers("GET", &url)?)
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        response
            .json::<SecurityStats>()
            .await
            .map_err(|e| Error::from_reason(format!("Failed to parse response: {}", e)))
    }

    // ============================================
    // SETUP & WORKFLOW SUPPORT
    // ============================================

    /// Check if setup is required
    #[napi]
    pub async fn requires_setup(&self) -> Result<SetupStatus> {
        let url = format!("{}/api/v1/setup/status", self.base_url);

        let response = self
            .client
            .get(&url)
            .headers(self.auth_headers("GET", &url)?)
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        response
            .json::<SetupStatus>()
            .await
            .map_err(|e| Error::from_reason(format!("Failed to parse response: {}", e)))
    }

    /// Perform initial setup
    #[napi]
    pub async fn perform_setup(
        &self,
        admin_username: String,
        admin_email: String,
        admin_password: String,
        tenant_name: Option<String>,
        tenant_slug: Option<String>,
    ) -> Result<()> {
        let url = format!("{}/api/v1/setup", self.base_url);

        #[derive(Serialize)]
        struct SetupPayload {
            admin_username: String,
            admin_email: String,
            admin_password: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            tenant_name: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            tenant_slug: Option<String>,
        }

        let response = self
            .client
            .post(&url)
            .headers(self.auth_headers("POST", &url)?)
            .json(&SetupPayload {
                admin_username,
                admin_email,
                admin_password,
                tenant_name,
                tenant_slug,
            })
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        Ok(())
    }

    /// Assign permission to role
    #[napi]
    pub async fn assign_permission_to_role(
        &self,
        tenant_id: String,
        role_id: String,
        permission_id: String,
    ) -> Result<()> {
        let url = format!(
            "{}/api/v1/tenants/{}/roles/{}/permissions",
            self.base_url, tenant_id, role_id
        );

        #[derive(Serialize)]
        struct AssignRequest {
            permission_id: String,
        }

        let response = self
            .client
            .post(&url)
            .headers(self.auth_headers("POST", &url)?)
            .json(&AssignRequest { permission_id })
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        Ok(())
    }

    /// Revoke all sessions for a user
    #[napi]
    pub async fn revoke_user_sessions(&self, tenant_id: String, user_id: String) -> Result<()> {
        let url = format!(
            "{}/api/v1/tenants/{}/users/{}/sessions",
            self.base_url, tenant_id, user_id
        );

        let response = self
            .client
            .delete(&url)
            .headers(self.auth_headers("DELETE", &url)?)
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP {}", response.status())));
        }

        Ok(())
    }

    // ============================================
    // WORKFLOW METHODS
    // ============================================

    /// Setup if needed (check and perform if required)
    #[napi]
    pub async fn setup_if_needed(
        &self,
        admin_username: String,
        admin_email: String,
        admin_password: String,
        tenant_name: Option<String>,
        tenant_slug: Option<String>,
    ) -> Result<bool> {
        let status = self.requires_setup().await?;
        if status.requires_setup {
            self.perform_setup(
                admin_username,
                admin_email,
                admin_password,
                tenant_name,
                tenant_slug,
            )
            .await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Provision a user and assign roles atomically
    #[napi]
    pub async fn provision_user(
        &self,
        tenant_id: String,
        input: CreateUserInput,
        role_ids: Vec<String>,
    ) -> Result<User> {
        let user = self.create_user(tenant_id.clone(), input).await?;
        let user_id = user.id.clone();

        for role_id in role_ids {
            if let Err(e) = self
                .assign_role_to_user(tenant_id.clone(), user_id.clone(), role_id)
                .await
            {
                let _ = self.delete_user(tenant_id.clone(), user_id.clone()).await;
                return Err(e);
            }
        }

        Ok(user)
    }

    /// Guard: require a permission or return error
    #[napi]
    pub async fn require_permission(
        &self,
        tenant_id: String,
        user_id: String,
        resource: String,
        action: String,
    ) -> Result<()> {
        let perm = self
            .check_permission(tenant_id.clone(), user_id, resource, action)
            .await?;
        if perm.allowed {
            Ok(())
        } else {
            Err(Error::from_reason("Permission denied".to_string()))
        }
    }

    /// Validate token and check permission in one call
    #[napi]
    pub async fn check_token_permission(
        &self,
        token: String,
        resource: String,
        action: String,
    ) -> Result<()> {
        let token_clean = token.trim_start_matches("Bearer ").trim();
        let validation = self.validate_token(token_clean.to_string()).await?;

        if !validation.valid {
            return Err(Error::from_reason(
                validation
                    .error
                    .unwrap_or_else(|| "Invalid token".to_string()),
            ));
        }

        let tenant_id = validation
            .tenant_id
            .ok_or_else(|| Error::from_reason("Token missing tenant_id".to_string()))?;
        let user_id = validation
            .user_id
            .ok_or_else(|| Error::from_reason("Token missing user_id".to_string()))?;

        self.require_permission(tenant_id, user_id, resource, action)
            .await
    }

    /// Setup RBAC: create roles with permissions
    #[napi]
    pub async fn setup_rbac(
        &self,
        tenant_id: String,
        roles: Vec<RoleDefinitionInput>,
    ) -> Result<Vec<String>> {
        let mut role_ids = Vec::with_capacity(roles.len());

        for role_def in roles {
            let role = self
                .create_role(
                    tenant_id.clone(),
                    CreateRoleInput {
                        name: role_def.name,
                        display_name: Some(role_def.display_name),
                        description: None,
                    },
                )
                .await?;

            for perm_def in role_def.permissions {
                let name = format!("{}:{}", perm_def.resource, perm_def.action);
                let permission = self
                    .create_permission(
                        tenant_id.clone(),
                        CreatePermissionInput {
                            name: name.clone(),
                            resource: perm_def.resource,
                            action: perm_def.action,
                        },
                    )
                    .await?;

                self.assign_permission_to_role(
                    tenant_id.clone(),
                    role.id.clone(),
                    permission.id.clone(),
                )
                .await?;
            }

            role_ids.push(role.id);
        }

        Ok(role_ids)
    }

    /// Collect all users with auto-pagination
    #[napi]
    pub async fn collect_users(&self, tenant_id: String) -> Result<Vec<User>> {
        let mut all = Vec::new();
        let mut page = 1i64;
        let per_page = 100i64;

        loop {
            let result = self.list_users(tenant_id.clone(), page, per_page).await?;
            let has_next = result["has_next"].as_bool().unwrap_or(false);
            if let Ok(items) = serde_json::from_value::<Vec<User>>(result["data"].clone()) {
                all.extend(items);
            }
            if !has_next {
                break;
            }
            page += 1;
        }

        Ok(all)
    }

    /// Collect all roles with auto-pagination
    #[napi]
    pub async fn collect_roles(&self, tenant_id: String) -> Result<Vec<Role>> {
        let mut all = Vec::new();
        let mut page = 1i64;
        let per_page = 100i64;

        loop {
            let result = self.list_roles(tenant_id.clone(), page, per_page).await?;
            let has_next = result["has_next"].as_bool().unwrap_or(false);
            if let Ok(items) = serde_json::from_value::<Vec<Role>>(result["data"].clone()) {
                all.extend(items);
            }
            if !has_next {
                break;
            }
            page += 1;
        }

        Ok(all)
    }

    /// Bootstrap a complete tenant
    #[napi]
    pub async fn bootstrap_tenant(&self, input: BootstrapTenantInput) -> Result<BootstrapResult> {
        let tenant = self
            .create_tenant(input.tenant_name.clone(), input.tenant_slug.clone())
            .await?;
        let tenant_id = tenant.id.clone();

        let admin_user = self
            .create_user(
                tenant_id.clone(),
                CreateUserInput {
                    username: input.admin_username,
                    email: input.admin_email,
                    password: Some(input.admin_password),
                    first_name: None,
                    last_name: None,
                },
            )
            .await?;

        let role_ids = if input.initial_roles.is_empty() {
            Vec::new()
        } else {
            self.setup_rbac(tenant_id.clone(), input.initial_roles)
                .await?
        };

        if let Some(first_role_id) = role_ids.first() {
            self.assign_role_to_user(
                tenant_id.clone(),
                admin_user.id.clone(),
                first_role_id.clone(),
            )
            .await?;
        }

        Ok(BootstrapResult {
            tenant,
            admin_user,
            role_ids,
        })
    }
}
