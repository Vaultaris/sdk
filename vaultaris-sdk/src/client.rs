//! Vaultaris HTTP client

use std::time::Duration;
use uuid::Uuid;

use crate::config::VaultarisConfig;
use crate::error::Error;
use crate::types::*;

/// Vaultaris SDK client for interacting with Vaultaris IAM
#[derive(Clone)]
pub struct VaultarisClient {
    config: VaultarisConfig,
    #[cfg(feature = "async")]
    http: reqwest::Client,
}

impl VaultarisClient {
    #[cfg(feature = "async")]
    pub fn new(config: VaultarisConfig) -> Result<Self, Error> {
        config.validate()?;

        let mut builder =
            reqwest::Client::builder().timeout(Duration::from_secs(config.timeout_seconds));

        if !config.verify_tls {
            builder = builder.danger_accept_invalid_certs(true);
        }

        if let Some(ua) = &config.user_agent {
            builder = builder.user_agent(ua);
        } else {
            builder =
                builder.user_agent(format!("vaultaris-sdk-rust/{}", env!("CARGO_PKG_VERSION")));
        }

        let http = builder
            .build()
            .map_err(|e| Error::Config(format!("Failed to build HTTP client: {}", e)))?;

        Ok(Self { config, http })
    }

    #[cfg(feature = "async")]
    pub fn from_env() -> Result<Self, Error> {
        let config = crate::config::VaultarisConfigBuilder::new()
            .from_env()
            .build()?;
        Self::new(config)
    }

    pub fn base_url(&self) -> &str {
        &self.config.base_url
    }

    pub fn tenant_id(&self) -> Option<&str> {
        self.config.tenant_id.as_deref()
    }

    // ============================================
    // INTERNAL HELPERS
    // ============================================

    #[cfg(feature = "async")]
    fn auth_header(&self) -> Option<String> {
        self.config.auth_header()
    }

    #[cfg(feature = "async")]
    fn url(&self, path: &str) -> String {
        self.config.build_url(path)
    }

    /// Apply auth + (optional) DPoP headers to a request builder.
    ///
    /// Centralises the per-request crypto so individual handlers stay free
    /// of DPoP awareness — the only thing the SDK user ever sees is the
    /// `with_dpop_key(...)` / `with_dpop_signer(...)` builder call on
    /// the config.
    #[cfg(feature = "async")]
    async fn apply_auth(
        &self,
        mut req: reqwest::RequestBuilder,
        method: &str,
        url: &str,
    ) -> Result<reqwest::RequestBuilder, Error> {
        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }
        #[cfg(feature = "dpop")]
        if let Some(proof) = self.config.dpop_proof(method, url).await {
            req = req.header("DPoP", proof?);
        }
        // Suppress unused-variable warnings when DPoP is compiled out.
        #[cfg(not(feature = "dpop"))]
        {
            let _ = (method, url);
        }
        if let Some(fp) = &self.config.device_fingerprint {
            req = req.header("X-Device-Fingerprint", fp);
        }
        Ok(req)
    }

    #[cfg(feature = "async")]
    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, Error> {
        let url = self.url(path);
        let req = self.apply_auth(self.http.get(&url), "GET", &url).await?;
        let response = req.send().await?;
        self.handle_response(response).await
    }

    #[cfg(feature = "async")]
    async fn get_query<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<T, Error> {
        let url = self.url(path);
        let req = self.apply_auth(self.http.get(&url).query(query), "GET", &url).await?;
        let response = req.send().await?;
        self.handle_response(response).await
    }

    #[cfg(feature = "async")]
    async fn post<B: serde::Serialize, T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, Error> {
        let url = self.url(path);
        let req = self.apply_auth(self.http.post(&url).json(body), "POST", &url).await?;
        let response = req.send().await?;
        self.handle_response(response).await
    }

    #[cfg(feature = "async")]
    async fn put<B: serde::Serialize, T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, Error> {
        let url = self.url(path);
        let req = self.apply_auth(self.http.put(&url).json(body), "PUT", &url).await?;
        let response = req.send().await?;
        self.handle_response(response).await
    }

    #[cfg(feature = "async")]
    async fn delete_no_body(&self, path: &str) -> Result<(), Error> {
        let url = self.url(path);
        let req = self.apply_auth(self.http.delete(&url), "DELETE", &url).await?;
        let response = req.send().await?;
        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            let text = response.text().await.unwrap_or_default();
            match status.as_u16() {
                401 => Err(Error::Auth(text)),
                403 => Err(Error::PermissionDenied(text)),
                404 => Err(Error::NotFound(text)),
                429 => Err(Error::RateLimited),
                500..=599 => Err(Error::Server(text)),
                _ => Err(Error::Http(format!("{}: {}", status, text))),
            }
        }
    }

    /// Unwrap `{ success, data }` envelope then deserialize inner `data`
    #[cfg(feature = "async")]
    async fn handle_response<T: serde::de::DeserializeOwned>(
        &self,
        response: reqwest::Response,
    ) -> Result<T, Error> {
        let status = response.status();

        if status.is_success() {
            let bytes = response.bytes().await.map_err(Error::from)?;
            // Try to deserialize as ApiResponse<T> first, then fall back to T directly
            if let Ok(wrapped) = serde_json::from_slice::<ApiResponse<T>>(&bytes) {
                return Ok(wrapped.data);
            }
            serde_json::from_slice::<T>(&bytes).map_err(|e| Error::Json(e.to_string()))
        } else {
            let error_text = response.text().await.unwrap_or_default();
            match status.as_u16() {
                401 => Err(Error::Auth(error_text)),
                403 => Err(Error::PermissionDenied(error_text)),
                404 => Err(Error::NotFound(error_text)),
                429 => Err(Error::RateLimited),
                500..=599 => Err(Error::Server(error_text)),
                _ => Err(Error::Http(format!("{}: {}", status, error_text))),
            }
        }
    }

    // ============================================
    // SETUP
    // ============================================

    #[cfg(feature = "async")]
    pub async fn get_setup_status(&self) -> Result<SetupStatus, Error> {
        self.get("/setup/status").await
    }

    #[cfg(feature = "async")]
    pub async fn requires_setup(&self) -> Result<SetupStatus, Error> {
        self.get("/setup/check").await
    }

    #[cfg(feature = "async")]
    pub async fn perform_setup(&self, req: &SetupRequest) -> Result<Tenant, Error> {
        self.post("/setup", req).await
    }

    // ============================================
    // TOKEN OPERATIONS
    // ============================================

    #[cfg(feature = "async")]
    pub async fn validate_token(&self, token: &str) -> Result<TokenValidation, Error> {
        self.validate_token_with_requirements(token, None, None)
            .await
    }

    #[cfg(feature = "async")]
    pub async fn validate_token_with_requirements(
        &self,
        token: &str,
        required_scopes: Option<Vec<String>>,
        required_permissions: Option<Vec<String>>,
    ) -> Result<TokenValidation, Error> {
        let request = ValidateTokenRequest {
            token: token.to_string(),
            required_scopes,
            required_permissions,
        };
        self.post("/api/v1/integration/token/validate", &request)
            .await
    }

    // ============================================
    // PERMISSION OPERATIONS
    // ============================================

    #[cfg(feature = "async")]
    pub async fn check_permission(
        &self,
        tenant_id: &str,
        user_id: &str,
        resource: &str,
        action: &str,
    ) -> Result<bool, Error> {
        let result = self
            .check_permission_detailed(tenant_id, user_id, resource, action, None)
            .await?;
        Ok(result.allowed)
    }

    #[cfg(feature = "async")]
    pub async fn check_permission_detailed(
        &self,
        tenant_id: &str,
        user_id: &str,
        resource: &str,
        action: &str,
        context: Option<serde_json::Value>,
    ) -> Result<PermissionCheck, Error> {
        let user_uuid =
            Uuid::parse_str(user_id).map_err(|_| Error::Config("Invalid user_id".to_string()))?;
        let request = CheckPermissionRequest {
            user_id: user_uuid,
            resource: resource.to_string(),
            action: action.to_string(),
            context,
        };
        self.post(
            &format!("/api/v1/tenants/{}/integration/check-permission", tenant_id),
            &request,
        )
        .await
    }

    #[cfg(feature = "async")]
    pub async fn batch_check_permissions(
        &self,
        tenant_id: &str,
        user_id: &str,
        checks: Vec<PermissionToCheck>,
    ) -> Result<BatchPermissionCheck, Error> {
        let user_uuid =
            Uuid::parse_str(user_id).map_err(|_| Error::Config("Invalid user_id".to_string()))?;
        let request = BatchCheckPermissionRequest {
            user_id: user_uuid,
            checks,
        };
        self.post(
            &format!(
                "/api/v1/tenants/{}/integration/check-permissions",
                tenant_id
            ),
            &request,
        )
        .await
    }

    // ============================================
    // INTEGRATION USER (read-only, lightweight)
    // ============================================

    #[cfg(feature = "async")]
    pub async fn get_user(&self, tenant_id: &str, user_id: &str) -> Result<UserInfo, Error> {
        self.get(&format!(
            "/api/v1/tenants/{}/integration/users/{}",
            tenant_id, user_id
        ))
        .await
    }

    // ============================================
    // SESSION (integration)
    // ============================================

    #[cfg(feature = "async")]
    pub async fn validate_session(&self, token: &str) -> Result<SessionValidation, Error> {
        self.get_query(
            "/api/v1/integration/session/validate",
            &[("token", token.to_string())],
        )
        .await
    }

    // ============================================
    // TENANT MANAGEMENT
    // ============================================

    #[cfg(feature = "async")]
    pub async fn list_tenants(&self, page: i64, per_page: i64) -> Result<Page<Tenant>, Error> {
        self.get_query(
            "/api/v1/tenants",
            &[
                ("page", page.to_string()),
                ("per_page", per_page.to_string()),
            ],
        )
        .await
    }

    #[cfg(feature = "async")]
    pub async fn create_tenant(&self, req: &CreateTenantRequest) -> Result<Tenant, Error> {
        self.post("/api/v1/tenants", req).await
    }

    #[cfg(feature = "async")]
    pub async fn get_tenant(&self, tenant_id: &str) -> Result<Tenant, Error> {
        self.get(&format!("/api/v1/tenants/{}", tenant_id)).await
    }

    #[cfg(feature = "async")]
    pub async fn update_tenant(
        &self,
        tenant_id: &str,
        req: &UpdateTenantRequest,
    ) -> Result<Tenant, Error> {
        self.put(&format!("/api/v1/tenants/{}", tenant_id), req)
            .await
    }

    #[cfg(feature = "async")]
    pub async fn delete_tenant(&self, tenant_id: &str) -> Result<(), Error> {
        self.delete_no_body(&format!("/api/v1/tenants/{}", tenant_id))
            .await
    }

    // ============================================
    // USER MANAGEMENT
    // ============================================

    #[cfg(feature = "async")]
    pub async fn list_users(
        &self,
        tenant_id: &str,
        page: i64,
        per_page: i64,
    ) -> Result<Page<User>, Error> {
        self.get_query(
            &format!("/api/v1/tenants/{}/users", tenant_id),
            &[
                ("page", page.to_string()),
                ("per_page", per_page.to_string()),
            ],
        )
        .await
    }

    #[cfg(feature = "async")]
    pub async fn create_user(
        &self,
        tenant_id: &str,
        req: &CreateUserRequest,
    ) -> Result<User, Error> {
        self.post(&format!("/api/v1/tenants/{}/users", tenant_id), req)
            .await
    }

    #[cfg(feature = "async")]
    pub async fn get_user_by_id(&self, tenant_id: &str, user_id: &str) -> Result<User, Error> {
        self.get(&format!("/api/v1/tenants/{}/users/{}", tenant_id, user_id))
            .await
    }

    #[cfg(feature = "async")]
    pub async fn update_user(
        &self,
        tenant_id: &str,
        user_id: &str,
        req: &UpdateUserRequest,
    ) -> Result<User, Error> {
        self.put(
            &format!("/api/v1/tenants/{}/users/{}", tenant_id, user_id),
            req,
        )
        .await
    }

    #[cfg(feature = "async")]
    pub async fn delete_user(&self, tenant_id: &str, user_id: &str) -> Result<(), Error> {
        self.delete_no_body(&format!("/api/v1/tenants/{}/users/{}", tenant_id, user_id))
            .await
    }

    #[cfg(feature = "async")]
    pub async fn get_user_roles(&self, tenant_id: &str, user_id: &str) -> Result<Vec<Role>, Error> {
        self.get(&format!(
            "/api/v1/tenants/{}/users/{}/roles",
            tenant_id, user_id
        ))
        .await
    }

    #[cfg(feature = "async")]
    pub async fn assign_role_to_user(
        &self,
        tenant_id: &str,
        user_id: &str,
        role_id: &str,
    ) -> Result<(), Error> {
        let role_uuid =
            Uuid::parse_str(role_id).map_err(|_| Error::Config("Invalid role_id".to_string()))?;
        let req = AssignRoleRequest { role_id: role_uuid };
        let _: serde_json::Value = self
            .post(
                &format!("/api/v1/tenants/{}/users/{}/roles", tenant_id, user_id),
                &req,
            )
            .await?;
        Ok(())
    }

    #[cfg(feature = "async")]
    pub async fn remove_role_from_user(
        &self,
        tenant_id: &str,
        user_id: &str,
        role_id: &str,
    ) -> Result<(), Error> {
        self.delete_no_body(&format!(
            "/api/v1/tenants/{}/users/{}/roles/{}",
            tenant_id, user_id, role_id
        ))
        .await
    }

    #[cfg(feature = "async")]
    pub async fn get_user_groups(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<Vec<Group>, Error> {
        self.get(&format!(
            "/api/v1/tenants/{}/users/{}/groups",
            tenant_id, user_id
        ))
        .await
    }

    #[cfg(feature = "async")]
    pub async fn assign_group_to_user(
        &self,
        tenant_id: &str,
        user_id: &str,
        group_id: &str,
    ) -> Result<(), Error> {
        let group_uuid =
            Uuid::parse_str(group_id).map_err(|_| Error::Config("Invalid group_id".to_string()))?;
        let req = AssignGroupRequest {
            group_id: group_uuid,
        };
        let _: serde_json::Value = self
            .post(
                &format!("/api/v1/tenants/{}/users/{}/groups", tenant_id, user_id),
                &req,
            )
            .await?;
        Ok(())
    }

    #[cfg(feature = "async")]
    pub async fn remove_group_from_user(
        &self,
        tenant_id: &str,
        user_id: &str,
        group_id: &str,
    ) -> Result<(), Error> {
        self.delete_no_body(&format!(
            "/api/v1/tenants/{}/users/{}/groups/{}",
            tenant_id, user_id, group_id
        ))
        .await
    }

    // ============================================
    // ROLE MANAGEMENT
    // ============================================

    #[cfg(feature = "async")]
    pub async fn list_roles(
        &self,
        tenant_id: &str,
        page: i64,
        per_page: i64,
    ) -> Result<Page<Role>, Error> {
        self.get_query(
            &format!("/api/v1/tenants/{}/roles", tenant_id),
            &[
                ("page", page.to_string()),
                ("per_page", per_page.to_string()),
            ],
        )
        .await
    }

    #[cfg(feature = "async")]
    pub async fn create_role(
        &self,
        tenant_id: &str,
        req: &CreateRoleRequest,
    ) -> Result<Role, Error> {
        self.post(&format!("/api/v1/tenants/{}/roles", tenant_id), req)
            .await
    }

    #[cfg(feature = "async")]
    pub async fn get_role(&self, tenant_id: &str, role_id: &str) -> Result<Role, Error> {
        self.get(&format!("/api/v1/tenants/{}/roles/{}", tenant_id, role_id))
            .await
    }

    #[cfg(feature = "async")]
    pub async fn update_role(
        &self,
        tenant_id: &str,
        role_id: &str,
        req: &UpdateRoleRequest,
    ) -> Result<Role, Error> {
        self.put(
            &format!("/api/v1/tenants/{}/roles/{}", tenant_id, role_id),
            req,
        )
        .await
    }

    #[cfg(feature = "async")]
    pub async fn delete_role(&self, tenant_id: &str, role_id: &str) -> Result<(), Error> {
        self.delete_no_body(&format!("/api/v1/tenants/{}/roles/{}", tenant_id, role_id))
            .await
    }

    #[cfg(feature = "async")]
    pub async fn get_role_permissions(
        &self,
        tenant_id: &str,
        role_id: &str,
    ) -> Result<Vec<Permission>, Error> {
        self.get(&format!(
            "/api/v1/tenants/{}/roles/{}/permissions",
            tenant_id, role_id
        ))
        .await
    }

    #[cfg(feature = "async")]
    pub async fn assign_permission_to_role(
        &self,
        tenant_id: &str,
        role_id: &str,
        permission_id: &str,
    ) -> Result<(), Error> {
        let perm_uuid = Uuid::parse_str(permission_id)
            .map_err(|_| Error::Config("Invalid permission_id".to_string()))?;
        let req = AssignPermissionRequest {
            permission_id: perm_uuid,
        };
        let _: serde_json::Value = self
            .post(
                &format!(
                    "/api/v1/tenants/{}/roles/{}/permissions",
                    tenant_id, role_id
                ),
                &req,
            )
            .await?;
        Ok(())
    }

    #[cfg(feature = "async")]
    pub async fn remove_permission_from_role(
        &self,
        tenant_id: &str,
        role_id: &str,
        permission_id: &str,
    ) -> Result<(), Error> {
        self.delete_no_body(&format!(
            "/api/v1/tenants/{}/roles/{}/permissions/{}",
            tenant_id, role_id, permission_id
        ))
        .await
    }

    // ============================================
    // PERMISSION MANAGEMENT
    // ============================================

    #[cfg(feature = "async")]
    pub async fn list_permissions(
        &self,
        tenant_id: &str,
        page: i64,
        per_page: i64,
    ) -> Result<Page<Permission>, Error> {
        self.get_query(
            &format!("/api/v1/tenants/{}/permissions", tenant_id),
            &[
                ("page", page.to_string()),
                ("per_page", per_page.to_string()),
            ],
        )
        .await
    }

    #[cfg(feature = "async")]
    pub async fn create_permission(
        &self,
        tenant_id: &str,
        req: &CreatePermissionRequest,
    ) -> Result<Permission, Error> {
        self.post(&format!("/api/v1/tenants/{}/permissions", tenant_id), req)
            .await
    }

    #[cfg(feature = "async")]
    pub async fn get_permission(
        &self,
        tenant_id: &str,
        permission_id: &str,
    ) -> Result<Permission, Error> {
        self.get(&format!(
            "/api/v1/tenants/{}/permissions/{}",
            tenant_id, permission_id
        ))
        .await
    }

    #[cfg(feature = "async")]
    pub async fn update_permission(
        &self,
        tenant_id: &str,
        permission_id: &str,
        req: &UpdatePermissionRequest,
    ) -> Result<Permission, Error> {
        self.put(
            &format!(
                "/api/v1/tenants/{}/permissions/{}",
                tenant_id, permission_id
            ),
            req,
        )
        .await
    }

    #[cfg(feature = "async")]
    pub async fn delete_permission(
        &self,
        tenant_id: &str,
        permission_id: &str,
    ) -> Result<(), Error> {
        self.delete_no_body(&format!(
            "/api/v1/tenants/{}/permissions/{}",
            tenant_id, permission_id
        ))
        .await
    }

    // ============================================
    // GROUP MANAGEMENT
    // ============================================

    #[cfg(feature = "async")]
    pub async fn list_groups(
        &self,
        tenant_id: &str,
        page: i64,
        per_page: i64,
    ) -> Result<Page<Group>, Error> {
        self.get_query(
            &format!("/api/v1/tenants/{}/groups", tenant_id),
            &[
                ("page", page.to_string()),
                ("per_page", per_page.to_string()),
            ],
        )
        .await
    }

    #[cfg(feature = "async")]
    pub async fn create_group(
        &self,
        tenant_id: &str,
        req: &CreateGroupRequest,
    ) -> Result<Group, Error> {
        self.post(&format!("/api/v1/tenants/{}/groups", tenant_id), req)
            .await
    }

    #[cfg(feature = "async")]
    pub async fn get_group(&self, tenant_id: &str, group_id: &str) -> Result<Group, Error> {
        self.get(&format!(
            "/api/v1/tenants/{}/groups/{}",
            tenant_id, group_id
        ))
        .await
    }

    #[cfg(feature = "async")]
    pub async fn update_group(
        &self,
        tenant_id: &str,
        group_id: &str,
        req: &UpdateGroupRequest,
    ) -> Result<Group, Error> {
        self.put(
            &format!("/api/v1/tenants/{}/groups/{}", tenant_id, group_id),
            req,
        )
        .await
    }

    #[cfg(feature = "async")]
    pub async fn delete_group(&self, tenant_id: &str, group_id: &str) -> Result<(), Error> {
        self.delete_no_body(&format!(
            "/api/v1/tenants/{}/groups/{}",
            tenant_id, group_id
        ))
        .await
    }

    #[cfg(feature = "async")]
    pub async fn get_group_members(
        &self,
        tenant_id: &str,
        group_id: &str,
    ) -> Result<Vec<User>, Error> {
        self.get(&format!(
            "/api/v1/tenants/{}/groups/{}/members",
            tenant_id, group_id
        ))
        .await
    }

    #[cfg(feature = "async")]
    pub async fn get_group_roles(
        &self,
        tenant_id: &str,
        group_id: &str,
    ) -> Result<Vec<Role>, Error> {
        self.get(&format!(
            "/api/v1/tenants/{}/groups/{}/roles",
            tenant_id, group_id
        ))
        .await
    }

    #[cfg(feature = "async")]
    pub async fn assign_role_to_group(
        &self,
        tenant_id: &str,
        group_id: &str,
        role_id: &str,
    ) -> Result<(), Error> {
        let role_uuid =
            Uuid::parse_str(role_id).map_err(|_| Error::Config("Invalid role_id".to_string()))?;
        let req = AssignRoleRequest { role_id: role_uuid };
        let _: serde_json::Value = self
            .post(
                &format!("/api/v1/tenants/{}/groups/{}/roles", tenant_id, group_id),
                &req,
            )
            .await?;
        Ok(())
    }

    #[cfg(feature = "async")]
    pub async fn remove_role_from_group(
        &self,
        tenant_id: &str,
        group_id: &str,
        role_id: &str,
    ) -> Result<(), Error> {
        self.delete_no_body(&format!(
            "/api/v1/tenants/{}/groups/{}/roles/{}",
            tenant_id, group_id, role_id
        ))
        .await
    }

    // ============================================
    // OAUTH CLIENT MANAGEMENT
    // ============================================

    #[cfg(feature = "async")]
    pub async fn list_clients(
        &self,
        tenant_id: &str,
        page: i64,
        per_page: i64,
    ) -> Result<Page<OAuthClient>, Error> {
        self.get_query(
            &format!("/api/v1/tenants/{}/clients", tenant_id),
            &[
                ("page", page.to_string()),
                ("per_page", per_page.to_string()),
            ],
        )
        .await
    }

    #[cfg(feature = "async")]
    pub async fn create_client(
        &self,
        tenant_id: &str,
        req: &CreateOAuthClientRequest,
    ) -> Result<ClientWithSecret, Error> {
        self.post(&format!("/api/v1/tenants/{}/clients", tenant_id), req)
            .await
    }

    #[cfg(feature = "async")]
    pub async fn get_client(&self, tenant_id: &str, client_id: &str) -> Result<OAuthClient, Error> {
        self.get(&format!(
            "/api/v1/tenants/{}/clients/{}",
            tenant_id, client_id
        ))
        .await
    }

    #[cfg(feature = "async")]
    pub async fn update_client(
        &self,
        tenant_id: &str,
        client_id: &str,
        req: &UpdateOAuthClientRequest,
    ) -> Result<OAuthClient, Error> {
        self.put(
            &format!("/api/v1/tenants/{}/clients/{}", tenant_id, client_id),
            req,
        )
        .await
    }

    #[cfg(feature = "async")]
    pub async fn delete_client(&self, tenant_id: &str, client_id: &str) -> Result<(), Error> {
        self.delete_no_body(&format!(
            "/api/v1/tenants/{}/clients/{}",
            tenant_id, client_id
        ))
        .await
    }

    #[cfg(feature = "async")]
    pub async fn regenerate_client_secret(
        &self,
        tenant_id: &str,
        client_id: &str,
    ) -> Result<ClientWithSecret, Error> {
        let empty = serde_json::json!({});
        self.post(
            &format!("/api/v1/tenants/{}/clients/{}/secret", tenant_id, client_id),
            &empty,
        )
        .await
    }

    // ============================================
    // SESSION MANAGEMENT
    // ============================================

    #[cfg(feature = "async")]
    pub async fn list_sessions(
        &self,
        tenant_id: &str,
        page: i64,
        per_page: i64,
    ) -> Result<Page<Session>, Error> {
        self.get_query(
            &format!("/api/v1/tenants/{}/sessions", tenant_id),
            &[
                ("page", page.to_string()),
                ("per_page", per_page.to_string()),
            ],
        )
        .await
    }

    #[cfg(feature = "async")]
    pub async fn revoke_session(&self, tenant_id: &str, session_id: &str) -> Result<(), Error> {
        self.delete_no_body(&format!(
            "/api/v1/tenants/{}/sessions/{}",
            tenant_id, session_id
        ))
        .await
    }

    #[cfg(feature = "async")]
    pub async fn get_user_sessions(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<Vec<Session>, Error> {
        self.get(&format!(
            "/api/v1/tenants/{}/users/{}/sessions",
            tenant_id, user_id
        ))
        .await
    }

    #[cfg(feature = "async")]
    pub async fn revoke_user_sessions(&self, tenant_id: &str, user_id: &str) -> Result<(), Error> {
        self.delete_no_body(&format!(
            "/api/v1/tenants/{}/users/{}/sessions",
            tenant_id, user_id
        ))
        .await
    }

    // ============================================
    // ABAC POLICIES
    // ============================================

    #[cfg(feature = "async")]
    pub async fn list_policies(
        &self,
        tenant_id: &str,
        page: i64,
        per_page: i64,
    ) -> Result<Page<AbacPolicy>, Error> {
        self.get_query(
            &format!("/api/v1/tenants/{}/policies", tenant_id),
            &[
                ("page", page.to_string()),
                ("per_page", per_page.to_string()),
            ],
        )
        .await
    }

    #[cfg(feature = "async")]
    pub async fn create_policy(
        &self,
        tenant_id: &str,
        req: &CreateAbacPolicyRequest,
    ) -> Result<AbacPolicy, Error> {
        self.post(&format!("/api/v1/tenants/{}/policies", tenant_id), req)
            .await
    }

    #[cfg(feature = "async")]
    pub async fn get_policy(&self, tenant_id: &str, policy_id: &str) -> Result<AbacPolicy, Error> {
        self.get(&format!(
            "/api/v1/tenants/{}/policies/{}",
            tenant_id, policy_id
        ))
        .await
    }

    #[cfg(feature = "async")]
    pub async fn update_policy(
        &self,
        tenant_id: &str,
        policy_id: &str,
        req: &UpdateAbacPolicyRequest,
    ) -> Result<AbacPolicy, Error> {
        self.put(
            &format!("/api/v1/tenants/{}/policies/{}", tenant_id, policy_id),
            req,
        )
        .await
    }

    #[cfg(feature = "async")]
    pub async fn delete_policy(&self, tenant_id: &str, policy_id: &str) -> Result<(), Error> {
        self.delete_no_body(&format!(
            "/api/v1/tenants/{}/policies/{}",
            tenant_id, policy_id
        ))
        .await
    }

    #[cfg(feature = "async")]
    pub async fn evaluate_policies(
        &self,
        tenant_id: &str,
        req: &EvaluatePoliciesRequest,
    ) -> Result<PolicyEvaluationResult, Error> {
        self.post(
            &format!("/api/v1/tenants/{}/policies/evaluate", tenant_id),
            req,
        )
        .await
    }

    // ============================================
    // AUDIT LOGS
    // ============================================

    #[cfg(feature = "async")]
    pub async fn list_audit_logs(
        &self,
        tenant_id: &str,
        page: i64,
        per_page: i64,
    ) -> Result<Page<AuditLog>, Error> {
        self.get_query(
            &format!("/api/v1/tenants/{}/audit-logs", tenant_id),
            &[
                ("page", page.to_string()),
                ("per_page", per_page.to_string()),
            ],
        )
        .await
    }

    #[cfg(feature = "async")]
    pub async fn get_audit_log(&self, tenant_id: &str, log_id: &str) -> Result<AuditLog, Error> {
        self.get(&format!(
            "/api/v1/tenants/{}/audit-logs/{}",
            tenant_id, log_id
        ))
        .await
    }

    // ============================================
    // IDENTITY PROVIDERS
    // ============================================

    #[cfg(feature = "async")]
    pub async fn list_identity_providers(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<IdentityProvider>, Error> {
        self.get(&format!("/api/v1/tenants/{}/identity-providers", tenant_id))
            .await
    }

    #[cfg(feature = "async")]
    pub async fn create_identity_provider(
        &self,
        tenant_id: &str,
        req: &CreateIdentityProviderRequest,
    ) -> Result<IdentityProvider, Error> {
        self.post(
            &format!("/api/v1/tenants/{}/identity-providers", tenant_id),
            req,
        )
        .await
    }

    #[cfg(feature = "async")]
    pub async fn get_identity_provider(
        &self,
        tenant_id: &str,
        provider_id: &str,
    ) -> Result<IdentityProvider, Error> {
        self.get(&format!(
            "/api/v1/tenants/{}/identity-providers/{}",
            tenant_id, provider_id
        ))
        .await
    }

    // ============================================
    // JWT KEYS
    // ============================================

    #[cfg(feature = "async")]
    pub async fn list_keys(&self, tenant_id: &str) -> Result<Vec<JwtKey>, Error> {
        self.get(&format!("/api/v1/tenants/{}/keys", tenant_id))
            .await
    }

    #[cfg(feature = "async")]
    pub async fn rotate_keys(&self, tenant_id: &str) -> Result<JwtKey, Error> {
        let empty = serde_json::json!({});
        self.post(
            &format!("/api/v1/tenants/{}/keys/rotate", tenant_id),
            &empty,
        )
        .await
    }

    // ============================================
    // MFA
    // ============================================

    #[cfg(feature = "async")]
    pub async fn setup_totp(&self) -> Result<TotpSetupResult, Error> {
        let empty = serde_json::json!({});
        self.post("/api/v1/mfa/totp/setup", &empty).await
    }

    #[cfg(feature = "async")]
    pub async fn verify_totp_setup(&self, code: &str) -> Result<TotpVerifyResult, Error> {
        let req = TotpVerifyRequest {
            code: code.to_string(),
            is_backup_code: false,
        };
        self.post("/api/v1/mfa/totp/verify", &req).await
    }

    #[cfg(feature = "async")]
    pub async fn verify_totp(
        &self,
        user_id: &str,
        code: &str,
        is_backup_code: bool,
    ) -> Result<TotpVerifyResult, Error> {
        let req = TotpVerifyRequest {
            code: code.to_string(),
            is_backup_code,
        };
        self.post(&format!("/api/v1/mfa/totp/{}/verify", user_id), &req)
            .await
    }

    #[cfg(feature = "async")]
    pub async fn disable_totp(&self) -> Result<(), Error> {
        self.delete_no_body("/api/v1/mfa/totp/disable").await
    }

    #[cfg(feature = "async")]
    pub async fn get_webauthn_credentials(&self) -> Result<Vec<WebAuthnCredential>, Error> {
        self.get("/api/v1/mfa/webauthn/credentials").await
    }

    #[cfg(feature = "async")]
    pub async fn begin_webauthn_registration(&self) -> Result<RegistrationBeginResponse, Error> {
        let empty = serde_json::json!({});
        self.post("/api/v1/mfa/webauthn/register/begin", &empty)
            .await
    }

    #[cfg(feature = "async")]
    pub async fn complete_webauthn_registration(
        &self,
        challenge_id: Uuid,
        credential_id: impl AsRef<str>,
        client_data_json: impl AsRef<str>,
        attestation_object: impl AsRef<str>,
        device_name: Option<&str>,
        transports: Option<Vec<String>>,
    ) -> Result<WebAuthnCredential, Error> {
        let body = serde_json::json!({
            "challenge_id": challenge_id,
            "device_name": device_name,
            "id": credential_id.as_ref(),
            "response": {
                "clientDataJSON": client_data_json.as_ref(),
                "attestationObject": attestation_object.as_ref(),
                "transports": transports.unwrap_or_default(),
            }
        });
        self.post("/api/v1/mfa/webauthn/register/complete", &body)
            .await
    }

    #[cfg(feature = "async")]
    pub async fn begin_webauthn_authentication(
        &self,
    ) -> Result<AuthenticationBeginResponse, Error> {
        let empty = serde_json::json!({});
        self.post("/api/v1/mfa/webauthn/authenticate/begin", &empty)
            .await
    }

    #[cfg(feature = "async")]
    pub async fn complete_webauthn_authentication(
        &self,
        challenge_id: Uuid,
        credential_id: impl AsRef<str>,
        client_data_json: impl AsRef<str>,
        authenticator_data: impl AsRef<str>,
        signature: impl AsRef<str>,
        user_handle: Option<&str>,
    ) -> Result<WebAuthnCredential, Error> {
        let body = serde_json::json!({
            "challenge_id": challenge_id,
            "id": credential_id.as_ref(),
            "response": {
                "clientDataJSON": client_data_json.as_ref(),
                "authenticatorData": authenticator_data.as_ref(),
                "signature": signature.as_ref(),
                "userHandle": user_handle,
            }
        });
        self.post("/api/v1/mfa/webauthn/authenticate/complete", &body)
            .await
    }

    #[cfg(feature = "async")]
    pub async fn delete_webauthn_credential(&self, credential_id: &str) -> Result<(), Error> {
        self.delete_no_body(&format!(
            "/api/v1/mfa/webauthn/credentials/{}",
            credential_id
        ))
        .await
    }

    // ============================================
    // PASSWORD RESET
    // ============================================

    #[cfg(feature = "async")]
    pub async fn request_password_reset(&self, tenant_id: &str, email: &str) -> Result<(), Error> {
        let req = PasswordResetRequest {
            email: email.to_string(),
        };
        let _: serde_json::Value = self
            .post(
                &format!("/api/v1/tenants/{}/auth/password-reset", tenant_id),
                &req,
            )
            .await?;
        Ok(())
    }

    #[cfg(feature = "async")]
    pub async fn validate_reset_token(&self, token: &str) -> Result<ResetTokenValidation, Error> {
        self.get(&format!("/api/v1/auth/password-reset/{}/validate", token))
            .await
    }

    #[cfg(feature = "async")]
    pub async fn complete_password_reset(
        &self,
        token: &str,
        new_password: &str,
    ) -> Result<(), Error> {
        let req = PasswordResetConfirmRequest {
            token: token.to_string(),
            new_password: new_password.to_string(),
        };
        let _: serde_json::Value = self
            .post("/api/v1/auth/password-reset/complete", &req)
            .await?;
        Ok(())
    }

    // ============================================
    // EMAIL VERIFICATION
    // ============================================

    #[cfg(feature = "async")]
    pub async fn resend_verification_email(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<(), Error> {
        let empty = serde_json::json!({});
        let _: serde_json::Value = self
            .post(
                &format!(
                    "/api/v1/tenants/{}/users/{}/verify-email",
                    tenant_id, user_id
                ),
                &empty,
            )
            .await?;
        Ok(())
    }

    #[cfg(feature = "async")]
    pub async fn verify_email(&self, token: &str) -> Result<(), Error> {
        let req = EmailVerificationRequest {
            token: token.to_string(),
        };
        let _: serde_json::Value = self.post("/api/v1/auth/verify-email", &req).await?;
        Ok(())
    }

    // ============================================
    // STATISTICS
    // ============================================

    #[cfg(feature = "async")]
    pub async fn get_tenant_overview(&self, tenant_id: &str) -> Result<TenantOverview, Error> {
        self.get(&format!("/api/v1/tenants/{}/stats/overview", tenant_id))
            .await
    }

    #[cfg(feature = "async")]
    pub async fn get_auth_stats(&self, tenant_id: &str) -> Result<AuthenticationStats, Error> {
        self.get(&format!("/api/v1/tenants/{}/stats/auth", tenant_id))
            .await
    }

    #[cfg(feature = "async")]
    pub async fn get_session_stats(&self, tenant_id: &str) -> Result<SessionStats, Error> {
        self.get(&format!("/api/v1/tenants/{}/stats/sessions", tenant_id))
            .await
    }

    #[cfg(feature = "async")]
    pub async fn get_security_stats(&self, tenant_id: &str) -> Result<SecurityStats, Error> {
        self.get(&format!("/api/v1/tenants/{}/stats/security", tenant_id))
            .await
    }

    #[cfg(feature = "async")]
    pub async fn get_dashboard_summary(&self, tenant_id: &str) -> Result<DashboardSummary, Error> {
        self.get(&format!("/api/v1/tenants/{}/stats/dashboard", tenant_id))
            .await
    }
}

// ============================================
// CONVENIENCE METHODS
// ============================================

impl VaultarisClient {
    #[cfg(feature = "async")]
    pub async fn has_any_permission(
        &self,
        tenant_id: &str,
        user_id: &str,
        permissions: &[(&str, &str)],
    ) -> Result<bool, Error> {
        let checks: Vec<PermissionToCheck> = permissions
            .iter()
            .map(|(r, a)| PermissionToCheck::new(*r, *a))
            .collect();

        let results = self
            .batch_check_permissions(tenant_id, user_id, checks)
            .await?;

        Ok(results.results.iter().any(|r| r.allowed))
    }

    #[cfg(feature = "async")]
    pub async fn has_all_permissions(
        &self,
        tenant_id: &str,
        user_id: &str,
        permissions: &[(&str, &str)],
    ) -> Result<bool, Error> {
        let checks: Vec<PermissionToCheck> = permissions
            .iter()
            .map(|(r, a)| PermissionToCheck::new(*r, *a))
            .collect();

        let results = self
            .batch_check_permissions(tenant_id, user_id, checks)
            .await?;

        Ok(results.results.iter().all(|r| r.allowed))
    }

    #[cfg(feature = "async")]
    pub async fn is_token_valid(&self, token: &str) -> bool {
        self.validate_token(token)
            .await
            .map(|v| v.valid)
            .unwrap_or(false)
    }
}

impl std::fmt::Debug for VaultarisClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultarisClient")
            .field("base_url", &self.config.base_url)
            .field("has_api_key", &self.config.api_key.is_some())
            .finish()
    }
}
