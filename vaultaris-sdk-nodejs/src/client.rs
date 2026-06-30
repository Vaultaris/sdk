//! Node.js client — thin napi shell around `vaultaris_sdk::VaultarisClient`.
//!
//! Re-using the Rust SDK guarantees endpoint paths, auth scheme, DPoP, and
//! envelope handling stay in lock-step with the canonical client. Each napi
//! method here just converts JS-friendly types (Strings/UUID-strings, JSON
//! objects) to/from the underlying SDK request/response types.

use std::str::FromStr;
use std::time::Duration;

use napi::bindgen_prelude::*;
use napi_derive::napi;
use serde_json::Value as JsonValue;

use crate::dpop::DpopKey;
use crate::*;

use vaultaris_sdk::{
    AuthScheme, Pagination as SdkPagination, StatsQuery as SdkStatsQuery,
    VaultarisConfig as SdkConfig, types as sdk_types,
};

fn sdk_err(e: vaultaris_sdk::Error) -> Error {
    Error::from_reason(e.to_string())
}

fn parse_uuid(name: &'static str, value: &str) -> Result<uuid::Uuid> {
    uuid::Uuid::from_str(value).map_err(|e| Error::from_reason(format!("invalid {name}: {e}")))
}

/// Vaultaris client for Node.js.
#[napi]
pub struct VaultarisClient {
    inner: vaultaris_sdk::VaultarisClient,
}

#[napi]
impl VaultarisClient {
    /// Construct a new client.
    ///
    /// ```js
    /// const client = new VaultarisClient({
    ///   baseUrl: 'https://auth.example.com',
    ///   apiKey:  'vk_live_...',
    /// });
    /// ```
    ///
    /// Pass a `DpopKey` as the second arg to transparently attach a
    /// freshly-signed DPoP proof to every request.
    #[napi(constructor)]
    pub fn new(config: VaultarisConfig, dpop_key: Option<&DpopKey>) -> Result<Self> {
        let mut sdk_config = SdkConfig::new(config.base_url)
            .with_auth_scheme(AuthScheme::ApiKey)
            .with_timeout(Duration::from_millis(u64::from(
                config.timeout_ms.unwrap_or(30_000),
            )));
        if let Some(key) = config.api_key {
            sdk_config = sdk_config.with_api_key(key);
        }
        if let Some(key) = dpop_key {
            sdk_config = sdk_config.with_dpop_key(key.inner.clone());
        }
        sdk_config = match config.device_fingerprint.as_deref() {
            Some("auto") => sdk_config.with_auto_fingerprint(),
            Some(fp) => sdk_config.with_device_fingerprint(fp.to_string()),
            None => sdk_config,
        };
        let inner = vaultaris_sdk::VaultarisClient::try_from(sdk_config).map_err(sdk_err)?;
        Ok(Self { inner })
    }

    // ── Integration ───────────────────────────────────────────────────────

    #[napi]
    pub async fn validate_token(&self, token: String) -> Result<TokenValidation> {
        let v = self.inner.validate_token(&token).await.map_err(sdk_err)?;
        Ok(token_validation_from(v))
    }

    #[napi]
    pub async fn check_permission(
        &self,
        tenant_id: String,
        user_id: String,
        resource: String,
        action: String,
    ) -> Result<PermissionCheck> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let uid = parse_uuid("user_id", &user_id)?;
        let p = self
            .inner
            .check_permission_detailed(tid, uid, &resource, &action, None)
            .await
            .map_err(sdk_err)?;
        Ok(PermissionCheck {
            allowed: p.allowed,
            reason: p.reason,
            policy: p.matched_policy,
        })
    }

    #[napi]
    pub async fn check_permissions(
        &self,
        tenant_id: String,
        user_id: String,
        permissions: Vec<PermissionDefinitionInput>,
    ) -> Result<BatchPermissionResponse> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let uid = parse_uuid("user_id", &user_id)?;
        let checks = permissions
            .into_iter()
            .map(|p| sdk_types::PermissionToCheck::new(p.resource, p.action))
            .collect();
        let r = self
            .inner
            .batch_check_permissions(tid, uid, checks)
            .await
            .map_err(sdk_err)?;
        let all_allowed = r.results.iter().all(|x| x.allowed);
        Ok(BatchPermissionResponse {
            results: r
                .results
                .into_iter()
                .map(|x| BatchPermissionResult {
                    resource: x.resource,
                    action: x.action,
                    allowed: x.allowed,
                })
                .collect(),
            all_allowed,
        })
    }

    #[napi]
    pub async fn get_user(&self, tenant_id: String, user_id: String) -> Result<UserInfo> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let uid = parse_uuid("user_id", &user_id)?;
        let u = self
            .inner
            .integration_user(tid, uid)
            .await
            .map_err(sdk_err)?;
        Ok(user_info_from(u))
    }

    #[napi]
    pub async fn validate_session(&self, token: String) -> Result<SessionValidation> {
        let v = self.inner.validate_session(&token).await.map_err(sdk_err)?;
        Ok(SessionValidation {
            valid: v.valid,
            session_id: None,
            user_id: v.session.as_ref().map(|s| s.user_id.to_string()),
            username: v.user.as_ref().map(|u| u.username.clone()),
            tenant_id: v.session.as_ref().map(|s| s.tenant_id.to_string()),
            expires_at: v.session.as_ref().map(|s| s.expires_at.to_rfc3339()),
            error: v.error,
        })
    }

    // ── Tenants ───────────────────────────────────────────────────────────

    #[napi]
    pub async fn list_tenants(&self, page: i64, per_page: i64) -> Result<JsonValue> {
        let res = self
            .inner
            .list_tenants(pagination(page, per_page))
            .await
            .map_err(sdk_err)?;
        serde_json::to_value(res).map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn create_tenant(&self, name: String, slug: String) -> Result<Tenant> {
        let t = self
            .inner
            .create_tenant(&sdk_types::CreateTenantRequest {
                name,
                slug,
                ..Default::default()
            })
            .await
            .map_err(sdk_err)?;
        Ok(tenant_from(t))
    }

    #[napi]
    pub async fn get_tenant(&self, tenant_id: String) -> Result<Tenant> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let t = self.inner.get_tenant(tid).await.map_err(sdk_err)?;
        Ok(tenant_from(t))
    }

    #[napi]
    pub async fn delete_tenant(&self, tenant_id: String) -> Result<()> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        self.inner.delete_tenant(tid).await.map_err(sdk_err)
    }

    // ── Users ─────────────────────────────────────────────────────────────

    #[napi]
    pub async fn list_users(
        &self,
        tenant_id: String,
        page: i64,
        per_page: i64,
    ) -> Result<JsonValue> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let res = self
            .inner
            .list_users(tid, pagination(page, per_page))
            .await
            .map_err(sdk_err)?;
        serde_json::to_value(res).map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn create_user(&self, tenant_id: String, input: CreateUserInput) -> Result<User> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let req = sdk_types::CreateUserRequest {
            username: input.username,
            email: input.email,
            password: input.password,
            first_name: input.first_name,
            last_name: input.last_name,
            ..Default::default()
        };
        let u = self.inner.create_user(tid, &req).await.map_err(sdk_err)?;
        Ok(user_from(u))
    }

    #[napi]
    pub async fn get_user_by_id(&self, tenant_id: String, user_id: String) -> Result<User> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let uid = parse_uuid("user_id", &user_id)?;
        let u = self.inner.get_user(tid, uid).await.map_err(sdk_err)?;
        Ok(user_from(u))
    }

    #[napi]
    pub async fn delete_user(&self, tenant_id: String, user_id: String) -> Result<()> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let uid = parse_uuid("user_id", &user_id)?;
        self.inner.delete_user(tid, uid).await.map_err(sdk_err)
    }

    #[napi]
    pub async fn get_user_roles(&self, tenant_id: String, user_id: String) -> Result<Vec<Role>> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let uid = parse_uuid("user_id", &user_id)?;
        let roles = self.inner.user_roles(tid, uid).await.map_err(sdk_err)?;
        Ok(roles.into_iter().map(role_from).collect())
    }

    #[napi]
    pub async fn assign_role_to_user(
        &self,
        tenant_id: String,
        user_id: String,
        role_id: String,
    ) -> Result<()> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let uid = parse_uuid("user_id", &user_id)?;
        let rid = parse_uuid("role_id", &role_id)?;
        self.inner
            .assign_role_to_user(tid, uid, rid)
            .await
            .map_err(sdk_err)
    }

    #[napi]
    pub async fn revoke_user_sessions(&self, tenant_id: String, user_id: String) -> Result<()> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let uid = parse_uuid("user_id", &user_id)?;
        self.inner
            .revoke_user_sessions(tid, uid)
            .await
            .map_err(sdk_err)
    }

    // ── Roles ─────────────────────────────────────────────────────────────

    #[napi]
    pub async fn list_roles(
        &self,
        tenant_id: String,
        page: i64,
        per_page: i64,
    ) -> Result<JsonValue> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let res = self
            .inner
            .list_roles(tid, pagination(page, per_page))
            .await
            .map_err(sdk_err)?;
        serde_json::to_value(res).map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn create_role(&self, tenant_id: String, input: CreateRoleInput) -> Result<Role> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let req = sdk_types::CreateRoleRequest {
            name: input.name,
            display_name: input.display_name,
            description: input.description,
            ..Default::default()
        };
        let r = self.inner.create_role(tid, &req).await.map_err(sdk_err)?;
        Ok(role_from(r))
    }

    #[napi]
    pub async fn get_role(&self, tenant_id: String, role_id: String) -> Result<Role> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let rid = parse_uuid("role_id", &role_id)?;
        let r = self.inner.get_role(tid, rid).await.map_err(sdk_err)?;
        Ok(role_from(r))
    }

    #[napi]
    pub async fn delete_role(&self, tenant_id: String, role_id: String) -> Result<()> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let rid = parse_uuid("role_id", &role_id)?;
        self.inner.delete_role(tid, rid).await.map_err(sdk_err)
    }

    #[napi]
    pub async fn assign_permission_to_role(
        &self,
        tenant_id: String,
        role_id: String,
        permission_id: String,
    ) -> Result<()> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let rid = parse_uuid("role_id", &role_id)?;
        let pid = parse_uuid("permission_id", &permission_id)?;
        self.inner
            .assign_permission_to_role(tid, rid, pid)
            .await
            .map_err(sdk_err)
    }

    // ── Permissions ───────────────────────────────────────────────────────

    #[napi]
    pub async fn list_permissions(
        &self,
        tenant_id: String,
        page: i64,
        per_page: i64,
    ) -> Result<JsonValue> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let res = self
            .inner
            .list_permissions(tid, pagination(page, per_page))
            .await
            .map_err(sdk_err)?;
        serde_json::to_value(res).map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn create_permission(
        &self,
        tenant_id: String,
        input: CreatePermissionInput,
    ) -> Result<Permission> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let req = sdk_types::CreatePermissionRequest {
            name: input.name,
            resource: input.resource,
            action: input.action,
            ..Default::default()
        };
        let p = self
            .inner
            .create_permission(tid, &req)
            .await
            .map_err(sdk_err)?;
        Ok(permission_from(p))
    }

    #[napi]
    pub async fn delete_permission(&self, tenant_id: String, permission_id: String) -> Result<()> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let pid = parse_uuid("permission_id", &permission_id)?;
        self.inner
            .delete_permission(tid, pid)
            .await
            .map_err(sdk_err)
    }

    // ── Groups ────────────────────────────────────────────────────────────

    #[napi]
    pub async fn list_groups(
        &self,
        tenant_id: String,
        page: i64,
        per_page: i64,
    ) -> Result<JsonValue> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let res = self
            .inner
            .list_groups(tid, pagination(page, per_page))
            .await
            .map_err(sdk_err)?;
        serde_json::to_value(res).map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn create_group(&self, tenant_id: String, input: CreateGroupInput) -> Result<Group> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let req = sdk_types::CreateGroupRequest {
            name: input.name,
            display_name: input.display_name,
            description: input.description,
            ..Default::default()
        };
        let g = self.inner.create_group(tid, &req).await.map_err(sdk_err)?;
        Ok(group_from(g))
    }

    #[napi]
    pub async fn get_group(&self, tenant_id: String, group_id: String) -> Result<Group> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let gid = parse_uuid("group_id", &group_id)?;
        let g = self.inner.get_group(tid, gid).await.map_err(sdk_err)?;
        Ok(group_from(g))
    }

    #[napi]
    pub async fn delete_group(&self, tenant_id: String, group_id: String) -> Result<()> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let gid = parse_uuid("group_id", &group_id)?;
        self.inner.delete_group(tid, gid).await.map_err(sdk_err)
    }

    // ── OAuth clients ─────────────────────────────────────────────────────

    #[napi]
    pub async fn list_clients(
        &self,
        tenant_id: String,
        page: i64,
        per_page: i64,
    ) -> Result<JsonValue> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let res = self
            .inner
            .list_clients(tid, pagination(page, per_page))
            .await
            .map_err(sdk_err)?;
        serde_json::to_value(res).map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn create_client(
        &self,
        tenant_id: String,
        input: CreateClientInput,
    ) -> Result<ClientWithSecret> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let req = sdk_types::CreateOAuthClientRequest {
            client_id: input.client_id,
            name: input.name,
            redirect_uris: input.redirect_uris,
            ..Default::default()
        };
        let r = self.inner.create_client(tid, &req).await.map_err(sdk_err)?;
        Ok(ClientWithSecret {
            client: oauth_client_from(r.client),
            client_secret: r.client_secret,
        })
    }

    #[napi]
    pub async fn get_client(&self, tenant_id: String, client_id: String) -> Result<OAuthClient> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let cid = parse_uuid("client_id", &client_id)?;
        let c = self.inner.get_client(tid, cid).await.map_err(sdk_err)?;
        Ok(oauth_client_from(c))
    }

    #[napi]
    pub async fn delete_client(&self, tenant_id: String, client_id: String) -> Result<()> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let cid = parse_uuid("client_id", &client_id)?;
        self.inner.delete_client(tid, cid).await.map_err(sdk_err)
    }

    // ── Sessions ──────────────────────────────────────────────────────────

    #[napi]
    pub async fn list_sessions(
        &self,
        tenant_id: String,
        page: i64,
        per_page: i64,
    ) -> Result<JsonValue> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let res = self
            .inner
            .list_sessions(tid, pagination(page, per_page))
            .await
            .map_err(sdk_err)?;
        serde_json::to_value(res).map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn revoke_session(&self, tenant_id: String, session_id: String) -> Result<()> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let sid = parse_uuid("session_id", &session_id)?;
        self.inner.revoke_session(tid, sid).await.map_err(sdk_err)
    }

    // ── Audit ─────────────────────────────────────────────────────────────

    #[napi]
    pub async fn list_audit_logs(
        &self,
        tenant_id: String,
        page: i64,
        per_page: i64,
    ) -> Result<JsonValue> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let res = self
            .inner
            .list_audit_logs(tid, pagination(page, per_page))
            .await
            .map_err(sdk_err)?;
        serde_json::to_value(res).map_err(|e| Error::from_reason(e.to_string()))
    }

    // ── Statistics ────────────────────────────────────────────────────────

    #[napi]
    pub async fn get_tenant_overview(&self, tenant_id: String) -> Result<TenantOverview> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let o = self.inner.tenant_overview(tid).await.map_err(sdk_err)?;
        Ok(TenantOverview {
            tenant_id: o.tenant_id.to_string(),
            total_users: o.total_users,
            active_users: o.active_users,
            total_roles: o.total_roles,
            total_groups: o.total_groups,
            total_clients: o.total_clients,
            active_sessions: o.active_sessions,
        })
    }

    #[napi]
    pub async fn get_auth_stats(&self, tenant_id: String) -> Result<AuthenticationStats> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let s = self
            .inner
            .auth_stats(tid, &SdkStatsQuery::last_7d())
            .await
            .map_err(sdk_err)?;
        Ok(AuthenticationStats {
            total_attempts: s.total_attempts,
            successful: s.successful,
            failed: s.failed,
            success_rate: s.success_rate,
        })
    }

    #[napi]
    pub async fn get_session_stats(&self, tenant_id: String) -> Result<SessionStats> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let s = self
            .inner
            .session_stats(tid, &SdkStatsQuery::last_7d())
            .await
            .map_err(sdk_err)?;
        Ok(SessionStats {
            active_sessions: s.active_sessions,
            sessions_today: s.sessions_today,
            avg_session_duration: s.avg_session_duration,
        })
    }

    #[napi]
    pub async fn get_security_stats(&self, tenant_id: String) -> Result<SecurityStats> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let s = self
            .inner
            .security_stats(tid, &SdkStatsQuery::last_7d())
            .await
            .map_err(sdk_err)?;
        Ok(SecurityStats {
            blocked_attempts: s.blocked_attempts,
            locked_accounts: s.locked_accounts,
            suspicious_activities: s.suspicious_activities,
        })
    }

    // ── API keys ──────────────────────────────────────────────────────────

    #[napi]
    pub async fn list_api_keys(
        &self,
        tenant_id: String,
        page: i64,
        per_page: i64,
    ) -> Result<JsonValue> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let res = self
            .inner
            .list_api_keys(tid, pagination(page, per_page))
            .await
            .map_err(sdk_err)?;
        serde_json::to_value(res).map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn create_api_key(
        &self,
        tenant_id: String,
        input: CreateApiKeyInput,
    ) -> Result<ApiKeyWithSecret> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let req = sdk_types::CreateApiKeyRequest {
            name: input.name,
            description: input.description,
            scopes: input.scopes,
            ip_restrictions: input.ip_restrictions,
            ..Default::default()
        };
        let r = self
            .inner
            .create_api_key(tid, &req)
            .await
            .map_err(sdk_err)?;
        Ok(ApiKeyWithSecret {
            api_key_id: r.api_key.id.to_string(),
            name: r.api_key.name,
            prefix: r.api_key.prefix,
            secret: r.secret,
        })
    }

    #[napi]
    pub async fn revoke_api_key(&self, tenant_id: String, key_id: String) -> Result<()> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let kid = parse_uuid("key_id", &key_id)?;
        self.inner.revoke_api_key(tid, kid).await.map_err(sdk_err)
    }

    #[napi]
    pub async fn delete_api_key(&self, tenant_id: String, key_id: String) -> Result<()> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let kid = parse_uuid("key_id", &key_id)?;
        self.inner.delete_api_key(tid, kid).await.map_err(sdk_err)
    }

    // ── OAuth token (client credentials) ──────────────────────────────────

    #[napi]
    pub async fn token_client_credentials(&self, scope: Option<String>) -> Result<TokenResponse> {
        let t = self
            .inner
            .token_client_credentials(scope.as_deref())
            .await
            .map_err(sdk_err)?;
        Ok(TokenResponse {
            access_token: t.access_token,
            token_type: t.token_type,
            expires_in: t.expires_in,
            refresh_token: t.refresh_token,
            scope: t.scope,
        })
    }

    // ── Setup ─────────────────────────────────────────────────────────────

    #[napi]
    pub async fn requires_setup(&self) -> Result<SetupStatus> {
        let s = self.inner.requires_setup().await.map_err(sdk_err)?;
        Ok(SetupStatus {
            requires_setup: s.requires_setup,
        })
    }

    #[napi]
    pub async fn perform_setup(
        &self,
        admin_username: String,
        admin_email: String,
        admin_password: String,
        tenant_name: Option<String>,
        tenant_slug: Option<String>,
    ) -> Result<()> {
        let req = sdk_types::SetupRequest {
            admin_username,
            admin_email,
            admin_password,
            tenant_name,
            tenant_slug,
        };
        self.inner.perform_setup(&req).await.map_err(sdk_err)?;
        Ok(())
    }

    // ── Workflows ─────────────────────────────────────────────────────────

    #[napi]
    pub async fn setup_if_needed(
        &self,
        admin_username: String,
        admin_email: String,
        admin_password: String,
        tenant_name: Option<String>,
        tenant_slug: Option<String>,
    ) -> Result<bool> {
        let req = sdk_types::SetupRequest {
            admin_username,
            admin_email,
            admin_password,
            tenant_name,
            tenant_slug,
        };
        self.inner.setup_if_needed(req).await.map_err(sdk_err)
    }

    #[napi]
    pub async fn require_permission(
        &self,
        tenant_id: String,
        user_id: String,
        resource: String,
        action: String,
    ) -> Result<()> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let uid = parse_uuid("user_id", &user_id)?;
        self.inner
            .require_permission(tid, uid, &resource, &action)
            .await
            .map_err(sdk_err)
    }

    #[napi]
    pub async fn check_token_permission(
        &self,
        token: String,
        resource: String,
        action: String,
    ) -> Result<()> {
        self.inner
            .check_token_permission(&token, &resource, &action)
            .await
            .map_err(sdk_err)
    }

    #[napi]
    pub async fn provision_user(
        &self,
        tenant_id: String,
        input: CreateUserInput,
        role_ids: Vec<String>,
    ) -> Result<User> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let req = sdk_types::CreateUserRequest {
            username: input.username,
            email: input.email,
            password: input.password,
            first_name: input.first_name,
            last_name: input.last_name,
            ..Default::default()
        };
        let role_ids: Result<Vec<uuid::Uuid>> =
            role_ids.iter().map(|s| parse_uuid("role_id", s)).collect();
        let role_ids = role_ids?;
        let u = self
            .inner
            .provision_user(tid, &req, &role_ids)
            .await
            .map_err(sdk_err)?;
        Ok(user_from(u))
    }

    #[napi]
    pub async fn setup_rbac(
        &self,
        tenant_id: String,
        roles: Vec<RoleDefinitionInput>,
    ) -> Result<Vec<String>> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let defs: Vec<vaultaris_sdk::workflows::RoleDefinition> = roles
            .into_iter()
            .map(|r| {
                let mut def = vaultaris_sdk::workflows::RoleDefinition::new(r.name, r.display_name);
                for p in r.permissions {
                    def = def.with_permission(vaultaris_sdk::workflows::PermissionDefinition::new(
                        p.resource, p.action,
                    ));
                }
                def
            })
            .collect();
        let ids = self.inner.setup_rbac(tid, &defs).await.map_err(sdk_err)?;
        Ok(ids.into_iter().map(|u| u.to_string()).collect())
    }

    #[napi]
    pub async fn collect_users(&self, tenant_id: String) -> Result<Vec<User>> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let users = self.inner.collect_users(tid).await.map_err(sdk_err)?;
        Ok(users.into_iter().map(user_from).collect())
    }

    #[napi]
    pub async fn collect_roles(&self, tenant_id: String) -> Result<Vec<Role>> {
        let tid = parse_uuid("tenant_id", &tenant_id)?;
        let roles = self.inner.collect_roles(tid).await.map_err(sdk_err)?;
        Ok(roles.into_iter().map(role_from).collect())
    }

    #[napi]
    pub async fn bootstrap_tenant(&self, input: BootstrapTenantInput) -> Result<BootstrapResult> {
        let req = vaultaris_sdk::workflows::BootstrapTenantRequest {
            tenant_name: input.tenant_name,
            tenant_slug: input.tenant_slug,
            admin_email: input.admin_email,
            admin_username: input.admin_username,
            admin_password: input.admin_password,
            initial_roles: input
                .initial_roles
                .into_iter()
                .map(|r| {
                    let mut def =
                        vaultaris_sdk::workflows::RoleDefinition::new(r.name, r.display_name);
                    for p in r.permissions {
                        def = def.with_permission(
                            vaultaris_sdk::workflows::PermissionDefinition::new(
                                p.resource, p.action,
                            ),
                        );
                    }
                    def
                })
                .collect(),
        };
        let r = self.inner.bootstrap_tenant(req).await.map_err(sdk_err)?;
        Ok(BootstrapResult {
            tenant: tenant_from(r.tenant),
            admin_user: user_from(r.admin_user),
            role_ids: r.role_ids.into_iter().map(|u| u.to_string()).collect(),
        })
    }
}

// ── napi ↔ sdk type adapters ────────────────────────────────────────────────

fn pagination(page: i64, per_page: i64) -> SdkPagination {
    SdkPagination {
        page: u32::try_from(page).unwrap_or(1),
        per_page: u32::try_from(per_page).unwrap_or(20),
    }
}

fn token_validation_from(v: sdk_types::TokenValidation) -> TokenValidation {
    TokenValidation {
        valid: v.valid,
        user_id: v.user_id.map(|u| u.to_string()),
        username: v.username,
        email: v.email,
        tenant_id: v.tenant_id.map(|u| u.to_string()),
        expires_at: v.expires_at.map(|i| i.to_string()),
        scopes: v.scopes,
        roles: v.roles,
        error: v.error,
    }
}

fn user_info_from(u: sdk_types::UserInfo) -> UserInfo {
    UserInfo {
        id: u.id.to_string(),
        username: u.username,
        email: u.email,
        email_verified: u.email_verified,
        first_name: u.first_name,
        last_name: u.last_name,
        name: u.display_name,
        picture: None,
        roles: u.roles.into_iter().map(|r| r.name).collect(),
        groups: u.groups.into_iter().map(|g| g.name).collect(),
    }
}

fn tenant_from(t: sdk_types::Tenant) -> Tenant {
    Tenant {
        id: t.id.to_string(),
        name: t.name,
        slug: t.slug,
        display_name: t.display_name,
        description: t.description,
        logo_url: t.logo_url,
        primary_color: t.primary_color,
        mfa_enabled: t.mfa_enabled,
        mfa_required: t.mfa_required,
        created_at: t.created_at.to_rfc3339(),
        updated_at: t.updated_at.to_rfc3339(),
    }
}

fn user_from(u: sdk_types::User) -> User {
    User {
        id: u.id.to_string(),
        tenant_id: u.tenant_id.to_string(),
        username: u.username,
        email: u.email,
        email_verified: u.email_verified,
        first_name: u.first_name,
        last_name: u.last_name,
        display_name: u.display_name,
        status: u.status,
        created_at: u.created_at.to_rfc3339(),
        updated_at: u.updated_at.to_rfc3339(),
    }
}

fn role_from(r: sdk_types::Role) -> Role {
    Role {
        id: r.id.to_string(),
        tenant_id: r.tenant_id.to_string(),
        name: r.name,
        display_name: r.display_name,
        description: r.description,
        is_composite: r.is_composite,
        created_at: r.created_at.to_rfc3339(),
    }
}

fn permission_from(p: sdk_types::Permission) -> Permission {
    Permission {
        id: p.id.to_string(),
        tenant_id: p.tenant_id.to_string(),
        name: p.name,
        resource: p.resource,
        action: p.action,
        created_at: p.created_at.to_rfc3339(),
    }
}

fn group_from(g: sdk_types::Group) -> Group {
    Group {
        id: g.id.to_string(),
        tenant_id: g.tenant_id.to_string(),
        name: g.name,
        display_name: g.display_name,
        description: g.description,
        path: g.path,
        created_at: g.created_at.to_rfc3339(),
    }
}

fn oauth_client_from(c: sdk_types::OAuthClient) -> OAuthClient {
    OAuthClient {
        id: c.id.to_string(),
        client_id: c.client_id,
        name: c.name,
        is_enabled: c.is_enabled,
        redirect_uris: c.redirect_uris,
        created_at: c.created_at.to_rfc3339(),
    }
}
