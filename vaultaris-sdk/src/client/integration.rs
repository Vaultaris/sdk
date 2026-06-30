//! Integration endpoints (`/api/v1/integration/*` and tenant variants).
//!
//! These are the low-overhead endpoints SDK clients hit most often:
//! token validation, permission checks, session validation, lightweight
//! user lookups.

use uuid::Uuid;

use crate::client::VaultarisClient;
use crate::error::Result;
use crate::types::{
    BatchCheckPermissionRequest, BatchPermissionCheck, CheckPermissionRequest, PermissionCheck,
    PermissionToCheck, SessionValidation, TokenValidation, UserInfo, ValidateTokenRequest,
};

impl VaultarisClient {
    /// Validate an access token without scope or permission constraints.
    pub async fn validate_token(&self, token: &str) -> Result<TokenValidation> {
        self.validate_token_with(token, None, None).await
    }

    /// Validate a token, optionally requiring a set of scopes or permissions.
    pub async fn validate_token_with(
        &self,
        token: &str,
        required_scopes: Option<Vec<String>>,
        required_permissions: Option<Vec<String>>,
    ) -> Result<TokenValidation> {
        let req = ValidateTokenRequest {
            token: token.to_string(),
            required_scopes,
            required_permissions,
        };
        self.post_json("/api/v1/integration/token/validate", &req)
            .await
    }

    /// Yes/no shortcut: does the user have this permission?
    pub async fn check_permission(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        resource: &str,
        action: &str,
    ) -> Result<bool> {
        let detail = self
            .check_permission_detailed(tenant_id, user_id, resource, action, None)
            .await?;
        Ok(detail.allowed)
    }

    /// Full permission check — returns the matched policy and reason.
    pub async fn check_permission_detailed(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        resource: &str,
        action: &str,
        context: Option<serde_json::Value>,
    ) -> Result<PermissionCheck> {
        let req = CheckPermissionRequest {
            user_id,
            resource: resource.to_string(),
            action: action.to_string(),
            context,
        };
        self.post_json(
            &format!("/api/v1/tenants/{tenant_id}/integration/check-permission"),
            &req,
        )
        .await
    }

    /// Evaluate many permission checks in one round trip.
    pub async fn batch_check_permissions(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        checks: Vec<PermissionToCheck>,
    ) -> Result<BatchPermissionCheck> {
        let req = BatchCheckPermissionRequest { user_id, checks };
        self.post_json(
            &format!("/api/v1/tenants/{tenant_id}/integration/batch-check-permissions"),
            &req,
        )
        .await
    }

    /// Lightweight integration user info — roles, groups, permissions only.
    pub async fn integration_user(&self, tenant_id: Uuid, user_id: Uuid) -> Result<UserInfo> {
        self.get_json(&format!(
            "/api/v1/tenants/{tenant_id}/integration/users/{user_id}"
        ))
        .await
    }

    /// Validate an active session token.
    pub async fn validate_session(&self, token: &str) -> Result<SessionValidation> {
        self.get_json_query("/api/v1/integration/session/validate", &[("token", token)])
            .await
    }

    /// Convenience: does the user hold any of these `(resource, action)`?
    pub async fn has_any_permission(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        permissions: &[(&str, &str)],
    ) -> Result<bool> {
        let checks: Vec<PermissionToCheck> = permissions
            .iter()
            .map(|(r, a)| PermissionToCheck::new(*r, *a))
            .collect();
        let results = self
            .batch_check_permissions(tenant_id, user_id, checks)
            .await?;
        Ok(results.results.iter().any(|r| r.allowed))
    }

    /// Convenience: does the user hold all of these `(resource, action)`?
    pub async fn has_all_permissions(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        permissions: &[(&str, &str)],
    ) -> Result<bool> {
        let checks: Vec<PermissionToCheck> = permissions
            .iter()
            .map(|(r, a)| PermissionToCheck::new(*r, *a))
            .collect();
        let results = self
            .batch_check_permissions(tenant_id, user_id, checks)
            .await?;
        Ok(results.results.iter().all(|r| r.allowed))
    }

    /// Convenience: returns `false` if validation failed for any reason.
    pub async fn is_token_valid(&self, token: &str) -> bool {
        self.validate_token(token).await.is_ok_and(|v| v.valid)
    }
}
