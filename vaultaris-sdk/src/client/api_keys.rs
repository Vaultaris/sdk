//! API key management (`/api/v1/tenants/{tenant_id}/api-keys/*`,
//! `/api/v1/api-keys/*`).

use uuid::Uuid;

use crate::client::VaultarisClient;
use crate::error::Result;
use crate::types::{
    ApiKey, ApiKeyAuthorizeRequest, ApiKeyAuthorizeResult, ApiKeyMe, ApiKeyWithSecret,
    CreateApiKeyRequest, Page, Pagination, UpdateApiKeyRequest,
};

impl VaultarisClient {
    pub async fn list_api_keys(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> Result<Page<ApiKey>> {
        self.get_json_query(
            &format!("/api/v1/tenants/{tenant_id}/api-keys"),
            &pagination,
        )
        .await
    }

    /// Create a tenant-scoped API key. The plain-text secret is returned
    /// once — store it; the server only keeps the hash.
    pub async fn create_api_key(
        &self,
        tenant_id: Uuid,
        req: &CreateApiKeyRequest,
    ) -> Result<ApiKeyWithSecret> {
        self.post_json(&format!("/api/v1/tenants/{tenant_id}/api-keys"), req)
            .await
    }

    pub async fn get_api_key(&self, tenant_id: Uuid, key_id: Uuid) -> Result<ApiKey> {
        self.get_json(&format!("/api/v1/tenants/{tenant_id}/api-keys/{key_id}"))
            .await
    }

    pub async fn update_api_key(
        &self,
        tenant_id: Uuid,
        key_id: Uuid,
        req: &UpdateApiKeyRequest,
    ) -> Result<ApiKey> {
        self.put_json(
            &format!("/api/v1/tenants/{tenant_id}/api-keys/{key_id}"),
            req,
        )
        .await
    }

    pub async fn delete_api_key(&self, tenant_id: Uuid, key_id: Uuid) -> Result<()> {
        self.delete_no_content(&format!("/api/v1/tenants/{tenant_id}/api-keys/{key_id}"))
            .await
    }

    pub async fn revoke_api_key(&self, tenant_id: Uuid, key_id: Uuid) -> Result<()> {
        self.post_empty_no_content(&format!(
            "/api/v1/tenants/{tenant_id}/api-keys/{key_id}/revoke"
        ))
        .await
    }

    /// Create an application-scoped API key.
    pub async fn create_app_api_key(
        &self,
        tenant_id: Uuid,
        app_id: Uuid,
        req: &CreateApiKeyRequest,
    ) -> Result<ApiKeyWithSecret> {
        self.post_json(
            &format!("/api/v1/tenants/{tenant_id}/applications/{app_id}/api-keys"),
            req,
        )
        .await
    }

    /// Create a group-scoped API key.
    pub async fn create_group_api_key(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        req: &CreateApiKeyRequest,
    ) -> Result<ApiKeyWithSecret> {
        self.post_json(
            &format!("/api/v1/tenants/{tenant_id}/groups/{group_id}/api-keys"),
            req,
        )
        .await
    }

    // ---- Self-service (caller is the API key itself) ----

    /// Introspect the API key currently authenticating the request.
    pub async fn current_api_key(&self) -> Result<ApiKeyMe> {
        self.get_json("/api/v1/api-keys/me").await
    }

    /// Server-side IAM check for the calling key — returns whether the key
    /// is allowed to perform the requested `(resource, action)`.
    pub async fn authorize_api_key(
        &self,
        req: &ApiKeyAuthorizeRequest,
    ) -> Result<ApiKeyAuthorizeResult> {
        self.post_json("/api/v1/api-keys/authorize", req).await
    }
}
