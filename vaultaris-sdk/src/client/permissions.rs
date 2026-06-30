//! Permission management (`/api/v1/tenants/{tenant_id}/permissions/*`).

use uuid::Uuid;

use crate::client::VaultarisClient;
use crate::error::Result;
use crate::types::{
    CreatePermissionRequest, Page, Pagination, Permission, UpdatePermissionRequest,
};

impl VaultarisClient {
    pub async fn list_permissions(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> Result<Page<Permission>> {
        self.get_json_query(
            &format!("/api/v1/tenants/{tenant_id}/permissions"),
            &pagination,
        )
        .await
    }

    pub async fn create_permission(
        &self,
        tenant_id: Uuid,
        req: &CreatePermissionRequest,
    ) -> Result<Permission> {
        self.post_json(&format!("/api/v1/tenants/{tenant_id}/permissions"), req)
            .await
    }

    pub async fn get_permission(&self, tenant_id: Uuid, permission_id: Uuid) -> Result<Permission> {
        self.get_json(&format!(
            "/api/v1/tenants/{tenant_id}/permissions/{permission_id}"
        ))
        .await
    }

    pub async fn update_permission(
        &self,
        tenant_id: Uuid,
        permission_id: Uuid,
        req: &UpdatePermissionRequest,
    ) -> Result<Permission> {
        self.put_json(
            &format!("/api/v1/tenants/{tenant_id}/permissions/{permission_id}"),
            req,
        )
        .await
    }

    pub async fn delete_permission(&self, tenant_id: Uuid, permission_id: Uuid) -> Result<()> {
        self.delete_no_content(&format!(
            "/api/v1/tenants/{tenant_id}/permissions/{permission_id}"
        ))
        .await
    }

    pub async fn restore_permission(
        &self,
        tenant_id: Uuid,
        permission_id: Uuid,
    ) -> Result<Permission> {
        self.post_empty(&format!(
            "/api/v1/tenants/{tenant_id}/permissions/{permission_id}/restore"
        ))
        .await
    }
}
