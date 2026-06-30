//! Role management (`/api/v1/tenants/{tenant_id}/roles/*`).

use uuid::Uuid;

use crate::client::VaultarisClient;
use crate::error::Result;
use crate::types::{
    AssignPermissionRequest, CreateRoleRequest, Page, Pagination, Permission, Role,
    UpdateRoleRequest,
};

impl VaultarisClient {
    pub async fn list_roles(&self, tenant_id: Uuid, pagination: Pagination) -> Result<Page<Role>> {
        self.get_json_query(&format!("/api/v1/tenants/{tenant_id}/roles"), &pagination)
            .await
    }

    pub async fn create_role(&self, tenant_id: Uuid, req: &CreateRoleRequest) -> Result<Role> {
        self.post_json(&format!("/api/v1/tenants/{tenant_id}/roles"), req)
            .await
    }

    pub async fn get_role(&self, tenant_id: Uuid, role_id: Uuid) -> Result<Role> {
        self.get_json(&format!("/api/v1/tenants/{tenant_id}/roles/{role_id}"))
            .await
    }

    pub async fn update_role(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        req: &UpdateRoleRequest,
    ) -> Result<Role> {
        self.put_json(&format!("/api/v1/tenants/{tenant_id}/roles/{role_id}"), req)
            .await
    }

    pub async fn delete_role(&self, tenant_id: Uuid, role_id: Uuid) -> Result<()> {
        self.delete_no_content(&format!("/api/v1/tenants/{tenant_id}/roles/{role_id}"))
            .await
    }

    pub async fn restore_role(&self, tenant_id: Uuid, role_id: Uuid) -> Result<Role> {
        self.post_empty(&format!(
            "/api/v1/tenants/{tenant_id}/roles/{role_id}/restore"
        ))
        .await
    }

    pub async fn role_permissions(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<Vec<Permission>> {
        self.get_json(&format!(
            "/api/v1/tenants/{tenant_id}/roles/{role_id}/permissions"
        ))
        .await
    }

    pub async fn assign_permission_to_role(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        permission_id: Uuid,
    ) -> Result<()> {
        self.post_no_content(
            &format!("/api/v1/tenants/{tenant_id}/roles/{role_id}/permissions"),
            &AssignPermissionRequest { permission_id },
        )
        .await
    }

    pub async fn remove_permission_from_role(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        permission_id: Uuid,
    ) -> Result<()> {
        self.delete_no_content(&format!(
            "/api/v1/tenants/{tenant_id}/roles/{role_id}/permissions/{permission_id}"
        ))
        .await
    }
}
