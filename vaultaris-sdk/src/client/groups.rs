//! Group management (`/api/v1/tenants/{tenant_id}/groups/*`).

use uuid::Uuid;

use crate::client::VaultarisClient;
use crate::error::Result;
use crate::types::{
    AssignRoleRequest, CreateGroupRequest, Group, Page, Pagination, Role, UpdateGroupRequest, User,
};

impl VaultarisClient {
    pub async fn list_groups(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> Result<Page<Group>> {
        self.get_json_query(&format!("/api/v1/tenants/{tenant_id}/groups"), &pagination)
            .await
    }

    pub async fn create_group(&self, tenant_id: Uuid, req: &CreateGroupRequest) -> Result<Group> {
        self.post_json(&format!("/api/v1/tenants/{tenant_id}/groups"), req)
            .await
    }

    pub async fn get_group(&self, tenant_id: Uuid, group_id: Uuid) -> Result<Group> {
        self.get_json(&format!("/api/v1/tenants/{tenant_id}/groups/{group_id}"))
            .await
    }

    pub async fn update_group(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        req: &UpdateGroupRequest,
    ) -> Result<Group> {
        self.put_json(
            &format!("/api/v1/tenants/{tenant_id}/groups/{group_id}"),
            req,
        )
        .await
    }

    pub async fn delete_group(&self, tenant_id: Uuid, group_id: Uuid) -> Result<()> {
        self.delete_no_content(&format!("/api/v1/tenants/{tenant_id}/groups/{group_id}"))
            .await
    }

    pub async fn restore_group(&self, tenant_id: Uuid, group_id: Uuid) -> Result<Group> {
        self.post_empty(&format!(
            "/api/v1/tenants/{tenant_id}/groups/{group_id}/restore"
        ))
        .await
    }

    pub async fn group_members(&self, tenant_id: Uuid, group_id: Uuid) -> Result<Vec<User>> {
        self.get_json(&format!(
            "/api/v1/tenants/{tenant_id}/groups/{group_id}/members"
        ))
        .await
    }

    pub async fn group_roles(&self, tenant_id: Uuid, group_id: Uuid) -> Result<Vec<Role>> {
        self.get_json(&format!(
            "/api/v1/tenants/{tenant_id}/groups/{group_id}/roles"
        ))
        .await
    }

    pub async fn assign_role_to_group(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        role_id: Uuid,
    ) -> Result<()> {
        self.post_no_content(
            &format!("/api/v1/tenants/{tenant_id}/groups/{group_id}/roles"),
            &AssignRoleRequest { role_id },
        )
        .await
    }

    pub async fn remove_role_from_group(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        role_id: Uuid,
    ) -> Result<()> {
        self.delete_no_content(&format!(
            "/api/v1/tenants/{tenant_id}/groups/{group_id}/roles/{role_id}"
        ))
        .await
    }
}
