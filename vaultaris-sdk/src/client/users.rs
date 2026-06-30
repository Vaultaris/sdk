//! User management (`/api/v1/tenants/{tenant_id}/users/*`).

use uuid::Uuid;

use crate::client::VaultarisClient;
use crate::error::Result;
use crate::types::{
    AssignGroupRequest, AssignRoleRequest, CreateUserRequest, Group, Page, Pagination, Role,
    UpdateUserRequest, User,
};

impl VaultarisClient {
    pub async fn list_users(&self, tenant_id: Uuid, pagination: Pagination) -> Result<Page<User>> {
        self.get_json_query(&format!("/api/v1/tenants/{tenant_id}/users"), &pagination)
            .await
    }

    pub async fn create_user(&self, tenant_id: Uuid, req: &CreateUserRequest) -> Result<User> {
        self.post_json(&format!("/api/v1/tenants/{tenant_id}/users"), req)
            .await
    }

    pub async fn get_user(&self, tenant_id: Uuid, user_id: Uuid) -> Result<User> {
        self.get_json(&format!("/api/v1/tenants/{tenant_id}/users/{user_id}"))
            .await
    }

    pub async fn update_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        req: &UpdateUserRequest,
    ) -> Result<User> {
        self.put_json(&format!("/api/v1/tenants/{tenant_id}/users/{user_id}"), req)
            .await
    }

    pub async fn delete_user(&self, tenant_id: Uuid, user_id: Uuid) -> Result<()> {
        self.delete_no_content(&format!("/api/v1/tenants/{tenant_id}/users/{user_id}"))
            .await
    }

    pub async fn restore_user(&self, tenant_id: Uuid, user_id: Uuid) -> Result<User> {
        self.post_empty(&format!(
            "/api/v1/tenants/{tenant_id}/users/{user_id}/restore"
        ))
        .await
    }

    pub async fn user_roles(&self, tenant_id: Uuid, user_id: Uuid) -> Result<Vec<Role>> {
        self.get_json(&format!(
            "/api/v1/tenants/{tenant_id}/users/{user_id}/roles"
        ))
        .await
    }

    pub async fn assign_role_to_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        role_id: Uuid,
    ) -> Result<()> {
        self.post_no_content(
            &format!("/api/v1/tenants/{tenant_id}/users/{user_id}/roles"),
            &AssignRoleRequest { role_id },
        )
        .await
    }

    pub async fn remove_role_from_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        role_id: Uuid,
    ) -> Result<()> {
        self.delete_no_content(&format!(
            "/api/v1/tenants/{tenant_id}/users/{user_id}/roles/{role_id}"
        ))
        .await
    }

    pub async fn user_groups(&self, tenant_id: Uuid, user_id: Uuid) -> Result<Vec<Group>> {
        self.get_json(&format!(
            "/api/v1/tenants/{tenant_id}/users/{user_id}/groups"
        ))
        .await
    }

    pub async fn assign_group_to_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        group_id: Uuid,
    ) -> Result<()> {
        self.post_no_content(
            &format!("/api/v1/tenants/{tenant_id}/users/{user_id}/groups"),
            &AssignGroupRequest { group_id },
        )
        .await
    }

    pub async fn remove_group_from_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        group_id: Uuid,
    ) -> Result<()> {
        self.delete_no_content(&format!(
            "/api/v1/tenants/{tenant_id}/users/{user_id}/groups/{group_id}"
        ))
        .await
    }
}
