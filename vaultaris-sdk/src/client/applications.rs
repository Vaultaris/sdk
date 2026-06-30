//! Application (mini-tenant) management.
//!
//! Applications are an optional logical grouping of OAuth clients,
//! roles, groups, permissions, IdPs, and ABAC policies within a tenant —
//! think "Enterprise Applications" in Azure AD.

use uuid::Uuid;

use crate::client::VaultarisClient;
use crate::error::Result;
use crate::types::{
    AddApplicationMemberRequest, Application, ApplicationMember, CreateApplicationRequest,
    LinkApplicationResourceRequest, Page, Pagination, UpdateApplicationMemberRequest,
    UpdateApplicationRequest,
};

impl VaultarisClient {
    pub async fn list_applications(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> Result<Page<Application>> {
        self.get_json_query(
            &format!("/api/v1/tenants/{tenant_id}/applications"),
            &pagination,
        )
        .await
    }

    pub async fn create_application(
        &self,
        tenant_id: Uuid,
        req: &CreateApplicationRequest,
    ) -> Result<Application> {
        self.post_json(&format!("/api/v1/tenants/{tenant_id}/applications"), req)
            .await
    }

    pub async fn get_application(&self, tenant_id: Uuid, app_id: Uuid) -> Result<Application> {
        self.get_json(&format!(
            "/api/v1/tenants/{tenant_id}/applications/{app_id}"
        ))
        .await
    }

    pub async fn update_application(
        &self,
        tenant_id: Uuid,
        app_id: Uuid,
        req: &UpdateApplicationRequest,
    ) -> Result<Application> {
        self.put_json(
            &format!("/api/v1/tenants/{tenant_id}/applications/{app_id}"),
            req,
        )
        .await
    }

    pub async fn delete_application(&self, tenant_id: Uuid, app_id: Uuid) -> Result<()> {
        self.delete_no_content(&format!(
            "/api/v1/tenants/{tenant_id}/applications/{app_id}"
        ))
        .await
    }

    // ---- Resource links — share or own existing tenant-level resources ----

    pub async fn link_app_oauth_client(
        &self,
        tenant_id: Uuid,
        app_id: Uuid,
        client_id: Uuid,
        req: &LinkApplicationResourceRequest,
    ) -> Result<()> {
        self.post_no_content(
            &format!(
                "/api/v1/tenants/{tenant_id}/applications/{app_id}/oauth-clients/link/{client_id}"
            ),
            req,
        )
        .await
    }

    pub async fn unlink_app_oauth_client(
        &self,
        tenant_id: Uuid,
        app_id: Uuid,
        client_id: Uuid,
    ) -> Result<()> {
        self.delete_no_content(&format!(
            "/api/v1/tenants/{tenant_id}/applications/{app_id}/oauth-clients/link/{client_id}"
        ))
        .await
    }

    pub async fn link_app_role(
        &self,
        tenant_id: Uuid,
        app_id: Uuid,
        role_id: Uuid,
        req: &LinkApplicationResourceRequest,
    ) -> Result<()> {
        self.post_no_content(
            &format!("/api/v1/tenants/{tenant_id}/applications/{app_id}/roles/link/{role_id}"),
            req,
        )
        .await
    }

    pub async fn unlink_app_role(
        &self,
        tenant_id: Uuid,
        app_id: Uuid,
        role_id: Uuid,
    ) -> Result<()> {
        self.delete_no_content(&format!(
            "/api/v1/tenants/{tenant_id}/applications/{app_id}/roles/link/{role_id}"
        ))
        .await
    }

    pub async fn link_app_group(
        &self,
        tenant_id: Uuid,
        app_id: Uuid,
        group_id: Uuid,
        req: &LinkApplicationResourceRequest,
    ) -> Result<()> {
        self.post_no_content(
            &format!("/api/v1/tenants/{tenant_id}/applications/{app_id}/groups/link/{group_id}"),
            req,
        )
        .await
    }

    pub async fn unlink_app_group(
        &self,
        tenant_id: Uuid,
        app_id: Uuid,
        group_id: Uuid,
    ) -> Result<()> {
        self.delete_no_content(&format!(
            "/api/v1/tenants/{tenant_id}/applications/{app_id}/groups/link/{group_id}"
        ))
        .await
    }

    pub async fn link_app_permission(
        &self,
        tenant_id: Uuid,
        app_id: Uuid,
        permission_id: Uuid,
        req: &LinkApplicationResourceRequest,
    ) -> Result<()> {
        self.post_no_content(
            &format!(
                "/api/v1/tenants/{tenant_id}/applications/{app_id}/permissions/link/{permission_id}"
            ),
            req,
        )
        .await
    }

    pub async fn unlink_app_permission(
        &self,
        tenant_id: Uuid,
        app_id: Uuid,
        permission_id: Uuid,
    ) -> Result<()> {
        self.delete_no_content(&format!(
            "/api/v1/tenants/{tenant_id}/applications/{app_id}/permissions/link/{permission_id}"
        ))
        .await
    }

    pub async fn link_app_policy(
        &self,
        tenant_id: Uuid,
        app_id: Uuid,
        policy_id: Uuid,
        req: &LinkApplicationResourceRequest,
    ) -> Result<()> {
        self.post_no_content(
            &format!("/api/v1/tenants/{tenant_id}/applications/{app_id}/policies/link/{policy_id}"),
            req,
        )
        .await
    }

    pub async fn unlink_app_policy(
        &self,
        tenant_id: Uuid,
        app_id: Uuid,
        policy_id: Uuid,
    ) -> Result<()> {
        self.delete_no_content(&format!(
            "/api/v1/tenants/{tenant_id}/applications/{app_id}/policies/link/{policy_id}"
        ))
        .await
    }

    // ---- Members (isolated applications) ----

    pub async fn list_app_members(
        &self,
        tenant_id: Uuid,
        app_id: Uuid,
        pagination: Pagination,
    ) -> Result<Page<ApplicationMember>> {
        self.get_json_query(
            &format!("/api/v1/tenants/{tenant_id}/applications/{app_id}/members"),
            &pagination,
        )
        .await
    }

    pub async fn add_app_member(
        &self,
        tenant_id: Uuid,
        app_id: Uuid,
        req: &AddApplicationMemberRequest,
    ) -> Result<ApplicationMember> {
        self.post_json(
            &format!("/api/v1/tenants/{tenant_id}/applications/{app_id}/members"),
            req,
        )
        .await
    }

    pub async fn accept_app_invite(
        &self,
        tenant_id: Uuid,
        app_id: Uuid,
    ) -> Result<ApplicationMember> {
        self.post_empty(&format!(
            "/api/v1/tenants/{tenant_id}/applications/{app_id}/members/accept"
        ))
        .await
    }

    pub async fn update_app_member(
        &self,
        tenant_id: Uuid,
        app_id: Uuid,
        user_id: Uuid,
        req: &UpdateApplicationMemberRequest,
    ) -> Result<ApplicationMember> {
        self.put_json(
            &format!("/api/v1/tenants/{tenant_id}/applications/{app_id}/members/{user_id}"),
            req,
        )
        .await
    }

    pub async fn remove_app_member(
        &self,
        tenant_id: Uuid,
        app_id: Uuid,
        user_id: Uuid,
    ) -> Result<()> {
        self.delete_no_content(&format!(
            "/api/v1/tenants/{tenant_id}/applications/{app_id}/members/{user_id}"
        ))
        .await
    }
}
