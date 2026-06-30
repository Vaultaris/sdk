//! OAuth client management (`/api/v1/tenants/{tenant_id}/clients/*`).

use uuid::Uuid;

use crate::client::VaultarisClient;
use crate::error::Result;
use crate::types::{
    ClientWithSecret, CreateOAuthClientRequest, OAuthClient, Page, Pagination,
    UpdateOAuthClientRequest,
};

impl VaultarisClient {
    pub async fn list_clients(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> Result<Page<OAuthClient>> {
        self.get_json_query(&format!("/api/v1/tenants/{tenant_id}/clients"), &pagination)
            .await
    }

    pub async fn create_client(
        &self,
        tenant_id: Uuid,
        req: &CreateOAuthClientRequest,
    ) -> Result<ClientWithSecret> {
        self.post_json(&format!("/api/v1/tenants/{tenant_id}/clients"), req)
            .await
    }

    pub async fn get_client(&self, tenant_id: Uuid, client_id: Uuid) -> Result<OAuthClient> {
        self.get_json(&format!("/api/v1/tenants/{tenant_id}/clients/{client_id}"))
            .await
    }

    pub async fn update_client(
        &self,
        tenant_id: Uuid,
        client_id: Uuid,
        req: &UpdateOAuthClientRequest,
    ) -> Result<OAuthClient> {
        self.put_json(
            &format!("/api/v1/tenants/{tenant_id}/clients/{client_id}"),
            req,
        )
        .await
    }

    pub async fn delete_client(&self, tenant_id: Uuid, client_id: Uuid) -> Result<()> {
        self.delete_no_content(&format!("/api/v1/tenants/{tenant_id}/clients/{client_id}"))
            .await
    }

    pub async fn regenerate_client_secret(
        &self,
        tenant_id: Uuid,
        client_id: Uuid,
    ) -> Result<ClientWithSecret> {
        self.post_empty(&format!(
            "/api/v1/tenants/{tenant_id}/clients/{client_id}/secret"
        ))
        .await
    }
}
