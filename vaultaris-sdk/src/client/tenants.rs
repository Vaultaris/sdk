//! Tenant management (`/api/v1/tenants/*`).

use uuid::Uuid;

use crate::client::VaultarisClient;
use crate::error::Result;
use crate::types::{CreateTenantRequest, Page, Pagination, Tenant, UpdateTenantRequest};

impl VaultarisClient {
    pub async fn list_tenants(&self, pagination: Pagination) -> Result<Page<Tenant>> {
        self.get_json_query("/api/v1/tenants", &pagination).await
    }

    pub async fn create_tenant(&self, req: &CreateTenantRequest) -> Result<Tenant> {
        self.post_json("/api/v1/tenants", req).await
    }

    pub async fn get_tenant(&self, tenant_id: Uuid) -> Result<Tenant> {
        self.get_json(&format!("/api/v1/tenants/{tenant_id}")).await
    }

    pub async fn update_tenant(
        &self,
        tenant_id: Uuid,
        req: &UpdateTenantRequest,
    ) -> Result<Tenant> {
        self.put_json(&format!("/api/v1/tenants/{tenant_id}"), req)
            .await
    }

    pub async fn delete_tenant(&self, tenant_id: Uuid) -> Result<()> {
        self.delete_no_content(&format!("/api/v1/tenants/{tenant_id}"))
            .await
    }
}
