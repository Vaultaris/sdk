//! Tenant template export/import (`/api/v1/tenants/{tenant_id}/templates/*`).

use uuid::Uuid;

use crate::client::VaultarisClient;
use crate::error::Result;

impl VaultarisClient {
    /// Export the tenant's configuration template (KDL/JSON depending on
    /// server config).
    pub async fn export_template(&self, tenant_id: Uuid) -> Result<serde_json::Value> {
        self.get_json(&format!("/api/v1/tenants/{tenant_id}/templates/export"))
            .await
    }

    /// Import a template body (apply roles/permissions/policies wholesale).
    pub async fn import_template(
        &self,
        tenant_id: Uuid,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.post_json(
            &format!("/api/v1/tenants/{tenant_id}/templates/import"),
            body,
        )
        .await
    }
}
