//! JWT signing key management (`/api/v1/tenants/{tenant_id}/keys/*`).

use uuid::Uuid;

use crate::client::VaultarisClient;
use crate::error::Result;
use crate::types::JwtKey;

impl VaultarisClient {
    pub async fn list_keys(&self, tenant_id: Uuid) -> Result<Vec<JwtKey>> {
        self.get_json(&format!("/api/v1/tenants/{tenant_id}/keys"))
            .await
    }

    pub async fn rotate_keys(&self, tenant_id: Uuid) -> Result<JwtKey> {
        self.post_empty(&format!("/api/v1/tenants/{tenant_id}/keys/rotate"))
            .await
    }
}
