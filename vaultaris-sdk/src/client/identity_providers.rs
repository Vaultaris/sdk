//! Identity-provider management (`/api/v1/tenants/{tenant_id}/identity-providers/*`).

use uuid::Uuid;

use crate::client::VaultarisClient;
use crate::error::Result;
use crate::types::{CreateIdentityProviderRequest, IdentityProvider};

impl VaultarisClient {
    pub async fn list_identity_providers(&self, tenant_id: Uuid) -> Result<Vec<IdentityProvider>> {
        self.get_json(&format!("/api/v1/tenants/{tenant_id}/identity-providers"))
            .await
    }

    pub async fn create_identity_provider(
        &self,
        tenant_id: Uuid,
        req: &CreateIdentityProviderRequest,
    ) -> Result<IdentityProvider> {
        self.post_json(
            &format!("/api/v1/tenants/{tenant_id}/identity-providers"),
            req,
        )
        .await
    }

    pub async fn get_identity_provider(
        &self,
        tenant_id: Uuid,
        provider_id: Uuid,
    ) -> Result<IdentityProvider> {
        self.get_json(&format!(
            "/api/v1/tenants/{tenant_id}/identity-providers/{provider_id}"
        ))
        .await
    }

    pub async fn update_identity_provider(
        &self,
        tenant_id: Uuid,
        provider_id: Uuid,
        req: &CreateIdentityProviderRequest,
    ) -> Result<IdentityProvider> {
        self.put_json(
            &format!("/api/v1/tenants/{tenant_id}/identity-providers/{provider_id}"),
            req,
        )
        .await
    }

    pub async fn delete_identity_provider(&self, tenant_id: Uuid, provider_id: Uuid) -> Result<()> {
        self.delete_no_content(&format!(
            "/api/v1/tenants/{tenant_id}/identity-providers/{provider_id}"
        ))
        .await
    }
}
