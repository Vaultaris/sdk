//! Device management (`/api/v1/tenants/{tenant_id}/users/{user_id}/devices/*`).

use uuid::Uuid;

use crate::client::VaultarisClient;
use crate::error::Result;
use crate::types::{Device, Session};

impl VaultarisClient {
    pub async fn list_devices(&self, tenant_id: Uuid, user_id: Uuid) -> Result<Vec<Device>> {
        self.get_json(&format!(
            "/api/v1/tenants/{tenant_id}/users/{user_id}/devices"
        ))
        .await
    }

    pub async fn revoke_device(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        device_id: Uuid,
    ) -> Result<()> {
        self.delete_no_content(&format!(
            "/api/v1/tenants/{tenant_id}/users/{user_id}/devices/{device_id}"
        ))
        .await
    }

    pub async fn trust_device(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        device_id: Uuid,
        trusted: bool,
    ) -> Result<Device> {
        let body = serde_json::json!({ "trusted": trusted });
        self.put_json(
            &format!("/api/v1/tenants/{tenant_id}/users/{user_id}/devices/{device_id}/trust"),
            &body,
        )
        .await
    }

    pub async fn device_sessions(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        device_id: Uuid,
    ) -> Result<Vec<Session>> {
        self.get_json(&format!(
            "/api/v1/tenants/{tenant_id}/users/{user_id}/devices/{device_id}/sessions"
        ))
        .await
    }
}
