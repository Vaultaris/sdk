//! Session management (`/api/v1/tenants/{tenant_id}/sessions/*`).

use uuid::Uuid;

use crate::client::VaultarisClient;
use crate::error::Result;
use crate::types::{Page, Pagination, Session};

impl VaultarisClient {
    pub async fn list_sessions(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> Result<Page<Session>> {
        self.get_json_query(
            &format!("/api/v1/tenants/{tenant_id}/sessions"),
            &pagination,
        )
        .await
    }

    pub async fn revoke_session(&self, tenant_id: Uuid, session_id: Uuid) -> Result<()> {
        self.delete_no_content(&format!(
            "/api/v1/tenants/{tenant_id}/sessions/{session_id}"
        ))
        .await
    }

    pub async fn user_sessions(&self, tenant_id: Uuid, user_id: Uuid) -> Result<Vec<Session>> {
        self.get_json(&format!(
            "/api/v1/tenants/{tenant_id}/users/{user_id}/sessions"
        ))
        .await
    }

    pub async fn revoke_user_sessions(&self, tenant_id: Uuid, user_id: Uuid) -> Result<()> {
        self.delete_no_content(&format!(
            "/api/v1/tenants/{tenant_id}/users/{user_id}/sessions"
        ))
        .await
    }
}
