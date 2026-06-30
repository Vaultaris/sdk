//! Audit logs (`/api/v1/tenants/{tenant_id}/audit-logs/*`).

use uuid::Uuid;

use crate::client::VaultarisClient;
use crate::error::Result;
use crate::types::{AuditLog, Page, Pagination};

impl VaultarisClient {
    pub async fn list_audit_logs(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> Result<Page<AuditLog>> {
        self.get_json_query(
            &format!("/api/v1/tenants/{tenant_id}/audit-logs"),
            &pagination,
        )
        .await
    }

    pub async fn get_audit_log(&self, tenant_id: Uuid, log_id: Uuid) -> Result<AuditLog> {
        self.get_json(&format!("/api/v1/tenants/{tenant_id}/audit-logs/{log_id}"))
            .await
    }
}
