//! Statistics endpoints (`/api/v1/tenants/{tenant_id}/statistics/*`).

use uuid::Uuid;

use crate::client::VaultarisClient;
use crate::error::Result;
use crate::types::{
    AuthenticationStats, DashboardSummary, SecurityStats, SessionStats, StatsQuery, TenantOverview,
};

impl VaultarisClient {
    pub async fn tenant_overview(&self, tenant_id: Uuid) -> Result<TenantOverview> {
        self.get_json(&format!("/api/v1/tenants/{tenant_id}/statistics/overview"))
            .await
    }

    pub async fn auth_stats(
        &self,
        tenant_id: Uuid,
        query: &StatsQuery,
    ) -> Result<AuthenticationStats> {
        self.get_json_query(
            &format!("/api/v1/tenants/{tenant_id}/statistics/authentication"),
            query,
        )
        .await
    }

    pub async fn session_stats(&self, tenant_id: Uuid, query: &StatsQuery) -> Result<SessionStats> {
        self.get_json_query(
            &format!("/api/v1/tenants/{tenant_id}/statistics/sessions"),
            query,
        )
        .await
    }

    pub async fn security_stats(
        &self,
        tenant_id: Uuid,
        query: &StatsQuery,
    ) -> Result<SecurityStats> {
        self.get_json_query(
            &format!("/api/v1/tenants/{tenant_id}/statistics/security"),
            query,
        )
        .await
    }

    pub async fn dashboard_summary(&self, tenant_id: Uuid) -> Result<DashboardSummary> {
        self.get_json(&format!("/api/v1/tenants/{tenant_id}/statistics/dashboard"))
            .await
    }
}
