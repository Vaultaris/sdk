//! Initial-setup endpoints (`/setup/*`).

use crate::client::VaultarisClient;
use crate::error::Result;
use crate::types::{SetupRequest, SetupStatus, Tenant};

impl VaultarisClient {
    /// Whether the instance has any tenants configured yet.
    pub async fn setup_status(&self) -> Result<SetupStatus> {
        self.get_json("/setup/status").await
    }

    /// Lightweight variant — server returns the same shape.
    pub async fn requires_setup(&self) -> Result<SetupStatus> {
        self.get_json("/setup/check").await
    }

    /// Run the first-tenant setup flow.
    pub async fn perform_setup(&self, req: &SetupRequest) -> Result<Tenant> {
        self.post_json("/setup", req).await
    }
}
