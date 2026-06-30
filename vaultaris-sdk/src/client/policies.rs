//! ABAC policy management (`/api/v1/tenants/{tenant_id}/policies/*`).

use uuid::Uuid;

use crate::client::VaultarisClient;
use crate::error::Result;
use crate::types::{
    AbacPolicy, CreateAbacPolicyRequest, EvaluatePoliciesRequest, Page, Pagination,
    PolicyEvaluationResult, UpdateAbacPolicyRequest,
};

impl VaultarisClient {
    pub async fn list_policies(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> Result<Page<AbacPolicy>> {
        self.get_json_query(
            &format!("/api/v1/tenants/{tenant_id}/policies"),
            &pagination,
        )
        .await
    }

    pub async fn create_policy(
        &self,
        tenant_id: Uuid,
        req: &CreateAbacPolicyRequest,
    ) -> Result<AbacPolicy> {
        self.post_json(&format!("/api/v1/tenants/{tenant_id}/policies"), req)
            .await
    }

    pub async fn get_policy(&self, tenant_id: Uuid, policy_id: Uuid) -> Result<AbacPolicy> {
        self.get_json(&format!("/api/v1/tenants/{tenant_id}/policies/{policy_id}"))
            .await
    }

    pub async fn update_policy(
        &self,
        tenant_id: Uuid,
        policy_id: Uuid,
        req: &UpdateAbacPolicyRequest,
    ) -> Result<AbacPolicy> {
        self.put_json(
            &format!("/api/v1/tenants/{tenant_id}/policies/{policy_id}"),
            req,
        )
        .await
    }

    pub async fn delete_policy(&self, tenant_id: Uuid, policy_id: Uuid) -> Result<()> {
        self.delete_no_content(&format!("/api/v1/tenants/{tenant_id}/policies/{policy_id}"))
            .await
    }

    pub async fn evaluate_policies(
        &self,
        tenant_id: Uuid,
        req: &EvaluatePoliciesRequest,
    ) -> Result<PolicyEvaluationResult> {
        self.post_json(
            &format!("/api/v1/tenants/{tenant_id}/policies/evaluate"),
            req,
        )
        .await
    }

    /// User-scoped access check — wraps the ABAC engine with the user's
    /// subject attributes resolved server-side.
    pub async fn check_user_access(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        req: &serde_json::Value,
    ) -> Result<PolicyEvaluationResult> {
        self.post_json(
            &format!("/api/v1/tenants/{tenant_id}/users/{user_id}/check-access"),
            req,
        )
        .await
    }
}
