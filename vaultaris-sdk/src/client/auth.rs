//! Password-reset and email-verification endpoints.

use uuid::Uuid;

use crate::client::VaultarisClient;
use crate::error::Result;
use crate::types::{
    EmailVerificationRequest, PasswordResetConfirmRequest, PasswordResetRequest,
    ResetTokenValidation,
};

impl VaultarisClient {
    /// Trigger a password-reset email for `email` within `tenant_id`.
    pub async fn request_password_reset(&self, tenant_id: Uuid, email: &str) -> Result<()> {
        let req = PasswordResetRequest {
            email: email.to_string(),
        };
        self.post_no_content(
            &format!("/api/v1/tenants/{tenant_id}/auth/password-reset"),
            &req,
        )
        .await
    }

    pub async fn validate_reset_token(&self, token: &str) -> Result<ResetTokenValidation> {
        self.get_json(&format!("/api/v1/auth/password-reset/{token}/validate"))
            .await
    }

    pub async fn complete_password_reset(&self, token: &str, new_password: &str) -> Result<()> {
        let req = PasswordResetConfirmRequest {
            token: token.to_string(),
            new_password: new_password.to_string(),
        };
        self.post_no_content("/api/v1/auth/password-reset/complete", &req)
            .await
    }

    pub async fn resend_verification_email(&self, tenant_id: Uuid, user_id: Uuid) -> Result<()> {
        self.post_empty_no_content(&format!(
            "/api/v1/tenants/{tenant_id}/users/{user_id}/verify-email"
        ))
        .await
    }

    pub async fn verify_email(&self, token: &str) -> Result<()> {
        let req = EmailVerificationRequest {
            token: token.to_string(),
        };
        self.post_no_content("/api/v1/auth/verify-email", &req)
            .await
    }
}
