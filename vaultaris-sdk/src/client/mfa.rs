//! MFA (`/api/v1/mfa/*`).
//!
//! Endpoints are caller-scoped — the authenticated principal (the user
//! whose token is on the request) is the subject of the operation.

use uuid::Uuid;

use crate::client::VaultarisClient;
use crate::error::Result;
use crate::types::{
    AuthenticationBeginResponse, RegistrationBeginResponse, TotpSetupResult, TotpVerifyRequest,
    TotpVerifyResult, WebAuthnCredential,
};

impl VaultarisClient {
    pub async fn setup_totp(&self) -> Result<TotpSetupResult> {
        self.post_empty("/api/v1/mfa/totp/setup").await
    }

    pub async fn verify_totp_setup(&self, code: &str) -> Result<TotpVerifyResult> {
        let req = TotpVerifyRequest {
            code: code.to_string(),
            is_backup_code: false,
        };
        self.post_json("/api/v1/mfa/totp/verify", &req).await
    }

    /// Verify a TOTP code for an arbitrary user (admin-only on the server).
    pub async fn verify_totp_for_user(
        &self,
        user_id: Uuid,
        code: &str,
        is_backup_code: bool,
    ) -> Result<TotpVerifyResult> {
        let req = TotpVerifyRequest {
            code: code.to_string(),
            is_backup_code,
        };
        self.post_json(&format!("/api/v1/mfa/totp/{user_id}/verify"), &req)
            .await
    }

    pub async fn disable_totp(&self) -> Result<()> {
        self.delete_no_content("/api/v1/mfa/totp/disable").await
    }

    pub async fn webauthn_credentials(&self) -> Result<Vec<WebAuthnCredential>> {
        self.get_json("/api/v1/mfa/webauthn/credentials").await
    }

    pub async fn webauthn_begin_registration(&self) -> Result<RegistrationBeginResponse> {
        self.post_empty("/api/v1/mfa/webauthn/register/begin").await
    }

    pub async fn webauthn_complete_registration(
        &self,
        challenge_id: Uuid,
        credential_id: &str,
        client_data_json: &str,
        attestation_object: &str,
        device_name: Option<&str>,
        transports: Option<Vec<String>>,
    ) -> Result<WebAuthnCredential> {
        let body = serde_json::json!({
            "challenge_id": challenge_id,
            "device_name": device_name,
            "id": credential_id,
            "response": {
                "clientDataJSON": client_data_json,
                "attestationObject": attestation_object,
                "transports": transports.unwrap_or_default(),
            }
        });
        self.post_json("/api/v1/mfa/webauthn/register/complete", &body)
            .await
    }

    pub async fn webauthn_begin_authentication(&self) -> Result<AuthenticationBeginResponse> {
        self.post_empty("/api/v1/mfa/webauthn/authenticate/begin")
            .await
    }

    pub async fn webauthn_complete_authentication(
        &self,
        challenge_id: Uuid,
        credential_id: &str,
        client_data_json: &str,
        authenticator_data: &str,
        signature: &str,
        user_handle: Option<&str>,
    ) -> Result<WebAuthnCredential> {
        let body = serde_json::json!({
            "challenge_id": challenge_id,
            "id": credential_id,
            "response": {
                "clientDataJSON": client_data_json,
                "authenticatorData": authenticator_data,
                "signature": signature,
                "userHandle": user_handle,
            }
        });
        self.post_json("/api/v1/mfa/webauthn/authenticate/complete", &body)
            .await
    }

    pub async fn delete_webauthn_credential(&self, credential_id: Uuid) -> Result<()> {
        self.delete_no_content(&format!("/api/v1/mfa/webauthn/credentials/{credential_id}"))
            .await
    }
}
