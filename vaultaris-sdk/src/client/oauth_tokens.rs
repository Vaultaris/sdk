//! OAuth token endpoint (`POST /oauth/token`) — direct grant helpers.
//!
//! The high-level [`crate::oauth::OAuthFlow`] typestate builder is the
//! recommended path for user-facing flows. These helpers exist for the
//! common case of issuing a single token without leaving the
//! [`VaultarisClient`] surface.

use std::collections::HashMap;

use crate::client::VaultarisClient;
use crate::error::{Error, Result};
use crate::types::TokenResponse;

impl VaultarisClient {
    /// Issue an access token via the OAuth2 `client_credentials` grant.
    ///
    /// Uses [`crate::config::VaultarisConfig::client_id`] /
    /// [`crate::config::VaultarisConfig::client_secret`]; returns
    /// `Error::Config` if either is missing.
    ///
    /// # Errors
    /// Returns `Error::Config` when client credentials are unset, or
    /// propagates the underlying transport/API error otherwise.
    pub async fn token_client_credentials(&self, scope: Option<&str>) -> Result<TokenResponse> {
        let client_id = self
            .config
            .client_id
            .as_deref()
            .ok_or_else(|| Error::Config("client_id is required".to_string()))?;
        let client_secret = self
            .config
            .client_secret
            .as_deref()
            .ok_or_else(|| Error::Config("client_secret is required".to_string()))?;

        let mut form: HashMap<&str, &str> = HashMap::new();
        form.insert("grant_type", "client_credentials");
        form.insert("client_id", client_id);
        form.insert("client_secret", client_secret);
        if let Some(scope) = scope {
            form.insert("scope", scope);
        }

        self.form_post("/oauth/token", &form).await
    }

    /// Issue tokens via the OAuth2 `password` grant.
    pub async fn token_password(
        &self,
        username: &str,
        password: &str,
        scope: Option<&str>,
    ) -> Result<TokenResponse> {
        let client_id = self
            .config
            .client_id
            .as_deref()
            .ok_or_else(|| Error::Config("client_id is required".to_string()))?;
        let mut form: HashMap<&str, &str> = HashMap::new();
        form.insert("grant_type", "password");
        form.insert("client_id", client_id);
        form.insert("username", username);
        form.insert("password", password);
        if let Some(secret) = self.config.client_secret.as_deref() {
            form.insert("client_secret", secret);
        }
        if let Some(scope) = scope {
            form.insert("scope", scope);
        }
        self.form_post("/oauth/token", &form).await
    }

    /// Refresh a previously-issued token.
    pub async fn token_refresh(&self, refresh_token: &str) -> Result<TokenResponse> {
        let client_id = self
            .config
            .client_id
            .as_deref()
            .ok_or_else(|| Error::Config("client_id is required".to_string()))?;
        let mut form: HashMap<&str, &str> = HashMap::new();
        form.insert("grant_type", "refresh_token");
        form.insert("refresh_token", refresh_token);
        form.insert("client_id", client_id);
        if let Some(secret) = self.config.client_secret.as_deref() {
            form.insert("client_secret", secret);
        }
        self.form_post("/oauth/token", &form).await
    }

    async fn form_post<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        form: &HashMap<&str, &str>,
    ) -> Result<T> {
        let url = self.url(path);
        let req = self
            .apply_auth(self.http.post(&url).form(form), "POST", &url)
            .await?;
        let response = req.send().await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        if !status.is_success() {
            return Err(Error::from_response(
                status.as_u16(),
                String::from_utf8_lossy(&bytes).into_owned(),
            ));
        }
        serde_json::from_slice(&bytes).map_err(Error::from)
    }
}
