//! HTTP transport — shared by every resource method.
//!
//! Centralises auth header injection, DPoP proof attachment, request body
//! serialisation, and `{ success, data }` envelope unwrapping.

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::client::VaultarisClient;
use crate::error::{Error, Result};
use crate::types::ApiResponse;

impl VaultarisClient {
    /// Apply auth + (optional) DPoP + fingerprint headers to a request.
    pub(crate) async fn apply_auth(
        &self,
        mut req: reqwest::RequestBuilder,
        method: &str,
        url: &str,
    ) -> Result<reqwest::RequestBuilder> {
        if let Some(auth) = self.config.auth_header() {
            req = req.header(reqwest::header::AUTHORIZATION, auth);
        }
        #[cfg(feature = "dpop")]
        if let Some(proof) = self.config.dpop_proof(method, url).await {
            req = req.header("DPoP", proof?);
        }
        #[cfg(not(feature = "dpop"))]
        let _ = (method, url);
        if let Some(fp) = &self.config.device_fingerprint {
            req = req.header("X-Device-Fingerprint", fp);
        }
        Ok(req)
    }

    pub(crate) fn url(&self, path: &str) -> String {
        self.config.build_url(path)
    }

    pub(crate) async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = self.url(path);
        let req = self.apply_auth(self.http.get(&url), "GET", &url).await?;
        self.handle_response(req.send().await?).await
    }

    pub(crate) async fn get_json_query<T, Q>(&self, path: &str, query: &Q) -> Result<T>
    where
        T: DeserializeOwned,
        Q: Serialize + ?Sized,
    {
        let url = self.url(path);
        let req = self
            .apply_auth(self.http.get(&url).query(query), "GET", &url)
            .await?;
        self.handle_response(req.send().await?).await
    }

    pub(crate) async fn post_json<B, T>(&self, path: &str, body: &B) -> Result<T>
    where
        B: Serialize + ?Sized,
        T: DeserializeOwned,
    {
        let url = self.url(path);
        let req = self
            .apply_auth(self.http.post(&url).json(body), "POST", &url)
            .await?;
        self.handle_response(req.send().await?).await
    }

    /// POST that ignores any response body. Server may return `{}` or 204.
    pub(crate) async fn post_no_content<B>(&self, path: &str, body: &B) -> Result<()>
    where
        B: Serialize + ?Sized,
    {
        let url = self.url(path);
        let req = self
            .apply_auth(self.http.post(&url).json(body), "POST", &url)
            .await?;
        Self::check_status(req.send().await?).await
    }

    pub(crate) async fn post_empty<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.post_json(path, &serde_json::json!({})).await
    }

    pub(crate) async fn post_empty_no_content(&self, path: &str) -> Result<()> {
        self.post_no_content(path, &serde_json::json!({})).await
    }

    pub(crate) async fn put_json<B, T>(&self, path: &str, body: &B) -> Result<T>
    where
        B: Serialize + ?Sized,
        T: DeserializeOwned,
    {
        let url = self.url(path);
        let req = self
            .apply_auth(self.http.put(&url).json(body), "PUT", &url)
            .await?;
        self.handle_response(req.send().await?).await
    }

    pub(crate) async fn delete_no_content(&self, path: &str) -> Result<()> {
        let url = self.url(path);
        let req = self
            .apply_auth(self.http.delete(&url), "DELETE", &url)
            .await?;
        Self::check_status(req.send().await?).await
    }

    /// Map a body-less response to a typed error, or `Ok(())`.
    async fn check_status(response: reqwest::Response) -> Result<()> {
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let body = response.text().await.unwrap_or_default();
        Err(Error::from_response(status.as_u16(), body))
    }

    /// Decode `{ success, data: T }` (or bare `T`) on 2xx; build typed error otherwise.
    async fn handle_response<T: DeserializeOwned>(&self, response: reqwest::Response) -> Result<T> {
        let status = response.status();
        let bytes = response.bytes().await?;

        if !status.is_success() {
            let body = String::from_utf8_lossy(&bytes).into_owned();
            return Err(Error::from_response(status.as_u16(), body));
        }

        if bytes.is_empty() {
            return serde_json::from_slice::<T>(b"null").map_err(Error::from);
        }
        if let Ok(wrapped) = serde_json::from_slice::<ApiResponse<T>>(&bytes) {
            return Ok(wrapped.data);
        }
        serde_json::from_slice::<T>(&bytes).map_err(Error::from)
    }
}
