//! DPoP keypair exposed to Node.js.
//!
//! ```js
//! const { VaultarisClient, DpopKey } = require('@vaultaris/sdk');
//!
//! // Generate (or load) once per install.
//! const key = DpopKey.generate();
//! require('fs').writeFileSync('/var/lib/myapp/dpop.pem', key.toPkcs8Pem());
//!
//! const client = new VaultarisClient({
//!   baseUrl: 'https://auth.example.com',
//!   apiKey:  'eyJ...',
//!   dpopKey: key,                 // ← every request signed automatically
//! });
//! ```

use napi::bindgen_prelude::*;
use napi_derive::napi;

/// ES256 keypair used by the client to attach DPoP proofs to outgoing
/// requests. Cheap to clone — internally an `Arc`.
#[napi]
#[derive(Clone)]
pub struct DpopKey {
    pub(crate) inner: vaultaris_sdk::DpopKey,
}

#[napi]
impl DpopKey {
    /// Generate a fresh ES256 (P-256) keypair using the OS RNG.
    #[napi(factory)]
    pub fn generate() -> Self {
        Self {
            inner: vaultaris_sdk::DpopKey::generate(),
        }
    }

    /// Load a key previously saved with `toPkcs8Pem()`.
    #[napi(factory, js_name = "fromPkcs8Pem")]
    pub fn from_pkcs8_pem(pem: String) -> Result<Self> {
        vaultaris_sdk::DpopKey::from_pkcs8_pem(&pem)
            .map(|inner| Self { inner })
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    /// Serialize the private key as PKCS#8 PEM. Treat the output as a secret.
    #[napi(js_name = "toPkcs8Pem")]
    pub fn to_pkcs8_pem(&self) -> Result<String> {
        self.inner
            .to_pkcs8_pem()
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    /// JWK thumbprint (RFC 7638) of the public key — the value the server
    /// pins in the access token's `cnf.jkt` claim.
    #[napi]
    pub fn jkt(&self) -> String {
        self.inner.jkt().to_string()
    }

    /// Build and sign a DPoP proof for a given HTTP request.  The client
    /// calls this internally on every outgoing request, but it is exposed
    /// so applications using a custom HTTP stack can do the same.
    ///
    /// - `htm`: HTTP method (`"GET"`, `"POST"`, …)
    /// - `htu`: full request URL
    /// - `accessToken`: present only when the request also carries an
    ///   access token. Pass `null` on the `/oauth/token` endpoint.
    #[napi(js_name = "signProof")]
    pub fn sign_proof(
        &self,
        htm: String,
        htu: String,
        access_token: Option<String>,
    ) -> Result<String> {
        self.inner
            .sign_proof(&htm, &htu, access_token.as_deref())
            .map_err(|e| Error::from_reason(e.to_string()))
    }
}
