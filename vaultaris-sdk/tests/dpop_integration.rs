//! End-to-end check that `VaultarisClient` automatically attaches a DPoP
//! proof to every outgoing request — the calling application never has to
//! touch the crypto.

#![cfg(all(feature = "async", feature = "dpop"))]

use vaultaris_sdk::{DpopKey, VaultarisClient, VaultarisConfig};
use wiremock::matchers::{header, header_exists, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

#[tokio::test]
async fn dpop_header_is_attached_to_every_request() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/integration/token/validate"))
        // The client must switch the Authorization scheme to `DPoP`.
        .and(header("Authorization", "DPoP my-access-token"))
        // … and attach a freshly-signed proof JWT.
        .and(header_exists("DPoP"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "valid": true,
            "scopes": [],
            "roles": [],
            "permissions": [],
        })))
        .expect(1)
        .mount(&server)
        .await;

    let key = DpopKey::generate();
    let expected_jkt = key.jkt().to_string();

    let config = VaultarisConfig::new(server.uri())
        .with_api_key("my-access-token")
        .with_dpop_key(key);
    let client = VaultarisClient::new(config).expect("client builds");

    client.validate_token("opaque").await.expect("call succeeds");

    // Spot-check: the proof's JWK actually matches the key we configured.
    let recorded = server.received_requests().await.expect("requests");
    let req: &Request = recorded.first().expect("one request was made");
    let proof = req
        .headers
        .get("dpop")
        .and_then(|v| v.to_str().ok())
        .expect("DPoP header present");

    let claims_b64 = proof.split('.').nth(1).expect("3-part JWT");
    let claims_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        claims_b64,
    )
    .expect("base64url claims");
    let claims: serde_json::Value = serde_json::from_slice(&claims_bytes).unwrap();
    assert_eq!(claims["htm"], "POST");
    assert!(
        claims["htu"]
            .as_str()
            .unwrap()
            .ends_with("/api/v1/integration/token/validate"),
        "htu should match the request URL"
    );
    // ath = sha256(api_key) — bound to the access token.
    assert!(claims["ath"].is_string(), "ath claim should be present");

    // The JWK in the header decodes to the same thumbprint we configured.
    let header_b64 = proof.split('.').next().unwrap();
    let header_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        header_b64,
    )
    .unwrap();
    let header_json: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
    let jwk = &header_json["jwk"];
    let canonical = format!(
        r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
        jwk["crv"].as_str().unwrap(),
        jwk["kty"].as_str().unwrap(),
        jwk["x"].as_str().unwrap(),
        jwk["y"].as_str().unwrap(),
    );
    use sha2::{Digest, Sha256};
    let observed_jkt = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        Sha256::digest(canonical.as_bytes()),
    );
    assert_eq!(observed_jkt, expected_jkt);
}

#[tokio::test]
async fn custom_dpop_signer_works_end_to_end() {
    // Wrap the default in-memory key so the trait machinery — not the
    // DpopKey fast-path inside the config — is exercised. A real-world
    // user would instead implement DpopSigner on top of an HSM/KMS/TPM.
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use vaultaris_sdk::dpop::{DpopPublicJwk, DpopSigner};

    struct CountingSigner {
        inner: DpopKey,
        calls: AtomicUsize,
    }

    impl DpopSigner for CountingSigner {
        fn alg(&self) -> &'static str {
            self.inner.alg()
        }
        fn public_jwk(&self) -> &DpopPublicJwk {
            self.inner.public_jwk()
        }
        fn jkt(&self) -> &str {
            self.inner.jkt()
        }
        fn sign<'a>(
            &'a self,
            message: &'a [u8],
        ) -> Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, vaultaris_sdk::Error>> + Send + 'a>>
        {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.inner.sign(message)
        }
    }

    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/integration/token/validate"))
        .and(header("Authorization", "DPoP custom-signer-token"))
        .and(header_exists("DPoP"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "valid": true,
            "scopes": [],
            "roles": [],
            "permissions": [],
        })))
        .expect(1)
        .mount(&server)
        .await;

    let signer = Arc::new(CountingSigner {
        inner: DpopKey::generate(),
        calls: AtomicUsize::new(0),
    });
    let signer_handle = signer.clone();

    let config = vaultaris_sdk::VaultarisConfig::new(server.uri())
        .with_api_key("custom-signer-token")
        .with_dpop_signer(signer);
    let client = VaultarisClient::new(config).expect("client builds");

    client.validate_token("opaque").await.expect("call succeeds");

    assert_eq!(
        signer_handle.calls.load(Ordering::Relaxed),
        1,
        "the user-supplied signer should have been called exactly once"
    );
}

#[tokio::test]
async fn without_dpop_key_authorization_falls_back_to_bearer() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/integration/token/validate"))
        .and(header("Authorization", "Bearer my-access-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "valid": true,
            "scopes": [],
            "roles": [],
            "permissions": [],
        })))
        .expect(1)
        .mount(&server)
        .await;

    let config = VaultarisConfig::new(server.uri()).with_api_key("my-access-token");
    let client = VaultarisClient::new(config).expect("client builds");

    client.validate_token("opaque").await.expect("call succeeds");

    let recorded = server.received_requests().await.expect("requests");
    let req: &Request = recorded.first().expect("one request was made");
    assert!(
        req.headers.get("dpop").is_none(),
        "no DPoP header without a key"
    );
}
