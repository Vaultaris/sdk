//! DPoP — Demonstrating Proof of Possession at the Application Layer.
//!
//! Two layers:
//!
//! 1. [`DpopSigner`] — the abstraction. Anything that can expose a public
//!    JWK and produce JWS signatures over a message implements it. The
//!    SDK uses this trait whenever it builds a proof, so the actual key
//!    material can live anywhere: in-process memory, an OS keychain, an
//!    HSM via PKCS#11, a cloud KMS, a TPM, a mobile Secure Enclave …
//!
//! 2. [`DpopKey`] — the default in-memory implementation. Generates an
//!    ES256 keypair, persists it as PKCS#8, signs proofs in-process.
//!    Covers the 95% case (web servers, CLI tools, native apps without
//!    hardware-backed key storage).
//!
//! ## In-memory (default)
//!
//! ```rust,no_run
//! use vaultaris_sdk::{VaultarisClient, VaultarisConfig, DpopKey};
//!
//! # async fn run() -> Result<(), vaultaris_sdk::Error> {
//! let key = DpopKey::generate();
//! let config = VaultarisConfig::new("https://auth.example.com")
//!     .with_api_key("eyJ...")
//!     .with_dpop_key(key);
//! let client = VaultarisClient::new(config)?;
//! let _ = client.validate_token("...").await?;
//! # Ok(()) }
//! ```
//!
//! ## Custom signer (HSM / KMS / Secure Enclave)
//!
//! Implement [`DpopSigner`] over your hardware-backed key:
//!
//! ```rust,no_run
//! use std::pin::Pin;
//! use std::future::Future;
//! use std::sync::Arc;
//! use vaultaris_sdk::dpop::{DpopPublicJwk, DpopSigner};
//! use vaultaris_sdk::{VaultarisClient, VaultarisConfig, Error};
//!
//! struct KmsSigner { /* aws_sdk_kms::Client, key_id, cached jwk + jkt */ }
//!
//! impl DpopSigner for KmsSigner {
//!     fn alg(&self) -> &'static str { "ES256" }
//!     fn public_jwk(&self) -> &DpopPublicJwk { unimplemented!() }
//!     fn jkt(&self) -> &str { unimplemented!() }
//!     fn sign<'a>(&'a self, _msg: &'a [u8])
//!         -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Error>> + Send + 'a>>
//!     {
//!         Box::pin(async move {
//!             // call KMS, return the JOSE-format signature bytes
//!             Ok(vec![])
//!         })
//!     }
//! }
//!
//! # async fn run() -> Result<(), Error> {
//! let signer: Arc<dyn DpopSigner> = Arc::new(KmsSigner { /* … */ });
//! let config = VaultarisConfig::new("https://auth.example.com")
//!     .with_api_key("eyJ...")
//!     .with_dpop_signer(signer);
//! let _ = VaultarisClient::new(config)?;
//! # Ok(()) }
//! ```

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use p256::elliptic_curve::rand_core::OsRng;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::Error;

/// Members of a public JWK needed to build the DPoP proof header and
/// compute the RFC 7638 thumbprint.
#[derive(Clone, Debug)]
pub enum DpopPublicJwk {
    /// P-256 EC key. `x` and `y` are base64url-no-pad coordinates.
    Ec { x: String, y: String },
    /// RSA key. `n` and `e` are base64url-no-pad bigints.
    Rsa { n: String, e: String },
}

impl DpopPublicJwk {
    /// JSON serialisation suitable for the `jwk` header member.
    pub fn to_jwk_json(&self) -> String {
        match self {
            Self::Ec { x, y } => format!(
                r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
                x, y
            ),
            Self::Rsa { n, e } => format!(r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#, e, n),
        }
    }

    /// RFC 7638 JWK thumbprint of the public key, base64url-no-pad SHA-256
    /// of the canonical JSON members in lexicographic order.
    pub fn thumbprint(&self) -> String {
        // `to_jwk_json` already produces canonical, sorted JSON for both
        // variants — `crv,kty,x,y` for EC and `e,kty,n` for RSA.
        let canonical = self.to_jwk_json();
        B64URL.encode(Sha256::digest(canonical.as_bytes()))
    }
}

/// Anything that can produce DPoP proof signatures for the SDK.
///
/// Implementations must be `Send + Sync` and dyn-compatible. `sign` is
/// async-returning a boxed future so HSM- and KMS-backed signers (which
/// typically need to make network calls) can plug in without forcing the
/// trait into either-sync-or-async-only.
pub trait DpopSigner: Send + Sync {
    /// JWS `alg` name (e.g. `"ES256"`, `"RS256"`, `"PS256"`).
    fn alg(&self) -> &'static str;

    /// Public JWK members.
    fn public_jwk(&self) -> &DpopPublicJwk;

    /// RFC 7638 JWK thumbprint of the public key (base64url-no-pad).
    fn jkt(&self) -> &str;

    /// Sign `message` and return the JWS signature bytes.
    ///
    /// For ES256 that's the IEEE-P1363 `r || s` concatenation (64 bytes).
    /// For RS256/PS256 it's the raw RSA signature.
    fn sign<'a>(
        &'a self,
        message: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Error>> + Send + 'a>>;
}

/// Build, sign and serialize a DPoP proof JWT using the given signer.
///
/// - `htm`: HTTP method (`"GET"`, `"POST"`, …). Uppercased internally.
/// - `htu`: full request URL. Query string and fragment are stripped
///   automatically per RFC 9449 §4.3.
/// - `access_token`: when set, embeds the `ath` claim binding the proof
///   to that specific token. Pass `None` only on the token endpoint.
pub async fn sign_proof_with(
    signer: &dyn DpopSigner,
    htm: &str,
    htu: &str,
    access_token: Option<&str>,
) -> Result<String, Error> {
    let htu = normalize_htu(htu);
    let htm = htm.to_ascii_uppercase();
    let iat = chrono::Utc::now().timestamp();
    let jti = Uuid::new_v4().to_string();

    let header = format!(
        r#"{{"alg":"{}","typ":"dpop+jwt","jwk":{}}}"#,
        signer.alg(),
        signer.public_jwk().to_jwk_json()
    );
    let header_b64 = B64URL.encode(header.as_bytes());

    let claims = match access_token {
        Some(token) => {
            let ath = B64URL.encode(Sha256::digest(token.as_bytes()));
            format!(
                r#"{{"htm":"{}","htu":"{}","iat":{},"jti":"{}","ath":"{}"}}"#,
                htm, htu, iat, jti, ath
            )
        }
        None => format!(
            r#"{{"htm":"{}","htu":"{}","iat":{},"jti":"{}"}}"#,
            htm, htu, iat, jti
        ),
    };
    let claims_b64 = B64URL.encode(claims.as_bytes());

    let signing_input = format!("{}.{}", header_b64, claims_b64);
    let signature = signer.sign(signing_input.as_bytes()).await?;
    let sig_b64 = B64URL.encode(signature);

    Ok(format!("{}.{}", signing_input, sig_b64))
}

// ─────────────────────────────────────────────────────────────────────────
// Default in-memory implementation
// ─────────────────────────────────────────────────────────────────────────

/// ES256 keypair backing a DPoP proof, held entirely in process memory.
///
/// Cheap to clone — internally an `Arc`. The private side never leaves
/// this struct except through the explicit PKCS#8 serializers.
#[derive(Clone)]
pub struct DpopKey {
    inner: Arc<DpopKeyInner>,
}

struct DpopKeyInner {
    signing: SigningKey,
    public_jwk: DpopPublicJwk,
    jkt: String,
}

impl DpopKey {
    /// Generate a fresh ES256 (P-256) keypair using the OS RNG.
    pub fn generate() -> Self {
        Self::from_signing(SigningKey::random(&mut OsRng))
    }

    /// Load a key previously saved with [`Self::to_pkcs8_pem`].
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, Error> {
        let signing = SigningKey::from_pkcs8_pem(pem)
            .map_err(|e| Error::Config(format!("invalid PKCS#8 PEM: {}", e)))?;
        Ok(Self::from_signing(signing))
    }

    /// Load a key previously saved with [`Self::to_pkcs8_der`].
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, Error> {
        let signing = SigningKey::from_pkcs8_der(der)
            .map_err(|e| Error::Config(format!("invalid PKCS#8 DER: {}", e)))?;
        Ok(Self::from_signing(signing))
    }

    /// Serialize the private key as PKCS#8 PEM. Treat the result as a
    /// secret — anyone who reads it can impersonate this client.
    pub fn to_pkcs8_pem(&self) -> Result<String, Error> {
        self.inner
            .signing
            .to_pkcs8_pem(LineEnding::LF)
            .map(|s| s.to_string())
            .map_err(|e| Error::Config(format!("failed to encode PKCS#8 PEM: {}", e)))
    }

    /// Serialize the private key as PKCS#8 DER bytes.
    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>, Error> {
        self.inner
            .signing
            .to_pkcs8_der()
            .map(|d| d.as_bytes().to_vec())
            .map_err(|e| Error::Config(format!("failed to encode PKCS#8 DER: {}", e)))
    }

    /// JWK thumbprint (RFC 7638) of the public key, base64url-encoded.
    pub fn jkt(&self) -> &str {
        &self.inner.jkt
    }

    /// Build a signed DPoP proof for the given request.
    ///
    /// Equivalent to [`sign_proof_with`] but avoids the async machinery
    /// when the caller knows it's using the in-memory signer.
    pub fn sign_proof(
        &self,
        htm: &str,
        htu: &str,
        access_token: Option<&str>,
    ) -> Result<String, Error> {
        // Synchronous fast path — futures::executor would be overkill and
        // adds a dep. We just inline the proof construction.
        let htu = normalize_htu(htu);
        let htm = htm.to_ascii_uppercase();
        let iat = chrono::Utc::now().timestamp();
        let jti = Uuid::new_v4().to_string();

        let header = format!(
            r#"{{"alg":"ES256","typ":"dpop+jwt","jwk":{}}}"#,
            self.inner.public_jwk.to_jwk_json()
        );
        let header_b64 = B64URL.encode(header.as_bytes());

        let claims = match access_token {
            Some(token) => {
                let ath = B64URL.encode(Sha256::digest(token.as_bytes()));
                format!(
                    r#"{{"htm":"{}","htu":"{}","iat":{},"jti":"{}","ath":"{}"}}"#,
                    htm, htu, iat, jti, ath
                )
            }
            None => format!(
                r#"{{"htm":"{}","htu":"{}","iat":{},"jti":"{}"}}"#,
                htm, htu, iat, jti
            ),
        };
        let claims_b64 = B64URL.encode(claims.as_bytes());

        let signing_input = format!("{}.{}", header_b64, claims_b64);
        let sig: Signature = self.inner.signing.sign(signing_input.as_bytes());
        let sig_b64 = B64URL.encode(sig.to_bytes());

        Ok(format!("{}.{}", signing_input, sig_b64))
    }

    fn from_signing(signing: SigningKey) -> Self {
        let verifying = signing.verifying_key();
        let point = verifying.to_encoded_point(false);
        let x = B64URL.encode(point.x().expect("P-256 point has x"));
        let y = B64URL.encode(point.y().expect("P-256 point has y"));

        let public_jwk = DpopPublicJwk::Ec { x, y };
        let jkt = public_jwk.thumbprint();

        Self {
            inner: Arc::new(DpopKeyInner {
                signing,
                public_jwk,
                jkt,
            }),
        }
    }
}

impl DpopSigner for DpopKey {
    fn alg(&self) -> &'static str {
        "ES256"
    }

    fn public_jwk(&self) -> &DpopPublicJwk {
        &self.inner.public_jwk
    }

    fn jkt(&self) -> &str {
        &self.inner.jkt
    }

    fn sign<'a>(
        &'a self,
        message: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Error>> + Send + 'a>> {
        let signing = &self.inner.signing;
        let sig: Signature = signing.sign(message);
        let bytes = sig.to_bytes().to_vec();
        Box::pin(async move { Ok(bytes) })
    }
}

impl std::fmt::Debug for DpopKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpopKey")
            .field("jkt", &self.inner.jkt)
            .finish()
    }
}

fn normalize_htu(url: &str) -> String {
    let no_fragment = url.split('#').next().unwrap_or("");
    no_fragment.split('?').next().unwrap_or("").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_key_round_trips_pem() {
        let key = DpopKey::generate();
        let pem = key.to_pkcs8_pem().unwrap();
        let reloaded = DpopKey::from_pkcs8_pem(&pem).unwrap();
        assert_eq!(key.jkt(), reloaded.jkt());
    }

    #[test]
    fn proof_has_three_dot_separated_parts() {
        let key = DpopKey::generate();
        let proof = key
            .sign_proof("POST", "https://x/oauth/token", None)
            .unwrap();
        assert_eq!(proof.matches('.').count(), 2);
    }

    #[test]
    fn proof_with_access_token_embeds_ath() {
        let key = DpopKey::generate();
        let proof = key
            .sign_proof("GET", "https://x/api", Some("the-access-token"))
            .unwrap();

        let claims_b64 = proof.split('.').nth(1).unwrap();
        let claims_bytes = B64URL.decode(claims_b64).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&claims_bytes).unwrap();
        let expected = B64URL.encode(Sha256::digest(b"the-access-token"));
        assert_eq!(claims["ath"], expected);
    }

    #[test]
    fn jkt_is_stable_across_invocations() {
        let key = DpopKey::generate();
        let a = key.jkt().to_string();
        let b = key.jkt().to_string();
        assert_eq!(a, b);
    }

    #[tokio::test]
    async fn dyn_signer_produces_same_proof_shape() {
        let key = DpopKey::generate();
        let signer: &dyn DpopSigner = &key;
        let proof = sign_proof_with(signer, "POST", "https://x/oauth/token", None)
            .await
            .unwrap();
        assert_eq!(proof.matches('.').count(), 2);
    }

    #[tokio::test]
    async fn custom_signer_can_be_plugged_in() {
        // A toy signer that wraps DpopKey but adds a recorded counter, to
        // prove the trait can carry user state without forcing it into
        // `DpopKey`.
        struct CountingSigner {
            inner: DpopKey,
            calls: std::sync::atomic::AtomicUsize,
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
            ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Error>> + Send + 'a>> {
                self.calls
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.inner.sign(message)
            }
        }

        let signer = CountingSigner {
            inner: DpopKey::generate(),
            calls: std::sync::atomic::AtomicUsize::new(0),
        };
        let _ = sign_proof_with(&signer, "GET", "https://x/y", Some("tok"))
            .await
            .unwrap();
        let _ = sign_proof_with(&signer, "GET", "https://x/y", Some("tok"))
            .await
            .unwrap();
        assert_eq!(
            signer.calls.load(std::sync::atomic::Ordering::Relaxed),
            2,
            "custom signer should be invoked once per proof"
        );
    }
}
