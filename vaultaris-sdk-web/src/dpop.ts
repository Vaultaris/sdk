/**
 * DPoP — Demonstrating Proof of Possession at the Application Layer (RFC 9449).
 *
 * Browser-native implementation: the keypair lives inside a WebCrypto
 * `CryptoKey` created with `extractable: false`. The private bytes never
 * touch JavaScript memory — `crypto.subtle.sign` is the only operation
 * available — so even an XSS that achieves arbitrary code execution
 * inside the page cannot exfiltrate the key. It can use it (sign proofs)
 * only while the page is alive, which makes credential theft strictly
 * worse for the attacker than with bearer tokens.
 *
 * The default storage backend persists the same `CryptoKey` across
 * reloads via IndexedDB — IndexedDB is one of the few APIs that can
 * round-trip a non-extractable `CryptoKey` without ever materialising
 * the bytes in JS-land.
 */

import { bytesToBase64Url, stringToBase64Url } from './base64url.js';

/**
 * Re-allocate `view` into a fresh `Uint8Array<ArrayBuffer>` so WebCrypto's
 * strict TS typings (which forbid `SharedArrayBuffer`-backed views) are
 * satisfied. The runtime cost is one small copy; we only do it on
 * per-request data, never on the access token itself.
 */
function toBufferSource(view: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(view.byteLength);
  copy.set(view);
  return copy;
}

function utf8(s: string): Uint8Array<ArrayBuffer> {
  return toBufferSource(new TextEncoder().encode(s));
}

/** Public JWK members the SDK uses to build the proof header. */
export interface DpopPublicJwk {
  kty: 'EC';
  crv: 'P-256';
  x: string;
  y: string;
}

/**
 * Anything that can sign a DPoP proof. The default implementation
 * ([`DpopKey`]) wraps a WebCrypto `CryptoKey`, but applications can
 * implement this interface against any signing backend — e.g. a service
 * worker, a remote signing endpoint, or `navigator.credentials`-issued
 * passkeys exposed as signing keys.
 */
export interface DpopSigner {
  /** JWS alg, e.g. `"ES256"`. */
  readonly alg: string;
  /** Public JWK to embed in the proof header. */
  readonly publicJwk: DpopPublicJwk;
  /** RFC 7638 JWK thumbprint of the public key. */
  readonly jkt: string;
  /** Sign `message` and return the JWS signature bytes (raw r||s for ES256). */
  sign(message: Uint8Array): Promise<Uint8Array>;
}

/**
 * ES256 keypair backed by WebCrypto. The private key is held inside a
 * non-extractable `CryptoKey`, so once instantiated there is no API to
 * read its bytes back out — it can only be used for signing.
 */
export class DpopKey implements DpopSigner {
  readonly alg = 'ES256';
  readonly publicJwk: DpopPublicJwk;
  readonly jkt: string;

  /** @internal */
  readonly privateKey: CryptoKey;

  /** @internal */
  readonly publicKey: CryptoKey;

  private constructor(
    privateKey: CryptoKey,
    publicKey: CryptoKey,
    publicJwk: DpopPublicJwk,
    jkt: string,
  ) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.publicJwk = publicJwk;
    this.jkt = jkt;
  }

  /**
   * Generate a fresh ES256 keypair. The private key is created with
   * `extractable: false` — the only operation the platform will allow on
   * it is signing.
   */
  static async generate(): Promise<DpopKey> {
    const pair = (await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign', 'verify'],
    )) as CryptoKeyPair;

    return DpopKey.fromCryptoKeyPair(pair);
  }

  /**
   * Wrap an existing `CryptoKeyPair` — typically one round-tripped from
   * IndexedDB. The private key may be non-extractable; the public key
   * must be extractable (so we can export the JWK).
   */
  static async fromCryptoKeyPair(pair: CryptoKeyPair): Promise<DpopKey> {
    const fullJwk = (await crypto.subtle.exportKey(
      'jwk',
      pair.publicKey,
    )) as JsonWebKey;

    if (fullJwk.kty !== 'EC' || fullJwk.crv !== 'P-256' || !fullJwk.x || !fullJwk.y) {
      throw new Error('DpopKey: public key must be EC P-256 with x/y components');
    }

    const publicJwk: DpopPublicJwk = {
      kty: 'EC',
      crv: 'P-256',
      x: fullJwk.x,
      y: fullJwk.y,
    };
    const jkt = await thumbprint(publicJwk);

    return new DpopKey(pair.privateKey, pair.publicKey, publicJwk, jkt);
  }

  async sign(message: Uint8Array): Promise<Uint8Array> {
    const sig = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      this.privateKey,
      toBufferSource(message),
    );
    // WebCrypto already returns the JOSE-format `r || s` for ECDSA, so
    // we can pass it through verbatim.
    return new Uint8Array(sig);
  }
}

/**
 * Compute the RFC 7638 JWK thumbprint of an EC P-256 public key.
 * The thumbprint is `base64url(SHA-256(canonical-jwk))` where the
 * canonical form lists members `crv,kty,x,y` in lexicographic order
 * with no whitespace.
 */
export async function thumbprint(jwk: DpopPublicJwk): Promise<string> {
  const canonical = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`;
  const digest = await crypto.subtle.digest('SHA-256', utf8(canonical));
  return bytesToBase64Url(new Uint8Array(digest));
}

/**
 * Build a signed DPoP proof JWT for an HTTP request.
 *
 * - `htm`: HTTP method (uppercased internally).
 * - `htu`: full request URL. Query string and fragment are stripped
 *   automatically (RFC 9449 §4.3).
 * - `accessToken`: when set, embeds `ath = base64url(sha256(token))` so
 *   the proof is bound to that exact token. Omit only on the token
 *   endpoint, where no access token exists yet.
 */
export async function signProof(
  signer: DpopSigner,
  htm: string,
  htu: string,
  accessToken?: string,
): Promise<string> {
  const normalizedHtu = normalizeHtu(htu);
  const normalizedHtm = htm.toUpperCase();
  const iat = Math.floor(Date.now() / 1000);
  const jti = generateJti();

  const header = {
    alg: signer.alg,
    typ: 'dpop+jwt',
    jwk: signer.publicJwk,
  };
  const headerB64 = stringToBase64Url(JSON.stringify(header));

  const claims: Record<string, unknown> = {
    htm: normalizedHtm,
    htu: normalizedHtu,
    iat,
    jti,
  };
  if (accessToken !== undefined) {
    claims['ath'] = await accessTokenHash(accessToken);
  }
  const claimsB64 = stringToBase64Url(JSON.stringify(claims));

  const signingInput = `${headerB64}.${claimsB64}`;
  const sig = await signer.sign(utf8(signingInput));
  const sigB64 = bytesToBase64Url(sig);

  return `${signingInput}.${sigB64}`;
}

async function accessTokenHash(token: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', utf8(token));
  return bytesToBase64Url(new Uint8Array(digest));
}

function normalizeHtu(url: string): string {
  const noFragment = url.split('#')[0] ?? '';
  return noFragment.split('?')[0] ?? '';
}

function generateJti(): string {
  // `crypto.randomUUID` is universal in modern browsers and Node 19+.
  if (typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  // Fallback: 16 random bytes hex-encoded.
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
