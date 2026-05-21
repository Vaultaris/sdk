import { describe, expect, it } from 'vitest';

import { DpopKey, signProof, thumbprint } from '../src/dpop.js';
import { base64UrlToBytes, bytesToBase64Url } from '../src/base64url.js';

function decodeJwtPart<T = unknown>(b64: string): T {
  const bytes = base64UrlToBytes(b64);
  return JSON.parse(new TextDecoder().decode(bytes)) as T;
}

async function sha256B64(s: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return bytesToBase64Url(new Uint8Array(digest));
}

describe('DpopKey', () => {
  it('generates an ES256 key with a stable thumbprint', async () => {
    const key = await DpopKey.generate();
    expect(key.alg).toBe('ES256');
    expect(key.publicJwk.kty).toBe('EC');
    expect(key.publicJwk.crv).toBe('P-256');

    const observed = await thumbprint(key.publicJwk);
    expect(observed).toBe(key.jkt);
  });

  it('rfc 7638 thumbprint matches the canonical form for known input', async () => {
    // Hand-crafted P-256 public JWK so we can validate the canonical
    // SHA-256 against a fixed expectation.
    const jwk = {
      kty: 'EC' as const,
      crv: 'P-256' as const,
      x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
      y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
    };
    const canonical = `{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`;
    const expected = await sha256B64(canonical);
    expect(await thumbprint(jwk)).toBe(expected);
  });

  it('the private key really is non-extractable', async () => {
    const key = await DpopKey.generate();
    // `crypto.subtle.exportKey('jwk', privateKey)` must throw because the
    // key was generated with extractable=false. This is the property
    // that makes XSS materially harder — the attacker can use the key
    // (sign with it) but cannot read its bytes back out.
    await expect(crypto.subtle.exportKey('jwk', key.privateKey)).rejects.toThrow();
  });
});

describe('signProof', () => {
  it('produces a well-formed 3-part JWT bound to the request', async () => {
    const key = await DpopKey.generate();
    const proof = await signProof(key, 'POST', 'https://auth.example.com/oauth/token');

    const parts = proof.split('.');
    expect(parts).toHaveLength(3);

    const header = decodeJwtPart<{ alg: string; typ: string; jwk: unknown }>(parts[0]!);
    expect(header.alg).toBe('ES256');
    expect(header.typ).toBe('dpop+jwt');
    expect(header.jwk).toEqual(key.publicJwk);

    const claims = decodeJwtPart<{ htm: string; htu: string; iat: number; jti: string }>(
      parts[1]!,
    );
    expect(claims.htm).toBe('POST');
    expect(claims.htu).toBe('https://auth.example.com/oauth/token');
    expect(typeof claims.iat).toBe('number');
    expect(claims.jti).toMatch(/[0-9a-f-]+/i);
  });

  it('embeds an ath claim that matches sha256(accessToken)', async () => {
    const key = await DpopKey.generate();
    const proof = await signProof(key, 'GET', 'https://x/api', 'the-access-token');
    const claims = decodeJwtPart<{ ath: string }>(proof.split('.')[1]!);
    expect(claims.ath).toBe(await sha256B64('the-access-token'));
  });

  it('strips the query string and fragment from htu', async () => {
    const key = await DpopKey.generate();
    const proof = await signProof(
      key,
      'GET',
      'https://x/api/users?page=1&per_page=20#frag',
    );
    const claims = decodeJwtPart<{ htu: string }>(proof.split('.')[1]!);
    expect(claims.htu).toBe('https://x/api/users');
  });

  it('signatures verify under the same key', async () => {
    const key = await DpopKey.generate();
    const proof = await signProof(key, 'POST', 'https://x/oauth/token');
    const [headerB64, claimsB64, sigB64] = proof.split('.');
    const signingInput = new TextEncoder().encode(`${headerB64}.${claimsB64}`);
    const sig = base64UrlToBytes(sigB64!);

    const ok = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key.publicKey,
      sig,
      signingInput,
    );
    expect(ok).toBe(true);
  });

  it('uppercases the method', async () => {
    const key = await DpopKey.generate();
    const proof = await signProof(key, 'post', 'https://x/oauth/token');
    const claims = decodeJwtPart<{ htm: string }>(proof.split('.')[1]!);
    expect(claims.htm).toBe('POST');
  });
});
