import { describe, expect, it } from 'vitest';

import { DpopKey } from '../src/dpop.js';
import { base64UrlToBytes } from '../src/base64url.js';
import { VaultarisClient } from '../src/client.js';

interface RecordedRequest {
  url: string;
  method: string;
  headers: Headers;
  body: string | null;
}

/**
 * Build a mock `fetch` that records every call and returns the given
 * JSON payload. Mirrors the wiremock-based tests on the Rust side.
 */
function mockFetch(payload: unknown, recorded: RecordedRequest[]): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = new Request(input as Request, init);
    recorded.push({
      url: req.url,
      method: req.method,
      headers: req.headers,
      body: init?.body ? String(init.body) : null,
    });
    return new Response(JSON.stringify(payload), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }) as typeof fetch;
}

function decodeClaims(proof: string): Record<string, unknown> {
  const parts = proof.split('.');
  return JSON.parse(new TextDecoder().decode(base64UrlToBytes(parts[1]!)));
}

describe('VaultarisClient', () => {
  it('attaches a DPoP header and DPoP scheme when configured', async () => {
    const recorded: RecordedRequest[] = [];
    const key = await DpopKey.generate();

    const client = new VaultarisClient({
      baseUrl: 'https://auth.example.com',
      apiKey: 'eyJ.abc',
      dpopSigner: key,
      fetch: mockFetch(
        { valid: true, scopes: [], roles: [], permissions: [] },
        recorded,
      ),
    });

    const v = await client.validateToken('opaque');
    expect(v.valid).toBe(true);

    expect(recorded).toHaveLength(1);
    const req = recorded[0]!;
    expect(req.method).toBe('POST');
    expect(req.url).toBe('https://auth.example.com/api/v1/integration/token/validate');
    expect(req.headers.get('Authorization')).toBe('DPoP eyJ.abc');

    const proof = req.headers.get('DPoP');
    expect(proof).not.toBeNull();

    const claims = decodeClaims(proof!) as {
      htm: string;
      htu: string;
      ath: string;
      jti: string;
    };
    expect(claims.htm).toBe('POST');
    expect(claims.htu).toBe(
      'https://auth.example.com/api/v1/integration/token/validate',
    );
    expect(typeof claims.ath).toBe('string');
    expect(typeof claims.jti).toBe('string');
  });

  it('defaults to ApiKey scheme when no DPoP signer is configured', async () => {
    const recorded: RecordedRequest[] = [];
    const client = new VaultarisClient({
      baseUrl: 'https://auth.example.com',
      apiKey: 'vk_live_abc',
      fetch: mockFetch(
        { valid: true, scopes: [], roles: [], permissions: [] },
        recorded,
      ),
    });

    await client.validateToken('opaque');

    const req = recorded[0]!;
    expect(req.headers.get('Authorization')).toBe('ApiKey vk_live_abc');
    expect(req.headers.get('DPoP')).toBeNull();
  });

  it('Bearer scheme is opt-in for OAuth access tokens', async () => {
    const recorded: RecordedRequest[] = [];
    const client = new VaultarisClient({
      baseUrl: 'https://auth.example.com',
      apiKey: 'eyJ.abc',
      authScheme: 'Bearer',
      fetch: mockFetch(
        { valid: true, scopes: [], roles: [], permissions: [] },
        recorded,
      ),
    });

    await client.validateToken('opaque');

    const req = recorded[0]!;
    expect(req.headers.get('Authorization')).toBe('Bearer eyJ.abc');
  });

  it('signs every request, not just the first', async () => {
    const recorded: RecordedRequest[] = [];
    const key = await DpopKey.generate();

    const client = new VaultarisClient({
      baseUrl: 'https://auth.example.com',
      apiKey: 'eyJ.abc',
      dpopSigner: key,
      fetch: mockFetch(
        { valid: true, scopes: [], roles: [], permissions: [] },
        recorded,
      ),
    });

    await client.validateToken('one');
    await client.validateToken('two');
    await client.validateToken('three');

    expect(recorded).toHaveLength(3);
    const jtis = recorded.map((r) => {
      const claims = decodeClaims(r.headers.get('DPoP')!);
      return claims.jti as string;
    });
    // Every proof must carry a unique jti — otherwise the server's
    // replay cache would reject our own follow-up requests.
    expect(new Set(jtis).size).toBe(3);
  });

  it('unwraps the { success, data } envelope when present', async () => {
    const recorded: RecordedRequest[] = [];
    const client = new VaultarisClient({
      baseUrl: 'https://auth.example.com',
      apiKey: 'eyJ.abc',
      fetch: mockFetch(
        { success: true, data: { allowed: true, reason: 'role:admin' } },
        recorded,
      ),
    });

    const r = await client.checkPermission('t1', 'u1', 'orders', 'read');
    expect(r.allowed).toBe(true);
    expect(r.reason).toBe('role:admin');
  });
});
