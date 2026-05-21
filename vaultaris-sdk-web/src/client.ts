/**
 * Browser-side Vaultaris client.
 *
 * Mirrors the surface of the Rust / Node / Python SDKs for the calls
 * applications typically make from a browser (token validation,
 * permission checks, user info). When constructed with a [`DpopSigner`],
 * every outgoing `fetch` automatically carries a freshly-signed proof
 * and the Authorization scheme switches from `Bearer` to `DPoP`.
 */

import type { DpopSigner } from './dpop.js';
import { signProof } from './dpop.js';
import { computeFingerprint } from './fingerprint.js';

export interface VaultarisConfig {
  /** Base URL of the Vaultaris server, e.g. `https://auth.example.com`. */
  baseUrl: string;
  /** Access token presented to the server. */
  apiKey?: string;
  /** Default tenant ID used by tenant-scoped endpoints. */
  tenantId?: string;
  /** Per-request timeout in milliseconds (default: 30 000). */
  timeoutMs?: number;
  /**
   * DPoP signer. When set, the client signs and attaches a proof on
   * every request and uses the `DPoP` Authorization scheme. The default
   * implementation is [`DpopKey`]; for advanced backends, pass any
   * object implementing [`DpopSigner`].
   */
  dpopSigner?: DpopSigner;
  /**
   * Device fingerprint. When set, it is sent on every request via the
   * `X-Device-Fingerprint` header. Pass a pre-computed hex string, or
   * `true` to auto-compute via {@link computeFingerprint} on the first
   * request and cache the result.
   */
  deviceFingerprint?: string | boolean;
  /** Override the global `fetch`; useful in tests. */
  fetch?: typeof fetch;
}

export interface TokenValidation {
  valid: boolean;
  user_id?: string;
  tenant_id?: string;
  username?: string;
  email?: string;
  roles: string[];
  permissions: string[];
  scopes: string[];
  expires_at?: number;
  error?: string;
}

export interface PermissionCheck {
  allowed: boolean;
  reason?: string;
  matched_policy?: string;
}

export interface UserInfo {
  id: string;
  tenant_id: string;
  username: string;
  email: string;
  email_verified: boolean;
  first_name?: string;
  last_name?: string;
  name?: string;
  picture?: string;
  roles: string[];
  groups: string[];
}

export class VaultarisError extends Error {
  readonly status: number | null;
  readonly body: string;

  constructor(message: string, status: number | null, body: string) {
    super(message);
    this.name = 'VaultarisError';
    this.status = status;
    this.body = body;
  }
}

export class VaultarisClient {
  private readonly baseUrl: string;
  private readonly apiKey: string | undefined;
  private readonly tenantId: string | undefined;
  private readonly timeoutMs: number;
  private readonly dpopSigner: DpopSigner | undefined;
  private readonly fetchImpl: typeof fetch;
  private readonly autoFingerprint: boolean;
  private cachedFingerprint: string | undefined;

  constructor(config: VaultarisConfig) {
    if (!config.baseUrl) {
      throw new Error('VaultarisClient: baseUrl is required');
    }
    this.baseUrl = config.baseUrl.replace(/\/+$/, '');
    this.apiKey = config.apiKey;
    this.tenantId = config.tenantId;
    this.timeoutMs = config.timeoutMs ?? 30_000;
    this.dpopSigner = config.dpopSigner;
    this.fetchImpl = config.fetch ?? fetch.bind(globalThis);

    if (typeof config.deviceFingerprint === 'string') {
      this.cachedFingerprint = config.deviceFingerprint;
      this.autoFingerprint = false;
    } else {
      this.autoFingerprint = config.deviceFingerprint === true;
    }
  }

  /** JWK thumbprint of the configured DPoP key, if any — useful for debugging. */
  get jkt(): string | undefined {
    return this.dpopSigner?.jkt;
  }

  // ── Public API ────────────────────────────────────────────────────────

  async validateToken(token: string): Promise<TokenValidation> {
    return this.unwrap<TokenValidation>(
      await this.request('POST', '/api/v1/integration/token/validate', { token }),
    );
  }

  async checkPermission(
    tenantId: string,
    userId: string,
    resource: string,
    action: string,
  ): Promise<PermissionCheck> {
    return this.unwrap<PermissionCheck>(
      await this.request(
        'POST',
        `/api/v1/tenants/${encodeURIComponent(tenantId)}/integration/check-permission`,
        { user_id: userId, resource, action },
      ),
    );
  }

  async getUserInfo(): Promise<UserInfo> {
    return this.unwrap<UserInfo>(await this.request('GET', '/oauth/userinfo'));
  }

  // ── Internals ─────────────────────────────────────────────────────────

  /**
   * Build a request with the right Authorization scheme + DPoP proof and
   * dispatch it through the configured `fetch`. Public so applications
   * with custom endpoints can route their own calls through the same
   * machinery instead of building a parallel HTTP stack.
   */
  async request(
    method: string,
    path: string,
    body?: unknown,
    query?: Record<string, string | number | undefined>,
  ): Promise<Response> {
    const url = this.buildUrl(path, query);
    const headers = new Headers({ 'Content-Type': 'application/json' });

    if (this.apiKey) {
      const scheme = this.dpopSigner ? 'DPoP' : 'Bearer';
      headers.set('Authorization', `${scheme} ${this.apiKey}`);
    }

    if (this.dpopSigner) {
      const proof = await signProof(this.dpopSigner, method, url, this.apiKey);
      headers.set('DPoP', proof);
    }

    // Resolve and attach device fingerprint
    if (this.autoFingerprint && !this.cachedFingerprint) {
      try {
        this.cachedFingerprint = await computeFingerprint();
      } catch {
        // Fingerprint computation is best-effort; never block requests.
      }
    }
    if (this.cachedFingerprint) {
      headers.set('X-Device-Fingerprint', this.cachedFingerprint);
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const init: RequestInit = {
        method,
        headers,
        signal: controller.signal,
      };
      if (body !== undefined) {
        init.body = JSON.stringify(body);
      }
      return await this.fetchImpl(url, init);
    } finally {
      clearTimeout(timer);
    }
  }

  private buildUrl(path: string, query?: Record<string, string | number | undefined>): string {
    const normalized = path.startsWith('/') ? path : `/${path}`;
    let url = `${this.baseUrl}${normalized}`;
    if (query) {
      const params = new URLSearchParams();
      for (const [k, v] of Object.entries(query)) {
        if (v !== undefined) params.set(k, String(v));
      }
      const qs = params.toString();
      if (qs) url += `?${qs}`;
    }
    return url;
  }

  private async unwrap<T>(response: Response): Promise<T> {
    if (!response.ok) {
      const text = await safeText(response);
      throw new VaultarisError(
        `Vaultaris request failed: HTTP ${response.status}`,
        response.status,
        text,
      );
    }
    const text = await response.text();
    if (!text) return undefined as T;
    const parsed = JSON.parse(text) as unknown;
    // Unwrap `{ success, data }` envelope when present.
    if (
      parsed &&
      typeof parsed === 'object' &&
      'data' in (parsed as Record<string, unknown>) &&
      'success' in (parsed as Record<string, unknown>)
    ) {
      return (parsed as { data: T }).data;
    }
    return parsed as T;
  }
}

async function safeText(response: Response): Promise<string> {
  try {
    return await response.text();
  } catch {
    return '';
  }
}
