/**
 * Browser-side Vaultaris client.
 *
 * Mirrors the surface of the Rust / Node SDKs for calls applications
 * typically make from a browser (token validation, permission checks,
 * user info, plus enough management endpoints to power a dashboard).
 *
 * When constructed with a {@link DpopSigner}, every outgoing `fetch`
 * automatically carries a freshly-signed proof and the Authorization
 * scheme switches from `ApiKey` (default) or `Bearer` to `DPoP`.
 */

import type { DpopSigner } from './dpop.js';
import { signProof } from './dpop.js';
import { computeFingerprint } from './fingerprint.js';

export type AuthScheme = 'ApiKey' | 'Bearer';

export interface VaultarisConfig {
  /** Base URL of the Vaultaris server, e.g. `https://auth.example.com`. */
  baseUrl: string;
  /** Token or API key presented to the server. */
  apiKey?: string;
  /** Default tenant ID used by tenant-scoped endpoints. */
  tenantId?: string;
  /** Per-request timeout in milliseconds (default: 30 000). */
  timeoutMs?: number;
  /**
   * Wire `Authorization` scheme. Defaults to `ApiKey` — matches the
   * server's API-key extractor. Pass `'Bearer'` for OAuth access tokens.
   */
  authScheme?: AuthScheme;
  /**
   * DPoP signer. When set, the client signs and attaches a proof on
   * every request and uses the `DPoP` Authorization scheme.
   */
  dpopSigner?: DpopSigner;
  /**
   * Device fingerprint sent via `X-Device-Fingerprint`. Pass a hex
   * string, or `true` to auto-compute on first request.
   */
  deviceFingerprint?: string | boolean;
  /** Override the global `fetch`; useful in tests. */
  fetch?: typeof fetch;
}

// ── Response shapes ────────────────────────────────────────────────────

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

export interface PermissionToCheck {
  resource: string;
  action: string;
}

export interface BatchPermissionResult extends PermissionToCheck {
  allowed: boolean;
}

export interface BatchPermissionCheck {
  results: BatchPermissionResult[];
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
  roles: Array<{ id: string; name: string }>;
  groups: Array<{ id: string; name: string; path: string }>;
  permissions: string[];
}

export interface Pagination {
  page?: number;
  per_page?: number;
}

export interface Page<T> {
  data: T[];
  total: number;
  page: number;
  per_page: number;
}

export interface User {
  id: string;
  tenant_id: string;
  username: string;
  email: string;
  email_verified: boolean;
  status: string;
  first_name?: string;
  last_name?: string;
  display_name?: string;
  created_at: string;
  updated_at: string;
}

export interface Role {
  id: string;
  tenant_id: string;
  name: string;
  display_name?: string;
  description?: string;
  is_composite: boolean;
  created_at: string;
}

export interface Permission {
  id: string;
  tenant_id: string;
  name: string;
  resource: string;
  action: string;
  created_at: string;
}

export interface Group {
  id: string;
  tenant_id: string;
  name: string;
  display_name?: string;
  description?: string;
  path: string;
  created_at: string;
}

export interface Tenant {
  id: string;
  name: string;
  slug: string;
  display_name?: string;
  description?: string;
  mfa_enabled: boolean;
  mfa_required: boolean;
  created_at: string;
  updated_at: string;
}

export interface ApiKey {
  id: string;
  tenant_id: string;
  name: string;
  prefix: string;
  description?: string;
  scopes?: string[];
  ip_restrictions?: string[];
  is_enabled: boolean;
  revoked_at?: string;
  expires_at?: string;
  last_used_at?: string;
  created_at: string;
}

export interface ApiKeyWithSecret {
  api_key: ApiKey;
  secret: string;
}

export interface CreateApiKeyInput {
  name: string;
  description?: string;
  scopes?: string[];
  ip_restrictions?: string[];
}

export interface AuditLog {
  id: string;
  tenant_id: string;
  actor_id?: string;
  actor_type: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  description?: string;
  created_at: string;
}

export interface StatsQuery {
  from?: string;
  to?: string;
  interval?: 'hour' | 'day' | 'week' | 'month';
}

export interface TenantOverview {
  tenantId: string;
  totalUsers: number;
  activeUsers: number;
  totalRoles: number;
  totalGroups: number;
  totalClients: number;
  activeSessions: number;
}

export interface AuthenticationStats {
  totalAttempts: number;
  successful: number;
  failed: number;
  successRate: number;
  byMethod?: Array<{ method: string; count: number }>;
  timeSeries?: Array<{ timestamp: string; value: number }>;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  scope: string;
}

// ── Errors ─────────────────────────────────────────────────────────────

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

// ── Client ─────────────────────────────────────────────────────────────

export class VaultarisClient {
  private readonly baseUrl: string;
  private readonly apiKey: string | undefined;
  private readonly tenantId: string | undefined;
  private readonly timeoutMs: number;
  private readonly authScheme: AuthScheme;
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
    this.authScheme = config.authScheme ?? 'ApiKey';
    this.dpopSigner = config.dpopSigner;
    this.fetchImpl = config.fetch ?? fetch.bind(globalThis);

    if (typeof config.deviceFingerprint === 'string') {
      this.cachedFingerprint = config.deviceFingerprint;
      this.autoFingerprint = false;
    } else {
      this.autoFingerprint = config.deviceFingerprint === true;
    }
  }

  /** JWK thumbprint of the configured DPoP key, if any. */
  get jkt(): string | undefined {
    return this.dpopSigner?.jkt;
  }

  // ── Integration ─────────────────────────────────────────────────────

  async validateToken(
    token: string,
    requiredScopes?: string[],
    requiredPermissions?: string[],
  ): Promise<TokenValidation> {
    return this.unwrap<TokenValidation>(
      await this.request('POST', '/api/v1/integration/token/validate', {
        token,
        required_scopes: requiredScopes,
        required_permissions: requiredPermissions,
      }),
    );
  }

  async checkPermission(
    tenantId: string,
    userId: string,
    resource: string,
    action: string,
    context?: Record<string, unknown>,
  ): Promise<PermissionCheck> {
    return this.unwrap<PermissionCheck>(
      await this.request(
        'POST',
        `/api/v1/tenants/${encodeURIComponent(tenantId)}/integration/check-permission`,
        { user_id: userId, resource, action, context },
      ),
    );
  }

  async batchCheckPermissions(
    tenantId: string,
    userId: string,
    checks: PermissionToCheck[],
  ): Promise<BatchPermissionCheck> {
    return this.unwrap<BatchPermissionCheck>(
      await this.request(
        'POST',
        `/api/v1/tenants/${encodeURIComponent(tenantId)}/integration/batch-check-permissions`,
        { user_id: userId, checks },
      ),
    );
  }

  async getIntegrationUser(tenantId: string, userId: string): Promise<UserInfo> {
    return this.unwrap<UserInfo>(
      await this.request(
        'GET',
        `/api/v1/tenants/${encodeURIComponent(tenantId)}/integration/users/${encodeURIComponent(userId)}`,
      ),
    );
  }

  /** OAuth `/oauth/userinfo`. */
  async getUserInfo(): Promise<UserInfo> {
    return this.unwrap<UserInfo>(await this.request('GET', '/oauth/userinfo'));
  }

  // ── OAuth token ─────────────────────────────────────────────────────

  /** Client-credentials grant via `POST /oauth/token`. */
  async tokenClientCredentials(
    clientId: string,
    clientSecret: string,
    scope?: string,
  ): Promise<TokenResponse> {
    return this.unwrap<TokenResponse>(
      await this.formRequest('POST', '/oauth/token', {
        grant_type: 'client_credentials',
        client_id: clientId,
        client_secret: clientSecret,
        ...(scope ? { scope } : {}),
      }),
    );
  }

  // ── Users ───────────────────────────────────────────────────────────

  async listUsers(tenantId: string, pagination?: Pagination): Promise<Page<User>> {
    return this.unwrap<Page<User>>(
      await this.request(
        'GET',
        `/api/v1/tenants/${encodeURIComponent(tenantId)}/users`,
        undefined,
        pageQuery(pagination),
      ),
    );
  }

  async getUser(tenantId: string, userId: string): Promise<User> {
    return this.unwrap<User>(
      await this.request(
        'GET',
        `/api/v1/tenants/${encodeURIComponent(tenantId)}/users/${encodeURIComponent(userId)}`,
      ),
    );
  }

  // ── Roles ───────────────────────────────────────────────────────────

  async listRoles(tenantId: string, pagination?: Pagination): Promise<Page<Role>> {
    return this.unwrap<Page<Role>>(
      await this.request(
        'GET',
        `/api/v1/tenants/${encodeURIComponent(tenantId)}/roles`,
        undefined,
        pageQuery(pagination),
      ),
    );
  }

  async userRoles(tenantId: string, userId: string): Promise<Role[]> {
    return this.unwrap<Role[]>(
      await this.request(
        'GET',
        `/api/v1/tenants/${encodeURIComponent(tenantId)}/users/${encodeURIComponent(userId)}/roles`,
      ),
    );
  }

  // ── Permissions ─────────────────────────────────────────────────────

  async listPermissions(tenantId: string, pagination?: Pagination): Promise<Page<Permission>> {
    return this.unwrap<Page<Permission>>(
      await this.request(
        'GET',
        `/api/v1/tenants/${encodeURIComponent(tenantId)}/permissions`,
        undefined,
        pageQuery(pagination),
      ),
    );
  }

  // ── Groups ──────────────────────────────────────────────────────────

  async listGroups(tenantId: string, pagination?: Pagination): Promise<Page<Group>> {
    return this.unwrap<Page<Group>>(
      await this.request(
        'GET',
        `/api/v1/tenants/${encodeURIComponent(tenantId)}/groups`,
        undefined,
        pageQuery(pagination),
      ),
    );
  }

  // ── Tenants ─────────────────────────────────────────────────────────

  async listTenants(pagination?: Pagination): Promise<Page<Tenant>> {
    return this.unwrap<Page<Tenant>>(
      await this.request('GET', '/api/v1/tenants', undefined, pageQuery(pagination)),
    );
  }

  async getTenant(tenantId: string): Promise<Tenant> {
    return this.unwrap<Tenant>(
      await this.request('GET', `/api/v1/tenants/${encodeURIComponent(tenantId)}`),
    );
  }

  // ── API keys ────────────────────────────────────────────────────────

  async listApiKeys(tenantId: string, pagination?: Pagination): Promise<Page<ApiKey>> {
    return this.unwrap<Page<ApiKey>>(
      await this.request(
        'GET',
        `/api/v1/tenants/${encodeURIComponent(tenantId)}/api-keys`,
        undefined,
        pageQuery(pagination),
      ),
    );
  }

  /** Plain-text `secret` is returned ONLY here — copy it then. */
  async createApiKey(tenantId: string, input: CreateApiKeyInput): Promise<ApiKeyWithSecret> {
    return this.unwrap<ApiKeyWithSecret>(
      await this.request(
        'POST',
        `/api/v1/tenants/${encodeURIComponent(tenantId)}/api-keys`,
        input,
      ),
    );
  }

  async revokeApiKey(tenantId: string, keyId: string): Promise<void> {
    await this.request(
      'POST',
      `/api/v1/tenants/${encodeURIComponent(tenantId)}/api-keys/${encodeURIComponent(keyId)}/revoke`,
      {},
    );
  }

  async deleteApiKey(tenantId: string, keyId: string): Promise<void> {
    await this.request(
      'DELETE',
      `/api/v1/tenants/${encodeURIComponent(tenantId)}/api-keys/${encodeURIComponent(keyId)}`,
    );
  }

  // ── Audit ───────────────────────────────────────────────────────────

  async listAuditLogs(tenantId: string, pagination?: Pagination): Promise<Page<AuditLog>> {
    return this.unwrap<Page<AuditLog>>(
      await this.request(
        'GET',
        `/api/v1/tenants/${encodeURIComponent(tenantId)}/audit-logs`,
        undefined,
        pageQuery(pagination),
      ),
    );
  }

  // ── Statistics ──────────────────────────────────────────────────────

  async tenantOverview(tenantId: string): Promise<TenantOverview> {
    return this.unwrap<TenantOverview>(
      await this.request(
        'GET',
        `/api/v1/tenants/${encodeURIComponent(tenantId)}/statistics/overview`,
      ),
    );
  }

  async authStats(tenantId: string, query?: StatsQuery): Promise<AuthenticationStats> {
    return this.unwrap<AuthenticationStats>(
      await this.request(
        'GET',
        `/api/v1/tenants/${encodeURIComponent(tenantId)}/statistics/authentication`,
        undefined,
        statsQueryToParams(query),
      ),
    );
  }

  // ── Internals ───────────────────────────────────────────────────────

  /**
   * Build a request with the right Authorization scheme + DPoP proof and
   * dispatch it through the configured `fetch`. Public so applications
   * with custom endpoints can route their own calls through the same
   * machinery.
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
      const scheme = this.dpopSigner ? 'DPoP' : this.authScheme;
      headers.set('Authorization', `${scheme} ${this.apiKey}`);
    }

    if (this.dpopSigner) {
      const proof = await signProof(this.dpopSigner, method, url, this.apiKey);
      headers.set('DPoP', proof);
    }

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
      const init: RequestInit = { method, headers, signal: controller.signal };
      if (body !== undefined) {
        init.body = JSON.stringify(body);
      }
      return await this.fetchImpl(url, init);
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Form-encoded variant for OAuth `/oauth/token` (RFC 6749 §4.4).
   */
  async formRequest(
    method: string,
    path: string,
    fields: Record<string, string>,
  ): Promise<Response> {
    const url = this.buildUrl(path);
    const headers = new Headers({
      'Content-Type': 'application/x-www-form-urlencoded',
    });
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(fields)) {
      params.set(k, v);
    }
    if (this.apiKey) {
      const scheme = this.dpopSigner ? 'DPoP' : this.authScheme;
      headers.set('Authorization', `${scheme} ${this.apiKey}`);
    }
    if (this.dpopSigner) {
      const proof = await signProof(this.dpopSigner, method, url, this.apiKey);
      headers.set('DPoP', proof);
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      return await this.fetchImpl(url, {
        method,
        headers,
        body: params.toString(),
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }
  }

  private buildUrl(
    path: string,
    query?: Record<string, string | number | undefined>,
  ): string {
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

function pageQuery(p?: Pagination): Record<string, number> {
  return {
    page: p?.page ?? 1,
    per_page: p?.per_page ?? 20,
  };
}

function statsQueryToParams(q?: StatsQuery): Record<string, string | undefined> {
  return {
    from: q?.from,
    to: q?.to,
    interval: q?.interval,
  };
}

async function safeText(response: Response): Promise<string> {
  try {
    return await response.text();
  } catch {
    return '';
  }
}
