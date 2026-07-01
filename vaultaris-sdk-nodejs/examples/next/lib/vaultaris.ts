/**
 * Server-side Vaultaris singleton + helpers for Next.js App Router.
 *
 * The client lives only on the server — Node-bindings can't run in
 * Edge/Browser. Use `getVaultaris()` from Route Handlers, Server
 * Components, or Server Actions; never import this file into a
 * `"use client"` component.
 */

import 'server-only';
import { VaultarisClient } from '@vaultaris/sdk';

let _client: VaultarisClient | null = null;

export function getVaultaris(): VaultarisClient {
  if (_client) return _client;
  const baseUrl = process.env.VAULTARIS_URL;
  const apiKey = process.env.VAULTARIS_API_KEY;
  if (!baseUrl || !apiKey) {
    throw new Error('VAULTARIS_URL / VAULTARIS_API_KEY env vars are required');
  }
  _client = new VaultarisClient({ baseUrl, apiKey });
  return _client;
}

export interface AuthedPrincipal {
  tenantId: string;
  userId: string;
  username?: string;
  roles: string[];
}

/**
 * Validate the `Authorization` header on a Route Handler request.
 *
 * Returns the resolved principal, or a `Response` to short-circuit with
 * 401/403. Use like:
 *
 *   const auth = await authenticate(req);
 *   if (auth instanceof Response) return auth;
 *   // use auth.tenantId / auth.userId
 */
export async function authenticate(
  req: Request,
): Promise<AuthedPrincipal | Response> {
  const auth = req.headers.get('authorization') ?? '';
  const token = auth.replace(/^(Bearer|ApiKey)\s+/, '');
  if (!token) {
    return Response.json({ error: 'Missing Authorization header' }, { status: 401 });
  }
  const v = await getVaultaris().validateToken(token);
  if (!v.valid || !v.tenant_id || !v.user_id) {
    return Response.json(
      { error: v.error ?? 'Invalid token' },
      { status: 401 },
    );
  }
  return {
    tenantId: v.tenant_id,
    userId: v.user_id,
    username: v.username,
    roles: v.roles,
  };
}

/**
 * Combined token + permission check. Returns the principal or a
 * pre-built 401/403 `Response`.
 */
export async function authorize(
  req: Request,
  resource: string,
  action: string,
): Promise<AuthedPrincipal | Response> {
  const auth = await authenticate(req);
  if (auth instanceof Response) return auth;

  const allowed = await getVaultaris().checkPermission(
    auth.tenantId,
    auth.userId,
    resource,
    action,
  );
  if (!allowed.allowed) {
    return Response.json(
      { error: `Missing permission ${resource}:${action}` },
      { status: 403 },
    );
  }
  return auth;
}
