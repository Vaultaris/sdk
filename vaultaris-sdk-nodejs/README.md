# Vaultaris SDK for Node.js

Native Node.js bindings for Vaultaris IAM, built with napi-rs. Wraps the canonical Rust SDK so endpoint paths, auth scheme (`ApiKey` by default), DPoP, and `{ success, data }` envelope handling stay in lock-step.

## Installation

```bash
npm install @vaultaris/sdk
# yarn add @vaultaris/sdk
# pnpm add @vaultaris/sdk
```

## Quick start

```javascript
const { VaultarisClient } = require('@vaultaris/sdk');

const client = new VaultarisClient({
  baseUrl: 'https://auth.example.com',
  apiKey: 'vk_live_...',
});

const v = await client.validateToken('user-access-token');
if (v.valid) {
  console.log(`user: ${v.username}`);
}
```

## DPoP

```javascript
const { VaultarisClient, DpopKey } = require('@vaultaris/sdk');

const key = DpopKey.generate();
// Persist `key.toPkcs8Pem()` for restart-stable proofs.
const client = new VaultarisClient(
  { baseUrl: 'https://auth.example.com', apiKey: 'eyJ...' },
  key,
);
```

## Endpoint coverage

- **Tenants** — list/create/get/delete
- **Users** — list/create/get/delete, role + group assignment, sessions
- **Roles, Permissions, Groups** — list/create/get/delete
- **OAuth clients** — list/create/get/delete
- **Sessions** — list/revoke
- **Audit logs** — list
- **Statistics** — `getTenantOverview`, `getAuthStats`, `getSessionStats`, `getSecurityStats`
- **API keys** — `listApiKeys`, `createApiKey` (returns plain-text secret once), `revokeApiKey`, `deleteApiKey`
- **OAuth tokens** — `tokenClientCredentials` (machine-to-machine grant)
- **Setup + workflows** — `setupIfNeeded`, `provisionUser`, `setupRbac`, `bootstrapTenant`, `requirePermission`, `checkTokenPermission`, `collectUsers`, `collectRoles`

## Auth schemes

Defaults to `ApiKey` — matches the server's API-key extractor. Override via `authScheme: 'Bearer'` in the constructor when carrying OAuth-issued access tokens (planned; for now, pass tokens through the `tokenClientCredentials` flow).

## License

MIT OR Apache-2.0
