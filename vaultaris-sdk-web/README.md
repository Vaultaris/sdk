# @vaultaris/sdk-web

Browser SDK for [Vaultaris](https://github.com/RustLangES/vaultaris) with
**transparent DPoP** ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449))
sender-constrained access tokens.

The killer feature: the DPoP private key lives inside a WebCrypto
`CryptoKey` created with `extractable: false`. The browser will sign
proofs with it but will **never** let JavaScript read the bytes back
out — so even a successful XSS that achieves arbitrary code execution
inside the page cannot exfiltrate the credential. The attacker can use
the key only while sitting inside the victim's tab, which is a
qualitatively different threat profile from "I stole the token and
I'm hitting your API from my own machine for an hour".

## Install

```bash
npm install @vaultaris/sdk-web
# or
pnpm add @vaultaris/sdk-web
```

## Quick start

```ts
import {
  VaultarisClient,
  IndexedDbKeyStore,
  loadOrCreateDpopKey,
} from '@vaultaris/sdk-web';

// Generate-or-load the DPoP key once, persist it across reloads
// without ever materialising the private bytes in JS-land.
const key = await loadOrCreateDpopKey(new IndexedDbKeyStore());

const client = new VaultarisClient({
  baseUrl: 'https://auth.example.com',
  apiKey: accessToken,         // your DPoP-bound access token
  dpopSigner: key,             // ← only line of crypto your app touches
});

// Every fetch from here on signs and attaches a DPoP proof automatically.
const v = await client.validateToken(accessToken);
const ok = await client.checkPermission('tenant-1', 'user-1', 'orders', 'create');
```

## API

### `DpopKey`

ES256 keypair backed by WebCrypto. Construct with `DpopKey.generate()`
or — preferred — let `loadOrCreateDpopKey(store)` create it the first
time and reuse it forever.

| Member | Description |
|---|---|
| `alg` | Always `"ES256"`. |
| `publicJwk` | `{ kty, crv, x, y }` — what the SDK puts in the proof header. |
| `jkt` | RFC 7638 JWK thumbprint — matches `cnf.jkt` on the issued access token. |
| `sign(message)` | Returns a JOSE-format signature. Called automatically by `signProof`. |

### `DpopKeyStore`

Pluggable persistence. Two implementations ship:

- `IndexedDbKeyStore({ dbName?, storeName?, recordKey? })` — default for
  browsers. Round-trips the non-extractable `CryptoKey` losslessly.
- `MemoryKeyStore` — volatile; useful for ephemeral sessions and tests.

Implement the `DpopKeyStore` interface yourself for custom backends
(extension `chrome.storage`, service-worker `Cache`, etc.).

### `VaultarisClient`

The constructor takes a single config object:

| Field | Required | Description |
|---|---|---|
| `baseUrl` | yes | `https://auth.example.com` |
| `apiKey` | no | Access token or API key to send. |
| `authScheme` | no | `'ApiKey'` (default — matches Vaultaris API keys) or `'Bearer'` (OAuth access tokens). DPoP overrides both when configured. |
| `dpopSigner` | no | A `DpopSigner` (typically a `DpopKey`). When set, every request gets a DPoP proof and switches the Authorization scheme to `DPoP`. |
| `tenantId` | no | Default tenant for tenant-scoped calls. |
| `timeoutMs` | no | Per-request timeout. Default 30 000. |
| `deviceFingerprint` | no | Hex string, or `true` to auto-compute. Sent via `X-Device-Fingerprint`. |
| `fetch` | no | Override `globalThis.fetch`; useful in tests. |

#### Methods

| Group | Methods |
|---|---|
| Integration | `validateToken`, `checkPermission`, `batchCheckPermissions`, `getIntegrationUser`, `getUserInfo` |
| Tenants | `listTenants`, `getTenant` |
| Users | `listUsers`, `getUser`, `userRoles` |
| Roles | `listRoles` |
| Permissions | `listPermissions` |
| Groups | `listGroups` |
| API keys | `listApiKeys`, `createApiKey` (returns secret once), `revokeApiKey`, `deleteApiKey` |
| Audit | `listAuditLogs` |
| Statistics | `tenantOverview`, `authStats` |
| OAuth token | `tokenClientCredentials` |
| Escape hatch | `request(method, path, body?, query?)`, `formRequest(method, path, fields)` |

## Default auth scheme

`authScheme` defaults to `'ApiKey'` — matches the server's API-key extractor (`Authorization: ApiKey <token>` or `X-Api-Key`). Set to `'Bearer'` only when carrying OAuth-issued access tokens.

## Why not `Bearer`?

| Threat | Bearer | DPoP |
|---|---|---|
| Token stolen via XSS | Attacker uses it from their machine for its full lifetime. | Attacker can only use the key while inside the victim's tab; cannot read it out. |
| Token leaks in a proxy log | Anyone with the log replays it. | Useless without the matching private key. |
| Token leaks in a browser history / referrer | Same. | Same. |

DPoP is opt-in per OAuth client on the server side
(`dpop_bound_access_tokens=true`), so adopting it is a per-app rollout
decision — apps that don't enable it keep working with plain Bearer.

## Building

```bash
pnpm install
pnpm build       # tsup → dist/{index.js,index.cjs,index.d.ts}
pnpm test        # vitest, including IndexedDB + WebCrypto round-trip
pnpm lint        # tsc --noEmit
```

## License

MIT OR Apache-2.0.
