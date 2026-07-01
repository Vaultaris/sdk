# Next.js (App Router) + Vaultaris

End-to-end Next.js example showing:

- `lib/vaultaris.ts` — `server-only` singleton + `authenticate` / `authorize` helpers wrapping `@vaultaris/sdk`.
- `middleware.ts` — Edge-runtime fast-path that rejects requests with no `Authorization` header before they hit Node handlers.
- App Router Route Handlers:

| Route | Requirement |
|---|---|
| `GET /api/health` | public |
| `GET /api/me` | any valid token |
| `GET /api/orders` | token + `orders:read` |
| `DELETE /api/orders?id=...` | token + `orders:delete` |

## Run

```bash
pnpm install
VAULTARIS_URL=http://localhost:8080 \
VAULTARIS_API_KEY=vk_live_... \
pnpm dev
```

Test:

```bash
curl -H "Authorization: Bearer $USER_TOKEN" http://localhost:3000/api/orders
```

## Edge runtime caveat

`@vaultaris/sdk` ships native (napi-rs) bindings, so it **cannot** run in the Edge runtime. The Route Handlers in this example use the default Node runtime; the Edge `middleware.ts` only short-circuits on missing headers and does not call the SDK.
