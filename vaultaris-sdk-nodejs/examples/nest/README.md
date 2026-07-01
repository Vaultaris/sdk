# NestJS + Vaultaris

End-to-end Nest example that:

- Wraps `@vaultaris/sdk` in a `VaultarisModule` (`forRoot`-style config).
- Implements `VaultarisAuthGuard` — validates the incoming token, attaches the principal to `req.user`, and enforces per-route `@RequirePermission('resource', 'action')`.
- Exposes three real routes on `OrdersController`:

| Route | Requirement |
|---|---|
| `GET /orders/me` | any valid token |
| `GET /orders` | token + `orders:read` |
| `DELETE /orders/:id` | token + `orders:delete` |

## Run

```bash
pnpm install
VAULTARIS_URL=http://localhost:8080 \
VAULTARIS_API_KEY=vk_live_... \
pnpm start
```

Test:

```bash
curl -H "Authorization: Bearer $USER_TOKEN" http://localhost:3000/orders
```
