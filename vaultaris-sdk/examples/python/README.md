# Python + Vaultaris

Three real-world framework examples backed by a shared async `httpx`
client (`vaultaris_client.py`). The PyO3 bindings on the main SDK are
being refreshed against the new API surface; until then, these examples
use the REST API directly with the same auth conventions.

## Layout

| File | Purpose |
|---|---|
| `vaultaris_client.py` | Shared async client — token validate, permission check, batch check, require. Handles `ApiKey` default scheme, `{ success, data }` envelope. |
| `fastapi_app.py` | FastAPI with `Depends(get_vaultaris)`, `current_user`, `require_permission(r, a)` dependency factory. |
| `flask_app.py` | Flask with `@authenticated` + `@require_permission("r", "a")` decorators. |
| `django_middleware.py` | Django `VaultarisAuthMiddleware` + `@require_permission("r", "a")` view decorator. |

## Routes (identical across all three examples)

| Route | Requirement |
|---|---|
| `GET /health` | public |
| `GET /me` | any valid token |
| `GET /orders` | token + `orders:read` |
| `DELETE /orders/<id>` | token + `orders:delete` |

## Run

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

export VAULTARIS_URL=http://localhost:8080
export VAULTARIS_API_KEY=vk_live_...

# Pick one:
uvicorn fastapi_app:app --reload             # → :8000
flask --app flask_app run                    # → :5000
python manage.py runserver                   # (wire django_middleware in your project)
```

Test:

```bash
curl -H "Authorization: Bearer $USER_TOKEN" http://localhost:8000/orders
```

## Auth scheme note

The client sends `Authorization: ApiKey <token>` by default (matches the
server's ApiKey extractor). Pass `auth_scheme="Bearer"` to
`VaultarisClient(...)` when carrying an OAuth access token instead.
