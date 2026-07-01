"""
FastAPI + Vaultaris.

Demonstrates:
- `Depends(get_vaultaris)` — request-scoped client (re-uses a process-wide
  pool via lifespan).
- `current_user` — dependency that validates the incoming token and
  returns the resolved principal.
- `require_permission(resource, action)` — dependency factory that gates
  a route on `resource:action`.

Run:
    uvicorn fastapi_app:app --reload

Test:
    curl -H "Authorization: Bearer $USER_TOKEN" http://localhost:8000/orders
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import AsyncIterator

from fastapi import Depends, FastAPI, HTTPException, Request, status

from vaultaris_client import VaultarisClient, VaultarisError


# ── App + lifespan ────────────────────────────────────────────────────

_client: VaultarisClient | None = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    global _client
    _client = VaultarisClient(
        base_url=os.environ["VAULTARIS_URL"],
        api_key=os.environ["VAULTARIS_API_KEY"],
    )
    try:
        yield
    finally:
        await _client.aclose()
        _client = None


app = FastAPI(lifespan=lifespan)


def get_vaultaris() -> VaultarisClient:
    assert _client is not None, "lifespan must run before any handler"
    return _client


# ── Dependencies ──────────────────────────────────────────────────────


@dataclass
class CurrentUser:
    tenant_id: str
    user_id: str
    username: str | None
    roles: list[str]


async def current_user(
    request: Request,
    vaultaris: VaultarisClient = Depends(get_vaultaris),
) -> CurrentUser:
    auth = request.headers.get("authorization")
    if not auth:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing Authorization header")
    token = auth.removeprefix("Bearer ").removeprefix("ApiKey ").strip()
    try:
        v = await vaultaris.validate_token(token)
    except VaultarisError as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"upstream: {e}") from e
    if not v.valid or not v.tenant_id or not v.user_id:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, v.error or "invalid token"
        )
    return CurrentUser(
        tenant_id=v.tenant_id,
        user_id=v.user_id,
        username=v.username,
        roles=v.roles or [],
    )


def require_permission(resource: str, action: str):
    """Factory: build a dependency that enforces `resource:action`."""

    async def _check(
        user: CurrentUser = Depends(current_user),
        vaultaris: VaultarisClient = Depends(get_vaultaris),
    ) -> CurrentUser:
        result = await vaultaris.check_permission(
            user.tenant_id, user.user_id, resource, action
        )
        if not result.allowed:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"missing permission {resource}:{action}",
            )
        return user

    return _check


# ── Routes ────────────────────────────────────────────────────────────


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/me")
def me(user: CurrentUser = Depends(current_user)) -> dict:
    return {
        "tenant_id": user.tenant_id,
        "user_id": user.user_id,
        "username": user.username,
        "roles": user.roles,
    }


@app.get("/orders")
def list_orders(
    user: CurrentUser = Depends(require_permission("orders", "read")),
) -> dict:
    return {"orders": ["ORD-001", "ORD-002"], "served_to": user.username}


@app.delete("/orders/{order_id}")
def delete_order(
    order_id: str,
    user: CurrentUser = Depends(require_permission("orders", "delete")),
) -> dict:
    return {
        "deleted_id": order_id,
        "deleted_by": user.username,
        "user_id": user.user_id,
    }
