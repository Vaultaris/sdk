"""
Flask + Vaultaris.

Flask is sync — we drive the async Vaultaris client with `asyncio.run`
inside the request handler. For high-throughput services, prefer the
FastAPI example.

Run:
    flask --app flask_app run

Test:
    curl -H "Authorization: Bearer $USER_TOKEN" http://localhost:5000/orders
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from functools import wraps
from typing import Callable

from flask import Flask, g, jsonify, request

from vaultaris_client import VaultarisClient, VaultarisError


app = Flask(__name__)


# ── Vaultaris singleton ──────────────────────────────────────────────


_loop = asyncio.new_event_loop()


def _vaultaris() -> VaultarisClient:
    if "vaultaris" not in g:
        g.vaultaris = VaultarisClient(
            base_url=os.environ["VAULTARIS_URL"],
            api_key=os.environ["VAULTARIS_API_KEY"],
        )
    return g.vaultaris


@app.teardown_appcontext
def _close_vaultaris(_exc: BaseException | None) -> None:
    client = g.pop("vaultaris", None)
    if client is not None:
        _loop.run_until_complete(client.aclose())


# ── Decorators ───────────────────────────────────────────────────────


@dataclass
class CurrentUser:
    tenant_id: str
    user_id: str
    username: str | None
    roles: list[str]


def authenticated(f: Callable) -> Callable:
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        token = auth.removeprefix("Bearer ").removeprefix("ApiKey ").strip()
        if not token:
            return jsonify(error="Missing Authorization header"), 401
        try:
            v = _loop.run_until_complete(_vaultaris().validate_token(token))
        except VaultarisError as e:
            return jsonify(error=f"upstream: {e}"), 502
        if not v.valid or not v.tenant_id or not v.user_id:
            return jsonify(error=v.error or "invalid token"), 401
        g.user = CurrentUser(
            tenant_id=v.tenant_id,
            user_id=v.user_id,
            username=v.username,
            roles=v.roles or [],
        )
        return f(*args, **kwargs)

    return wrapper


def require_permission(resource: str, action: str) -> Callable:
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        @authenticated
        def wrapper(*args, **kwargs):
            user: CurrentUser = g.user
            try:
                check = _loop.run_until_complete(
                    _vaultaris().check_permission(
                        user.tenant_id, user.user_id, resource, action
                    )
                )
            except VaultarisError as e:
                return jsonify(error=f"upstream: {e}"), 502
            if not check.allowed:
                return (
                    jsonify(error=f"missing permission {resource}:{action}"),
                    403,
                )
            return f(*args, **kwargs)

        return wrapper

    return decorator


# ── Routes ───────────────────────────────────────────────────────────


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.get("/me")
@authenticated
def me():
    user: CurrentUser = g.user
    return jsonify(
        tenant_id=user.tenant_id,
        user_id=user.user_id,
        username=user.username,
        roles=user.roles,
    )


@app.get("/orders")
@require_permission("orders", "read")
def list_orders():
    user: CurrentUser = g.user
    return jsonify(orders=["ORD-001", "ORD-002"], served_to=user.username)


@app.delete("/orders/<order_id>")
@require_permission("orders", "delete")
def delete_order(order_id: str):
    user: CurrentUser = g.user
    return jsonify(deleted_id=order_id, deleted_by=user.username, user_id=user.user_id)
