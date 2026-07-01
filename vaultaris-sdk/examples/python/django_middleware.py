"""
Django + Vaultaris.

Provides:
- `VaultarisAuthMiddleware` — validates the incoming token on every
  request and attaches the resolved principal to `request.vaultaris_user`.
- `@require_permission("resource", "action")` — view decorator gating a
  route on the Vaultaris check.

Wire in your `settings.py`:

    MIDDLEWARE = [
        ...,
        "django_middleware.VaultarisAuthMiddleware",
    ]

Then decorate views:

    from django_middleware import require_permission

    @require_permission("orders", "read")
    def list_orders(request):
        return JsonResponse({"orders": [...]})

Run:
    python manage.py runserver
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from functools import wraps
from typing import Callable

from django.http import HttpRequest, HttpResponse, JsonResponse

from vaultaris_client import VaultarisClient, VaultarisError


# ── Singleton client ─────────────────────────────────────────────────


_loop = asyncio.new_event_loop()
_client: VaultarisClient | None = None


def _vaultaris() -> VaultarisClient:
    global _client
    if _client is None:
        _client = VaultarisClient(
            base_url=os.environ["VAULTARIS_URL"],
            api_key=os.environ["VAULTARIS_API_KEY"],
        )
    return _client


@dataclass
class VaultarisUser:
    tenant_id: str
    user_id: str
    username: str | None
    roles: list[str]


# ── Middleware ───────────────────────────────────────────────────────


PUBLIC_PATHS = frozenset({"/health", "/health/"})


class VaultarisAuthMiddleware:
    """
    Validates every incoming request's Authorization header against
    Vaultaris. Public paths (see PUBLIC_PATHS) are skipped so the health
    check and static assets stay reachable without a token.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        if request.path in PUBLIC_PATHS:
            return self.get_response(request)

        auth = request.META.get("HTTP_AUTHORIZATION", "")
        token = auth.removeprefix("Bearer ").removeprefix("ApiKey ").strip()
        if not token:
            return JsonResponse({"error": "Missing Authorization header"}, status=401)

        try:
            v = _loop.run_until_complete(_vaultaris().validate_token(token))
        except VaultarisError as e:
            return JsonResponse({"error": f"upstream: {e}"}, status=502)

        if not v.valid or not v.tenant_id or not v.user_id:
            return JsonResponse(
                {"error": v.error or "invalid token"}, status=401
            )

        request.vaultaris_user = VaultarisUser(
            tenant_id=v.tenant_id,
            user_id=v.user_id,
            username=v.username,
            roles=v.roles or [],
        )
        return self.get_response(request)


# ── View decorator ───────────────────────────────────────────────────


def require_permission(resource: str, action: str) -> Callable:
    def decorator(view: Callable) -> Callable:
        @wraps(view)
        def wrapper(request: HttpRequest, *args, **kwargs):
            user: VaultarisUser | None = getattr(request, "vaultaris_user", None)
            if user is None:
                return JsonResponse({"error": "not authenticated"}, status=401)
            try:
                check = _loop.run_until_complete(
                    _vaultaris().check_permission(
                        user.tenant_id, user.user_id, resource, action
                    )
                )
            except VaultarisError as e:
                return JsonResponse({"error": f"upstream: {e}"}, status=502)
            if not check.allowed:
                return JsonResponse(
                    {"error": f"missing permission {resource}:{action}"},
                    status=403,
                )
            return view(request, *args, **kwargs)

        return wrapper

    return decorator


# ── Example views (wire these in your urls.py) ───────────────────────


def health(_request: HttpRequest) -> JsonResponse:
    return JsonResponse({"status": "ok"})


def me(request: HttpRequest) -> JsonResponse:
    user: VaultarisUser = request.vaultaris_user
    return JsonResponse(
        {
            "tenant_id": user.tenant_id,
            "user_id": user.user_id,
            "username": user.username,
            "roles": user.roles,
        }
    )


@require_permission("orders", "read")
def list_orders(request: HttpRequest) -> JsonResponse:
    user: VaultarisUser = request.vaultaris_user
    return JsonResponse(
        {"orders": ["ORD-001", "ORD-002"], "served_to": user.username}
    )


@require_permission("orders", "delete")
def delete_order(request: HttpRequest, order_id: str) -> JsonResponse:
    user: VaultarisUser = request.vaultaris_user
    return JsonResponse(
        {
            "deleted_id": order_id,
            "deleted_by": user.username,
            "user_id": user.user_id,
        }
    )
