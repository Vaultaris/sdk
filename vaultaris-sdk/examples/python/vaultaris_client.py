"""
Thin async Vaultaris client used by the framework examples in this
directory. We use `httpx` directly while the PyO3 bindings catch up to
the new SDK surface — every example then shares the same client and
auth conventions.

The client mirrors the auth scheme rules of the official SDKs:

- Default scheme: `Authorization: ApiKey <token>` (matches the server's
  ApiKey extractor).
- Override with `auth_scheme="Bearer"` when carrying OAuth tokens.
- Optional `device_fingerprint` is forwarded via `X-Device-Fingerprint`.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Iterable

import httpx


@dataclass
class TokenValidation:
    valid: bool
    tenant_id: str | None = None
    user_id: str | None = None
    username: str | None = None
    email: str | None = None
    roles: list[str] | None = None
    permissions: list[str] | None = None
    scopes: list[str] | None = None
    error: str | None = None


@dataclass
class PermissionCheck:
    allowed: bool
    reason: str | None = None
    matched_policy: str | None = None


class VaultarisError(Exception):
    def __init__(self, status: int, body: str) -> None:
        super().__init__(f"Vaultaris API error: HTTP {status}: {body}")
        self.status = status
        self.body = body


class VaultarisClient:
    """Async Vaultaris client."""

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        *,
        auth_scheme: str = "ApiKey",
        timeout: float = 30.0,
        device_fingerprint: str | None = None,
    ) -> None:
        self.base_url = (base_url or os.environ["VAULTARIS_URL"]).rstrip("/")
        self.api_key = api_key or os.environ.get("VAULTARIS_API_KEY")
        self.auth_scheme = auth_scheme
        self.device_fingerprint = device_fingerprint
        self._http = httpx.AsyncClient(base_url=self.base_url, timeout=timeout)

    # ── Lifecycle ──────────────────────────────────────────────────────

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> "VaultarisClient":
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        await self.aclose()

    # ── Integration endpoints ─────────────────────────────────────────

    async def validate_token(
        self,
        token: str,
        required_scopes: Iterable[str] | None = None,
        required_permissions: Iterable[str] | None = None,
    ) -> TokenValidation:
        data = await self._post(
            "/api/v1/integration/token/validate",
            {
                "token": token,
                "required_scopes": list(required_scopes) if required_scopes else None,
                "required_permissions": (
                    list(required_permissions) if required_permissions else None
                ),
            },
        )
        return TokenValidation(
            valid=bool(data.get("valid")),
            tenant_id=data.get("tenant_id"),
            user_id=data.get("user_id"),
            username=data.get("username"),
            email=data.get("email"),
            roles=data.get("roles") or [],
            permissions=data.get("permissions") or [],
            scopes=data.get("scopes") or [],
            error=data.get("error"),
        )

    async def check_permission(
        self,
        tenant_id: str,
        user_id: str,
        resource: str,
        action: str,
        context: dict[str, Any] | None = None,
    ) -> PermissionCheck:
        data = await self._post(
            f"/api/v1/tenants/{tenant_id}/integration/check-permission",
            {
                "user_id": user_id,
                "resource": resource,
                "action": action,
                "context": context,
            },
        )
        return PermissionCheck(
            allowed=bool(data.get("allowed")),
            reason=data.get("reason"),
            matched_policy=data.get("matched_policy"),
        )

    async def batch_check_permissions(
        self,
        tenant_id: str,
        user_id: str,
        checks: list[dict[str, str]],
    ) -> list[dict[str, Any]]:
        data = await self._post(
            f"/api/v1/tenants/{tenant_id}/integration/batch-check-permissions",
            {"user_id": user_id, "checks": checks},
        )
        return data.get("results") or []

    async def require_permission(
        self,
        tenant_id: str,
        user_id: str,
        resource: str,
        action: str,
    ) -> None:
        """Raise PermissionError if the user lacks `resource:action`."""
        result = await self.check_permission(tenant_id, user_id, resource, action)
        if not result.allowed:
            raise PermissionError(
                f"missing permission {resource}:{action} for user {user_id}"
            )

    # ── Internal HTTP plumbing ────────────────────────────────────────

    async def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        resp = await self._http.post(path, json=body, headers=self._headers())
        return self._unwrap(resp)

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"{self.auth_scheme} {self.api_key}"
        if self.device_fingerprint:
            headers["X-Device-Fingerprint"] = self.device_fingerprint
        return headers

    @staticmethod
    def _unwrap(resp: httpx.Response) -> dict[str, Any]:
        if not resp.is_success:
            raise VaultarisError(resp.status_code, resp.text)
        if not resp.content:
            return {}
        payload = resp.json()
        # Strip `{ success, data }` envelope when present.
        if isinstance(payload, dict) and "success" in payload and "data" in payload:
            return payload["data"]
        return payload
