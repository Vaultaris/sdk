#!/usr/bin/env python3
"""
Vaultaris SDK Python Example

This example demonstrates how to use the Vaultaris SDK from Python.

First, install the SDK:
    pip install vaultaris-sdk

Or build from source:
    cd sdk
    maturin develop --features python
"""

from vaultaris_sdk import VaultarisClient

def main():
    # Create client with API key
    client = VaultarisClient(
        base_url="http://localhost:8080",
        api_key="your-api-key",
        tenant_id="your-tenant-id",  # Optional default tenant
        timeout=30  # Optional timeout in seconds
    )

    # Or create from environment variables
    # client = VaultarisClient.from_env()

    # ========================================
    # Token Validation
    # ========================================
    print("=== Token Validation ===")

    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

    # Simple validation
    result = client.validate_token(token)
    if result.valid:
        print(f"✅ Token is valid!")
        print(f"   User: {result.username}")
        print(f"   Email: {result.email}")
        print(f"   Roles: {result.roles}")
        print(f"   Scopes: {result.scopes}")
    else:
        print(f"❌ Token is invalid: {result.error}")

    # Validation with requirements
    result = client.validate_token_with_requirements(
        token,
        required_scopes=["read:users"],
        required_permissions=["users:read"]
    )

    # Quick boolean check
    if client.is_token_valid(token):
        print("Token is valid!")

    # ========================================
    # Permission Checking
    # ========================================
    print("\n=== Permission Checking ===")

    tenant_id = "your-tenant-id"
    user_id = "550e8400-e29b-41d4-a716-446655440000"

    # Simple check
    can_create = client.check_permission(tenant_id, user_id, "orders", "create")
    print(f"Can create orders: {can_create}")

    # Detailed check with context
    check = client.check_permission_detailed(
        tenant_id, user_id, "orders", "create",
        context={"department": "sales", "order_value": "1500"}
    )
    print(f"Permission allowed: {check.allowed}")
    if check.reason:
        print(f"Reason: {check.reason}")

    # Batch check
    results = client.batch_check_permissions(
        tenant_id, user_id,
        [
            ("orders", "read"),
            ("orders", "create"),
            ("orders", "delete"),
            ("users", "read"),
        ]
    )

    print("\nBatch permission results:")
    for resource, action, allowed in results:
        emoji = "✅" if allowed else "❌"
        print(f"  {emoji} {resource}:{action}")

    # Convenience methods
    permissions = [("orders", "read"), ("orders", "create")]

    if client.has_any_permission(tenant_id, user_id, permissions):
        print("User has at least one of the permissions!")

    if client.has_all_permissions(tenant_id, user_id, permissions):
        print("User has ALL of the permissions!")

    # ========================================
    # User Information
    # ========================================
    print("\n=== User Information ===")

    user = client.get_user(tenant_id, user_id)
    print(f"User: {user.username} ({user.email})")
    print(f"Name: {user.first_name} {user.last_name}")
    print(f"Permissions: {user.permissions}")


def flask_example():
    """Example Flask middleware using Vaultaris"""
    from functools import wraps
    from flask import Flask, request, jsonify, g

    app = Flask(__name__)
    client = VaultarisClient(
        base_url="http://localhost:8080",
        api_key="your-api-key"
    )

    def require_auth(f):
        """Authentication decorator"""
        @wraps(f)
        def decorated(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return jsonify({"error": "Missing token"}), 401

            token = auth_header[7:]  # Remove "Bearer " prefix
            result = client.validate_token(token)

            if not result.valid:
                return jsonify({"error": result.error}), 401

            g.user = {
                "user_id": result.user_id,
                "username": result.username,
                "email": result.email,
                "roles": result.roles,
                "permissions": result.permissions,
            }
            return f(*args, **kwargs)
        return decorated

    def require_permission(resource, action):
        """Permission decorator"""
        def decorator(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                if not hasattr(g, "user"):
                    return jsonify({"error": "Not authenticated"}), 401

                tenant_id = "your-tenant-id"  # Get from config or request
                allowed = client.check_permission(
                    tenant_id,
                    g.user["user_id"],
                    resource,
                    action
                )

                if not allowed:
                    return jsonify({"error": "Permission denied"}), 403

                return f(*args, **kwargs)
            return decorated
        return decorator

    @app.route("/api/me")
    @require_auth
    def get_me():
        return jsonify({
            "user": g.user
        })

    @app.route("/api/admin")
    @require_auth
    @require_permission("admin", "access")
    def admin_area():
        return jsonify({
            "message": "Welcome to admin area!"
        })

    return app


def fastapi_example():
    """Example FastAPI middleware using Vaultaris"""
    from fastapi import FastAPI, Depends, HTTPException, Header
    from typing import Optional

    app = FastAPI()
    client = VaultarisClient(
        base_url="http://localhost:8080",
        api_key="your-api-key"
    )

    async def get_current_user(authorization: Optional[str] = Header(None)):
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing token")

        token = authorization[7:]
        result = client.validate_token(token)

        if not result.valid:
            raise HTTPException(status_code=401, detail=result.error)

        return {
            "user_id": result.user_id,
            "username": result.username,
            "email": result.email,
            "roles": result.roles,
            "permissions": result.permissions,
        }

    def require_permission(resource: str, action: str):
        async def check_permission(user: dict = Depends(get_current_user)):
            tenant_id = "your-tenant-id"
            allowed = client.check_permission(
                tenant_id,
                user["user_id"],
                resource,
                action
            )
            if not allowed:
                raise HTTPException(status_code=403, detail="Permission denied")
            return user
        return check_permission

    @app.get("/api/me")
    async def get_me(user: dict = Depends(get_current_user)):
        return {"user": user}

    @app.get("/api/admin")
    async def admin_area(user: dict = Depends(require_permission("admin", "access"))):
        return {"message": "Welcome to admin area!"}

    return app


if __name__ == "__main__":
    main()
