# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for auth API endpoints.

Validates:
- Login with invalid credentials returns 401
- Missing fields return 422
- Unauthenticated access to protected endpoints returns 401/403
"""

import pytest


@pytest.mark.asyncio
async def test_login_invalid_credentials(client):
    """POST /api/v1/auth/login with wrong creds should return 401."""
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "nonexistent@example.com", "password": "wrongpassword"},
    )
    assert resp.status_code == 401

@pytest.mark.asyncio
async def test_login_missing_fields(client):
    """POST /api/v1/auth/login with missing fields should return 422."""
    resp = await client.post("/api/v1/auth/login", json={})
    assert resp.status_code == 422

@pytest.mark.asyncio
async def test_login_missing_password(client):
    """POST /api/v1/auth/login with missing password should return 422."""
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "user@example.com"},
    )
    assert resp.status_code == 422

@pytest.mark.asyncio
async def test_protected_endpoint_no_auth(client):
    """GET /api/v1/agents without auth should return 401 or 403."""
    resp = await client.get("/api/v1/agents")
    assert resp.status_code in (401, 403)

@pytest.mark.asyncio
async def test_protected_endpoint_invalid_token(client):
    """GET /api/v1/agents with garbage token should return 401 or 403."""
    resp = await client.get(
        "/api/v1/agents",
        headers={"Authorization": "Bearer invalid.token.here"},
    )
    assert resp.status_code in (401, 403)

@pytest.mark.asyncio
async def test_me_endpoint_no_auth(client):
    """GET /api/v1/auth/me without auth should return 401."""
    resp = await client.get("/api/v1/auth/me")
    assert resp.status_code in (401, 403)
