# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for protected resource endpoints.

Validates that unauthenticated requests to all major resource
endpoints return 401/403.
"""

import pytest

PROTECTED_ENDPOINTS = [
    ("GET", "/api/v1/agents"),
    ("GET", "/api/v1/events"),
    ("GET", "/api/v1/alerts"),
    ("GET", "/api/v1/rules"),
    ("GET", "/api/v1/dashboard/stats"),
    ("GET", "/api/v1/users"),
]

@pytest.mark.asyncio
@pytest.mark.parametrize("method,path", PROTECTED_ENDPOINTS)
async def test_protected_endpoints_require_auth(client, method, path):
    """All protected endpoints should reject unauthenticated requests."""
    resp = await client.request(method, path)
    assert resp.status_code in (401, 403), f"{method} {path} returned {resp.status_code}, expected 401/403"

@pytest.mark.asyncio
async def test_nonexistent_endpoint_returns_404(client):
    """Requesting a non-existent route should return 404."""
    resp = await client.get("/api/v1/nonexistent-route")
    assert resp.status_code == 404
