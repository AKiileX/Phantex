# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for health endpoints.

These are endpoint-level tests — they verify the API contract
(status codes, response shapes) without requiring a real database.
"""

import pytest


@pytest.mark.asyncio
async def test_healthz_returns_200(client):
    """GET /healthz should return 200 with status field."""
    resp = await client.get("/healthz")
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data
    assert data["status"] == "ok"

@pytest.mark.asyncio
async def test_root_redirects_or_returns(client):
    """GET / should return some response (redirect or health info)."""
    resp = await client.get("/", follow_redirects=False)
    assert resp.status_code in (200, 301, 307, 404)
