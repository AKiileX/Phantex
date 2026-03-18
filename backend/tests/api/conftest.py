# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
API-level test fixtures for Phantex backend.

Provides:
- async FastAPI TestClient via httpx
- In-memory SQLite for fast tests (no PostgreSQL needed)
- Auth helpers (get_auth_headers for authenticated requests)
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# ── Override DB to use SQLite for unit tests ──────────────────────────────────

@pytest_asyncio.fixture
async def client() -> AsyncGenerator[AsyncClient, None]:
    """
    Create an httpx AsyncClient pointing at the FastAPI app.

    We import app lazily to allow env overrides before import.
    """
    import os

    os.environ.setdefault("PHANTEX_ENVIRONMENT", "test")
    os.environ.setdefault("PHANTEX_JWT_SECRET", "test-secret-not-for-production")
    os.environ.setdefault("PHANTEX_DATABASE_URL", "sqlite+aiosqlite:///")
    os.environ.setdefault("PHANTEX_KAFKA_BOOTSTRAP", "localhost:9092")

    from app.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

def auth_headers(token: str) -> dict[str, str]:
    """Return Authorization header dict for a JWT token."""
    return {"Authorization": f"Bearer {token}"}
