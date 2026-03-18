# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Health Check Router.

GET /healthz  — Liveness probe (always 200 if process is running)
GET /readyz   — Readiness probe (checks database connectivity)
"""

from fastapi import APIRouter

from app.database import check_db_health
from app.schemas.health import HealthResponse, ReadinessResponse

router = APIRouter(tags=["health"])

@router.get(
    "/healthz",
    response_model=HealthResponse,
    summary="Liveness probe",
)
async def healthz():
    """Liveness probe — returns 200 if the process is running."""
    return HealthResponse(status="ok")

@router.get(
    "/readyz",
    response_model=ReadinessResponse,
    summary="Readiness probe",
)
async def readyz():
    """Readiness probe — checks database connectivity."""
    db_ok = await check_db_health()
    return ReadinessResponse(
        status="ok" if db_ok else "degraded",
    )
