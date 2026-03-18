# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Pydantic schemas — Health check responses."""

from pydantic import BaseModel

class HealthResponse(BaseModel):
    """Liveness probe response."""

    status: str = "ok"

class ReadinessResponse(BaseModel):
    """Readiness probe response."""

    status: str  # "ok" or "degraded"
