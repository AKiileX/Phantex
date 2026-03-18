# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Internal Sensor API.

Used by the gateway to report sensor registration and heartbeat data.
Internal-only — authenticated via a shared gateway-to-backend token.

POST /api/internal/sensors/register  — Register or re-register a sensor
POST /api/internal/sensors/heartbeat — Report heartbeat metrics

SECURITY:
  - Token comparison is timing-safe (hmac.compare_digest)
  - No default fallback token — env var MUST be set
  - sensor_id validated with regex to prevent path traversal / injection
  - Rate limited
"""

from __future__ import annotations

import hmac
import logging
import os
import re
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.rate_limit import rate_limit
from app.services import sensor_service

logger = logging.getLogger("phantex.routers.internal_sensors")

router = APIRouter(
    prefix="/api/internal/sensors",
    tags=["internal-sensors"],
    dependencies=[Depends(rate_limit)],
)

# ── Internal Auth ─────────────────────────────────────────────────────────────

_SENSOR_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-]{0,254}[a-zA-Z0-9]$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

INTERNAL_TOKEN: str | None = os.getenv("PHANTEX_INTERNAL_TOKEN")

async def _verify_internal_token(
    request: Request,
    x_internal_token: str = Header(..., alias="X-Internal-Token"),
) -> str:
    """Verify the gateway's internal auth token (timing-safe)."""
    if INTERNAL_TOKEN is None:
        logger.error("PHANTEX_INTERNAL_TOKEN env var not set — internal sensor API disabled")
        raise HTTPException(status_code=503, detail="Internal API not configured")

    if len(x_internal_token) < 16:
        raise HTTPException(status_code=403, detail="Forbidden")

    if not hmac.compare_digest(x_internal_token.encode(), INTERNAL_TOKEN.encode()):
        logger.warning(
            "invalid_internal_token",
            extra={"client_ip": request.client.host if request.client else "unknown"},
        )
        raise HTTPException(status_code=403, detail="Forbidden")

    return x_internal_token

# ── Models ────────────────────────────────────────────────────────────────────

class RegisterSensorRequest(BaseModel):
    """Payload from gateway when a sensor registers."""

    sensor_id: str = Field(..., max_length=256)
    tenant_id: str = Field(..., max_length=36)
    hostname: str | None = Field(None, max_length=255)
    ip_address: str | None = Field(None, max_length=45)
    kernel: str | None = Field(None, max_length=255)
    arch: str | None = Field(None, max_length=32)
    version: str | None = Field(None, max_length=64)
    os_type: str | None = Field(None, max_length=32)
    probes_loaded: int = Field(0, ge=0)
    probes_total: int = Field(0, ge=0)

    @field_validator("sensor_id")
    @classmethod
    def validate_sensor_id(cls, v: str) -> str:
        if not _SENSOR_ID_RE.match(v):
            raise ValueError("Invalid sensor_id format")
        return v

    @field_validator("tenant_id")
    @classmethod
    def validate_tenant_id(cls, v: str) -> str:
        if not _UUID_RE.match(v):
            raise ValueError("tenant_id must be a valid UUID")
        return v

class HeartbeatRequest(BaseModel):
    """Payload from gateway on sensor heartbeat."""

    sensor_id: str = Field(..., max_length=256)
    tenant_id: str = Field(..., max_length=36)
    metrics: dict[str, Any] = Field(default_factory=dict)

    @field_validator("sensor_id")
    @classmethod
    def validate_sensor_id(cls, v: str) -> str:
        if not _SENSOR_ID_RE.match(v):
            raise ValueError("Invalid sensor_id format")
        return v

    @field_validator("tenant_id")
    @classmethod
    def validate_tenant_id(cls, v: str) -> str:
        if not _UUID_RE.match(v):
            raise ValueError("tenant_id must be a valid UUID")
        return v

class RegisterSensorResponse(BaseModel):
    status: str
    sensor_uuid: str

class HeartbeatResponse(BaseModel):
    status: str

# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post(
    "/register",
    response_model=RegisterSensorResponse,
    summary="Register sensor (gateway-only)",
    dependencies=[Depends(_verify_internal_token)],
)
async def register_sensor(
    body: RegisterSensorRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Register or re-register a sensor. Called by the gateway when a sensor
    connects and sends RegisterSensor RPC.
    """
    tenant_uuid = uuid.UUID(body.tenant_id)

    sensor = await sensor_service.upsert_sensor_registration(
        db,
        tenant_id=tenant_uuid,
        sensor_id=body.sensor_id,
        hostname=body.hostname,
        ip_address=body.ip_address,
        kernel=body.kernel,
        arch=body.arch,
        version=body.version,
        os_type=body.os_type,
        probes_loaded=body.probes_loaded,
        probes_total=body.probes_total,
    )
    await db.commit()

    logger.info(
        "sensor_registered",
        extra={
            "sensor_id": body.sensor_id,
            "tenant_id": body.tenant_id,
            "sensor_uuid": str(sensor.id),
        },
    )

    return RegisterSensorResponse(status="ok", sensor_uuid=str(sensor.id))

@router.post(
    "/heartbeat",
    response_model=HeartbeatResponse,
    summary="Sensor heartbeat (gateway-only)",
    dependencies=[Depends(_verify_internal_token)],
)
async def sensor_heartbeat(
    body: HeartbeatRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Update sensor health metrics from a heartbeat.
    Called by the gateway on each sensor heartbeat.
    """
    tenant_uuid = uuid.UUID(body.tenant_id)

    sensor = await sensor_service.update_heartbeat(
        db,
        tenant_id=tenant_uuid,
        sensor_id=body.sensor_id,
        metrics=body.metrics,
    )

    if sensor is None:
        # Sensor not registered yet — auto-register with minimal info
        sensor = await sensor_service.upsert_sensor_registration(
            db,
            tenant_id=tenant_uuid,
            sensor_id=body.sensor_id,
        )
        await sensor_service.update_heartbeat(
            db,
            tenant_id=tenant_uuid,
            sensor_id=body.sensor_id,
            metrics=body.metrics,
        )

    await db.commit()

    return HeartbeatResponse(status="ok")
