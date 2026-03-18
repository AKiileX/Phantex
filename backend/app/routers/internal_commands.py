# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Internal Commands API.

Used by the gateway to poll pending commands for connected sensors,
acknowledge dispatched commands, and report command results.

These endpoints are ***internal-only*** — authenticated via a shared
gateway-to-backend token, NOT the normal user JWT.

SECURITY:
  - Token comparison is timing-safe (hmac.compare_digest) to prevent
    side-channel extraction.
  - No default fallback token — env var MUST be set.
  - agent_id is validated as UUID to prevent SSRF/path traversal.
  - Rate limited to prevent abuse.
"""

from __future__ import annotations

import hmac
import logging
import os
import re
from typing import Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.rate_limit import rate_limit
from app.services import agent_command_service

logger = logging.getLogger("phantex.routers.internal_commands")

router = APIRouter(
    prefix="/api/internal/commands",
    tags=["internal-commands"],
    dependencies=[Depends(rate_limit)],
)

# ── Internal Auth ─────────────────────────────────────────────────────────────
# The gateway authenticates with a shared secret.  In production this is
# Vault-issued.  PHANTEX_INTERNAL_TOKEN env var MUST be set — no fallback.

_UUID_PATTERN = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_SENSOR_ID_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-]{0,254}[a-zA-Z0-9]$")
_PAID_PATTERN = re.compile(r"^ptx-[a-z0-9][a-z0-9\-]{0,62}-[a-z0-9][a-z0-9\-]{0,30}-[0-9a-f]{12}$", re.ASCII)

INTERNAL_TOKEN: str | None = os.getenv("PHANTEX_INTERNAL_TOKEN")

async def verify_internal_token(
    request: Request,
    x_internal_token: str = Header(..., alias="X-Internal-Token"),
) -> str:
    """Verify the gateway's internal auth token (timing-safe)."""
    if INTERNAL_TOKEN is None:
        logger.error("PHANTEX_INTERNAL_TOKEN env var not set — internal API disabled")
        raise HTTPException(status_code=503, detail="Internal API not configured")

    if len(x_internal_token) < 16:
        raise HTTPException(status_code=403, detail="Forbidden")

    # Timing-safe comparison to prevent side-channel token extraction
    if not hmac.compare_digest(x_internal_token.encode(), INTERNAL_TOKEN.encode()):
        logger.warning(
            "invalid_internal_token",
            extra={"client_ip": request.client.host if request.client else "unknown"},
        )
        raise HTTPException(status_code=403, detail="Forbidden")

    return x_internal_token

# ── Models ────────────────────────────────────────────────────────────────────

class CommandOut(BaseModel):
    """A pending command for the sensor."""

    id: str
    command_type: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    alert_id: str | None = None
    reason: str = ""

class CommandAck(BaseModel):
    """Acknowledge or report result for a command."""

    command_id: str
    status: Literal["dispatched", "acknowledged", "completed", "failed"]
    result: dict[str, Any] = Field(default_factory=dict)

    @field_validator("command_id")
    @classmethod
    def validate_command_id(cls, v: str) -> str:
        if not _UUID_PATTERN.match(v):
            raise ValueError("command_id must be a valid UUID")
        return v

# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get(
    "/pending/{identifier}",
    response_model=list[CommandOut],
    summary="Get pending commands for agent or sensor",
    dependencies=[Depends(verify_internal_token)],
)
async def get_pending(
    identifier: str,
    limit: int = Query(10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
):
    """
    Gateway calls this on every sensor heartbeat to check for queued commands.
    Accepts either an agent UUID or a sensor_id string.
    Returns up to `limit` pending commands, oldest first.
    """
    if _UUID_PATTERN.match(identifier) or _PAID_PATTERN.match(identifier):
        # Direct agent UUID or PAID lookup
        commands = await agent_command_service.get_pending_commands(db, identifier, limit=limit)
    elif _SENSOR_ID_PATTERN.match(identifier):
        # Sensor-id lookup: find agents on this sensor and get their commands
        commands = await agent_command_service.get_pending_commands_by_sensor(db, identifier, limit=limit)
    else:
        raise HTTPException(status_code=400, detail="identifier must be a valid UUID, PAID, or sensor_id")

    return [
        CommandOut(
            id=c.id,
            command_type=c.command_type,
            parameters=c.parameters,
            alert_id=c.alert_id,
            reason=c.reason,
        )
        for c in commands
    ]

@router.post(
    "/ack",
    summary="Acknowledge command dispatch or completion",
    dependencies=[Depends(verify_internal_token)],
)
async def ack_command(
    body: CommandAck,
    db: AsyncSession = Depends(get_db),
):
    """
    Gateway reports command lifecycle:
    - "dispatched" — included in heartbeat response, sent to sensor
    - "acknowledged" — sensor confirmed receipt
    - "completed" — sensor executed successfully
    - "failed" — sensor execution failed
    """
    if body.status == "dispatched":
        await agent_command_service.mark_dispatched(db, body.command_id)
    elif body.status in ("completed", "acknowledged"):
        await agent_command_service.mark_completed(db, body.command_id, success=True, result_data=body.result)
    elif body.status == "failed":
        await agent_command_service.mark_completed(db, body.command_id, success=False, result_data=body.result)

    logger.info(
        "command_lifecycle",
        extra={"command_id": body.command_id, "status": body.status},
    )

    await db.commit()
    return {"ok": True, "command_id": body.command_id, "status": body.status}
