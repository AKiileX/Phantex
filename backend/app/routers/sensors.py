# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Sensors Router.

GET   /api/v1/sensors         — List sensors (paginated, filterable)
GET   /api/v1/sensors/{id}    — Get sensor details
POST  /api/v1/sensors/{id}/decommission — Soft-decommission a sensor (admin only)
"""

import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.middleware.auth import get_current_user
from app.middleware.rate_limit import rate_limit
from app.middleware.tenant import enforce_tenant_isolation
from app.schemas.auth import CurrentUser
from app.schemas.common import CursorPage
from app.schemas.sensor import SensorFilter, SensorResponse, SensorSummary
from app.services import sensor_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/sensors", tags=["sensors"], dependencies=[Depends(rate_limit)])

@router.get(
    "",
    response_model=CursorPage[SensorSummary],
    summary="List sensors",
)
async def list_sensors(
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    status_filter: str | None = Query(None, alias="status"),
    search: str | None = None,
    cursor: str | None = None,
    limit: int = Query(50, ge=1, le=100),
):
    """
    List deployed sensors for the current tenant.
    Supports filtering by status and search by sensor_id or hostname.
    """
    filters = SensorFilter(status=status_filter, search=search)
    page = await sensor_service.list_sensors(db, filters, cursor=cursor, limit=limit)

    return CursorPage(
        items=[SensorSummary.model_validate(s) for s in page.items],
        next_cursor=page.next_cursor,
        has_more=page.has_more,
    )

@router.get(
    "/{sensor_uuid}",
    response_model=SensorResponse,
    summary="Get sensor details",
)
async def get_sensor(
    sensor_uuid: uuid.UUID,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """Get full details of a specific sensor including health metrics."""
    sensor = await sensor_service.get_sensor(db, sensor_uuid)
    if sensor is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sensor not found")
    return sensor

# ── Decommission ──────────────────────────────────────────────────────────────

class DecommissionRequest(BaseModel):
    """Request body for sensor decommission."""

    reason: str = Field(..., min_length=5, max_length=500, description="Reason for decommission")

@router.post(
    "/{sensor_uuid}/decommission",
    response_model=SensorResponse,
    summary="Decommission a sensor (admin only)",
)
async def decommission_sensor(
    sensor_uuid: uuid.UUID,
    body: DecommissionRequest,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """
    Soft-decommission a sensor. Admin-only operation.
    The sensor is retained for audit trail — never deleted.
    Decommissioned sensors are excluded from active views.
    """
    # Require admin role — defense in depth beyond permission gates
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can decommission sensors",
        )

    sensor = await sensor_service.decommission_sensor(
        db,
        sensor_id=sensor_uuid,
        decommissioned_by=current_user.email,
        reason=body.reason,
    )
    if sensor is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sensor not found")

    await db.commit()

    logger.info(
        "sensor decommissioned",
        extra={
            "sensor_id": str(sensor_uuid),
            "decommissioned_by": current_user.email,
            "reason": body.reason,
        },
    )

    return sensor
