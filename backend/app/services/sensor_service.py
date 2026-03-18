# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Sensor Service.

Business logic for listing, retrieving, and upserting sensors.
All queries go through the RLS-enabled session.
"""

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.sensor import Sensor
from app.schemas.common import PageResult
from app.schemas.sensor import SensorFilter
from app.utils.pagination import decode_cursor, encode_cursor

import logging
_svc_log = logging.getLogger(__name__)

# Thresholds for auto-status computation
_ONLINE_THRESHOLD = timedelta(minutes=2)
_DEGRADED_THRESHOLD = timedelta(minutes=5)

async def list_sensors(
    db: AsyncSession,
    filters: SensorFilter,
    cursor: str | None = None,
    limit: int = 50,
) -> PageResult:
    """
    List sensors with optional filters and cursor-based pagination.
    RLS automatically filters by tenant.
    """
    limit = max(1, min(limit, 100))
    query = select(Sensor).order_by(Sensor.last_heartbeat.desc(), Sensor.id.desc())

    if filters.status:
        query = query.where(Sensor.status == filters.status)
    if filters.search:
        escaped = filters.search.replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        query = query.where(
            or_(Sensor.sensor_id.ilike(pattern), Sensor.hostname.ilike(pattern))
        )

    if cursor:
        decoded = decode_cursor(cursor)
        if decoded:
            ts, uid = decoded
            query = query.where(
                (Sensor.last_heartbeat < ts)
                | ((Sensor.last_heartbeat == ts) & (Sensor.id < uid))
            )

    result = await db.execute(query.limit(limit + 1))
    sensors = list(result.scalars().all())

    has_more = len(sensors) > limit
    items = sensors[:limit]

    next_cursor = None
    if has_more and items:
        last = items[-1]
        next_cursor = encode_cursor(last.last_heartbeat, last.id)

    return PageResult(items=items, next_cursor=next_cursor, has_more=has_more)

async def get_sensor(db: AsyncSession, sensor_uuid: uuid.UUID) -> Sensor | None:
    """Get a single sensor by primary key UUID. RLS filters by tenant."""
    result = await db.execute(select(Sensor).where(Sensor.id == sensor_uuid))
    return result.scalar_one_or_none()

async def get_sensor_by_sensor_id(
    db: AsyncSession, tenant_id: uuid.UUID, sensor_id: str
) -> Sensor | None:
    """Get a sensor by its sensor_id within a tenant."""
    result = await db.execute(
        select(Sensor).where(
            Sensor.tenant_id == tenant_id, Sensor.sensor_id == sensor_id
        )
    )
    return result.scalar_one_or_none()

async def upsert_sensor_registration(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    sensor_id: str,
    hostname: str | None = None,
    ip_address: str | None = None,
    kernel: str | None = None,
    arch: str | None = None,
    version: str | None = None,
    os_type: str | None = None,
    probes_loaded: int = 0,
    probes_total: int = 0,
) -> Sensor:
    """
    Register a sensor or update its registration info.
    Called by the gateway when a sensor sends RegisterSensor.
    """
    existing = await get_sensor_by_sensor_id(db, tenant_id, sensor_id)
    now = datetime.now(UTC)

    if existing is not None:
        existing.hostname = hostname or existing.hostname
        existing.ip_address = ip_address or existing.ip_address
        existing.kernel = kernel or existing.kernel
        existing.arch = arch or existing.arch
        existing.version = version or existing.version
        existing.os_type = os_type or existing.os_type
        existing.probes_loaded = probes_loaded or existing.probes_loaded
        existing.probes_total = probes_total or existing.probes_total
        existing.status = "online"
        existing.last_heartbeat = now
        existing.updated_at = now
        await db.flush()
        await db.refresh(existing)
        return existing

    sensor = Sensor(
        tenant_id=tenant_id,
        sensor_id=sensor_id,
        hostname=hostname,
        ip_address=ip_address,
        kernel=kernel,
        arch=arch,
        version=version,
        os_type=os_type,
        probes_loaded=probes_loaded,
        probes_total=probes_total,
        status="online",
        first_seen=now,
        last_heartbeat=now,
        updated_at=now,
    )
    db.add(sensor)
    await db.flush()
    await db.refresh(sensor)
    return sensor

async def update_heartbeat(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    sensor_id: str,
    metrics: dict,
) -> Sensor | None:
    """
    Update sensor metrics from a heartbeat.
    Called by the gateway on each sensor heartbeat.
    """
    sensor = await get_sensor_by_sensor_id(db, tenant_id, sensor_id)
    if sensor is None:
        return None

    now = datetime.now(UTC)
    sensor.probes_loaded = int(metrics.get("probes_loaded", sensor.probes_loaded))
    sensor.probes_total = int(metrics.get("probes_total", sensor.probes_total))
    sensor.events_read = int(metrics.get("events_read", sensor.events_read))
    sensor.events_sent = int(metrics.get("events_sent", sensor.events_sent))
    sensor.events_dropped = int(metrics.get("events_dropped", sensor.events_dropped))
    sensor.parse_errors = int(metrics.get("parse_errors", sensor.parse_errors))
    sensor.agents_tracked = int(metrics.get("agents_tracked", sensor.agents_tracked))
    sensor.uptime_seconds = int(metrics.get("uptime_seconds", sensor.uptime_seconds))
    sensor.cpu_percent = metrics.get("cpu_percent")
    sensor.memory_bytes = metrics.get("memory_bytes")
    sensor.buffer_used = int(metrics.get("buffer_used", sensor.buffer_used))
    sensor.status = "online"
    sensor.last_heartbeat = now
    sensor.updated_at = now

    await db.flush()
    await db.refresh(sensor)
    return sensor

async def count_sensors(db: AsyncSession) -> tuple[int, int]:
    """Return (total_sensors, online_sensors) for the current tenant."""
    total_result = await db.execute(select(func.count(Sensor.id)))
    online_result = await db.execute(
        select(func.count(Sensor.id)).where(Sensor.status == "online")
    )
    return total_result.scalar_one(), online_result.scalar_one()

async def refresh_sensor_statuses(db: AsyncSession) -> int:
    """
    Mark sensors as degraded/offline based on last_heartbeat age.
    Emits SENSOR_DEGRADED / SENSOR_DISCONNECTED events so the dashboard
    can show toast notifications without polling sensor state directly.
    Returns number of sensors updated. Should be called periodically.
    """
    from app.models.event import Event  # local import to avoid circular

    now = datetime.now(UTC)
    degraded_cutoff = now - _ONLINE_THRESHOLD
    offline_cutoff = now - _DEGRADED_THRESHOLD

    # Fetch sensors about to be marked degraded so we can emit events
    degraded_candidates = (
        await db.execute(
            select(Sensor)
            .where(
                Sensor.status == "online",
                Sensor.last_heartbeat < degraded_cutoff,
                Sensor.last_heartbeat >= offline_cutoff,
            )
        )
    ).scalars().all()

    # Fetch sensors about to go offline
    offline_candidates = (
        await db.execute(
            select(Sensor)
            .where(
                Sensor.status.notin_(["offline", "decommissioned"]),
                Sensor.last_heartbeat < offline_cutoff,
            )
        )
    ).scalars().all()

    # Mark offline (no heartbeat in 5 min)
    result_offline = await db.execute(
        update(Sensor)
        .where(Sensor.status.notin_(["offline", "decommissioned"]), Sensor.last_heartbeat < offline_cutoff)
        .values(status="offline", updated_at=now)
    )

    # Mark degraded (no heartbeat in 2 min but within 5 min)
    result_degraded = await db.execute(
        update(Sensor)
        .where(
            Sensor.status == "online",
            Sensor.last_heartbeat < degraded_cutoff,
            Sensor.last_heartbeat >= offline_cutoff,
        )
        .values(status="degraded", updated_at=now)
    )

    # Emit lifecycle events for state transitions
    for sensor in degraded_candidates:
        db.add(Event(
            id=uuid.uuid4(),
            tenant_id=sensor.tenant_id,
            sensor_id=str(sensor.id),
            event_type="SENSOR_DEGRADED",
            severity="high",
            timestamp=now,
            raw_data={"sensor_id": str(sensor.id), "hostname": sensor.hostname, "reason": "no heartbeat >2min"},
        ))
        _svc_log.info("sensor_degraded_event", extra={"sensor_id": str(sensor.id), "hostname": sensor.hostname})

    for sensor in offline_candidates:
        db.add(Event(
            id=uuid.uuid4(),
            tenant_id=sensor.tenant_id,
            sensor_id=str(sensor.id),
            event_type="SENSOR_DISCONNECTED",
            severity="high",
            timestamp=now,
            raw_data={"sensor_id": str(sensor.id), "hostname": sensor.hostname, "reason": "no heartbeat >5min"},
        ))
        _svc_log.info("sensor_disconnected_event", extra={"sensor_id": str(sensor.id), "hostname": sensor.hostname})

    return (result_offline.rowcount or 0) + (result_degraded.rowcount or 0)

async def decommission_sensor(
    db: AsyncSession,
    sensor_id: uuid.UUID,
    decommissioned_by: str,
    reason: str,
) -> Sensor | None:
    """
    Soft-decommission a sensor. Sets status to 'decommissioned' with audit trail.
    The sensor row is never deleted — retained for audit and forensic purposes.
    """
    result = await db.execute(
        select(Sensor).where(Sensor.id == sensor_id)
    )
    sensor = result.scalar_one_or_none()
    if sensor is None:
        return None

    if sensor.status == "decommissioned":
        return sensor

    now = datetime.now(UTC)
    sensor.status = "decommissioned"
    sensor.decommissioned_at = now
    sensor.decommissioned_by = decommissioned_by
    sensor.decommission_reason = reason
    sensor.updated_at = now

    await db.flush()
    await db.refresh(sensor)
    return sensor
