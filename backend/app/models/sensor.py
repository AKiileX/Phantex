# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""SQLAlchemy model — Sensor (deployed sensor instances)."""

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, CheckConstraint, DateTime, Float, ForeignKey, Integer, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base

class Sensor(Base):
    __tablename__ = "sensors"
    __table_args__ = (
        CheckConstraint(
            "status IN ('online', 'degraded', 'offline', 'decommissioned')",
            name="chk_sensors_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    sensor_id: Mapped[str] = mapped_column(Text, nullable=False)
    hostname: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(Text, nullable=True)
    kernel: Mapped[str | None] = mapped_column(Text, nullable=True)
    arch: Mapped[str | None] = mapped_column(Text, nullable=True)
    version: Mapped[str | None] = mapped_column(Text, nullable=True)
    os_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="online")

    # Health metrics (updated on each heartbeat)
    probes_loaded: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    probes_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    events_read: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    events_sent: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    events_dropped: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    parse_errors: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    agents_tracked: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    uptime_seconds: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    cpu_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    memory_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    buffer_used: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)

    # Timestamps
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_heartbeat: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    # Decommission info
    decommissioned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decommissioned_by: Mapped[str | None] = mapped_column(Text, nullable=True)
    decommission_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Metadata
    tags: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"), default=dict)
    metadata_: Mapped[dict] = mapped_column("metadata", JSONB, nullable=False, default=dict)
