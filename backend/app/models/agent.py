# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""SQLAlchemy model — Agent (AI agent discovered by sensors)."""

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, Float, ForeignKey, Integer, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

class Agent(Base):
    __tablename__ = "agents"
    __table_args__ = (
        CheckConstraint(
            "status IN ('active', 'stale', 'offline', 'terminated', 'quarantined')",
            name="chk_agents_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    paid: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    name: Mapped[str | None] = mapped_column(Text, nullable=True)
    framework: Mapped[str | None] = mapped_column(Text, nullable=True)
    framework_ver: Mapped[str | None] = mapped_column(Text, nullable=True)
    process_pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    exe_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    cmdline: Mapped[str | None] = mapped_column(Text, nullable=True)
    container_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    container_image: Mapped[str | None] = mapped_column(Text, nullable=True)
    host_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    sensor_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(Text, nullable=True)
    hostname: Mapped[str | None] = mapped_column(Text, nullable=True)
    os_type: Mapped[str | None] = mapped_column(Text, nullable=True)  # windows, linux, macos
    os_version: Mapped[str | None] = mapped_column(Text, nullable=True)  # e.g. "Windows 11 23H2"
    cpu_usage_pct: Mapped[float | None] = mapped_column(Float, nullable=True)
    memory_mb: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="active")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    tags: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"), default=dict)
    metadata_: Mapped[dict] = mapped_column("metadata", JSONB, nullable=False, default=dict)

    # Relationships
    tenant: Mapped["Tenant"] = relationship(back_populates="agents", lazy="selectin")  # noqa: F821
