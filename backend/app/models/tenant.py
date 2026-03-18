# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""SQLAlchemy model — Tenant (organization)."""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    slug: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    plan: Mapped[str] = mapped_column(Text, nullable=False, default="community")
    settings: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    # --- Phase 3: enterprise tenant fields ---
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    onboarded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    suspended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    max_users: Mapped[int] = mapped_column(Integer, nullable=False, server_default="50")
    max_agents: Mapped[int] = mapped_column(Integer, nullable=False, server_default="100")
    max_events_per_day: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1000000")

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    # Relationships — lazy loading to avoid loading ALL users/agents on every tenant query
    users: Mapped[list["User"]] = relationship(back_populates="tenant", lazy="raise")  # noqa: F821
    agents: Mapped[list["Agent"]] = relationship(back_populates="tenant", lazy="raise")  # noqa: F821
