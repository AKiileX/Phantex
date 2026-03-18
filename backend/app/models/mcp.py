# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""SQLAlchemy models — MCP Supply Chain"""

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, Float, ForeignKey, Integer, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base

class MCPServer(Base):
    __tablename__ = "mcp_servers"
    __table_args__ = (
        CheckConstraint(
            "trust_level IN ('verified','known','unknown','suspicious','blocked')",
            name="chk_mcp_servers_trust_level",
        ),
        CheckConstraint(
            "risk_level IN ('critical','high','medium','low','minimal')",
            name="chk_mcp_servers_risk_level",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    server_id: Mapped[str] = mapped_column(Text, nullable=False)
    name: Mapped[str | None] = mapped_column(Text, nullable=True)
    trust_level: Mapped[str] = mapped_column(Text, nullable=False, default="unknown")
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    risk_level: Mapped[str] = mapped_column(Text, nullable=False, default="minimal")
    content_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    protocol_version: Mapped[str | None] = mapped_column(Text, nullable=True)
    capabilities: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"), default=list)
    metadata_: Mapped[dict] = mapped_column(
        "metadata", JSONB, nullable=False, server_default=text("'{}'::jsonb"), default=dict
    )
    connection_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    anomaly_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_rate: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    blocked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    blocked_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

class MCPScanResult(Base):
    __tablename__ = "mcp_scan_results"
    __table_args__ = (
        CheckConstraint(
            "scan_type IN ('package','protocol','behavioral','full')",
            name="chk_mcp_scans_type",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    server_id: Mapped[str] = mapped_column(Text, nullable=False)
    scan_type: Mapped[str] = mapped_column(Text, nullable=False, default="package")
    ecosystem: Mapped[str | None] = mapped_column(Text, nullable=True)
    total_packages: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    clean_packages: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    vulnerable: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    malicious: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    typosquat: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    reputation_avg: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    findings: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"), default=list)
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

class MCPAnomaly(Base):
    __tablename__ = "mcp_anomalies"
    __table_args__ = (
        CheckConstraint(
            "severity IN ('critical','high','medium','low','info')",
            name="chk_mcp_anomalies_severity",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    server_id: Mapped[str] = mapped_column(Text, nullable=False)
    anomaly_type: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(Text, nullable=False, default="medium")
    detail: Mapped[str] = mapped_column(Text, nullable=False)
    raw_evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
