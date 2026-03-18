# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""SQLAlchemy models — SSO configurations (SAML + OIDC per tenant)."""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base

class SSOConfig(Base):
    """Per-tenant SSO configuration (SAML 2.0 or OIDC)."""

    __tablename__ = "sso_configs"
    __table_args__ = (
        UniqueConstraint("tenant_id", "provider_type", "name", name="uq_sso_configs_tenant_type_name"),
        CheckConstraint("provider_type IN ('saml', 'oidc')", name="chk_sso_provider_type"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    provider_type: Mapped[str] = mapped_column(Text, nullable=False)  # 'saml' or 'oidc'
    name: Mapped[str] = mapped_column(Text, nullable=False, default="")
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # SAML fields
    idp_entity_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    idp_sso_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    idp_slo_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    idp_certificate: Mapped[str | None] = mapped_column(Text, nullable=True)
    sp_entity_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    sp_acs_url: Mapped[str | None] = mapped_column(Text, nullable=True)

    # OIDC fields
    oidc_issuer: Mapped[str | None] = mapped_column(Text, nullable=True)
    oidc_client_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    oidc_client_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    oidc_scopes: Mapped[str] = mapped_column(Text, nullable=False, default="openid email profile")

    # Common
    attribute_mapping: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    default_role: Mapped[str] = mapped_column(Text, nullable=False, default="viewer")
    jit_provisioning: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

class SCIMToken(Base):
    """SCIM bearer token for automated user provisioning."""

    __tablename__ = "scim_tokens"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

class SSOAssertionID(Base):
    """Consumed SAML assertion IDs for replay protection."""

    __tablename__ = "sso_assertion_ids"

    assertion_id: Mapped[str] = mapped_column(Text, primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    consumed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
