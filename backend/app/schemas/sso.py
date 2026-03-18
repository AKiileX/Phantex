# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Pydantic schemas — SSO (SAML 2.0 + OIDC configuration and flows)."""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.common import PhantexBase

# ── SSO Config CRUD ───────────────────────────────────────────────────────────

class SSOConfigCreate(BaseModel):
    """Create a new SSO configuration."""

    provider_type: str = Field(..., pattern=r"^(saml|oidc)$")
    name: str = Field("", max_length=128)
    is_enabled: bool = False

    # SAML
    idp_entity_id: str | None = None
    idp_sso_url: str | None = None
    idp_slo_url: str | None = None
    idp_certificate: str | None = None  # PEM
    sp_entity_id: str | None = None
    sp_acs_url: str | None = None

    # OIDC
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: str | None = None
    oidc_scopes: str = "openid email profile"

    # Common
    attribute_mapping: dict = Field(default_factory=dict)
    default_role: str = "viewer"
    jit_provisioning: bool = True

class SSOConfigUpdate(BaseModel):
    """Update SSO config (partial)."""

    is_enabled: bool | None = None
    idp_entity_id: str | None = None
    idp_sso_url: str | None = None
    idp_slo_url: str | None = None
    idp_certificate: str | None = None
    sp_entity_id: str | None = None
    sp_acs_url: str | None = None
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: str | None = None
    oidc_scopes: str | None = None
    attribute_mapping: dict | None = None
    default_role: str | None = None
    jit_provisioning: bool | None = None

class SSOConfigResponse(PhantexBase):
    """SSO configuration (redacts secrets)."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    provider_type: str
    name: str
    is_enabled: bool

    # SAML (public fields only)
    idp_entity_id: str | None = None
    idp_sso_url: str | None = None
    idp_slo_url: str | None = None
    sp_entity_id: str | None = None
    sp_acs_url: str | None = None

    # OIDC (client_secret redacted)
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    oidc_scopes: str | None = None

    # Common
    attribute_mapping: dict = {}
    default_role: str = "viewer"
    jit_provisioning: bool = True
    created_at: datetime
    updated_at: datetime

# ── SSO Flow ──────────────────────────────────────────────────────────────────

class SAMLLoginResponse(BaseModel):
    """Response initiating SAML SSO — redirect URL to IdP."""

    redirect_url: str
    relay_state: str | None = None

class OIDCLoginResponse(BaseModel):
    """Response initiating OIDC SSO — redirect URL to IdP."""

    redirect_url: str
    state: str
    nonce: str

class SSOCallbackResponse(BaseModel):
    """Response after successful SSO callback — returns Phantex tokens."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: uuid.UUID
    email: str
    is_new_user: bool = False
