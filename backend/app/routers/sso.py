# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — SSO Router (S1: SAML 2.0 + S2: OIDC).

Endpoints:
  POST /api/v1/sso/saml/login      — Initiate SAML SP-initiated SSO
  POST /api/v1/sso/saml/acs        — SAML Assertion Consumer Service (callback)
  POST /api/v1/sso/oidc/login      — Initiate OIDC Authorization Code + PKCE
  GET  /api/v1/sso/oidc/callback   — OIDC callback (authorization code exchange)
  GET  /api/v1/sso/configs         — List SSO configs (admin)
  POST /api/v1/sso/configs         — Create SSO config (admin)
  PUT  /api/v1/sso/configs/{id}    — Update SSO config (admin)
  DELETE /api/v1/sso/configs/{id}  — Delete SSO config (admin)
"""

import os
import uuid
from typing import Annotated
from urllib.parse import urlparse

from cachetools import TTLCache
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_admin_db
from app.middleware.abac import require_permission
from app.middleware.rate_limit import sso_rate_limit
from app.schemas.auth import CurrentUser
from app.schemas.sso import (
    OIDCLoginResponse,
    SAMLLoginResponse,
    SSOCallbackResponse,
    SSOConfigCreate,
    SSOConfigResponse,
    SSOConfigUpdate,
)
from app.services.auth_service import create_token_pair
from app.services.sso_service import (
    build_oidc_auth_url,
    build_saml_authn_request,
    create_sso_config,
    exchange_oidc_code,
    get_sso_config,
    get_sso_config_by_id,
    jit_provision_or_link,
    list_sso_configs,
    update_sso_config,
    validate_saml_response,
)
from app.utils.logging import get_logger

logger = get_logger("phantex.routers.sso")

router = APIRouter(prefix="/api/v1/sso", tags=["sso"])

# Bounded state store with 5-minute TTL and 10K max entries (C-3 hardening)
_oidc_state_store: TTLCache = TTLCache(maxsize=10_000, ttl=300)

# ── SAML 2.0 Endpoints ───────────────────────────────────────────────────────

@router.post("/saml/login", response_model=SAMLLoginResponse, dependencies=[Depends(sso_rate_limit)])
async def saml_login(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_admin_db)],
    tenant_id: uuid.UUID | None = None,
):
    """
    Initiate SAML SP-initiated SSO.
    Returns redirect URL to the IdP.
    """
    # Resolve tenant from query param or request header
    if not tenant_id:
        tenant_slug = request.headers.get("X-Phantex-Tenant")
        if not tenant_slug:
            raise HTTPException(status_code=400, detail="tenant_id or X-Phantex-Tenant header required")
        from app.services.tenant_service import get_tenant_by_slug

        tenant = await get_tenant_by_slug(db, tenant_slug)
        if not tenant:
            raise HTTPException(status_code=404, detail="Tenant not found")
        tenant_id = tenant.id

    config = await get_sso_config(db, tenant_id, "saml")
    if not config:
        raise HTTPException(status_code=404, detail="SAML SSO not configured for this tenant")

    result = build_saml_authn_request(config)
    return SAMLLoginResponse(
        redirect_url=result["redirect_url"],
        relay_state=result["relay_state"],
    )

@router.post("/saml/acs", response_model=SSOCallbackResponse, dependencies=[Depends(sso_rate_limit)])
async def saml_acs(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_admin_db)],
):
    """
    SAML Assertion Consumer Service — IdP posts SAML Response here.
    Validates assertion, provisions/links user, returns Phantex JWT pair.
    """
    form_data = await request.form()
    saml_response = form_data.get("SAMLResponse")
    if not saml_response:
        raise HTTPException(status_code=400, detail="Missing SAMLResponse in form data")

    # M-10: Enforce max SAML response size (256 KB base64 ≈ 192 KB XML)
    if len(str(saml_response)) > 256_000:
        raise HTTPException(status_code=400, detail="SAMLResponse exceeds maximum allowed size")

    # Determine tenant from RelayState or form
    form_data.get("RelayState", "")
    tenant_id_str = request.query_params.get("tenant_id")
    if not tenant_id_str:
        raise HTTPException(status_code=400, detail="tenant_id required in query params")

    try:
        tenant_id = uuid.UUID(tenant_id_str)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid tenant_id")

    config = await get_sso_config(db, tenant_id, "saml")
    if not config:
        raise HTTPException(status_code=404, detail="SAML SSO not configured")

    try:
        user_attrs = await validate_saml_response(db, config, str(saml_response))
    except ValueError as e:
        logger.warning("saml_validation_failed", error=str(e), tenant_id=str(tenant_id))
        raise HTTPException(status_code=401, detail="SAML authentication failed")

    # JIT provision or link existing user
    try:
        user, is_new = await jit_provision_or_link(db, config, user_attrs, "saml")
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e))

    # Issue Phantex JWT pair
    token_pair = await create_token_pair(db, user)
    await db.commit()

    # Redirect browser to frontend SSO callback page with tokens in hash fragment.
    # Hash fragments are never sent to the server, reducing token exposure.
    frontend_url = os.getenv("PHANTEX_FRONTEND_URL", "http://localhost:3000")
    # Validate the redirect target to prevent open-redirect attacks
    parsed = urlparse(frontend_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        logger.error("invalid_frontend_url", frontend_url=frontend_url)
        raise HTTPException(status_code=500, detail="SSO redirect misconfigured")
    fragment = (
        f"access_token={token_pair.access_token}"
        f"&refresh_token={token_pair.refresh_token}"
        f"&expires_in={token_pair.expires_in}"
    )
    return RedirectResponse(
        url=f"{frontend_url}/sso/callback#{fragment}",
        status_code=302,
    )

# ── OIDC Endpoints ────────────────────────────────────────────────────────────

@router.post("/oidc/login", response_model=OIDCLoginResponse, dependencies=[Depends(sso_rate_limit)])
async def oidc_login(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_admin_db)],
    tenant_id: uuid.UUID | None = None,
):
    """
    Initiate OIDC Authorization Code + PKCE flow.
    Returns redirect URL to the IdP.
    """
    if not tenant_id:
        tenant_slug = request.headers.get("X-Phantex-Tenant")
        if not tenant_slug:
            raise HTTPException(status_code=400, detail="tenant_id or X-Phantex-Tenant header required")
        from app.services.tenant_service import get_tenant_by_slug

        tenant = await get_tenant_by_slug(db, tenant_slug)
        if not tenant:
            raise HTTPException(status_code=404, detail="Tenant not found")
        tenant_id = tenant.id

    config = await get_sso_config(db, tenant_id, "oidc")
    if not config:
        raise HTTPException(status_code=404, detail="OIDC SSO not configured for this tenant")

    result = build_oidc_auth_url(config)

    # Store state → code_verifier mapping (use Redis in production)
    _oidc_state_store[result["state"]] = {
        "code_verifier": result["code_verifier"],
        "tenant_id": str(tenant_id),
        "nonce": result["nonce"],
    }

    return OIDCLoginResponse(
        redirect_url=result["redirect_url"],
        state=result["state"],
        nonce=result["nonce"],
    )

@router.get("/oidc/callback", response_model=SSOCallbackResponse, dependencies=[Depends(sso_rate_limit)])
async def oidc_callback(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_admin_db)],
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
):
    """
    OIDC callback — exchange authorization code for tokens.
    """
    if error:
        raise HTTPException(status_code=401, detail=f"OIDC error: {error}")

    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing code or state parameter")

    # Retrieve state
    state_data = _oidc_state_store.pop(state, None)
    if not state_data:
        raise HTTPException(status_code=400, detail="Invalid or expired state parameter")

    tenant_id = uuid.UUID(state_data["tenant_id"])
    code_verifier = state_data["code_verifier"]
    expected_nonce = state_data.get("nonce")

    config = await get_sso_config(db, tenant_id, "oidc")
    if not config:
        raise HTTPException(status_code=404, detail="OIDC config not found")

    try:
        user_attrs = await exchange_oidc_code(config, code, code_verifier, expected_nonce)
    except ValueError as e:
        logger.warning("oidc_exchange_failed", error=str(e), tenant_id=str(tenant_id))
        raise HTTPException(status_code=401, detail=str(e))

    # JIT provision or link
    try:
        user, is_new = await jit_provision_or_link(db, config, user_attrs, "oidc")
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e))

    token_pair = await create_token_pair(db, user)
    await db.commit()

    # Redirect browser to frontend SSO callback page with tokens in hash fragment
    frontend_url = os.getenv("PHANTEX_FRONTEND_URL", "http://localhost:3000")
    parsed = urlparse(frontend_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        logger.error("invalid_frontend_url", frontend_url=frontend_url)
        raise HTTPException(status_code=500, detail="SSO redirect misconfigured")
    fragment = (
        f"access_token={token_pair.access_token}"
        f"&refresh_token={token_pair.refresh_token}"
        f"&expires_in={token_pair.expires_in}"
    )
    return RedirectResponse(
        url=f"{frontend_url}/sso/callback#{fragment}",
        status_code=302,
    )

# ── SSO Config Management (admin) ────────────────────────────────────────────

@router.get(
    "/configs",
    response_model=list[SSOConfigResponse],
    dependencies=[Depends(require_permission("auth.manage"))],
)
async def list_configs(
    current_user: Annotated[CurrentUser, Depends(require_permission("auth.manage"))],
    db: Annotated[AsyncSession, Depends(get_admin_db)],
):
    """List all SSO configurations for the current tenant."""
    configs = await list_sso_configs(db, current_user.tenant_id)
    return [SSOConfigResponse.model_validate(c) for c in configs]

@router.post(
    "/configs",
    response_model=SSOConfigResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_config(
    body: SSOConfigCreate,
    current_user: Annotated[CurrentUser, Depends(require_permission("auth.manage"))],
    db: Annotated[AsyncSession, Depends(get_admin_db)],
):
    """Create a new SSO configuration."""
    config = await create_sso_config(db, current_user.tenant_id, body.model_dump(exclude_unset=True))
    await db.commit()
    return SSOConfigResponse.model_validate(config)

@router.put("/configs/{config_id}", response_model=SSOConfigResponse)
async def update_config(
    config_id: uuid.UUID,
    body: SSOConfigUpdate,
    current_user: Annotated[CurrentUser, Depends(require_permission("auth.manage"))],
    db: Annotated[AsyncSession, Depends(get_admin_db)],
):
    """Update an SSO configuration."""
    config = await get_sso_config_by_id(db, config_id)
    if not config or config.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="SSO config not found")

    updated = await update_sso_config(db, config, body.model_dump(exclude_unset=True))
    await db.commit()
    return SSOConfigResponse.model_validate(updated)

@router.delete("/configs/{config_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_config(
    config_id: uuid.UUID,
    current_user: Annotated[CurrentUser, Depends(require_permission("auth.manage"))],
    db: Annotated[AsyncSession, Depends(get_admin_db)],
):
    """Delete an SSO configuration."""
    config = await get_sso_config_by_id(db, config_id)
    if not config or config.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="SSO config not found")

    await db.delete(config)
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
