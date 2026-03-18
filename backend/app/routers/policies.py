# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Policy Editor Router.

CRUD API for detection policies with YAML support, versioning,
and validation.

All endpoints are tenant-scoped via auth. Policy CRUD requires
admin or analyst role.

Endpoints:
  GET    /api/v1/policies              — List policies
  POST   /api/v1/policies              — Create policy
  GET    /api/v1/policies/:id          — Get policy detail
  PUT    /api/v1/policies/:id          — Update policy
  DELETE /api/v1/policies/:id          — Soft-delete policy
  POST   /api/v1/policies/validate     — Validate YAML/JSON without saving
  POST   /api/v1/policies/:id/apply    — Apply policy to matching agents
  GET    /api/v1/policies/:id/versions — Get version history
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query

from app.database import get_raw_db
from app.middleware.auth import get_current_active_user
from app.middleware.rate_limit import rate_limit
from app.schemas.auth import CurrentUser
from app.schemas.policy import (
    PolicyCreateRequest,
    PolicyListResponse,
    PolicyResponse,
    PolicyUpdateRequest,
    PolicyValidateRequest,
    PolicyValidationResult,
    PolicyVersionResponse,
)
from app.services.policy_service import (
    create_policy,
    delete_policy,
    get_policy,
    get_policy_versions,
    list_policies,
    parse_yaml_safe,
    update_policy,
    validate_policy_definition,
)
from app.utils.logging import get_logger

logger = get_logger("phantex.router.policies")

router = APIRouter(
    prefix="/api/v1/policies",
    tags=["policies"],
    dependencies=[Depends(rate_limit)],
)

# ── Auth Helpers ──────────────────────────────────────────────────────────────

def _require_policy_role(user: CurrentUser) -> None:
    """Raise 403 if user doesn't have admin or analyst role."""
    if user.role not in ("admin", "analyst"):
        raise HTTPException(
            status_code=403,
            detail="Policy management requires admin or analyst role",
        )

# ── List Policies ────────────────────────────────────────────────────────────

@router.get("", response_model=PolicyListResponse)
async def list_policies_endpoint(
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
    conn=Depends(get_raw_db),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    enabled_only: bool = Query(False),
):
    """List policies for the current tenant."""
    tenant_id = str(user.tenant_id)
    await conn.set_tenant(tenant_id)
    items, total = await list_policies(conn, tenant_id, page=page, page_size=page_size, enabled_only=enabled_only)
    return PolicyListResponse(
        items=[PolicyResponse(**item) for item in items],
        total=total,
        page=page,
        page_size=page_size,
    )

# ── Create Policy ────────────────────────────────────────────────────────────

@router.post("", response_model=PolicyResponse, status_code=201)
async def create_policy_endpoint(
    request: PolicyCreateRequest,
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
    conn=Depends(get_raw_db),
):
    """Create a new policy."""
    _require_policy_role(user)
    tenant_id = str(user.tenant_id)
    user_id = str(user.user_id)
    await conn.set_tenant(tenant_id)

    # Validate the definition
    validation = validate_policy_definition(request.definition.model_dump())
    if not validation.valid:
        raise HTTPException(status_code=422, detail={"errors": validation.errors})

    try:
        result = await create_policy(conn, tenant_id, user_id, request)
    except Exception as e:
        error_msg = str(e)
        if "uq_policies_tenant_name" in error_msg:
            raise HTTPException(
                status_code=409,
                detail=f"Policy with name '{request.name}' already exists",
            )
        raise HTTPException(status_code=500, detail="Failed to create policy")

    return PolicyResponse(**result)

# ── Get Policy ───────────────────────────────────────────────────────────────

@router.get("/{policy_id}", response_model=PolicyResponse)
async def get_policy_endpoint(
    policy_id: uuid.UUID,
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
    conn=Depends(get_raw_db),
):
    """Get a policy by ID."""
    tenant_id = str(user.tenant_id)
    await conn.set_tenant(tenant_id)
    result = await get_policy(conn, tenant_id, str(policy_id))
    if result is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    return PolicyResponse(**result)

# ── Update Policy ────────────────────────────────────────────────────────────

@router.put("/{policy_id}", response_model=PolicyResponse)
async def update_policy_endpoint(
    policy_id: uuid.UUID,
    request: PolicyUpdateRequest,
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
    conn=Depends(get_raw_db),
):
    """Update a policy (creates a new version)."""
    _require_policy_role(user)
    tenant_id = str(user.tenant_id)
    user_id = str(user.user_id)
    await conn.set_tenant(tenant_id)

    # Validate definition if provided
    if request.definition is not None:
        validation = validate_policy_definition(request.definition.model_dump())
        if not validation.valid:
            raise HTTPException(status_code=422, detail={"errors": validation.errors})

    result = await update_policy(conn, tenant_id, str(policy_id), user_id, request)
    if result is None:
        raise HTTPException(status_code=404, detail="Policy not found")

    return PolicyResponse(**result)

# ── Delete Policy ────────────────────────────────────────────────────────────

@router.delete("/{policy_id}", status_code=204)
async def delete_policy_endpoint(
    policy_id: uuid.UUID,
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
    conn=Depends(get_raw_db),
):
    """Soft-delete a policy (admin-recoverable)."""
    _require_policy_role(user)
    tenant_id = str(user.tenant_id)
    user_id = str(user.user_id)
    await conn.set_tenant(tenant_id)

    deleted = await delete_policy(conn, tenant_id, str(policy_id), user_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Policy not found")

# ── Validate Policy ──────────────────────────────────────────────────────────

@router.post("/validate", response_model=PolicyValidationResult)
async def validate_policy_endpoint(
    request: PolicyValidateRequest,
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Validate a policy definition without saving."""
    _require_policy_role(user)

    if request.yaml_content:
        parsed, errors = parse_yaml_safe(request.yaml_content)
        if errors:
            return PolicyValidationResult(valid=False, errors=errors)
        if parsed is None:
            return PolicyValidationResult(valid=False, errors=["Failed to parse YAML"])
        return validate_policy_definition(parsed)

    if request.json_content:
        return validate_policy_definition(request.json_content.model_dump())

    raise HTTPException(
        status_code=400,
        detail="Provide either yaml_content or json_content",
    )

# ── Apply Policy ─────────────────────────────────────────────────────────────

@router.post("/{policy_id}/apply")
async def apply_policy_endpoint(
    policy_id: uuid.UUID,
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
    conn=Depends(get_raw_db),
):
    """Apply policy to matching agents immediately."""
    _require_policy_role(user)
    tenant_id = str(user.tenant_id)
    await conn.set_tenant(tenant_id)

    policy = await get_policy(conn, tenant_id, str(policy_id))
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found")

    if not policy["enabled"]:
        raise HTTPException(status_code=400, detail="Cannot apply disabled policy")

    # The actual application happens in the policy engine consumer.
    # Here we just validate and signal that the policy should be applied.
    definition = policy["definition"]
    rules_count = len(definition.get("rules", []))
    scope_tags = policy["scope_agent_tags"]
    scope_frameworks = policy["scope_frameworks"]

    logger.info(
        "policy_apply_requested",
        policy_id=str(policy_id),
        rules=rules_count,
        scope_tags=scope_tags,
        scope_frameworks=scope_frameworks,
    )

    return {
        "status": "applied",
        "policy_id": str(policy_id),
        "policy_name": policy["name"],
        "rules_count": rules_count,
        "scope": {
            "agent_tags": scope_tags,
            "frameworks": scope_frameworks,
        },
    }

# ── Version History ──────────────────────────────────────────────────────────

@router.get("/{policy_id}/versions", response_model=list[PolicyVersionResponse])
async def get_versions_endpoint(
    policy_id: uuid.UUID,
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
    conn=Depends(get_raw_db),
):
    """Get version history for a policy."""
    tenant_id = str(user.tenant_id)
    await conn.set_tenant(tenant_id)

    # Verify policy exists
    policy = await get_policy(conn, tenant_id, str(policy_id))
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found")

    versions = await get_policy_versions(conn, tenant_id, str(policy_id))
    return [PolicyVersionResponse(**v) for v in versions]
