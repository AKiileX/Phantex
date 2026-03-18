# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Rules Router.

GET    /api/v1/rules         — List rules (paginated, filterable)
POST   /api/v1/rules         — Create a new detection rule
GET    /api/v1/rules/{id}    — Get rule details
PATCH  /api/v1/rules/{id}    — Update a rule
DELETE /api/v1/rules/{id}    — Soft-delete a rule (disable it)
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.middleware.abac import require_permission
from app.middleware.auth import get_current_user
from app.middleware.rate_limit import rate_limit
from app.middleware.tenant import enforce_tenant_isolation
from app.schemas.auth import CurrentUser
from app.schemas.common import CursorPage
from app.schemas.rule import RuleCreate, RuleFilter, RuleResponse, RuleSummary, RuleUpdate
from app.services import audit_service, rule_service

router = APIRouter(prefix="/api/v1/rules", tags=["rules"], dependencies=[Depends(rate_limit)])

@router.get(
    "",
    response_model=CursorPage[RuleSummary],
    summary="List detection rules",
)
async def list_rules(
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    enabled: bool | None = None,
    severity: str | None = None,
    attack_class: str | None = None,
    search: str | None = None,
    cursor: str | None = None,
    limit: int = Query(50, ge=1, le=100),
):
    """List detection rules for the current tenant (includes global rules)."""
    filters = RuleFilter(
        enabled=enabled,
        severity=severity,
        attack_class=attack_class,
        search=search,
    )
    page = await rule_service.list_rules(db, filters, cursor=cursor, limit=limit)

    return CursorPage(
        items=[RuleSummary.model_validate(r) for r in page.items],
        next_cursor=page.next_cursor,
        has_more=page.has_more,
    )

@router.post(
    "",
    response_model=RuleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create detection rule",
    dependencies=[Depends(require_permission("rules.write"))],
)
async def create_rule(
    body: RuleCreate,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """Create a new PRL detection rule. Requires admin or analyst role."""
    rule = await rule_service.create_rule(db, body, tenant_id=current_user.tenant_id, author=current_user.email)

    await audit_service.log_action(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action="rule.created",
        resource_type="rule",
        resource_id=rule.id,
        details={"name": rule.name, "severity": rule.severity},
    )

    return rule

@router.get(
    "/{rule_id}",
    response_model=RuleResponse,
    summary="Get rule details",
)
async def get_rule(
    rule_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """Get full details of a specific rule."""
    rule = await rule_service.get_rule(db, rule_id)
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return rule

@router.patch(
    "/{rule_id}",
    response_model=RuleResponse,
    summary="Update a rule",
    dependencies=[Depends(require_permission("rules.write"))],
)
async def update_rule(
    rule_id: uuid.UUID,
    body: RuleUpdate,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """Update a detection rule. Requires admin or analyst role."""
    try:
        rule = await rule_service.update_rule(db, rule_id, body)
    except PermissionError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot modify global rules")
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")

    await audit_service.log_action(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action="rule.updated",
        resource_type="rule",
        resource_id=rule_id,
        details=body.model_dump(exclude_unset=True),
    )

    return rule

@router.delete(
    "/{rule_id}",
    response_model=RuleResponse,
    summary="Soft-delete a rule",
    dependencies=[Depends(require_permission("rules.delete"))],
)
async def delete_rule(
    rule_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """
    Soft-delete a rule by disabling it. Only admin can delete.
    Global rules (shipped with Phantex) cannot be deleted.
    """
    try:
        rule = await rule_service.soft_delete_rule(db, rule_id)
    except PermissionError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot delete global rules",
        )
    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found",
        )

    await audit_service.log_action(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action="rule.deleted",
        resource_type="rule",
        resource_id=rule_id,
    )

    return rule
