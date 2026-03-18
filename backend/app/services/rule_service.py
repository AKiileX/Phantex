# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Rule Service.

Business logic for CRUD operations on PRL detection rules.
"""

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.rule import Rule
from app.schemas.common import PageResult
from app.schemas.rule import RuleCreate, RuleFilter, RuleUpdate
from app.utils.pagination import decode_cursor, encode_cursor

async def list_rules(
    db: AsyncSession,
    filters: RuleFilter,
    cursor: str | None = None,
    limit: int = 50,
) -> PageResult:
    """
    List rules with filters and cursor pagination.
    RLS returns tenant-specific + global (tenant_id IS NULL) rules.
    """
    limit = max(1, min(limit, 100))
    query = select(Rule).order_by(Rule.created_at.desc(), Rule.id.desc())

    if filters.enabled is not None:
        query = query.where(Rule.enabled == filters.enabled)
    if filters.severity:
        query = query.where(Rule.severity == filters.severity)
    if filters.attack_class:
        query = query.where(Rule.attack_class == filters.attack_class)
    if filters.search:
        escaped = filters.search.replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        query = query.where(Rule.name.ilike(pattern))

    if cursor:
        decoded = decode_cursor(cursor)
        if decoded:
            ts, uid = decoded
            query = query.where((Rule.created_at < ts) | ((Rule.created_at == ts) & (Rule.id < uid)))

    result = await db.execute(query.limit(limit + 1))
    rules = list(result.scalars().all())

    has_more = len(rules) > limit
    items = rules[:limit]

    next_cursor = None
    if has_more and items:
        last = items[-1]
        next_cursor = encode_cursor(last.created_at, last.id)

    return PageResult(items=items, next_cursor=next_cursor, has_more=has_more)

async def get_rule(db: AsyncSession, rule_id: uuid.UUID) -> Rule | None:
    """Get a single rule by ID."""
    result = await db.execute(select(Rule).where(Rule.id == rule_id))
    return result.scalar_one_or_none()

async def create_rule(
    db: AsyncSession,
    data: RuleCreate,
    tenant_id: uuid.UUID,
    author: str | None = None,
) -> Rule:
    """Create a new tenant-scoped detection rule."""
    rule = Rule(
        tenant_id=tenant_id,
        name=data.name,
        description=data.description,
        severity=data.severity,
        attack_class=data.attack_class,
        prl_source=data.prl_source,
        enabled=data.enabled,
        author=author,
    )
    db.add(rule)
    await db.flush()
    await db.refresh(rule)
    return rule

async def update_rule(db: AsyncSession, rule_id: uuid.UUID, data: RuleUpdate) -> Rule | None:
    """Update an existing rule. Returns None if not found."""
    rule = await get_rule(db, rule_id)
    if rule is None:
        return None

    update_data = data.model_dump(exclude_unset=True)

    # Global rules (tenant_id IS NULL): only allow toggling 'enabled'.
    # All other field changes are blocked — defense-in-depth alongside RLS.
    if rule.tenant_id is None:
        allowed_global_fields = {"enabled"}
        non_toggle_fields = set(update_data.keys()) - allowed_global_fields
        if non_toggle_fields:
            raise PermissionError("Cannot modify global rules (only enable/disable is allowed)")

    for field, value in update_data.items():
        setattr(rule, field, value)

    # Bump version on content changes
    if "prl_source" in update_data or "enabled" in update_data:
        rule.version += 1

    await db.flush()
    await db.refresh(rule)
    return rule

async def soft_delete_rule(db: AsyncSession, rule_id: uuid.UUID) -> Rule | None:
    """
    Soft-delete a rule by disabling it.
    We don't truly DELETE because phantex_app has no DELETE permission.
    """
    rule = await get_rule(db, rule_id)
    if rule is None:
        return None

    # Only allow deleting tenant-scoped rules, not global ones
    if rule.tenant_id is None:
        raise PermissionError("Cannot delete global rules")

    rule.enabled = False
    await db.flush()
    await db.refresh(rule)
    return rule

async def count_rules(db: AsyncSession) -> tuple[int, int]:
    """Return (total_rules, enabled_rules) for the current tenant."""
    total_result = await db.execute(select(func.count(Rule.id)))
    enabled_result = await db.execute(
        select(func.count(Rule.id)).where(Rule.enabled == True)  # noqa: E712
    )
    return total_result.scalar_one(), enabled_result.scalar_one()
