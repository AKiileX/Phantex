# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — User Management Service.

Admin-only operations: create, list, update, deactivate users.
Plus self-service password change for any authenticated user.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.schemas.common import PageResult
from app.services.auth_service import hash_password
from app.utils.pagination import decode_cursor, encode_cursor
from app.utils.password import assert_password_strength

async def create_user(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    email: str,
    password: str,
    role: str,
    name: str | None = None,
) -> User:
    """
    Create a new user (admin only).

    Validates password complexity and email uniqueness within tenant.
    """
    # Validate password complexity
    assert_password_strength(password)

    # Check email uniqueness within tenant
    existing = await db.execute(
        select(User.id).where(
            User.tenant_id == tenant_id,
            User.email == email,
        )
    )
    if existing.scalar_one_or_none() is not None:
        raise ValueError(f"A user with email '{email}' already exists in this tenant")

    user = User(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        email=email,
        password_hash=hash_password(password),
        role=role,
        name=name,
        is_active=True,
        must_change_password=True,
    )
    db.add(user)
    try:
        await db.flush()
    except Exception as exc:
        # Handle race condition: concurrent insert with same email hits the
        # uq_users_tenant_email constraint. Surface as a clean 409-able error
        # instead of a raw 500 IntegrityError.
        if "uq_users_tenant_email" in str(exc) or "unique" in str(exc).lower():
            raise ValueError(f"A user with email '{email}' already exists in this tenant")
        raise
    return user

async def list_users(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    cursor: str | None = None,
    limit: int = 50,
) -> PageResult:
    """List users for a tenant with cursor pagination."""
    query = select(User).where(User.tenant_id == tenant_id)

    if cursor:
        cursor_data = decode_cursor(cursor)
        if cursor_data is not None:
            # Seek-style pagination matching ORDER BY (created_at DESC, id DESC).
            # Fixes: old code used `User.id > cursor_id` which is inconsistent
            # with descending created_at order, causing skipped/duplicate rows.
            cursor_ts, cursor_id = cursor_data
            query = query.where(
                (User.created_at < cursor_ts) | ((User.created_at == cursor_ts) & (User.id < cursor_id))
            )

    query = query.order_by(User.created_at.desc(), User.id.desc()).limit(limit + 1)

    result = await db.execute(query)
    users = list(result.scalars().all())

    has_more = len(users) > limit
    if has_more:
        users = users[:limit]

    next_cursor = None
    if has_more and users:
        last_user = users[-1]
        next_cursor = encode_cursor(last_user.created_at, last_user.id)

    return PageResult(items=users, next_cursor=next_cursor, has_more=has_more)

async def get_user(
    db: AsyncSession,
    user_id: uuid.UUID,
) -> User | None:
    """Get a single user by ID."""
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()

async def update_user(
    db: AsyncSession,
    user_id: uuid.UUID,
    role: str | None = None,
    name: str | None = None,
    is_active: bool | None = None,
) -> User | None:
    """Update user attributes (admin only)."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if user is None:
        return None

    if role is not None:
        if role not in ("admin", "analyst", "viewer"):
            raise ValueError(f"Invalid role: {role}")
        user.role = role
    if name is not None:
        user.name = name
    if is_active is not None:
        user.is_active = is_active

    await db.flush()
    return user

async def change_password(
    db: AsyncSession,
    user_id: uuid.UUID,
    current_password: str,
    new_password: str,
) -> bool:
    """
    Change a user's own password.

    Validates current password and new password complexity.
    Returns True on success, raises on failure.
    """
    from app.services.auth_service import revoke_all_refresh_tokens, verify_password

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if user is None:
        raise ValueError("User not found")

    if not verify_password(current_password, user.password_hash):
        raise ValueError("Current password is incorrect")

    # Validate new password complexity
    assert_password_strength(new_password)

    user.password_hash = hash_password(new_password)
    user.updated_at = datetime.now(UTC)
    # Clear the forced password change flag — the user has set a strong password
    user.must_change_password = False

    # Revoke all refresh tokens — force re-login on all devices
    await revoke_all_refresh_tokens(db, user_id)

    return True

async def count_users(db: AsyncSession, tenant_id: uuid.UUID) -> int:
    """Count users for a tenant."""
    result = await db.execute(select(func.count(User.id)).where(User.tenant_id == tenant_id))
    return result.scalar_one()
