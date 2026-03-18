# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — SCIM 2.0 Service (RFC 7643/7644).

Handles automated user lifecycle management:
  - Create / Read / Update / Deactivate users via SCIM
  - Group membership → role mapping
  - Bearer token authentication for SCIM endpoints
"""

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.sso import SCIMToken
from app.models.user import User
from app.schemas.scim import SCIMEmail, SCIMMeta, SCIMName, SCIMUser
from app.services.auth_service import hash_password
from app.utils.logging import get_logger

logger = get_logger("phantex.services.scim")

# ── SCIM Token Management ────────────────────────────────────────────────────

def _hash_token(token: str) -> str:
    """SHA-256 hash of a SCIM bearer token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

async def create_scim_token(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    description: str = "",
    expires_in_days: int | None = None,
) -> tuple[SCIMToken, str]:
    """
    Create a SCIM bearer token. Returns (db_token, raw_token).
    The raw token is only returned once — store it securely.
    """
    raw_token = f"scim_{secrets.token_urlsafe(48)}"
    token_hash = _hash_token(raw_token)

    expires_at = None
    if expires_in_days:
        expires_at = datetime.now(UTC) + timedelta(days=expires_in_days)

    db_token = SCIMToken(
        tenant_id=tenant_id,
        token_hash=token_hash,
        description=description,
        expires_at=expires_at,
    )
    db.add(db_token)
    await db.flush()

    logger.info("scim_token_created", tenant_id=str(tenant_id), description=description)
    return db_token, raw_token

async def validate_scim_token(db: AsyncSession, raw_token: str) -> uuid.UUID | None:
    """
    Validate a SCIM bearer token and return the tenant_id.
    Returns None if token is invalid or expired.
    """
    token_hash = _hash_token(raw_token)

    result = await db.execute(
        select(SCIMToken).where(
            SCIMToken.token_hash == token_hash,
            SCIMToken.is_active == True,  # noqa: E712
        )
    )
    token = result.scalar_one_or_none()

    if token is None:
        return None

    # Check expiry
    if token.expires_at and token.expires_at < datetime.now(UTC):
        return None

    return token.tenant_id

async def list_scim_tokens(db: AsyncSession, tenant_id: uuid.UUID) -> list[SCIMToken]:
    """List all SCIM tokens for a tenant."""
    result = await db.execute(
        select(SCIMToken).where(SCIMToken.tenant_id == tenant_id).order_by(SCIMToken.created_at.desc())
    )
    return list(result.scalars().all())

async def revoke_scim_token(db: AsyncSession, token_id: uuid.UUID, tenant_id: uuid.UUID | None = None) -> bool:
    """Revoke a SCIM token by ID. Optionally scope to tenant_id for isolation (H-5)."""
    query = select(SCIMToken).where(SCIMToken.id == token_id)
    if tenant_id is not None:
        query = query.where(SCIMToken.tenant_id == tenant_id)
    result = await db.execute(query)
    token = result.scalar_one_or_none()
    if token is None:
        return False
    token.is_active = False
    await db.flush()
    logger.info("scim_token_revoked", token_id=str(token_id))
    return True

# ── SCIM User Operations ─────────────────────────────────────────────────────

def _user_to_scim(user: User, base_url: str = "") -> SCIMUser:
    """Convert a Phantex User to SCIM User resource."""
    return SCIMUser(
        id=str(user.id),
        externalId=user.scim_external_id,
        userName=user.email,
        name=SCIMName(formatted=user.name) if user.name else None,
        displayName=user.name,
        emails=[SCIMEmail(value=user.email, primary=True)] if user.email else [],
        active=user.is_active,
        meta=SCIMMeta(
            resourceType="User",
            created=user.created_at.isoformat() if user.created_at else None,
            lastModified=user.updated_at.isoformat() if user.updated_at else None,
            location=f"{base_url}/scim/v2/Users/{user.id}" if base_url else None,
        ),
    )

async def scim_list_users(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    start_index: int = 1,
    count: int = 100,
    filter_str: str | None = None,
) -> tuple[list[User], int]:
    """
    List users for SCIM (RFC 7644 §3.4.2).
    Supports basic filter: userName eq "user@example.com"
    """
    query = select(User).where(User.tenant_id == tenant_id)

    # Basic SCIM filter support (L-6: reject unsupported filters explicitly)
    if filter_str:
        parts = filter_str.strip().split(" ", 2)
        if len(parts) == 3 and parts[0].lower() == "username" and parts[1].lower() == "eq":
            email_value = parts[2].strip('"').strip("'")
            query = query.where(User.email == email_value.lower())
        else:
            raise ValueError(f"Unsupported SCIM filter: {filter_str}. Only 'userName eq \"value\"' is supported.")

    # Total count
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    # Pagination (SCIM uses 1-based indexing)
    offset = max(0, start_index - 1)
    query = query.order_by(User.created_at).offset(offset).limit(count)

    result = await db.execute(query)
    users = list(result.scalars().all())

    return users, total

async def scim_get_user(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
) -> User | None:
    """Get a single user by ID (SCIM)."""
    result = await db.execute(select(User).where(User.id == user_id, User.tenant_id == tenant_id))
    return result.scalar_one_or_none()

async def scim_create_user(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    data: dict,
) -> User:
    """
    Create a user via SCIM.

    data keys: userName, externalId, displayName, name, emails, password, active
    """
    email = data.get("userName", "").lower().strip()
    if not email:
        raise ValueError("userName (email) is required")

    # Check for existing user
    existing = await db.execute(select(User).where(User.tenant_id == tenant_id, User.email == email))
    if existing.scalar_one_or_none():
        raise ValueError(f"User {email} already exists")

    # Build name
    name = data.get("displayName")
    if not name and data.get("name"):
        name_obj = data["name"]
        if isinstance(name_obj, dict):
            name = (
                name_obj.get("formatted") or f"{name_obj.get('givenName', '')} {name_obj.get('familyName', '')}".strip()
            )

    # Password: if provided use it, else generate random (SCIM user, password set later)
    password = data.get("password") or secrets.token_urlsafe(32)

    user = User(
        tenant_id=tenant_id,
        email=email,
        password_hash=hash_password(password),
        role="viewer",  # Default SCIM role; mapped via groups later
        name=name,
        is_active=data.get("active", True),
        scim_external_id=data.get("externalId"),
        sso_provider="scim",
    )
    db.add(user)
    await db.flush()

    logger.info("scim_user_created", user_id=str(user.id), email=email, tenant_id=str(tenant_id))
    return user

async def scim_update_user(
    db: AsyncSession,
    user: User,
    data: dict,
) -> User:
    """
    Update user via SCIM (full replace).
    """
    if "userName" in data:
        user.email = data["userName"].lower().strip()
    if "displayName" in data:
        user.name = data["displayName"]
    if "name" in data and isinstance(data["name"], dict):
        user.name = data["name"].get("formatted") or user.name
    if "active" in data:
        user.is_active = data["active"]
    if "externalId" in data:
        user.scim_external_id = data["externalId"]

    # Update emails
    if "emails" in data and data["emails"]:
        primary_email = next(
            (e for e in data["emails"] if isinstance(e, dict) and e.get("primary")),
            data["emails"][0] if data["emails"] else None,
        )
        if primary_email and isinstance(primary_email, dict):
            user.email = primary_email.get("value", user.email).lower().strip()

    user.updated_at = datetime.now(UTC)
    await db.flush()

    logger.info("scim_user_updated", user_id=str(user.id), email=user.email)
    return user

async def scim_patch_user(
    db: AsyncSession,
    user: User,
    operations: list[dict],
) -> User:
    """
    Apply SCIM PATCH operations (RFC 7644 §3.5.2).
    """
    for op in operations:
        op_type = op.get("op", "").lower()
        path = op.get("path", "")
        value = op.get("value")

        if op_type == "replace":
            if path == "active" or (not path and isinstance(value, dict) and "active" in value):
                active_val = value if isinstance(value, bool) else value.get("active", True)
                user.is_active = active_val
            elif path == "userName":
                user.email = str(value).lower().strip()
            elif path == "displayName" or path == "name.formatted":
                user.name = str(value)
            elif path == "externalId":
                user.scim_external_id = str(value)
            elif not path and isinstance(value, dict):
                # Bulk replace
                if "userName" in value:
                    user.email = value["userName"].lower().strip()
                if "displayName" in value:
                    user.name = value["displayName"]
                if "active" in value:
                    user.is_active = value["active"]
        elif op_type == "add" and path == "emails" and isinstance(value, list) and value:
            user.email = value[0].get("value", user.email).lower().strip()

    user.updated_at = datetime.now(UTC)
    await db.flush()

    logger.info("scim_user_patched", user_id=str(user.id))
    return user
