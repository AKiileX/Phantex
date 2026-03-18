# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Shadow Mode Manager.

Shadow mode is the safe-rollout mechanism for auto-response policies.
When enabled (default for new tenants), the decision layer evaluates alerts
and determines which actions WOULD fire, but does NOT actually enforce them.

Instead, shadow decisions are:
  1. Logged to response_action_log with decision="shadow"
  2. Optionally notified to SOC via configured channel (audit visibility)
  3. Available in the dashboard for review before going live

Lifecycle:
  - New tenant → shadow_mode=true (safe default)
  - Admin reviews shadow logs → gains confidence in policy accuracy
  - Admin disables shadow mode → actions enforce in real-time
  - Optionally: shadow_expires_at allows time-boxed shadow periods

SECURITY:
  - All queries include explicit tenant_id (defense-in-depth)
  - Shadow mode is per-tenant (cannot be disabled globally by accident)
  - Default is ON — must be explicitly disabled
  - Expiry is checked on every evaluation (cannot be bypassed by clock drift)
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger("phantex.response.shadow")

async def is_shadow_mode(db: AsyncSession, tenant_id: str) -> bool:
    """
    Check if shadow mode is active for a tenant.

    Shadow mode is active if:
      - shadow_mode = true AND (shadow_expires_at IS NULL OR shadow_expires_at > now())
      - OR no config row exists (safe default = shadow ON)
    """
    query = text("""
        SELECT shadow_mode, shadow_expires_at
        FROM response_config
        WHERE tenant_id = :tid
    """)
    result = await db.execute(query, {"tid": tenant_id})
    row = result.mappings().first()

    if not row:
        # No config = safe default (shadow ON)
        return True

    if not row["shadow_mode"]:
        return False

    # Shadow mode is on — check expiry
    expires = row["shadow_expires_at"]
    if expires is not None:
        now = datetime.now(UTC)
        if now > expires:
            # Shadow expired — auto-transition to enforcement
            logger.info("shadow_mode_expired", tenant_id=tenant_id, expires_at=str(expires))
            # Update the row to reflect expiry
            await _set_shadow_mode(db, tenant_id, enabled=False, reason="Auto-expired")
            return False

    return True

async def _set_shadow_mode(
    db: AsyncSession,
    tenant_id: str,
    *,
    enabled: bool,
    reason: str = "",
    set_by: str | None = None,
    expires_at: datetime | None = None,
) -> None:
    """Internal helper to update shadow mode state."""
    query = text("""
        INSERT INTO response_config (tenant_id, shadow_mode, shadow_expires_at, shadow_set_by, updated_at)
        VALUES (:tid, :enabled, :expires_at, :set_by, now())
        ON CONFLICT (tenant_id) DO UPDATE SET
            shadow_mode = :enabled,
            shadow_expires_at = :expires_at,
            shadow_set_by = :set_by,
            updated_at = now()
    """)
    await db.execute(
        query,
        {
            "tid": tenant_id,
            "enabled": enabled,
            "expires_at": expires_at,
            "set_by": set_by,
        },
    )
    await db.commit()
    logger.info(
        "shadow_mode_updated",
        tenant_id=tenant_id,
        enabled=enabled,
        reason=reason,
    )

async def enable_shadow_mode(
    db: AsyncSession,
    tenant_id: str,
    *,
    set_by: str | None = None,
    duration_hours: int | None = None,
) -> dict[str, Any]:
    """
    Enable shadow mode for a tenant. Optionally set a time-boxed duration.

    Returns the new configuration state.
    """
    expires_at = None
    if duration_hours is not None and duration_hours > 0:
        from datetime import timedelta

        expires_at = datetime.now(UTC) + timedelta(hours=min(duration_hours, 8760))  # Cap 1 year

    await _set_shadow_mode(
        db,
        tenant_id,
        enabled=True,
        reason=f"Enabled by user (duration={duration_hours}h)" if duration_hours else "Enabled by user",
        set_by=set_by,
        expires_at=expires_at,
    )
    return {
        "shadow_mode": True,
        "expires_at": expires_at.isoformat() if expires_at else None,
    }

async def disable_shadow_mode(
    db: AsyncSession,
    tenant_id: str,
    *,
    set_by: str | None = None,
) -> dict[str, Any]:
    """
    Disable shadow mode — actions will now enforce in real-time.

    This is a high-impact operation and should require response.write permission.
    """
    await _set_shadow_mode(
        db,
        tenant_id,
        enabled=False,
        reason="Disabled by user — enforcement active",
        set_by=set_by,
    )
    return {"shadow_mode": False, "expires_at": None}

async def get_shadow_status(
    db: AsyncSession,
    tenant_id: str,
) -> dict[str, Any]:
    """Get current shadow mode status for a tenant."""
    query = text("""
        SELECT shadow_mode, shadow_expires_at, shadow_set_by, updated_at
        FROM response_config
        WHERE tenant_id = :tid
    """)
    result = await db.execute(query, {"tid": tenant_id})
    row = result.mappings().first()

    if not row:
        return {
            "shadow_mode": True,  # safe default
            "expires_at": None,
            "set_by": None,
            "updated_at": None,
            "effective": True,  # currently active
        }

    # Check if expired
    effective = bool(row["shadow_mode"])
    if effective and row["shadow_expires_at"]:
        now = datetime.now(UTC)
        if now > row["shadow_expires_at"]:
            effective = False

    return {
        "shadow_mode": bool(row["shadow_mode"]),
        "expires_at": row["shadow_expires_at"].isoformat() if row["shadow_expires_at"] else None,
        "set_by": str(row["shadow_set_by"]) if row["shadow_set_by"] else None,
        "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None,
        "effective": effective,
    }
