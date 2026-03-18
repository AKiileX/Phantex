# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Shared Input Validators.

Centralised validation for identifiers that appear across routers,
services and the engine.  Every entry-point that accepts an agent_id
(or similar opaque ID) MUST call the corresponding validator so format
checks are consistent and injection-safe.

PAID format: ``ptx-{tenant_slug}-{env_tag}-{hash12}``
             e.g. ``ptx-default-dev-fc66c4b32052``

UUID format: Standard RFC 4122 hex-and-dash, any version.
"""

from __future__ import annotations

import re
import uuid

from fastapi import HTTPException

# ── Compiled patterns ─────────────────────────────────────────────────────────

# PAID: ptx-<slug>-<env>-<12 hex>
_PAID_RE = re.compile(
    r"^ptx-[a-z0-9][a-z0-9\-]{0,62}-[a-z0-9][a-z0-9\-]{0,30}-[0-9a-f]{12}$",
    re.ASCII,
)

# Standard UUID (v1-v5 / nil)
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE | re.ASCII,
)

# agent_id may be EITHER a PAID string or a UUID
_AGENT_ID_MAX_LEN = 256

# ── Public helpers ────────────────────────────────────────────────────────────

def validate_agent_id(value: str) -> str:
    """Validate and return *value* if it is a legal agent identifier.

    Accepts both PAID strings (``ptx-…``) and UUID strings.
    Raises ``HTTPException(422)`` on bad input so FastAPI automatically
    returns a well-formed error body.
    """
    if not value or len(value) > _AGENT_ID_MAX_LEN:
        raise HTTPException(status_code=422, detail="agent_id: empty or too long")
    if _PAID_RE.match(value) or _UUID_RE.match(value):
        return value
    raise HTTPException(
        status_code=422,
        detail=f"agent_id: invalid format (expected PAID or UUID, got {value[:40]!r})",
    )

def validate_uuid(value: str, *, field: str = "id") -> uuid.UUID:
    """Parse *value* as a UUID or raise 422."""
    try:
        return uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise HTTPException(
            status_code=422, detail=f"{field}: invalid UUID ({value[:40]!r})"
        ) from exc

def is_paid(value: str) -> bool:
    """Return True if *value* looks like a PAID string."""
    return bool(_PAID_RE.match(value))

def is_uuid(value: str) -> bool:
    """Return True if *value* looks like a UUID string."""
    return bool(_UUID_RE.match(value))
