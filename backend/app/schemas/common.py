# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Pydantic schemas — Common types used across all schemas."""

from dataclasses import dataclass, field
from typing import Any, TypeVar

from pydantic import BaseModel, ConfigDict

T = TypeVar("T")

class PhantexBase(BaseModel):
    """Base schema with common config."""

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
    )

# ── Pagination ────────────────────────────────────────────────────────────────

@dataclass
class PageResult:
    """Internal (non-Pydantic) page result from services. Holds any type."""

    items: list[Any] = field(default_factory=list)
    next_cursor: str | None = None
    has_more: bool = False

class CursorPage[T](BaseModel):
    """Cursor-based pagination response wrapper (Pydantic, for API responses)."""

    model_config = ConfigDict(from_attributes=True)

    items: list[T]
    next_cursor: str | None = None
    has_more: bool = False
    total_count: int | None = None  # Optional — expensive on large tables

# ── Generic Response ──────────────────────────────────────────────────────────

class MessageResponse(BaseModel):
    """Simple status message response."""

    message: str
    detail: str | None = None

class ErrorResponse(BaseModel):
    """Standard error response body."""

    error: str
    detail: str | None = None
    code: str | None = None  # Machine-readable error code
