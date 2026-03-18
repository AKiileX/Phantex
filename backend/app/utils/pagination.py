# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Cursor-Based Pagination Utilities.

Uses opaque base64-encoded cursors for stable pagination across large datasets.
Cursor encodes the sort key (typically created_at + id) for seek-based pagination.
"""

import base64
import json
import uuid
from datetime import datetime

def encode_cursor(timestamp: datetime, id: uuid.UUID) -> str:
    """
    Encode a pagination cursor from a timestamp + UUID.

    The cursor is a base64-encoded JSON string containing the last row's
    sort key values. This avoids the performance problems of OFFSET-based
    pagination on large tables.
    """
    data = {
        "t": timestamp.isoformat(),
        "id": str(id),
    }
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode()

def decode_cursor(cursor: str) -> tuple[datetime, uuid.UUID] | None:
    """
    Decode a pagination cursor back into (timestamp, UUID).

    Returns None if the cursor is invalid (never raises user-visible errors).
    """
    try:
        data = json.loads(base64.urlsafe_b64decode(cursor.encode()))
        return (
            datetime.fromisoformat(data["t"]),
            uuid.UUID(data["id"]),
        )
    except (json.JSONDecodeError, KeyError, ValueError, UnicodeDecodeError):
        return None
