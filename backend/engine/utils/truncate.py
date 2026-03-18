# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Shared utility: truncate nested dict data for safe storage/transport.

Used by both the rule engine (alert creation) and the Kafka publisher
(alert streaming). Configurable size limits avoid duplication.
"""

from __future__ import annotations

import json
from typing import Any

def truncate_dict(
    data: dict[str, Any],
    *,
    max_size: int = 4096,
    max_str_len: int = 256,
    nested_str_len: int = 128,
    max_keys: int | None = None,
) -> dict[str, Any]:
    """
    Truncate a dict so its JSON representation fits within *max_size* bytes.

    - Top-level string values longer than *max_str_len* are cut.
    - Nested dict string values longer than *nested_str_len* are cut.
    - If *max_keys* is set, only the first N top-level keys are kept.
    """
    raw = json.dumps(data, default=str)
    if len(raw) <= max_size:
        return data

    items = list(data.items())
    if max_keys is not None:
        items = items[:max_keys]

    truncated: dict[str, Any] = {}
    for key, value in items:
        if isinstance(value, str) and len(value) > max_str_len:
            truncated[key] = value[:max_str_len] + "... [truncated]"
        elif isinstance(value, dict):
            truncated[key] = {
                k: (v[:nested_str_len] + "..." if isinstance(v, str) and len(v) > nested_str_len else v)
                for k, v in list(value.items())[:20]
            }
        elif isinstance(value, list):
            # Truncate list: cap elements and truncate strings within
            capped = value[:20]
            truncated[key] = [
                (elem[:nested_str_len] + "..." if isinstance(elem, str) and len(elem) > nested_str_len else elem)
                for elem in capped
            ]
        else:
            truncated[key] = value
    return truncated
