# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.pdr_schedule_runner import execute_channel_export


class _AsyncSessionContext:
    def __init__(self, session):
        self._session = session

    async def __aenter__(self):
        return self._session

    async def __aexit__(self, exc_type, exc, tb):
        return False

@pytest.mark.asyncio
async def test_execute_channel_export_queries_events_and_exports_batch():
    tenant_id = str(uuid.uuid4())
    now = datetime.now(UTC)
    rows = [
        {
            "id": uuid.uuid4(),
            "agent_id": "agent-1",
            "sensor_id": "sensor-1",
            "event_type": "PROCESS_EXEC",
            "severity": "medium",
            "timestamp": now,
            "raw_data": {"pid": 1},
        }
    ]

    execute_result = MagicMock()
    execute_result.mappings.return_value.all.return_value = rows
    session = AsyncMock()
    session.execute = AsyncMock(return_value=execute_result)

    channel = AsyncMock()
    channel.export_batch = AsyncMock(return_value={"delivered": 1})
    channel.close = AsyncMock()

    with (
        patch("app.services.pdr_schedule_runner.admin_session_factory", return_value=_AsyncSessionContext(session)),
        patch("app.services.pdr_schedule_runner.create_channel", return_value=channel),
    ):
        result = await execute_channel_export(
            tenant_id=tenant_id,
            channel_row={"channel_type": "webhook", "config": {}, "pii_fields": None},
            lookback_minutes=60,
            event_types=["PROCESS_EXEC"],
            max_events=100,
        )

    assert result["events_selected"] == 1
    channel.export_batch.assert_called_once()
    channel.close.assert_called_once()
