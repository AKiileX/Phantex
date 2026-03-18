# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.graphql.subscriptions import Subscription
from app.models.event import Event
from app.services.trust_client import TrustFactor, TrustScoreResult


def _make_info(ctx):
    return SimpleNamespace(context=ctx)

@pytest.mark.asyncio
async def test_event_created_yields_new_event():
    tenant_id = uuid.uuid4()
    event = Event(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        agent_id="agent-1",
        sensor_id="sensor-1",
        event_type="PROCESS_EXEC",
        severity="high",
        timestamp=datetime.now(UTC),
        raw_data={},
        created_at=datetime.now(UTC),
    )

    execute_result = MagicMock()
    execute_result.scalars.return_value.all.return_value = [event]
    db = AsyncMock()
    db.execute = AsyncMock(return_value=execute_result)

    ctx = SimpleNamespace(
        db=db,
        user=SimpleNamespace(tenant_id=tenant_id),
        request=SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(alert_broadcaster=None))),
    )

    subscription = Subscription()
    stream = subscription.event_created(_make_info(ctx), severity="high")
    first = await stream.__anext__()

    assert first.id == event.id
    assert first.event_type == "PROCESS_EXEC"
    assert first.severity == "high"

@pytest.mark.asyncio
async def test_trust_score_updated_yields_current_value():
    tenant_id = uuid.uuid4()
    result = TrustScoreResult(
        entity_id="agent-1",
        entity_type="agent",
        trust_score=0.72,
        factors=[TrustFactor(name="behavior", weight=0.5, value=0.8)],
        last_updated=123.0,
    )

    ctx = SimpleNamespace(
        db=AsyncMock(),
        user=SimpleNamespace(tenant_id=tenant_id),
        request=SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(alert_broadcaster=None))),
    )
    client = AsyncMock()
    client.get_trust_score = AsyncMock(return_value=result)

    subscription = Subscription()
    with patch("app.graphql.subscriptions.get_trust_client", return_value=client):
        stream = subscription.trust_score_updated(_make_info(ctx), entity_id="agent-1")
        first = await stream.__anext__()

    assert first.entity_id == "agent-1"
    assert first.trust_score == 0.72
    assert first.factors[0].name == "behavior"
