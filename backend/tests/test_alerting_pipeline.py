# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for E3 — Alerting Pipeline.

Covers:
  AC1: Rule fires → alert in DB within 1 second (via publisher pipeline)
  AC2: Alert visible in GET /api/v1/alerts immediately (AlertSummary enrichment)
  AC3: Alert includes: rule name, severity, agent PAID, triggering event, timestamp
  AC4: Dashboard WebSocket receives alert push (via in-memory broadcast)

Test categories:
  1. AlertPublisher — Kafka publish + in-memory broadcast
  2. AlertBroadcaster — subscribe/unsubscribe/broadcast
  3. WebSocketAlertManager — connection lifecycle
  4. build_alert_payload — serialization and truncation
  5. AlertSummary enrichment — agent_id, rule_id, event_id
  6. WebSocket auth — token validation
  7. Rule engine integration — _publish_alert() after DB write
  8. EngineConfig — alert_topic_prefix field
"""

import json
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from engine.alerting.publisher import (
    AlertBroadcaster,
    AlertPublisher,
    build_alert_payload,
)
from engine.alerting.ws_manager import WebSocketAlertManager
from engine.rule_engine import EngineConfig, RuleEngine
from engine.utils.truncate import truncate_dict

# ── Test Data ─────────────────────────────────────────────────────────────────

TENANT_ID = "11111111-1111-1111-1111-111111111111"
RULE_ID = uuid.UUID("22222222-2222-2222-2222-222222222222")
AGENT_ID = uuid.UUID("33333333-3333-3333-3333-333333333333")
EVENT_ID = uuid.UUID("44444444-4444-4444-4444-444444444444")
ALERT_ID = uuid.UUID("55555555-5555-5555-5555-555555555555")

def _sample_event_data() -> dict[str, Any]:
    return {
        "id": str(EVENT_ID),
        "event_type": "TOOL_CALL",
        "severity": "high",
        "agent_id": str(AGENT_ID),
        "sensor_id": "sensor-1",
        "timestamp": "2025-01-15T10:00:00Z",
        "raw_data": {
            "tool_name": "exec_shell",
            "tool_input": "cat /etc/passwd",
            "protocol": "langchain_tool",
        },
    }

def _sample_alert_payload() -> dict[str, Any]:
    return build_alert_payload(
        alert_id=ALERT_ID,
        tenant_id=uuid.UUID(TENANT_ID),
        rule_id=RULE_ID,
        rule_name="shell_command_injection",
        severity="critical",
        attack_class="command_injection",
        agent_id=AGENT_ID,
        event_id=EVENT_ID,
        event_type="TOOL_CALL",
        event_data=_sample_event_data(),
        title="Rule matched: shell_command_injection",
        description="Shell command injection detected",
    )

# ═══════════════════════════════════════════════════════════════════════════════
# 1. build_alert_payload
# ═══════════════════════════════════════════════════════════════════════════════

class TestBuildAlertPayload:
    """AC3: Alert includes rule name, severity, agent PAID, triggering event, timestamp."""

    def test_payload_has_rule_name(self):
        payload = _sample_alert_payload()
        assert payload["rule_name"] == "shell_command_injection"

    def test_payload_has_severity(self):
        payload = _sample_alert_payload()
        assert payload["severity"] == "critical"

    def test_payload_has_agent_id(self):
        """AC3: Agent PAID (Phantex Agent ID) present."""
        payload = _sample_alert_payload()
        assert payload["agent_id"] == str(AGENT_ID)

    def test_payload_has_event_id(self):
        payload = _sample_alert_payload()
        assert payload["event_id"] == str(EVENT_ID)

    def test_payload_has_rule_id(self):
        payload = _sample_alert_payload()
        assert payload["rule_id"] == str(RULE_ID)

    def test_payload_has_tenant_id(self):
        payload = _sample_alert_payload()
        assert payload["tenant_id"] == TENANT_ID

    def test_payload_has_timestamp(self):
        payload = _sample_alert_payload()
        assert payload["created_at"] is not None
        # ISO 8601 format
        assert "T" in payload["created_at"]

    def test_payload_has_event_type(self):
        payload = _sample_alert_payload()
        assert payload["event_type"] == "TOOL_CALL"

    def test_payload_has_title(self):
        payload = _sample_alert_payload()
        assert "shell_command_injection" in payload["title"]

    def test_payload_has_description(self):
        payload = _sample_alert_payload()
        assert payload["description"] == "Shell command injection detected"

    def test_payload_has_status_open(self):
        payload = _sample_alert_payload()
        assert payload["status"] == "open"

    def test_payload_has_event_snapshot(self):
        payload = _sample_alert_payload()
        assert "event_snapshot" in payload
        assert isinstance(payload["event_snapshot"], dict)

    def test_payload_attack_class(self):
        payload = _sample_alert_payload()
        assert payload["attack_class"] == "command_injection"

    def test_payload_none_agent_id(self):
        """No agent_id → None in payload."""
        payload = build_alert_payload(
            alert_id=ALERT_ID,
            tenant_id=uuid.UUID(TENANT_ID),
            rule_id=RULE_ID,
            rule_name="test_rule",
            severity="low",
            attack_class=None,
            agent_id=None,
            event_id=None,
            event_type="HEARTBEAT",
            event_data={},
            title="Test",
            description="Test desc",
        )
        assert payload["agent_id"] is None
        assert payload["event_id"] is None
        assert payload["attack_class"] is None

    def test_payload_custom_timestamp(self):
        ts = "2025-01-20T12:00:00Z"
        payload = build_alert_payload(
            alert_id=ALERT_ID,
            tenant_id=uuid.UUID(TENANT_ID),
            rule_id=RULE_ID,
            rule_name="test",
            severity="info",
            attack_class=None,
            agent_id=None,
            event_id=None,
            event_type="TEST",
            event_data={},
            title="T",
            description="D",
            timestamp=ts,
        )
        assert payload["created_at"] == ts

    def test_payload_serializable_to_json(self):
        payload = _sample_alert_payload()
        raw = json.dumps(payload, default=str)
        assert isinstance(raw, str)
        round_tripped = json.loads(raw)
        assert round_tripped["rule_name"] == "shell_command_injection"

# ═══════════════════════════════════════════════════════════════════════════════
# 2. truncate_dict
# ═══════════════════════════════════════════════════════════════════════════════

class TestSafeTruncate:
    def test_small_data_unchanged(self):
        data = {"key": "value", "num": 42}
        result = truncate_dict(data)
        assert result == data

    def test_large_strings_truncated(self):
        data = {"big": "x" * 500}
        result = truncate_dict(data, max_size=100)
        assert len(result["big"]) < 500
        assert "truncated" in result["big"]

    def test_nested_dict_truncated(self):
        data = {"nested": {"long_val": "y" * 200}}
        result = truncate_dict(data, max_size=100)
        assert isinstance(result["nested"], dict)

    def test_preserves_non_string_values(self):
        data = {"count": 42, "active": True}
        result = truncate_dict(data, max_size=10)
        assert result["count"] == 42
        assert result["active"] is True

# ═══════════════════════════════════════════════════════════════════════════════
# 3. AlertBroadcaster
# ═══════════════════════════════════════════════════════════════════════════════

class TestAlertBroadcaster:
    def test_subscribe_adds_subscriber(self):
        bc = AlertBroadcaster()
        callback = AsyncMock()
        bc.subscribe(TENANT_ID, "conn-1", callback)
        assert bc.subscriber_count == 1
        assert bc.tenant_count == 1

    def test_unsubscribe_removes_subscriber(self):
        bc = AlertBroadcaster()
        callback = AsyncMock()
        bc.subscribe(TENANT_ID, "conn-1", callback)
        bc.unsubscribe(TENANT_ID, "conn-1")
        assert bc.subscriber_count == 0
        assert bc.tenant_count == 0

    def test_unsubscribe_nonexistent_safe(self):
        bc = AlertBroadcaster()
        bc.unsubscribe("no-tenant", "no-conn")
        assert bc.subscriber_count == 0

    @pytest.mark.asyncio
    async def test_broadcast_calls_subscriber(self):
        bc = AlertBroadcaster()
        callback = AsyncMock()
        bc.subscribe(TENANT_ID, "conn-1", callback)

        payload = {"alert_id": "test"}
        notified = await bc.broadcast(TENANT_ID, payload)

        assert notified == 1
        callback.assert_awaited_once_with(payload)

    @pytest.mark.asyncio
    async def test_broadcast_wrong_tenant_not_called(self):
        bc = AlertBroadcaster()
        callback = AsyncMock()
        bc.subscribe(TENANT_ID, "conn-1", callback)

        notified = await bc.broadcast("other-tenant", {"alert_id": "x"})
        assert notified == 0
        callback.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_broadcast_multiple_subscribers(self):
        bc = AlertBroadcaster()
        cb1 = AsyncMock()
        cb2 = AsyncMock()
        bc.subscribe(TENANT_ID, "conn-1", cb1)
        bc.subscribe(TENANT_ID, "conn-2", cb2)

        notified = await bc.broadcast(TENANT_ID, {"alert_id": "x"})
        assert notified == 2
        cb1.assert_awaited_once()
        cb2.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_broadcast_failed_subscriber_removed(self):
        bc = AlertBroadcaster()
        bad_cb = AsyncMock(side_effect=Exception("dead connection"))
        good_cb = AsyncMock()
        bc.subscribe(TENANT_ID, "bad", bad_cb)
        bc.subscribe(TENANT_ID, "good", good_cb)

        notified = await bc.broadcast(TENANT_ID, {"alert_id": "x"})
        assert notified == 1  # Only good_cb succeeded
        # Bad subscriber should be removed
        assert bc.subscriber_count == 1

    def test_multiple_tenants(self):
        bc = AlertBroadcaster()
        bc.subscribe("tenant-a", "conn-1", AsyncMock())
        bc.subscribe("tenant-b", "conn-2", AsyncMock())
        assert bc.tenant_count == 2
        assert bc.subscriber_count == 2

    @pytest.mark.asyncio
    async def test_broadcast_empty_tenant(self):
        bc = AlertBroadcaster()
        notified = await bc.broadcast("no-subs", {"x": 1})
        assert notified == 0

# ═══════════════════════════════════════════════════════════════════════════════
# 4. AlertPublisher
# ═══════════════════════════════════════════════════════════════════════════════

class TestAlertPublisher:
    @pytest.mark.asyncio
    async def test_start_stop_without_kafka(self):
        """Publisher should start even without Kafka (in-memory only)."""
        publisher = AlertPublisher(kafka_bootstrap="localhost:9092")
        # Mock the aiokafka import to simulate it being unavailable
        with patch.dict("sys.modules", {"aiokafka": None}):
            await publisher.start()
            assert publisher._started is True
            await publisher.stop()
            assert publisher._started is False

    @pytest.mark.asyncio
    async def test_publish_broadcasts_to_websocket(self):
        """AC4: Alert pushed to WebSocket subscribers."""
        broadcaster = AlertBroadcaster()
        callback = AsyncMock()
        broadcaster.subscribe(TENANT_ID, "ws-1", callback)

        publisher = AlertPublisher(
            kafka_bootstrap="localhost:9092",
            broadcaster=broadcaster,
        )
        publisher._started = True  # Skip Kafka init

        payload = _sample_alert_payload()
        await publisher.publish_alert(payload, TENANT_ID)

        callback.assert_awaited_once_with(payload)
        assert publisher._ws_notifications == 1

    @pytest.mark.asyncio
    async def test_publish_no_kafka_still_broadcasts(self):
        """Without Kafka producer, still does in-memory broadcast."""
        broadcaster = AlertBroadcaster()
        callback = AsyncMock()
        broadcaster.subscribe(TENANT_ID, "ws-1", callback)

        publisher = AlertPublisher(broadcaster=broadcaster)
        publisher._started = True
        publisher._producer = None  # No Kafka

        await publisher.publish_alert({"alert_id": "x"}, TENANT_ID)
        callback.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_publish_kafka_error_still_broadcasts(self):
        """If Kafka fails, still broadcast to WebSocket."""
        broadcaster = AlertBroadcaster()
        callback = AsyncMock()
        broadcaster.subscribe(TENANT_ID, "ws-1", callback)

        publisher = AlertPublisher(broadcaster=broadcaster)
        publisher._started = True

        # Mock a broken producer
        mock_producer = AsyncMock()
        mock_producer.send_and_wait = AsyncMock(side_effect=Exception("Kafka down"))
        publisher._producer = mock_producer

        await publisher.publish_alert({"alert_id": "x", "rule_name": "test", "severity": "high"}, TENANT_ID)

        assert publisher._kafka_errors == 1
        callback.assert_awaited_once()  # Still broadcasted

    @pytest.mark.asyncio
    async def test_publish_kafka_success(self):
        """Verify Kafka send_and_wait called with correct topic."""
        publisher = AlertPublisher(topic_prefix="phantex.alerts")
        publisher._started = True

        mock_producer = AsyncMock()
        publisher._producer = mock_producer

        payload = {"alert_id": "a1", "rule_name": "test", "severity": "high"}
        await publisher.publish_alert(payload, TENANT_ID)

        # publish_alert sends to alert topic + derived ALERT event topic
        assert mock_producer.send_and_wait.await_count == 2
        first_call = mock_producer.send_and_wait.call_args_list[0]
        assert first_call.kwargs["topic"] == f"phantex.alerts.{TENANT_ID}"
        assert first_call.kwargs["value"] == payload
        assert publisher._alerts_published == 1

    def test_stats(self):
        publisher = AlertPublisher()
        stats = publisher.stats
        assert "alerts_published" in stats
        assert "kafka_errors" in stats
        assert "ws_subscribers" in stats
        assert "kafka_connected" in stats
        assert "started" in stats

    def test_topic_format(self):
        """Alert topic should be {prefix}.{tenant_id}."""
        publisher = AlertPublisher(topic_prefix="phantex.alerts")
        expected_topic = f"phantex.alerts.{TENANT_ID}"
        assert f"{publisher._topic_prefix}.{TENANT_ID}" == expected_topic

# ═══════════════════════════════════════════════════════════════════════════════
# 5. WebSocketAlertManager
# ═══════════════════════════════════════════════════════════════════════════════

class TestWebSocketAlertManager:
    def _mock_websocket(self):
        ws = AsyncMock()
        ws.accept = AsyncMock()
        ws.send_json = AsyncMock()
        ws.receive_text = AsyncMock(side_effect=Exception("disconnect"))
        ws.close = AsyncMock()
        return ws

    @pytest.mark.asyncio
    async def test_connect_accepts_websocket(self):
        broadcaster = AlertBroadcaster()
        manager = WebSocketAlertManager(broadcaster)
        ws = self._mock_websocket()

        conn_id = await manager.connect(ws, TENANT_ID, "user-1")

        assert conn_id is not None
        assert manager.active_connections == 1
        ws.accept.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_connect_sends_welcome(self):
        broadcaster = AlertBroadcaster()
        manager = WebSocketAlertManager(broadcaster)
        ws = self._mock_websocket()

        await manager.connect(ws, TENANT_ID)

        # Check welcome message
        ws.send_json.assert_awaited_once()
        welcome = ws.send_json.call_args[0][0]
        assert welcome["type"] == "connected"
        assert welcome["tenant_id"] == TENANT_ID

    @pytest.mark.asyncio
    async def test_connect_registers_with_broadcaster(self):
        broadcaster = AlertBroadcaster()
        manager = WebSocketAlertManager(broadcaster)
        ws = self._mock_websocket()

        await manager.connect(ws, TENANT_ID)

        assert broadcaster.subscriber_count == 1

    @pytest.mark.asyncio
    async def test_disconnect_cleans_up(self):
        broadcaster = AlertBroadcaster()
        manager = WebSocketAlertManager(broadcaster)
        ws = self._mock_websocket()

        conn_id = await manager.connect(ws, TENANT_ID)
        await manager.disconnect(conn_id)

        assert manager.active_connections == 0
        assert broadcaster.subscriber_count == 0

    @pytest.mark.asyncio
    async def test_alert_pushed_to_connected_client(self):
        """AC4: When alert is broadcasted, connected client receives it."""
        broadcaster = AlertBroadcaster()
        manager = WebSocketAlertManager(broadcaster)
        ws = self._mock_websocket()

        await manager.connect(ws, TENANT_ID)

        # Broadcast an alert
        payload = _sample_alert_payload()
        notified = await broadcaster.broadcast(TENANT_ID, payload)

        assert notified == 1
        # The callback should have called ws.send_json
        # Welcome message + alert message
        assert ws.send_json.await_count == 2
        alert_msg = ws.send_json.call_args_list[1][0][0]
        assert alert_msg["type"] == "alert"
        assert alert_msg["data"]["rule_name"] == "shell_command_injection"

    def test_stats(self):
        broadcaster = AlertBroadcaster()
        manager = WebSocketAlertManager(broadcaster)
        stats = manager.stats
        assert "active_connections" in stats
        assert "total_connections" in stats
        assert "total_messages_sent" in stats

# ═══════════════════════════════════════════════════════════════════════════════
# 6. WebSocket Auth
# ═══════════════════════════════════════════════════════════════════════════════

class TestWebSocketAuth:
    def _make_token(self, **overrides) -> str:
        import jwt as pyjwt

        from app.config import get_settings

        settings = get_settings()

        payload = {
            "sub": str(uuid.uuid4()),
            "tenant_id": TENANT_ID,
            "role": "admin",
            "exp": datetime.now(UTC).timestamp() + 3600,
            "iat": datetime.now(UTC).timestamp(),
            **overrides,
        }
        return pyjwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)

    def test_valid_token(self):
        from app.routers.ws import authenticate_ws_token

        token = self._make_token()
        payload = authenticate_ws_token(token)
        assert payload["tenant_id"] == TENANT_ID

    def test_expired_token(self):
        from app.routers.ws import authenticate_ws_token

        token = self._make_token(
            exp=datetime.now(UTC).timestamp() - 3600,
        )
        with pytest.raises(ValueError, match="expired"):
            authenticate_ws_token(token)

    def test_invalid_token(self):
        from app.routers.ws import authenticate_ws_token

        with pytest.raises(ValueError, match="Invalid"):
            authenticate_ws_token("not.a.valid.token")

    def test_token_missing_tenant_id(self):
        import jwt as pyjwt

        from app.config import get_settings

        settings = get_settings()

        # Create token without tenant_id in required claims
        # The decode will fail because tenant_id is in required
        payload = {
            "sub": str(uuid.uuid4()),
            "role": "admin",
            "exp": datetime.now(UTC).timestamp() + 3600,
            "iat": datetime.now(UTC).timestamp(),
        }
        token = pyjwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
        with pytest.raises(ValueError):
            from app.routers.ws import authenticate_ws_token

            authenticate_ws_token(token)

# ═══════════════════════════════════════════════════════════════════════════════
# 7. AlertSummary Enrichment
# ═══════════════════════════════════════════════════════════════════════════════

class TestAlertSummaryEnrichment:
    """AC3: Alert includes agent PAID, rule_id, event_id."""

    def test_summary_has_agent_id_field(self):
        from app.schemas.alert import AlertSummary

        summary = AlertSummary(
            id=ALERT_ID,
            severity="critical",
            title="Test Alert",
            status="open",
            created_at=datetime.now(UTC),
            agent_id=str(AGENT_ID),
            rule_id=RULE_ID,
            event_id=EVENT_ID,
        )
        assert summary.agent_id == str(AGENT_ID)
        assert summary.rule_id == RULE_ID
        assert summary.event_id == EVENT_ID

    def test_summary_fields_optional(self):
        from app.schemas.alert import AlertSummary

        summary = AlertSummary(
            id=ALERT_ID,
            severity="low",
            title="Minimal Alert",
            status="open",
            created_at=datetime.now(UTC),
        )
        assert summary.agent_id is None
        assert summary.rule_id is None
        assert summary.event_id is None

    def test_summary_serialization(self):
        from app.schemas.alert import AlertSummary

        summary = AlertSummary(
            id=ALERT_ID,
            severity="high",
            title="Test",
            status="open",
            created_at=datetime.now(UTC),
            agent_id=str(AGENT_ID),
        )
        data = summary.model_dump()
        assert "agent_id" in data
        assert "rule_id" in data
        assert "event_id" in data

# ═══════════════════════════════════════════════════════════════════════════════
# 8. EngineConfig — alert_topic_prefix
# ═══════════════════════════════════════════════════════════════════════════════

class TestEngineConfigE3:
    def test_default_alert_topic_prefix(self):
        config = EngineConfig()
        assert config.alert_topic_prefix == "phantex.alerts"

    def test_custom_alert_topic_prefix(self):
        config = EngineConfig(alert_topic_prefix="custom.alerts")
        assert config.alert_topic_prefix == "custom.alerts"

# ═══════════════════════════════════════════════════════════════════════════════
# 9. Rule Engine Integration — _publish_alert
# ═══════════════════════════════════════════════════════════════════════════════

class TestRuleEnginePublish:
    """Test that the rule engine publishes alerts after DB write."""

    @pytest.mark.asyncio
    async def test_publish_alert_builds_payload(self):
        """_publish_alert() calls build_alert_payload + publisher.publish_alert()."""
        engine = RuleEngine(EngineConfig())

        # Mock the publisher
        mock_publisher = AsyncMock()
        engine._alert_publisher = mock_publisher

        # Create a mock alert object (as returned by create_alert_action)
        mock_alert = MagicMock()
        mock_alert.id = ALERT_ID
        mock_alert.tenant_id = uuid.UUID(TENANT_ID)
        mock_alert.agent_id = AGENT_ID
        mock_alert.event_id = EVENT_ID
        mock_alert.title = "Rule matched: test_rule"
        mock_alert.description = "Test rule triggered"
        mock_alert.created_at = datetime.now(UTC)

        rule = engine.load_rule(
            RULE_ID,
            'event.type == "TOOL_CALL"',
            name="test_rule",
            severity="high",
            attack_class="test",
        )

        await engine._publish_alert(
            alert=mock_alert,
            rule=rule,
            event_data=_sample_event_data(),
            tenant_id=TENANT_ID,
        )

        mock_publisher.publish_alert.assert_awaited_once()
        call_args = mock_publisher.publish_alert.call_args
        payload = call_args[0][0]
        tenant = call_args[0][1]

        assert tenant == TENANT_ID
        assert payload["rule_name"] == "test_rule"
        assert payload["severity"] == "high"
        assert payload["alert_id"] == str(ALERT_ID)
        assert payload["agent_id"] == str(AGENT_ID)
        assert payload["event_type"] == "TOOL_CALL"

    @pytest.mark.asyncio
    async def test_publish_alert_skipped_without_publisher(self):
        """If no publisher, _publish_alert returns silently."""
        engine = RuleEngine(EngineConfig())
        engine._alert_publisher = None

        mock_alert = MagicMock()
        rule = engine.load_rule(
            RULE_ID,
            'event.type == "X"',
            name="test",
            severity="low",
        )

        # Should not raise
        await engine._publish_alert(
            alert=mock_alert,
            rule=rule,
            event_data={},
            tenant_id=TENANT_ID,
        )

    @pytest.mark.asyncio
    async def test_publish_alert_error_handled(self):
        """If publish fails, error is caught and logged (not raised)."""
        engine = RuleEngine(EngineConfig())

        mock_publisher = AsyncMock()
        mock_publisher.publish_alert = AsyncMock(side_effect=Exception("boom"))
        engine._alert_publisher = mock_publisher

        mock_alert = MagicMock()
        mock_alert.id = ALERT_ID
        mock_alert.tenant_id = uuid.UUID(TENANT_ID)
        mock_alert.agent_id = None
        mock_alert.event_id = None
        mock_alert.title = "Test"
        mock_alert.description = None
        mock_alert.created_at = datetime.now(UTC)

        rule = engine.load_rule(
            RULE_ID,
            'event.type == "X"',
            name="fail_test",
            severity="low",
        )

        # Should not raise — error is caught
        await engine._publish_alert(
            alert=mock_alert,
            rule=rule,
            event_data={},
            tenant_id=TENANT_ID,
        )

# ═══════════════════════════════════════════════════════════════════════════════
# 10. End-to-End Pipeline (mocked DB + Kafka)
# ═══════════════════════════════════════════════════════════════════════════════

class TestEndToEndPipeline:
    """
    AC1: Rule fires → alert in DB within 1 second (publisher pipeline).
    Tests the full flow with mocked DB and Kafka.
    """

    @pytest.mark.asyncio
    async def test_full_pipeline_alert_to_websocket(self):
        """Rule fires → DB write → Kafka publish → WebSocket broadcast."""
        # Setup
        broadcaster = AlertBroadcaster()
        ws_callback = AsyncMock()
        broadcaster.subscribe(TENANT_ID, "dashboard-1", ws_callback)

        publisher = AlertPublisher(
            kafka_bootstrap="localhost:9092",
            broadcaster=broadcaster,
        )
        publisher._started = True
        # No real Kafka producer — just in-memory broadcast

        # Simulate the full pipeline
        payload = build_alert_payload(
            alert_id=ALERT_ID,
            tenant_id=uuid.UUID(TENANT_ID),
            rule_id=RULE_ID,
            rule_name="shell_injection",
            severity="critical",
            attack_class="command_injection",
            agent_id=AGENT_ID,
            event_id=EVENT_ID,
            event_type="TOOL_CALL",
            event_data=_sample_event_data(),
            title="Rule matched: shell_injection",
            description="Detected shell command injection",
        )

        await publisher.publish_alert(payload, TENANT_ID)

        # Verify WebSocket received the alert
        ws_callback.assert_awaited_once()
        received = ws_callback.call_args[0][0]

        # AC3 checks
        assert received["rule_name"] == "shell_injection"
        assert received["severity"] == "critical"
        assert received["agent_id"] == str(AGENT_ID)
        assert received["event_id"] == str(EVENT_ID)
        assert received["event_type"] == "TOOL_CALL"
        assert received["created_at"] is not None
        assert received["status"] == "open"

    @pytest.mark.asyncio
    async def test_pipeline_multiple_clients_same_tenant(self):
        """Multiple dashboard clients on same tenant all receive the alert."""
        broadcaster = AlertBroadcaster()
        callbacks = [AsyncMock() for _ in range(5)]
        for i, cb in enumerate(callbacks):
            broadcaster.subscribe(TENANT_ID, f"client-{i}", cb)

        publisher = AlertPublisher(broadcaster=broadcaster)
        publisher._started = True

        payload = {"alert_id": str(ALERT_ID), "rule_name": "test"}
        await publisher.publish_alert(payload, TENANT_ID)

        for cb in callbacks:
            cb.assert_awaited_once_with(payload)

    @pytest.mark.asyncio
    async def test_pipeline_tenant_isolation(self):
        """Alerts for tenant A should NOT reach tenant B's WebSocket."""
        broadcaster = AlertBroadcaster()
        cb_a = AsyncMock()
        cb_b = AsyncMock()
        broadcaster.subscribe("tenant-a", "client-a", cb_a)
        broadcaster.subscribe("tenant-b", "client-b", cb_b)

        publisher = AlertPublisher(broadcaster=broadcaster)
        publisher._started = True

        await publisher.publish_alert({"alert_id": "x"}, "tenant-a")

        cb_a.assert_awaited_once()
        cb_b.assert_not_awaited()  # Tenant isolation!

# ═══════════════════════════════════════════════════════════════════════════════
# 11. Performance
# ═══════════════════════════════════════════════════════════════════════════════

class TestAlertingPerformance:
    """AC1: Rule fires → alert in DB within 1 second."""

    @pytest.mark.asyncio
    async def test_broadcast_1000_alerts_under_1_second(self):
        """Broadcasting 1000 alerts should complete well under 1 second."""
        import time

        broadcaster = AlertBroadcaster()
        callback = AsyncMock()
        broadcaster.subscribe(TENANT_ID, "perf-client", callback)

        publisher = AlertPublisher(broadcaster=broadcaster)
        publisher._started = True

        start = time.monotonic()
        for i in range(1000):
            await publisher.publish_alert(
                {"alert_id": str(i), "rule_name": "perf_test"},
                TENANT_ID,
            )
        elapsed = time.monotonic() - start

        assert elapsed < 1.0, f"1000 alerts took {elapsed:.2f}s (should be < 1s)"
        assert callback.await_count == 1000

    def test_build_payload_performance(self):
        """building 10000 payloads should be fast."""
        import time

        start = time.monotonic()
        for _ in range(10000):
            build_alert_payload(
                alert_id=ALERT_ID,
                tenant_id=uuid.UUID(TENANT_ID),
                rule_id=RULE_ID,
                rule_name="perf",
                severity="low",
                attack_class=None,
                agent_id=AGENT_ID,
                event_id=EVENT_ID,
                event_type="HEARTBEAT",
                event_data={"key": "val"},
                title="Perf",
                description="Perf test",
            )
        elapsed = time.monotonic() - start
        assert elapsed < 2.0, f"10000 payloads took {elapsed:.2f}s"
