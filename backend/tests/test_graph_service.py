# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for Graph Service helpers (I3).

Covers:
  - _dedupe_edges: edge deduplication
  - write_event_to_graph: input validation (skips incomplete events)
  - write_alert_to_graph: input validation

Note: Cypher execution is integration-tested against a real Neo4j;
unit tests validate the Python logic around the driver calls.
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.graph_service import (
    _dedupe_edges,
    write_alert_to_graph,
    write_event_to_graph,
)

# ── _dedupe_edges ────────────────────────────────────────────────────────────

class TestDedupeEdges:
    def test_empty_list(self):
        assert _dedupe_edges([]) == []

    def test_no_duplicates(self):
        edges = [
            {"type": "PERFORMED", "start": 1, "end": 2},
            {"type": "CONNECTED_TO", "start": 2, "end": 3},
        ]
        result = _dedupe_edges(edges)
        assert len(result) == 2

    def test_removes_duplicates(self):
        edges = [
            {"type": "PERFORMED", "start": 1, "end": 2},
            {"type": "PERFORMED", "start": 1, "end": 2},
            {"type": "CONNECTED_TO", "start": 2, "end": 3},
        ]
        result = _dedupe_edges(edges)
        assert len(result) == 2

    def test_preserves_order(self):
        edges = [
            {"type": "A", "start": 1, "end": 2},
            {"type": "B", "start": 2, "end": 3},
            {"type": "A", "start": 1, "end": 2},
            {"type": "C", "start": 3, "end": 4},
            {"type": "B", "start": 2, "end": 3},
        ]
        result = _dedupe_edges(edges)
        assert [e["type"] for e in result] == ["A", "B", "C"]

    def test_different_types_same_nodes_preserved(self):
        edges = [
            {"type": "A", "start": 1, "end": 2},
            {"type": "B", "start": 1, "end": 2},
        ]
        result = _dedupe_edges(edges)
        assert len(result) == 2

# ── Mock Neo4j Driver ────────────────────────────────────────────────────────

def _mock_neo4j_driver():
    """Build a mock AsyncDriver with chainable session().run()."""
    driver = MagicMock()
    session = AsyncMock()
    session.run = AsyncMock()

    # session() must return a sync context-manager-like that yields session
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=session)
    ctx.__aexit__ = AsyncMock(return_value=None)
    driver.session.return_value = ctx

    return driver, session

# ── write_event_to_graph ─────────────────────────────────────────────────────

class TestWriteEventToGraph:
    @pytest.mark.asyncio
    async def test_skips_event_missing_tenant_id(self):
        driver, session = _mock_neo4j_driver()
        event = {"agent_id": str(uuid.uuid4()), "event_id": str(uuid.uuid4())}
        await write_event_to_graph(driver, event)
        session.run.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_skips_event_missing_agent_id(self):
        driver, session = _mock_neo4j_driver()
        event = {"tenant_id": str(uuid.uuid4()), "event_id": str(uuid.uuid4())}
        await write_event_to_graph(driver, event)
        session.run.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_skips_event_missing_event_id(self):
        driver, session = _mock_neo4j_driver()
        event = {"tenant_id": str(uuid.uuid4()), "agent_id": str(uuid.uuid4())}
        await write_event_to_graph(driver, event)
        session.run.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_writes_base_agent_event(self):
        driver, session = _mock_neo4j_driver()
        event = {
            "tenant_id": str(uuid.uuid4()),
            "agent_id": str(uuid.uuid4()),
            "event_id": str(uuid.uuid4()),
            "event_type": "HEARTBEAT",
            "severity": "info",
            "timestamp": "2025-01-15T10:00:00Z",
        }
        await write_event_to_graph(driver, event)
        # At least the base Agent+Event MERGE is called
        assert session.run.await_count >= 1

    @pytest.mark.asyncio
    async def test_network_connect_creates_dest(self):
        driver, session = _mock_neo4j_driver()
        event = {
            "tenant_id": str(uuid.uuid4()),
            "agent_id": str(uuid.uuid4()),
            "event_id": str(uuid.uuid4()),
            "event_type": "NETWORK_CONNECT",
            "dest_ip": "10.0.0.1",
            "dest_port": 443,
        }
        await write_event_to_graph(driver, event)
        # Base MERGE + NETWORK_CONNECT MERGE = at least 2 calls
        assert session.run.await_count >= 2

    @pytest.mark.asyncio
    async def test_file_read_creates_file(self):
        driver, session = _mock_neo4j_driver()
        event = {
            "tenant_id": str(uuid.uuid4()),
            "agent_id": str(uuid.uuid4()),
            "event_id": str(uuid.uuid4()),
            "event_type": "FILE_READ",
            "file_path": "/etc/passwd",
        }
        await write_event_to_graph(driver, event)
        assert session.run.await_count >= 2

    @pytest.mark.asyncio
    async def test_tool_call_creates_tool(self):
        driver, session = _mock_neo4j_driver()
        event = {
            "tenant_id": str(uuid.uuid4()),
            "agent_id": str(uuid.uuid4()),
            "event_id": str(uuid.uuid4()),
            "event_type": "TOOL_CALL",
            "tool_name": "exec_shell",
        }
        await write_event_to_graph(driver, event)
        assert session.run.await_count >= 2

# ── write_alert_to_graph ─────────────────────────────────────────────────────

class TestWriteAlertToGraph:
    @pytest.mark.asyncio
    async def test_skips_alert_missing_alert_id(self):
        driver, session = _mock_neo4j_driver()
        await write_alert_to_graph(driver, {"tenant_id": "t1"})
        session.run.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_skips_alert_missing_tenant_id(self):
        driver, session = _mock_neo4j_driver()
        await write_alert_to_graph(driver, {"alert_id": "a1"})
        session.run.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_writes_alert_node(self):
        driver, session = _mock_neo4j_driver()
        alert = {
            "alert_id": str(uuid.uuid4()),
            "tenant_id": str(uuid.uuid4()),
            "rule_name": "test_rule",
            "severity": "high",
        }
        await write_alert_to_graph(driver, alert)
        assert session.run.await_count >= 1

    @pytest.mark.asyncio
    async def test_links_alert_to_event(self):
        driver, session = _mock_neo4j_driver()
        alert = {
            "alert_id": str(uuid.uuid4()),
            "event_id": str(uuid.uuid4()),
            "tenant_id": str(uuid.uuid4()),
        }
        await write_alert_to_graph(driver, alert)
        # Base Alert MERGE + event linking = at least 2 calls
        assert session.run.await_count >= 2
