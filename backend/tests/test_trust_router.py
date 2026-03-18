# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Trust Router unit tests (O4).

Tests the REST layer wrapping the gRPC TrustClient:
  - UUID validation (reject bad IDs → 422)
  - Node cap enforcement (truncation flag)
  - Graph endpoint response shape
  - Score endpoint response shape
  - Tenant isolation (tenant_id propagated)
  - Edge filtering on node cap
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── Inline data-classes matching trust_client ────────────────────────────────

@dataclass
class _FakeTrustFactor:
    name: str
    weight: float
    value: float

@dataclass
class _FakeScoreResult:
    trust_score: float
    factors: list[_FakeTrustFactor]
    entity_id: str = ""
    entity_type: str = "agent"
    last_updated: str = ""

@dataclass
class _FakeGraphNode:
    id: str
    entity_type: str
    trust_score: float
    metadata: dict[str, str] = field(default_factory=dict)

@dataclass
class _FakeGraphEdge:
    source_id: str
    target_id: str
    edge_type: str
    count: int = 1
    weight: float = 0.5

@dataclass
class _FakeNeighbourhood:
    nodes: list[_FakeGraphNode] = field(default_factory=list)
    edges: list[_FakeGraphEdge] = field(default_factory=list)

@dataclass
class _FakeHealth:
    status: str = "healthy"
    total_nodes: int = 42
    total_edges: int = 100
    tenants: int = 1
    uptime_secs: float = 3600.0

# ── Fixture helpers ──────────────────────────────────────────────────────────

VALID_UUID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
TENANT_UUID = "00000000-0000-0000-0000-000000000001"

def _make_neighbourhood(n_nodes: int = 3) -> _FakeNeighbourhood:
    nodes = [
        _FakeGraphNode(
            id=str(uuid.uuid4()),
            entity_type="agent",
            trust_score=round(0.1 + 0.8 * (i / max(n_nodes - 1, 1)), 4),
            metadata={"name": f"agent-{i}"},
        )
        for i in range(n_nodes)
    ]
    edges = [
        _FakeGraphEdge(
            source_id=nodes[0].id,
            target_id=nodes[i].id,
            edge_type="uses",
        )
        for i in range(1, len(nodes))
    ]
    return _FakeNeighbourhood(nodes=nodes, edges=edges)

def _make_score() -> _FakeScoreResult:
    return _FakeScoreResult(
        trust_score=0.85,
        factors=[
            _FakeTrustFactor(name="behaviour", weight=0.4, value=0.9),
            _FakeTrustFactor(name="lineage", weight=0.3, value=0.8),
        ],
        entity_id=VALID_UUID,
        entity_type="agent",
        last_updated=datetime.now(UTC).timestamp(),
    )

# ── Tests ────────────────────────────────────────────────────────────────────

class TestTrustRouterValidation:
    """Unit tests for _validate_uuid and UUID regex."""

    def test_valid_uuid_passes(self):
        from app.routers.trust import _validate_uuid

        result = _validate_uuid(VALID_UUID)
        assert result == VALID_UUID

    def test_uppercase_uuid_passes(self):
        from app.routers.trust import _validate_uuid

        result = _validate_uuid(VALID_UUID.upper())
        assert result == VALID_UUID.upper()

    def test_bad_uuid_raises_422(self):
        from fastapi import HTTPException

        from app.routers.trust import _validate_uuid

        with pytest.raises(HTTPException) as exc_info:
            _validate_uuid("not-a-uuid")
        assert exc_info.value.status_code == 422

    def test_empty_string_raises_422(self):
        from fastapi import HTTPException

        from app.routers.trust import _validate_uuid

        with pytest.raises(HTTPException) as exc_info:
            _validate_uuid("")
        assert exc_info.value.status_code == 422

    def test_path_traversal_raises_422(self):
        from fastapi import HTTPException

        from app.routers.trust import _validate_uuid

        with pytest.raises(HTTPException) as exc_info:
            _validate_uuid("../../etc/passwd")
        assert exc_info.value.status_code == 422

    def test_sql_injection_raises_422(self):
        from fastapi import HTTPException

        from app.routers.trust import _validate_uuid

        with pytest.raises(HTTPException) as exc_info:
            _validate_uuid("'; DROP TABLE agents; --")
        assert exc_info.value.status_code == 422

    def test_partial_uuid_raises_422(self):
        from fastapi import HTTPException

        from app.routers.trust import _validate_uuid

        with pytest.raises(HTTPException) as exc_info:
            _validate_uuid("a1b2c3d4-e5f6-7890-abcd")
        assert exc_info.value.status_code == 422

class TestTrustRouterUUIDRegex:
    """Regex boundary tests."""

    def test_uuid_regex_accepts_valid(self):
        from app.routers.trust import _UUID_RE

        assert _UUID_RE.match("a1b2c3d4-e5f6-7890-abcd-ef1234567890")

    def test_uuid_regex_rejects_trailing_chars(self):
        from app.routers.trust import _UUID_RE

        assert _UUID_RE.match("a1b2c3d4-e5f6-7890-abcd-ef1234567890extra") is None

    def test_uuid_regex_rejects_leading_chars(self):
        from app.routers.trust import _UUID_RE

        assert _UUID_RE.match("prefix-a1b2c3d4-e5f6-7890-abcd-ef1234567890") is None

    def test_uuid_regex_accepts_all_zeros(self):
        from app.routers.trust import _UUID_RE

        assert _UUID_RE.match("00000000-0000-0000-0000-000000000000")

class TestTrustGraphEndpoint:
    """Tests for the get_trust_graph endpoint logic."""

    @pytest.mark.asyncio
    async def test_graph_returns_correct_shape(self):
        from app.routers.trust import get_trust_graph

        neighbourhood = _make_neighbourhood(3)
        mock_client = AsyncMock()
        mock_client.get_trust_graph.return_value = neighbourhood

        user = MagicMock()
        user.tenant_id = uuid.UUID(TENANT_UUID)

        with patch("app.routers.trust.get_trust_client", return_value=mock_client):
            result = await get_trust_graph(current_user=user, depth=2, entity_id=VALID_UUID)

        assert len(result.nodes) == 3
        assert len(result.edges) == 2
        assert result.truncated is False

    @pytest.mark.asyncio
    async def test_graph_caps_at_max_nodes(self):
        from app.routers.trust import MAX_GRAPH_NODES, get_trust_graph

        # Create more nodes than the cap
        neighbourhood = _make_neighbourhood(MAX_GRAPH_NODES + 50)
        mock_client = AsyncMock()
        mock_client.get_trust_graph.return_value = neighbourhood

        user = MagicMock()
        user.tenant_id = uuid.UUID(TENANT_UUID)

        with patch("app.routers.trust.get_trust_client", return_value=mock_client):
            result = await get_trust_graph(current_user=user, depth=2, entity_id=VALID_UUID)

        assert len(result.nodes) == MAX_GRAPH_NODES
        assert result.truncated is True

    @pytest.mark.asyncio
    async def test_graph_edges_filtered_on_cap(self):
        """Edges referencing nodes beyond the cap must be pruned."""
        from app.routers.trust import MAX_GRAPH_NODES, get_trust_graph

        nodes = [_FakeGraphNode(id=str(i), entity_type="agent", trust_score=0.5) for i in range(MAX_GRAPH_NODES + 10)]
        # Edge connecting capped node [0] → beyond-cap node [MAX+5]
        edges = [
            _FakeGraphEdge(source_id="0", target_id=str(MAX_GRAPH_NODES + 5), edge_type="uses"),
            _FakeGraphEdge(source_id="0", target_id="1", edge_type="uses"),  # within cap
        ]
        neighbourhood = _FakeNeighbourhood(nodes=nodes, edges=edges)
        mock_client = AsyncMock()
        mock_client.get_trust_graph.return_value = neighbourhood

        user = MagicMock()
        user.tenant_id = uuid.UUID(TENANT_UUID)

        with patch("app.routers.trust.get_trust_client", return_value=mock_client):
            result = await get_trust_graph(current_user=user, depth=2, entity_id=VALID_UUID)

        # Only the 0→1 edge should survive
        assert len(result.edges) == 1
        assert result.edges[0].target_id == "1"

    @pytest.mark.asyncio
    async def test_graph_with_entity_id_validates(self):
        from fastapi import HTTPException

        from app.routers.trust import get_trust_graph

        user = MagicMock()
        user.tenant_id = uuid.UUID(TENANT_UUID)

        with pytest.raises(HTTPException) as exc_info:
            await get_trust_graph(current_user=user, depth=2, entity_id="bad-id")
        assert exc_info.value.status_code == 422

    @pytest.mark.asyncio
    async def test_graph_passes_tenant_id(self):
        from app.routers.trust import get_trust_graph

        neighbourhood = _make_neighbourhood(1)
        mock_client = AsyncMock()
        mock_client.get_trust_graph.return_value = neighbourhood

        user = MagicMock()
        user.tenant_id = uuid.UUID(TENANT_UUID)

        with patch("app.routers.trust.get_trust_client", return_value=mock_client):
            await get_trust_graph(current_user=user, depth=3, entity_id=VALID_UUID)

        mock_client.get_trust_graph.assert_called_once()
        call_kwargs = mock_client.get_trust_graph.call_args
        assert call_kwargs.kwargs["tenant_id"] == TENANT_UUID

    @pytest.mark.asyncio
    async def test_graph_clamps_trust_scores(self):
        """Trust scores outside [0,1] should be clamped."""
        from app.routers.trust import get_trust_graph

        nodes = [_FakeGraphNode(id="1", entity_type="agent", trust_score=1.5)]
        neighbourhood = _FakeNeighbourhood(nodes=nodes, edges=[])
        mock_client = AsyncMock()
        mock_client.get_trust_graph.return_value = neighbourhood

        user = MagicMock()
        user.tenant_id = uuid.UUID(TENANT_UUID)

        with patch("app.routers.trust.get_trust_client", return_value=mock_client):
            result = await get_trust_graph(current_user=user, depth=2, entity_id=VALID_UUID)

        assert result.nodes[0].trust_score == 1.0

class TestTrustScoreEndpoint:
    """Tests for the get_trust_score endpoint logic."""

    @pytest.mark.asyncio
    async def test_score_returns_correct_shape(self):
        from app.routers.trust import get_trust_score

        mock_client = AsyncMock()
        mock_client.get_trust_score.return_value = _make_score()

        user = MagicMock()
        user.tenant_id = uuid.UUID(TENANT_UUID)

        with patch("app.routers.trust.get_trust_client", return_value=mock_client):
            result = await get_trust_score(
                current_user=user,
                entity_id=VALID_UUID,
                entity_type="agent",
            )

        assert result.entity_id == VALID_UUID
        assert result.trust_score == 0.85
        assert len(result.factors) == 2

    @pytest.mark.asyncio
    async def test_score_bad_uuid_raises_422(self):
        from fastapi import HTTPException

        from app.routers.trust import get_trust_score

        user = MagicMock()
        user.tenant_id = uuid.UUID(TENANT_UUID)

        with pytest.raises(HTTPException) as exc_info:
            await get_trust_score(
                current_user=user,
                entity_id="not-a-uuid",
                entity_type="agent",
            )
        assert exc_info.value.status_code == 422

    @pytest.mark.asyncio
    async def test_score_clamps_negative(self):
        from app.routers.trust import get_trust_score

        score = _make_score()
        score.trust_score = -0.5

        mock_client = AsyncMock()
        mock_client.get_trust_score.return_value = score

        user = MagicMock()
        user.tenant_id = uuid.UUID(TENANT_UUID)

        with patch("app.routers.trust.get_trust_client", return_value=mock_client):
            result = await get_trust_score(
                current_user=user,
                entity_id=VALID_UUID,
                entity_type="agent",
            )
        assert result.trust_score == 0.0

    @pytest.mark.asyncio
    async def test_score_passes_tenant_id(self):
        from app.routers.trust import get_trust_score

        mock_client = AsyncMock()
        mock_client.get_trust_score.return_value = _make_score()

        user = MagicMock()
        user.tenant_id = uuid.UUID(TENANT_UUID)

        with patch("app.routers.trust.get_trust_client", return_value=mock_client):
            await get_trust_score(
                current_user=user,
                entity_id=VALID_UUID,
                entity_type="agent",
            )

        mock_client.get_trust_score.assert_called_once()
        call_kwargs = mock_client.get_trust_score.call_args
        assert call_kwargs.kwargs["tenant_id"] == TENANT_UUID
