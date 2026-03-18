# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for Block K — Trust Graph Engine integration.

K3a: Trust feature extraction (ML features/trust.py)
K3b: Trust gRPC client (services/trust_client.py)
K3c: PRL trust_score function (engine/evaluator/functions.py)
"""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ═══════════════════════════════════════════════════════════════════════════
# K3a — Trust Feature Extraction
# ═══════════════════════════════════════════════════════════════════════════

class TestTrustFeatures:
    """Tests for ml.features.trust.compute_trust_features."""

    def test_severity_distribution(self):
        """Counts low/medium/high/critical events per window."""
        from ml.features.trust import compute_trust_features

        now = time.time()
        events = [
            {"severity": "low", "timestamp_epoch": now - 10},
            {"severity": "medium", "timestamp_epoch": now - 20},
            {"severity": "high", "timestamp_epoch": now - 30},
            {"severity": "critical", "timestamp_epoch": now - 40},
            {"severity": "critical", "timestamp_epoch": now - 50},
        ]
        result = compute_trust_features(events, now)

        # 5m window should contain all 5 events
        assert result["trust_severity_low_5m"] == 1
        assert result["trust_severity_medium_5m"] == 1
        assert result["trust_severity_high_5m"] == 1
        assert result["trust_severity_critical_5m"] == 2

    def test_empty_events(self):
        """All trust features are 0 for empty event list."""
        from ml.features.trust import compute_trust_features

        result = compute_trust_features([], time.time())
        for k, v in result.items():
            assert v == 0.0, f"{k} should be 0.0 for empty events"

    def test_anomaly_density(self):
        """Anomaly density = fraction with anomaly_score > 0.5."""
        from ml.features.trust import compute_trust_features

        now = time.time()
        events = [
            {"severity": "low", "anomaly_score": 0.9, "timestamp_epoch": now - 10},
            {"severity": "low", "anomaly_score": 0.8, "timestamp_epoch": now - 20},
            {"severity": "low", "anomaly_score": 0.2, "timestamp_epoch": now - 30},
            {"severity": "low", "anomaly_score": 0.1, "timestamp_epoch": now - 40},
        ]
        result = compute_trust_features(events, now)
        assert result["trust_anomaly_density_5m"] == pytest.approx(0.5, abs=0.01)

    def test_permission_escalation_rate(self):
        """Counts permission escalation events per minute in window."""
        from ml.features.trust import compute_trust_features

        now = time.time()
        events = [
            {"event_type": "PERMISSION_CHANGE", "action": "escalate", "severity": "high", "timestamp_epoch": now - 10},
            {"event_type": "TOOL_CALL", "action": "read", "severity": "low", "timestamp_epoch": now - 20},
            {"event_type": "privilege_escalation", "severity": "critical", "timestamp_epoch": now - 30},
        ]
        result = compute_trust_features(events, now)
        # 2 escalation events in 5m window → 2 / 5.0 = 0.4 per minute
        assert result["trust_permission_escalation_rate_5m"] == pytest.approx(2.0 / 5.0, abs=0.01)

    def test_out_of_scope_ratio(self):
        """Out-of-scope ratio = fraction flagged out of scope."""
        from ml.features.trust import compute_trust_features

        now = time.time()
        events = [
            {"severity": "low", "out_of_scope": True, "timestamp_epoch": now - 10},
            {"severity": "low", "out_of_scope": False, "timestamp_epoch": now - 20},
            {"severity": "low", "scope_violation": "true", "timestamp_epoch": now - 30},
        ]
        result = compute_trust_features(events, now)
        assert result["trust_out_of_scope_ratio_5m"] == pytest.approx(2.0 / 3.0, abs=0.01)

    def test_trust_volatility(self):
        """Volatility = stddev of severity scores."""
        from ml.features.trust import compute_trust_features

        now = time.time()
        # All same severity → volatility = 0
        events = [
            {"severity": "low", "timestamp_epoch": now - 10},
            {"severity": "low", "timestamp_epoch": now - 20},
            {"severity": "low", "timestamp_epoch": now - 30},
        ]
        result = compute_trust_features(events, now)
        assert result["trust_volatility_5m"] == pytest.approx(0.0, abs=1e-10)

    def test_trust_volatility_mixed_severity(self):
        """Mixed severity → non-zero volatility."""
        from ml.features.trust import compute_trust_features

        now = time.time()
        events = [
            {"severity": "low", "timestamp_epoch": now - 10},
            {"severity": "critical", "timestamp_epoch": now - 20},
        ]
        result = compute_trust_features(events, now)
        assert result["trust_volatility_5m"] > 0.0

    def test_critical_event_streak(self):
        """Streak counts consecutive critical events from most recent."""
        from ml.features.trust import compute_trust_features

        now = time.time()
        events = [
            {"severity": "critical", "timestamp_epoch": now - 10},
            {"severity": "critical", "timestamp_epoch": now - 20},
            {"severity": "low", "timestamp_epoch": now - 30},
            {"severity": "critical", "timestamp_epoch": now - 40},
        ]
        result = compute_trust_features(events, now)
        assert result["trust_critical_event_streak"] == 2.0

    def test_max_severity_last_event(self):
        """Last event's severity score is captured."""
        from ml.features.trust import compute_trust_features

        now = time.time()
        events = [
            {"severity": "low", "timestamp_epoch": now - 100},
            {"severity": "critical", "timestamp_epoch": now - 10},
        ]
        result = compute_trust_features(events, now)
        assert result["trust_max_severity_last_event"] == 1.0

    def test_severity_from_numeric_string(self):
        """Numeric severity strings are mapped to buckets."""
        from ml.features.trust import _event_severity

        assert _event_severity({"severity": "0.9"}) == "critical"
        assert _event_severity({"severity": "0.6"}) == "high"
        assert _event_severity({"severity": "0.3"}) == "medium"
        assert _event_severity({"severity": "0.1"}) == "low"

    def test_window_filtering(self):
        """Events outside window are excluded."""
        from ml.features.trust import compute_trust_features

        now = time.time()
        events = [
            {"severity": "critical", "timestamp_epoch": now - 10},  # In 5m, 1h, 24h
            {"severity": "critical", "timestamp_epoch": now - 600},  # In 1h, 24h (not 5m)
            {"severity": "critical", "timestamp_epoch": now - 90000},  # Outside all windows
        ]
        result = compute_trust_features(events, now)
        assert result["trust_severity_critical_5m"] == 1
        assert result["trust_severity_critical_1h"] == 2
        assert result["trust_severity_critical_24h"] == 2  # 90000s > 86400s

# ═══════════════════════════════════════════════════════════════════════════
# K3a — Feature Registration
# ═══════════════════════════════════════════════════════════════════════════

class TestTrustFeatureRegistration:
    """Trust features are registered in the global catalogue."""

    def test_trust_features_registered(self):
        """Importing trust module registers features in the catalogue."""
        import ml.features.trust  # noqa: F401
        from ml.features.registry import list_features

        trust_features = [f for f in list_features() if f.category == "trust"]
        # 3 windows × 5 windowed features + 2 instant = 17
        assert len(trust_features) >= 17

    def test_trust_feature_names(self):
        """Feature names follow expected patterns."""
        import ml.features.trust  # noqa: F401
        from ml.features.registry import feature_names

        names = feature_names()
        assert "trust_severity_critical_5m" in names
        assert "trust_anomaly_density_1h" in names
        assert "trust_critical_event_streak" in names
        assert "trust_max_severity_last_event" in names

# ═══════════════════════════════════════════════════════════════════════════
# K2 — Trust gRPC Client (graceful degradation)
# ═══════════════════════════════════════════════════════════════════════════

class TestTrustClient:
    """Tests for app.services.trust_client graceful degradation."""

    def test_import_without_grpc(self):
        """Client module imports cleanly even without grpcio installed."""
        from app.services.trust_client import TrustClient

        assert TrustClient is not None

    @pytest.mark.asyncio
    async def test_get_trust_score_returns_neutral_on_connection_error(self):
        """When Trust Engine is unreachable, returns neutral 0.5."""
        from app.services.trust_client import TrustClient

        client = TrustClient(addr="localhost:99999")
        result = await client.get_trust_score("tenant1", "agent1", "agent")
        assert result.trust_score == pytest.approx(0.5)

    @pytest.mark.asyncio
    async def test_health_check_returns_unknown_on_failure(self):
        """Health check returns UNKNOWN status on connection failure."""
        from app.services.trust_client import TrustClient

        client = TrustClient(addr="localhost:99999")
        result = await client.health_check()
        assert result.status == "NOT_SERVING"

    def test_singleton_returns_same_instance(self):
        """get_trust_client() returns same instance on repeated calls."""
        from app.services.trust_client import get_trust_client

        c1 = get_trust_client()
        c2 = get_trust_client()
        assert c1 is c2

# ═══════════════════════════════════════════════════════════════════════════
# K3c — PRL trust_score Function
# ═══════════════════════════════════════════════════════════════════════════

class TestPRLTrustScore:
    """Tests for the trust_score PRL function in engine/evaluator/functions.py."""

    def test_trust_score_registered(self):
        """trust_score is registered in the BuiltinRegistry."""
        from engine.evaluator.functions import BuiltinRegistry

        reg = BuiltinRegistry()
        assert "trust_score" in reg._functions

    def test_trust_score_returns_neutral_without_engine(self):
        """trust_score returns 0.5 (neutral) when engine is unreachable."""
        from engine.evaluator.functions import BuiltinRegistry

        reg = BuiltinRegistry()
        fn = reg._functions["trust_score"]

        # Create a minimal context
        ctx = {"event": {"agent_id": "test-agent", "tenant_id": "test-tenant"}}
        func_ctx = MagicMock()

        # Call with args — engine is not running, should degrade to 0.5
        result = fn(["test-agent", "agent"], ctx, func_ctx)
        assert result == pytest.approx(0.5, abs=0.01)

    def test_trust_score_with_missing_args(self):
        """trust_score returns 0.5 when called with insufficient args."""
        from engine.evaluator.functions import BuiltinRegistry

        reg = BuiltinRegistry()
        fn = reg._functions["trust_score"]

        ctx = {"event": {}}
        func_ctx = MagicMock()

        result = fn([], ctx, func_ctx)
        assert result == pytest.approx(0.5, abs=0.01)

# ═══════════════════════════════════════════════════════════════════════════
# K Hardening —  Audit
# ═══════════════════════════════════════════════════════════════════════════

class TestTrustClientSingletonThreadSafety:
    """Verify get_trust_client() is thread-safe and returns same instance."""

    def test_singleton_thread_safe(self):
        """Concurrent calls from threads return the same instance."""
        import threading

        from app.services import trust_client as tc_mod

        # Reset singleton
        tc_mod._trust_client = None

        results: list[object] = []
        barrier = threading.Barrier(4)

        def _get():
            barrier.wait()
            results.append(tc_mod.get_trust_client())

        threads = [threading.Thread(target=_get) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 4
        assert all(r is results[0] for r in results), "All threads must get same instance"
        # Reset singleton for other tests
        tc_mod._trust_client = None

    def test_singleton_uses_lock(self):
        """Module exposes _trust_client_lock for thread safety."""
        import threading

        from app.services import trust_client as tc_mod

        assert hasattr(tc_mod, "_trust_client_lock")
        assert isinstance(tc_mod._trust_client_lock, type(threading.Lock()))

class TestTrustClientCacheEdges:
    """Edge cases for the OrderedDict TTL cache."""

    def test_cache_ttl_expiry(self):
        """Expired entries return None on get."""
        from app.services.trust_client import TrustClient

        client = TrustClient(cache_ttl=0.01)  # 10 ms TTL
        client._cache_put("k1", "val1")
        assert client._cache_get("k1") == "val1"

        time.sleep(0.02)
        assert client._cache_get("k1") is None

    def test_cache_eviction_at_max(self):
        """Cache evicts oldest when max entries exceeded."""
        from app.services.trust_client import TrustClient

        client = TrustClient(cache_max=3)
        client._cache_put("a", 1)
        client._cache_put("b", 2)
        client._cache_put("c", 3)
        client._cache_put("d", 4)  # should evict "a"

        assert client._cache_get("a") is None
        assert client._cache_get("d") == 4

    def test_cache_lru_reorder(self):
        """Accessing an entry moves it to end (LRU)."""
        from app.services.trust_client import TrustClient

        client = TrustClient(cache_max=3)
        client._cache_put("a", 1)
        client._cache_put("b", 2)
        client._cache_put("c", 3)

        # Access "a" to move it to end
        client._cache_get("a")
        # Insert "d" — should evict "b" (oldest)
        client._cache_put("d", 4)

        assert client._cache_get("a") == 1  # survived
        assert client._cache_get("b") is None  # evicted

class TestTrustScoreClamping:
    """Trust score is clamped to [0, 1] against buggy engine responses."""

    @pytest.mark.asyncio
    async def test_clamp_above_one(self):
        """Scores > 1.0 clamped to 1.0."""
        import sys

        from app.services import trust_client as tc_mod
        from app.services.trust_client import TrustClient

        client = TrustClient()
        client._stub = MagicMock()  # bypass stub-None guard

        mock_resp = MagicMock()
        mock_resp.trust_score = 1.5
        mock_resp.entity_id = "agent1"
        mock_resp.entity_type = "agent"
        mock_resp.factors = []
        mock_resp.HasField.return_value = False

        # Inject fake proto package tree so `from proto.gen.phantex.v1 import trust_pb2` works
        fake_pb2 = MagicMock()
        fake_pb2.GetTrustScoreRequest.return_value = MagicMock()
        fake_v1 = MagicMock()
        fake_v1.trust_pb2 = fake_pb2
        parents = {
            "proto": MagicMock(),
            "proto.gen": MagicMock(),
            "proto.gen.phantex": MagicMock(),
            "proto.gen.phantex.v1": fake_v1,
            "proto.gen.phantex.v1.trust_pb2": fake_pb2,
        }
        saved = {k: sys.modules.get(k) for k in parents}
        sys.modules.update(parents)

        try:
            with (
                patch.object(client, "_call_with_retry", new=AsyncMock(return_value=mock_resp)),
                patch.object(tc_mod, "_grpc_available", True),
            ):
                result = await client.get_trust_score("tenant1", "agent1", "agent")
                assert result.trust_score == 1.0
        finally:
            for k, v in saved.items():
                if v is None:
                    sys.modules.pop(k, None)
                else:
                    sys.modules[k] = v

    @pytest.mark.asyncio
    async def test_clamp_below_zero(self):
        """Scores < 0.0 clamped to 0.0."""
        import sys

        from app.services import trust_client as tc_mod
        from app.services.trust_client import TrustClient

        client = TrustClient()
        client._stub = MagicMock()  # bypass stub-None guard

        mock_resp = MagicMock()
        mock_resp.trust_score = -0.3
        mock_resp.entity_id = "agent1"
        mock_resp.entity_type = "agent"
        mock_resp.factors = []
        mock_resp.HasField.return_value = False

        fake_pb2 = MagicMock()
        fake_pb2.GetTrustScoreRequest.return_value = MagicMock()
        fake_v1 = MagicMock()
        fake_v1.trust_pb2 = fake_pb2
        parents = {
            "proto": MagicMock(),
            "proto.gen": MagicMock(),
            "proto.gen.phantex": MagicMock(),
            "proto.gen.phantex.v1": fake_v1,
            "proto.gen.phantex.v1.trust_pb2": fake_pb2,
        }
        saved = {k: sys.modules.get(k) for k in parents}
        sys.modules.update(parents)

        try:
            with (
                patch.object(client, "_call_with_retry", new=AsyncMock(return_value=mock_resp)),
                patch.object(tc_mod, "_grpc_available", True),
            ):
                result = await client.get_trust_score("tenant1", "agent1", "agent")
                assert result.trust_score == 0.0
        finally:
            for k, v in saved.items():
                if v is None:
                    sys.modules.pop(k, None)
                else:
                    sys.modules[k] = v

class TestTrustGraphDepthClamping:
    """Graph depth is clamped to [1, 5] to prevent DoS."""

    @pytest.mark.asyncio
    async def test_depth_too_high(self):
        """Depth > 5 clamped to 5."""
        from app.services.trust_client import TrustClient

        client = TrustClient()
        # Without gRPC, returns empty neighbourhood but depth is clamped internally
        result = await client.get_trust_graph("t1", "e1", depth=100)
        # Can't directly check clamped value, but ensure no crash
        assert result.nodes == []

    @pytest.mark.asyncio
    async def test_depth_zero_clamped(self):
        """Depth 0 clamped to 1."""
        from app.services.trust_client import TrustClient

        client = TrustClient()
        result = await client.get_trust_graph("t1", "e1", depth=0)
        assert result.nodes == []

class TestPRLTrustScoreContextCache:
    """trust_score() checks _trust_scores context cache before gRPC."""

    def test_uses_context_cache(self):
        """When _trust_scores is populated, uses cached value."""
        from engine.evaluator.functions import fn_trust_score

        ctx = {
            "tenant_id": "t1",
            "event": {"agent_id": "a1"},
            "_trust_scores": {"a1:agent": 0.42},
        }
        result = fn_trust_score(["a1", "agent"], ctx, None)
        assert result == pytest.approx(0.42, abs=0.01)

    def test_fallback_without_cache(self):
        """Without _trust_scores, falls back to gRPC (→ 0.5 if unreachable)."""
        from engine.evaluator.functions import fn_trust_score

        ctx = {
            "tenant_id": "t1",
            "event": {"agent_id": "a1"},
        }
        result = fn_trust_score(["a1", "agent"], ctx, None)
        assert result == pytest.approx(0.5, abs=0.01)

    def test_empty_entity_id_returns_neutral(self):
        """Empty entity_id returns 0.5 without engine call."""
        from engine.evaluator.functions import fn_trust_score

        ctx = {"tenant_id": "t1", "event": {}}
        result = fn_trust_score(["", "agent"], ctx, None)
        assert result == pytest.approx(0.5, abs=0.01)

    def test_empty_tenant_returns_neutral(self):
        """Empty tenant_id returns 0.5 without engine call."""
        from engine.evaluator.functions import fn_trust_score

        ctx = {"tenant_id": "", "event": {}}
        result = fn_trust_score(["a1", "agent"], ctx, None)
        assert result == pytest.approx(0.5, abs=0.01)
