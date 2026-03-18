# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for ML Baseline Engine — Builder, Comparator, Updater, Models (J4).
"""

import time

import pytest

from ml.baseline.builder import BASELINE_METRICS, BaselineBuilder
from ml.baseline.comparator import BaselineComparator
from ml.baseline.models import BaselineProfile, MetricBaseline
from ml.baseline.updater import BaselineUpdater

# ── BaselineProfile Tests ────────────────────────────────────────────────────

class TestBaselineProfile:
    """Tests for the BaselineProfile data class."""

    def test_create_default(self):
        """Create a baseline profile with defaults."""
        profile = BaselineProfile(agent_id="a1", tenant_id="t1")
        assert profile.mode == "LEARNING"
        assert profile.agent_id == "a1"
        assert profile.tenant_id == "t1"
        assert isinstance(profile.metrics, dict)
        assert len(profile.metrics) == 0

    def test_to_dict_roundtrip(self):
        """Serialize → deserialize produces equivalent profile."""
        profile = BaselineProfile(agent_id="a1", tenant_id="t1")
        profile.metrics["event_count_1h"] = MetricBaseline(mean=50.0, std=10.0, p95=66.45, count=100)
        profile.known_destinations.add("10.0.0.1")
        profile.event_type_histogram["TOOL_CALL"] = 42
        profile.hour_histogram[14] = 20

        data = profile.to_dict()
        restored = BaselineProfile.from_dict(data)

        assert restored.agent_id == "a1"
        assert restored.tenant_id == "t1"
        assert restored.mode == "LEARNING"
        assert "event_count_1h" in restored.metrics
        assert restored.metrics["event_count_1h"].mean == 50.0
        assert "10.0.0.1" in restored.known_destinations
        assert restored.event_type_histogram["TOOL_CALL"] == 42
        assert restored.hour_histogram[14] == 20

    def test_from_dict_missing_fields(self):
        """from_dict handles missing optional fields gracefully."""
        data = {"agent_id": "a1", "tenant_id": "t1"}
        profile = BaselineProfile.from_dict(data)
        assert profile.mode == "LEARNING"
        assert len(profile.metrics) == 0
        assert len(profile.known_destinations) == 0

class TestMetricBaseline:
    """Tests for the MetricBaseline data class."""

    def test_defaults(self):
        """MetricBaseline starts with zeros."""
        mb = MetricBaseline()
        assert mb.mean == 0.0
        assert mb.std == 0.0
        assert mb.p95 == 0.0
        assert mb.count == 0

# ── BaselineBuilder Tests ────────────────────────────────────────────────────

class TestBaselineBuilder:
    """Tests for the BaselineBuilder."""

    def test_create_profile(self):
        """create_profile returns a LEARNING profile."""
        builder = BaselineBuilder()
        profile = builder.create_profile("t1", "a1")
        assert profile.mode == "LEARNING"
        assert profile.agent_id == "a1"

    def test_update_learning_accumulates(self):
        """update_profile accumulates statistics in LEARNING mode."""
        builder = BaselineBuilder()
        profile = builder.create_profile("t1", "a1")

        for i in range(20):
            features = {"event_count_1h": float(10 + i)}
            profile = builder.update_profile(profile, features)

        mb = profile.metrics["event_count_1h"]
        assert mb.count == 20
        assert mb.mean > 0
        assert mb.std > 0

    def test_learning_to_active_transition(self):
        """Profile transitions from LEARNING to ACTIVE after learning_days + min events."""
        builder = BaselineBuilder()
        profile = builder.create_profile("t1", "a1")

        # Fake learning_start to 8 days ago
        profile.learning_start = time.time() - 8 * 86_400

        # Pre-populate metrics with enough observations to meet min_learning_events
        for metric_name in BASELINE_METRICS:
            profile.metrics[metric_name] = MetricBaseline(
                mean=50.0,
                std=5.0,
                count=1_001,
            )

        features = {"event_count_1h": 10.0}
        profile = builder.update_profile(profile, features)
        assert profile.mode == "ACTIVE"

    def test_stale_reset(self):
        """STALE profile resets to LEARNING on update."""
        builder = BaselineBuilder()
        profile = builder.create_profile("t1", "a1")
        profile.mode = "STALE"

        features = {"event_count_1h": 10.0}
        profile = builder.update_profile(profile, features)
        assert profile.mode == "LEARNING"

    def test_check_stale(self):
        """check_stale marks inactive profiles as STALE."""
        builder = BaselineBuilder()
        profile = builder.create_profile("t1", "a1")
        profile.mode = "ACTIVE"
        profile.last_event_at = time.time() - 31 * 86_400  # 31 days ago

        profile = builder.check_stale(profile)
        assert profile.mode == "STALE"

    def test_check_stale_skips_active(self):
        """check_stale does not mark active profiles as stale."""
        builder = BaselineBuilder()
        profile = builder.create_profile("t1", "a1")
        profile.mode = "ACTIVE"
        profile.last_event_at = time.time() - 10  # 10 seconds ago

        profile = builder.check_stale(profile)
        assert profile.mode == "ACTIVE"

    def test_network_destination_tracked(self):
        """update_profile tracks known network destinations."""
        builder = BaselineBuilder()
        profile = builder.create_profile("t1", "a1")

        event = {"dest_ip": "192.168.1.1"}
        profile = builder.update_profile(profile, {}, event)
        assert "192.168.1.1" in profile.known_destinations

    def test_event_type_histogram(self):
        """update_profile tracks event type distribution."""
        builder = BaselineBuilder()
        profile = builder.create_profile("t1", "a1")

        for _ in range(5):
            event = {"event_type": "TOOL_CALL"}
            profile = builder.update_profile(profile, {}, event)
        for _ in range(3):
            event = {"event_type": "FILE_READ"}
            profile = builder.update_profile(profile, {}, event)

        assert profile.event_type_histogram["TOOL_CALL"] == 5
        assert profile.event_type_histogram["FILE_READ"] == 3

    def test_welford_online_mean(self):
        """Welford's online algorithm computes correct mean."""
        builder = BaselineBuilder()
        profile = builder.create_profile("t1", "a1")

        values = [10.0, 20.0, 30.0, 40.0, 50.0]
        for v in values:
            features = {"event_count_1h": v}
            profile = builder.update_profile(profile, features)

        mb = profile.metrics["event_count_1h"]
        assert mb.mean == pytest.approx(30.0, rel=0.01)

# ── BaselineComparator Tests ─────────────────────────────────────────────────

class TestBaselineComparator:
    """Tests for the BaselineComparator."""

    def _active_profile(self):
        """Create an ACTIVE profile with established baselines."""
        profile = BaselineProfile(agent_id="a1", tenant_id="t1", mode="ACTIVE")
        profile.metrics["event_count_1h"] = MetricBaseline(
            mean=50.0, std=10.0, p95=66.45, count=1000, min_val=20.0, max_val=80.0
        )
        profile.metrics["bytes_sent_total_1h"] = MetricBaseline(
            mean=1000.0, std=200.0, p95=1329.0, count=1000, min_val=100.0, max_val=2000.0
        )
        profile.known_destinations = {"10.0.0.1", "10.0.0.2", "192.168.1.1"}
        profile.event_type_histogram = {"TOOL_CALL": 500, "FILE_READ": 300, "NETWORK_CONNECT": 200}
        return profile

    def test_no_alerts_in_learning_mode(self):
        """No alerts generated when profile is in LEARNING mode."""
        comp = BaselineComparator()
        profile = BaselineProfile(agent_id="a1", tenant_id="t1", mode="LEARNING")
        alerts = comp.compare(profile, {"event_count_1h": 9999.0})
        assert len(alerts) == 0

    def test_zscore_alert(self):
        """High z-score triggers deviation alert."""
        comp = BaselineComparator()
        profile = self._active_profile()

        # value = 90.0, mean = 50, std = 10 → z = 4.0 → alert
        features = {"event_count_1h": 90.0, "bytes_sent_total_1h": 1000.0}
        alerts = comp.compare(profile, features)
        metric_alerts = [a for a in alerts if a["type"] == "baseline_deviation"]
        assert len(metric_alerts) >= 1
        assert metric_alerts[0]["z_score"] == pytest.approx(4.0, abs=0.1)

    def test_no_alert_within_threshold(self):
        """No alert when value is within normal range."""
        comp = BaselineComparator()
        profile = self._active_profile()

        # value = 55.0, mean = 50, std = 10 → z = 0.5 → no alert
        features = {"event_count_1h": 55.0, "bytes_sent_total_1h": 1000.0}
        alerts = comp.compare(profile, features)
        metric_alerts = [a for a in alerts if a["type"] == "baseline_deviation"]
        assert len(metric_alerts) == 0

    def test_severity_levels(self):
        """Severity escalates with z-score: medium → high → critical."""
        comp = BaselineComparator()
        profile = self._active_profile()

        # z = 3.5 → medium
        features = {"event_count_1h": 85.0, "bytes_sent_total_1h": 1000.0}
        alerts = comp.compare(profile, features)
        deviation_alerts = [a for a in alerts if a["type"] == "baseline_deviation"]
        assert any(a["severity"] == "medium" for a in deviation_alerts)

        # z = 5.0 → high
        features = {"event_count_1h": 100.0, "bytes_sent_total_1h": 1000.0}
        alerts = comp.compare(profile, features)
        deviation_alerts = [a for a in alerts if a["type"] == "baseline_deviation"]
        assert any(a["severity"] == "high" for a in deviation_alerts)

        # z = 7.0 → critical
        features = {"event_count_1h": 120.0, "bytes_sent_total_1h": 1000.0}
        alerts = comp.compare(profile, features)
        deviation_alerts = [a for a in alerts if a["type"] == "baseline_deviation"]
        assert any(a["severity"] == "critical" for a in deviation_alerts)

    def test_new_destination_alert(self):
        """New network destination triggers alert."""
        comp = BaselineComparator()
        profile = self._active_profile()

        features = {"event_count_1h": 50.0, "bytes_sent_total_1h": 1000.0}
        event = {"dest_ip": "172.16.0.99"}
        alerts = comp.compare(profile, features, event)
        new_dest_alerts = [a for a in alerts if a["type"] == "new_destination"]
        assert len(new_dest_alerts) == 1
        assert new_dest_alerts[0]["dest_ip"] == "172.16.0.99"

    def test_known_destination_no_alert(self):
        """Known destination does not trigger alert."""
        comp = BaselineComparator()
        profile = self._active_profile()

        features = {"event_count_1h": 50.0, "bytes_sent_total_1h": 1000.0}
        event = {"dest_ip": "10.0.0.1"}
        alerts = comp.compare(profile, features, event)
        new_dest_alerts = [a for a in alerts if a["type"] == "new_destination"]
        assert len(new_dest_alerts) == 0

    def test_p95_exceedance_alert(self):
        """P95 exceedance triggers alert."""
        comp = BaselineComparator()
        profile = self._active_profile()

        # bytes_sent_total_1h: p95=1329, multiplier=2.0 → threshold=2658
        features = {"event_count_1h": 50.0, "bytes_sent_total_1h": 3000.0}
        alerts = comp.compare(profile, features)
        p95_alerts = [a for a in alerts if a["type"] == "baseline_p95_exceedance"]
        assert len(p95_alerts) == 1

    def test_zscore_static_method(self):
        """zscore computes correctly."""
        assert BaselineComparator.zscore(50.0, 10.0, 70.0) == 2.0
        assert BaselineComparator.zscore(50.0, 0.0, 70.0) == 0.0  # Zero std

    def test_in_baseline_destinations(self):
        """in_baseline_destinations checks correctly."""
        profile = self._active_profile()
        assert BaselineComparator.in_baseline_destinations("10.0.0.1", profile) is True
        assert BaselineComparator.in_baseline_destinations("1.2.3.4", profile) is False

    def test_baseline_p95(self):
        """baseline_p95 returns correct value."""
        profile = self._active_profile()
        assert BaselineComparator.baseline_p95(profile, "event_count_1h") == 66.45
        assert BaselineComparator.baseline_p95(profile, "nonexistent") == 0.0

    def test_js_divergence_unseen_event(self):
        """JS divergence is 1.0 for a never-seen event type."""
        comp = BaselineComparator()
        profile = self._active_profile()
        event = {"event_type": "NEVER_SEEN_BEFORE"}
        features = {"event_count_1h": 50.0, "bytes_sent_total_1h": 1000.0}
        alerts = comp.compare(profile, features, event)
        dist_alerts = [a for a in alerts if a["type"] == "distribution_shift"]
        # A never-seen event type should have high divergence
        assert len(dist_alerts) >= 1

# ── BaselineUpdater Tests ────────────────────────────────────────────────────

class TestBaselineUpdater:
    """Tests for the BaselineUpdater (without actual PostgreSQL)."""

    @pytest.mark.asyncio
    async def test_process_event_creates_profile(self):
        """process_event creates a new profile if none exists."""
        updater = BaselineUpdater(pg_pool=None)
        event = {"tenant_id": "t1", "agent_id": "a1"}
        features = {"event_count_1h": 10.0}

        alerts = await updater.process_event(event, features)
        assert isinstance(alerts, list)

        # Profile should be cached
        assert "t1:a1" in updater._profiles

    @pytest.mark.asyncio
    async def test_process_event_returns_alerts(self):
        """Active profile generates alerts on deviation."""
        updater = BaselineUpdater(pg_pool=None)

        # Pre-populate with an ACTIVE profile
        profile = BaselineProfile(agent_id="a1", tenant_id="t1", mode="ACTIVE")
        profile.metrics["event_count_1h"] = MetricBaseline(mean=50.0, std=10.0, p95=66.45, count=1000)
        updater._profiles["t1:a1"] = profile

        event = {"tenant_id": "t1", "agent_id": "a1", "event_id": "e1"}
        features = {"event_count_1h": 100.0}  # z-score = 5.0 → alert

        alerts = await updater.process_event(event, features)
        assert len(alerts) > 0
        assert all(a["tenant_id"] == "t1" for a in alerts)
        assert all(a["agent_id"] == "a1" for a in alerts)

    @pytest.mark.asyncio
    async def test_get_baseline_mode(self):
        """get_baseline_mode returns correct mode."""
        updater = BaselineUpdater(pg_pool=None)
        profile = BaselineProfile(agent_id="a1", tenant_id="t1", mode="ACTIVE")
        updater._profiles["t1:a1"] = profile

        mode = await updater.get_baseline_mode("t1", "a1")
        assert mode == "ACTIVE"

    @pytest.mark.asyncio
    async def test_get_baseline_mode_default(self):
        """get_baseline_mode returns LEARNING for unknown agents."""
        updater = BaselineUpdater(pg_pool=None)
        mode = await updater.get_baseline_mode("t1", "unknown_agent")
        assert mode == "LEARNING"

    @pytest.mark.asyncio
    async def test_missing_tenant_agent_skipped(self):
        """Events without tenant_id or agent_id are skipped."""
        updater = BaselineUpdater(pg_pool=None)

        alerts = await updater.process_event({}, {})
        assert alerts == []
        alerts = await updater.process_event({"tenant_id": "t1"}, {})
        assert alerts == []
        alerts = await updater.process_event({"agent_id": "a1"}, {})
        assert alerts == []

    @pytest.mark.asyncio
    async def test_get_profile(self):
        """get_profile returns the cached profile."""
        updater = BaselineUpdater(pg_pool=None)
        profile = BaselineProfile(agent_id="a1", tenant_id="t1")
        updater._profiles["t1:a1"] = profile

        result = await updater.get_profile("t1", "a1")
        assert result is profile

    @pytest.mark.asyncio
    async def test_get_profile_none_for_unknown(self):
        """get_profile returns None for unknown agents."""
        updater = BaselineUpdater(pg_pool=None)
        result = await updater.get_profile("t1", "unknown")
        assert result is None

# ── PRL Baseline Functions Tests ─────────────────────────────────────────────

class TestPRLBaselineFunctions:
    """Tests for the 4 PRL built-in baseline functions."""

    def test_fn_baseline_mode(self):
        """baseline_mode() returns the agent's baseline mode."""
        from engine.evaluator.functions import fn_baseline_mode
        from ml.baseline.models import BaselineProfile

        profile = BaselineProfile(agent_id="a1", tenant_id="t1", mode="ACTIVE")
        ctx = {
            "tenant_id": "t1",
            "event": {"agent_id": "a1"},
            "_baseline_profiles": {"t1:a1": profile},
        }
        result = fn_baseline_mode([], ctx, None)
        assert result == "ACTIVE"

    def test_fn_baseline_mode_default(self):
        """baseline_mode() returns LEARNING when no profile exists."""
        from engine.evaluator.functions import fn_baseline_mode

        ctx = {"tenant_id": "t1", "event": {"agent_id": "a1"}, "_baseline_profiles": {}}
        result = fn_baseline_mode([], ctx, None)
        assert result == "LEARNING"

    def test_fn_in_baseline_destinations(self):
        """in_baseline_destinations() checks known destinations."""
        from engine.evaluator.functions import fn_in_baseline_destinations
        from ml.baseline.models import BaselineProfile

        profile = BaselineProfile(agent_id="a1", tenant_id="t1")
        profile.known_destinations = {"10.0.0.1", "10.0.0.2"}
        ctx = {
            "tenant_id": "t1",
            "event": {"agent_id": "a1"},
            "_baseline_profiles": {"t1:a1": profile},
        }
        assert fn_in_baseline_destinations(["10.0.0.1"], ctx, None) is True
        assert fn_in_baseline_destinations(["1.2.3.4"], ctx, None) is False

    def test_fn_baseline_p95(self):
        """baseline_p95() returns the P95 from the baseline."""
        from engine.evaluator.functions import fn_baseline_p95
        from ml.baseline.models import BaselineProfile, MetricBaseline

        profile = BaselineProfile(agent_id="a1", tenant_id="t1")
        profile.metrics["event_count_1h"] = MetricBaseline(p95=66.45)
        ctx = {
            "tenant_id": "t1",
            "event": {"agent_id": "a1"},
            "_baseline_profiles": {"t1:a1": profile},
        }
        assert fn_baseline_p95(["event_count_1h"], ctx, None) == 66.45
        assert fn_baseline_p95(["nonexistent"], ctx, None) == 0.0

    def test_fn_baseline_zscore(self):
        """baseline_zscore() computes z-score against baseline."""
        from engine.evaluator.functions import fn_baseline_zscore
        from ml.baseline.models import BaselineProfile, MetricBaseline

        profile = BaselineProfile(agent_id="a1", tenant_id="t1")
        profile.metrics["event_count_1h"] = MetricBaseline(mean=50.0, std=10.0)
        ctx = {
            "tenant_id": "t1",
            "event": {"agent_id": "a1"},
            "_baseline_profiles": {"t1:a1": profile},
        }
        # z = (70 - 50) / 10 = 2.0
        result = fn_baseline_zscore(["event_count_1h", 70.0], ctx, None)
        assert result == pytest.approx(2.0)

    def test_fn_baseline_zscore_no_profile(self):
        """baseline_zscore() returns 0.0 when no profile exists."""
        from engine.evaluator.functions import fn_baseline_zscore

        ctx = {"tenant_id": "t1", "event": {"agent_id": "a1"}, "_baseline_profiles": {}}
        result = fn_baseline_zscore(["event_count_1h", 70.0], ctx, None)
        assert result == 0.0

    def test_builtin_registry_includes_baseline(self):
        """BuiltinRegistry registers all 4 baseline functions."""
        from engine.evaluator.functions import BuiltinRegistry

        registry = BuiltinRegistry()
        names = registry.names
        assert "baseline_mode" in names
        assert "in_baseline_destinations" in names
        assert "baseline_p95" in names
        assert "baseline_zscore" in names

# ── Sprint 3 Audit Hardening Tests ──────────────────────────────────────────

class TestEMAVarianceFix:
    """Verify the EMA variance bug fix (diff computed before mean update)."""

    def test_ema_variance_not_underestimated(self):
        """EMA variance should be reasonable (not systematically zero)."""
        builder = BaselineBuilder()
        profile = builder.create_profile("t1", "a1")
        # Force ACTIVE mode
        profile.mode = "ACTIVE"
        profile.metrics["event_count_1h"] = MetricBaseline(
            mean=100.0,
            std=10.0,
            count=100,
        )

        # Feed a value far from the mean
        features = {"event_count_1h": 200.0}
        builder.update_profile(profile, features)

        mb = profile.metrics["event_count_1h"]
        # After EMA update with value=200, mean should move toward 200
        # and std should NOT be zero (the old bug would underestimate)
        assert mb.std > 0, "EMA variance must not collapse to zero"
        assert mb.mean > 100.0, "EMA mean should increase toward 200"

    def test_ema_variance_stable_values(self):
        """Feeding the same value repeatedly should shrink variance toward 0."""
        builder = BaselineBuilder()
        profile = builder.create_profile("t1", "a1")
        profile.mode = "ACTIVE"
        profile.metrics["event_count_1h"] = MetricBaseline(
            mean=50.0,
            std=10.0,
            count=100,
        )
        # Feed mean value 50 times → variance should decrease
        for _ in range(50):
            builder.update_profile(profile, {"event_count_1h": 50.0})
        mb = profile.metrics["event_count_1h"]
        assert mb.std < 2.0, "Variance should decay toward 0 with constant input"

class TestComparatorActiveHours:
    """Tests for the active hours anomaly detection."""

    def test_unusual_hour_alert(self):
        """Activity at an hour with < 1% historical traffic → alert."""
        comparator = BaselineComparator()
        profile = BaselineProfile(agent_id="a1", tenant_id="t1", mode="ACTIVE")
        # Build histogram: most activity at hours 9-17
        for h in range(9, 18):
            profile.hour_histogram[h] = 100  # 900 total in business hours
        profile.hour_histogram[3] = 0  # No activity at 3 AM

        event = {"event_type": "TOOL_CALL", "timestamp_epoch": 1740459600.0}
        # 1740459600 is a specific timestamp; we patch to control the hour
        import datetime

        # Use a timestamp where UTC hour = 3
        # 2025-02-25 03:00:00 UTC
        ts_3am = datetime.datetime(2025, 2, 25, 3, 0, 0, tzinfo=datetime.UTC).timestamp()
        event["timestamp_epoch"] = ts_3am

        alerts = comparator.compare(profile, {}, event)
        types = [a["type"] for a in alerts]
        assert "unusual_hour" in types

    def test_normal_hour_no_alert(self):
        """Activity at a common hour → no unusual_hour alert."""
        comparator = BaselineComparator()
        profile = BaselineProfile(agent_id="a1", tenant_id="t1", mode="ACTIVE")
        for h in range(9, 18):
            profile.hour_histogram[h] = 100

        import datetime

        ts_noon = datetime.datetime(2025, 2, 25, 12, 0, 0, tzinfo=datetime.UTC).timestamp()
        event = {"event_type": "TOOL_CALL", "timestamp_epoch": ts_noon}
        alerts = comparator.compare(profile, {}, event)
        unusual = [a for a in alerts if a["type"] == "unusual_hour"]
        assert len(unusual) == 0

class TestComparatorNovelBigram:
    """Tests for novel sequence pattern detection."""

    def test_novel_event_type_alert(self):
        """Event type not in any known bigram → alert."""
        comparator = BaselineComparator()
        profile = BaselineProfile(agent_id="a1", tenant_id="t1", mode="ACTIVE")
        profile.top_bigrams = {
            "TOOL_CALL": 30,
            "FILE_READ": 20,
            "NETWORK_CONNECT": 10,
        }
        event = {"event_type": "NEVER_SEEN_BEFORE"}
        alerts = comparator.compare(profile, {}, event)
        types = [a["type"] for a in alerts]
        assert "novel_sequence_pattern" in types

    def test_known_event_type_no_alert(self):
        """Event type already in bigrams → no novel pattern alert."""
        comparator = BaselineComparator()
        profile = BaselineProfile(agent_id="a1", tenant_id="t1", mode="ACTIVE")
        profile.top_bigrams = {"TOOL_CALL": 30, "FILE_READ": 20}
        event = {"event_type": "TOOL_CALL"}
        alerts = comparator.compare(profile, {}, event)
        novel = [a for a in alerts if a["type"] == "novel_sequence_pattern"]
        assert len(novel) == 0

# ── Minimum Event Threshold Tests ────────────────────────────────────────────

class TestMinEventThreshold:
    """Tests for the LEARNING → ACTIVE minimum event requirement."""

    def test_time_met_but_events_not_met(self):
        """Profile stays LEARNING when time elapsed but events < min_learning_events."""
        builder = BaselineBuilder()
        profile = builder.create_profile("t1", "a1")
        profile.learning_start = time.time() - 8 * 86_400  # 8 days ago

        # Feed only a few events (way below 1000 threshold)
        for i in range(5):
            profile = builder.update_profile(profile, {"event_count_1h": float(i)})

        assert profile.mode == "LEARNING"

    def test_events_met_but_time_not_met(self):
        """Profile stays LEARNING when enough events but time < learning_days."""
        builder = BaselineBuilder()
        profile = builder.create_profile("t1", "a1")
        # learning_start = now, so time not met

        # Pre-populate metrics with enough count
        for metric_name in BASELINE_METRICS:
            profile.metrics[metric_name] = MetricBaseline(
                mean=50.0,
                std=5.0,
                count=2_000,
            )

        # Early graduation disabled for this test
        from unittest.mock import patch

        with patch.object(builder, "_check_variance_stability", return_value=False):
            profile = builder.update_profile(profile, {"event_count_1h": 50.0})
        assert profile.mode == "LEARNING"

    def test_both_met_transitions(self):
        """Profile transitions when both time AND events thresholds are met."""
        builder = BaselineBuilder()
        profile = builder.create_profile("t1", "a1")
        profile.learning_start = time.time() - 8 * 86_400

        for metric_name in BASELINE_METRICS:
            profile.metrics[metric_name] = MetricBaseline(
                mean=50.0,
                std=5.0,
                count=1_500,
            )

        profile = builder.update_profile(profile, {"event_count_1h": 50.0})
        assert profile.mode == "ACTIVE"

# ── Early Graduation Tests ───────────────────────────────────────────────────

class TestEarlyGraduation:
    """Tests for variance-stability-based early graduation."""

    def test_early_graduation_stable_variance(self):
        """Profile graduates early when variance is stable and enough events."""
        builder = BaselineBuilder()
        profile = builder.create_profile("t1", "a1")
        # Only 2 days in — time NOT met, but we have lots of stable data
        profile.learning_start = time.time() - 2 * 86_400

        for metric_name in BASELINE_METRICS:
            profile.metrics[metric_name] = MetricBaseline(
                mean=100.0,
                std=2.0,
                count=600,  # CV = 2/100 = 0.02 < 0.05
            )

        profile = builder.update_profile(profile, {"event_count_1h": 100.0})
        assert profile.mode == "ACTIVE"

    def test_no_early_grad_unstable_variance(self):
        """Profile does NOT graduate early when variance is high."""
        builder = BaselineBuilder()
        profile = builder.create_profile("t1", "a1")
        profile.learning_start = time.time() - 2 * 86_400

        for metric_name in BASELINE_METRICS:
            profile.metrics[metric_name] = MetricBaseline(
                mean=100.0,
                std=50.0,
                count=600,  # CV = 50/100 = 0.50 >> 0.05
            )

        profile = builder.update_profile(profile, {"event_count_1h": 100.0})
        assert profile.mode == "LEARNING"

    def test_no_early_grad_insufficient_events(self):
        """Early graduation requires minimum early_graduation_min_events."""
        builder = BaselineBuilder()
        profile = builder.create_profile("t1", "a1")
        profile.learning_start = time.time() - 2 * 86_400

        for metric_name in BASELINE_METRICS:
            profile.metrics[metric_name] = MetricBaseline(
                mean=100.0,
                std=2.0,
                count=50,  # Low count
            )

        profile = builder.update_profile(profile, {"event_count_1h": 100.0})
        assert profile.mode == "LEARNING"

# ── Alert-Aware Learning Tests ───────────────────────────────────────────────

class TestAlertAwareLearning:
    """Tests for excluding PRL-flagged events from baseline computation."""

    def test_flagged_event_excluded_from_metrics(self):
        """Alert-flagged events should not update metric baselines during LEARNING."""
        builder = BaselineBuilder()
        profile = builder.create_profile("t1", "a1")

        # Feed 10 normal events
        for _ in range(10):
            profile = builder.update_profile(
                profile,
                {"event_count_1h": 50.0},
                is_alert_flagged=False,
            )
        count_before = profile.metrics["event_count_1h"].count
        mean_before = profile.metrics["event_count_1h"].mean

        # Feed 1 alert-flagged event with extreme value
        profile = builder.update_profile(
            profile,
            {"event_count_1h": 99999.0},
            is_alert_flagged=True,
        )

        # Metric should NOT have been updated
        assert profile.metrics["event_count_1h"].count == count_before
        assert profile.metrics["event_count_1h"].mean == mean_before

    def test_flagged_event_still_tracks_destinations(self):
        """Alert-flagged events should still update destinations and histograms."""
        builder = BaselineBuilder()
        profile = builder.create_profile("t1", "a1")

        event = {"dest_ip": "10.0.0.99", "event_type": "NETWORK_CONNECT"}
        profile = builder.update_profile(
            profile,
            {"event_count_1h": 50.0},
            event,
            is_alert_flagged=True,
        )
        assert "10.0.0.99" in profile.known_destinations
        assert profile.event_type_histogram.get("NETWORK_CONNECT", 0) > 0

    def test_flagged_event_updates_metrics_in_active(self):
        """Alert-flagged events SHOULD update metrics when in ACTIVE mode (not LEARNING)."""
        builder = BaselineBuilder()
        profile = builder.create_profile("t1", "a1")
        profile.mode = "ACTIVE"
        profile.metrics["event_count_1h"] = MetricBaseline(
            mean=50.0,
            std=5.0,
            count=100,
        )

        profile = builder.update_profile(
            profile,
            {"event_count_1h": 200.0},
            is_alert_flagged=True,
        )
        # In ACTIVE mode, flagged events DO update (alert-aware only applies to LEARNING)
        assert profile.metrics["event_count_1h"].count == 101
