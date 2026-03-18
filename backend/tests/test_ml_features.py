# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for ML Feature Registry (J1).
"""

import pytest

from ml.features.registry import (
    FeatureDefinition,
    feature_defaults,
    feature_names,
    get_feature,
    list_features,
    register_feature,
)

class TestFeatureRegistry:
    """Tests for the global feature catalogue."""

    def test_registry_populated_at_import(self):
        """All feature modules register their features on import."""
        # Import all feature modules to trigger registration
        import ml.features.behavioral  # noqa: F401
        import ml.features.diversity  # noqa: F401
        import ml.features.network  # noqa: F401
        import ml.features.sequence  # noqa: F401
        import ml.features.temporal  # noqa: F401
        import ml.features.velocity  # noqa: F401
        import ml.features.volume  # noqa: F401

        names = feature_names()
        assert len(names) >= 40, f"Expected ≥40 features, got {len(names)}"

    def test_register_and_lookup(self):
        """register_feature + get_feature round-trip works."""
        defn = FeatureDefinition(
            name="test_metric_1h",
            category="test",
            description="A test metric",
            window="1h",
            default=42.0,
        )
        register_feature(defn)
        assert get_feature("test_metric_1h") is defn

    def test_feature_defaults_returns_dict(self):
        """feature_defaults returns a dict with float values."""
        defaults = feature_defaults()
        assert isinstance(defaults, dict)
        for k, v in defaults.items():
            assert isinstance(k, str)
            assert isinstance(v, int | float)

    def test_list_features_sorted(self):
        """list_features returns features sorted by name."""
        features = list_features()
        names = [f.name for f in features]
        assert names == sorted(names)

    def test_feature_categories_present(self):
        """All expected categories are represented."""
        import ml.features.mcp  # noqa: F401

        features = list_features()
        categories = {f.category for f in features}
        expected = {"volume", "velocity", "behavioral", "network", "temporal", "diversity", "sequence", "mcp"}
        # May have our test category too
        assert expected.issubset(categories | {"test"}) or expected.issubset(categories)

    def test_volume_features_registered(self):
        """Volume module registers 16 features (4 types × 4 windows)."""
        import ml.features.volume  # noqa: F401

        volume_features = [f for f in list_features() if f.category == "volume"]
        assert len(volume_features) == 16

    def test_temporal_features_registered(self):
        """Temporal module registers instant features (no window)."""
        import ml.features.temporal  # noqa: F401

        temporal_features = [f for f in list_features() if f.category == "temporal"]
        assert len(temporal_features) >= 4
        # All temporal features have window=None (instant)
        for f in temporal_features:
            assert f.window is None, f"{f.name} should have window=None"

# ── MCP Feature Tests ────────────────────────────────────────────────────────

class TestMCPFeatures:
    """Tests for MCP-specific feature extraction."""

    def test_mcp_features_registered(self):
        """MCP module registers 10 features."""
        import ml.features.mcp  # noqa: F401

        mcp_features = [f for f in list_features() if f.category == "mcp"]
        assert len(mcp_features) == 10

    def test_registry_total_with_mcp(self):
        """Total feature count includes MCP features (52 + 10 = 62)."""
        import ml.features.behavioral  # noqa: F401
        import ml.features.diversity  # noqa: F401
        import ml.features.mcp  # noqa: F401
        import ml.features.network  # noqa: F401
        import ml.features.sequence  # noqa: F401
        import ml.features.temporal  # noqa: F401
        import ml.features.velocity  # noqa: F401
        import ml.features.volume  # noqa: F401

        names = feature_names()
        assert len(names) >= 60, f"Expected ≥60 features with MCP, got {len(names)}"

    def test_compute_mcp_no_events(self):
        """Empty event list returns zero-value MCP features."""
        import time

        from ml.features.mcp import compute_mcp_features

        result = compute_mcp_features([], time.time())
        assert result["mcp_tool_call_count_1h"] == 0.0
        assert result["mcp_unique_tools_1h"] == 0.0
        assert result["mcp_tool_diversity_ratio"] == 0.0

    def test_compute_mcp_tool_calls(self):
        """MCP tool call events produce correct feature values."""
        import time

        from ml.features.mcp import compute_mcp_features

        now = time.time()
        events = [
            {
                "event_type": "MCP_TOOL_CALL",
                "tool_name": "web_search",
                "timestamp_epoch": now - 100,
                "tool_duration_ms": 50,
            },
            {
                "event_type": "MCP_TOOL_CALL",
                "tool_name": "web_search",
                "timestamp_epoch": now - 90,
                "tool_duration_ms": 60,
            },
            {
                "event_type": "MCP_TOOL_CALL",
                "tool_name": "read_file",
                "timestamp_epoch": now - 80,
                "tool_duration_ms": 20,
            },
        ]
        result = compute_mcp_features(events, now)
        assert result["mcp_tool_call_count_1h"] == 3.0
        assert result["mcp_unique_tools_1h"] == 2.0
        assert result["mcp_tool_diversity_ratio"] == pytest.approx(2.0 / 3.0, rel=0.01)
        assert result["mcp_avg_tool_duration_ms"] == pytest.approx(130 / 3, rel=0.01)
        assert result["mcp_top_tool_dominance"] == pytest.approx(2.0 / 3.0, rel=0.01)

    def test_compute_mcp_resource_reads(self):
        """MCP resource read events count correctly."""
        import time

        from ml.features.mcp import compute_mcp_features

        now = time.time()
        events = [
            {"event_type": "MCP_RESOURCE_READ", "file_path": "/data/config.json", "timestamp_epoch": now - 50},
            {"event_type": "MCP_RESOURCE_READ", "file_path": "/data/secrets.env", "timestamp_epoch": now - 40},
            {"event_type": "MCP_RESOURCE_READ", "file_path": "/data/config.json", "timestamp_epoch": now - 30},
        ]
        result = compute_mcp_features(events, now)
        assert result["mcp_resource_read_count_1h"] == 3.0
        assert result["mcp_unique_resources_1h"] == 2.0

    def test_compute_mcp_prompt_injection_pattern(self):
        """High prompt-to-tool ratio indicates potential prompt injection probing."""
        import time

        from ml.features.mcp import compute_mcp_features

        now = time.time()
        events = [
            {"event_type": "MCP_TOOL_CALL", "tool_name": "exec", "timestamp_epoch": now - 100, "tool_duration_ms": 10},
            {"event_type": "MCP_GET_PROMPT", "tool_name": "", "timestamp_epoch": now - 90},
            {"event_type": "MCP_GET_PROMPT", "tool_name": "", "timestamp_epoch": now - 80},
            {"event_type": "MCP_GET_PROMPT", "tool_name": "", "timestamp_epoch": now - 70},
        ]
        result = compute_mcp_features(events, now)
        assert result["mcp_prompt_to_tool_ratio"] == 3.0  # 3 prompts / 1 tool call

    def test_compute_mcp_enumeration_pattern(self):
        """High list_tools count indicates server enumeration."""
        import time

        from ml.features.mcp import compute_mcp_features

        now = time.time()
        events = [
            {"event_type": "MCP_LIST_TOOLS", "tool_name": "", "timestamp_epoch": now - 60},
            {"event_type": "MCP_LIST_TOOLS", "tool_name": "", "timestamp_epoch": now - 50},
            {"event_type": "MCP_LIST_TOOLS", "tool_name": "", "timestamp_epoch": now - 40},
        ]
        result = compute_mcp_features(events, now)
        assert result["mcp_list_tools_count_1h"] == 3.0

    def test_compute_mcp_sdk_prefixed_tools(self):
        """SDK TOOL_CALL events with mcp_ prefix are counted as MCP events."""
        import time

        from ml.features.mcp import compute_mcp_features

        now = time.time()
        events = [
            {
                "event_type": "TOOL_CALL",
                "tool_name": "mcp_web_search",
                "timestamp_epoch": now - 100,
                "tool_duration_ms": 25,
            },
            {
                "event_type": "TOOL_CALL",
                "tool_name": "mcp_read_file",
                "timestamp_epoch": now - 90,
                "tool_duration_ms": 15,
            },
            {
                "event_type": "TOOL_CALL",
                "tool_name": "regular_tool",
                "timestamp_epoch": now - 80,
                "tool_duration_ms": 10,
            },
        ]
        result = compute_mcp_features(events, now)
        # Only the mcp_-prefixed tools should be counted
        assert result["mcp_tool_call_count_1h"] == 2.0
        assert result["mcp_unique_tools_1h"] == 2.0

    def test_compute_mcp_outside_window(self):
        """Events outside the 1h window are excluded."""
        import time

        from ml.features.mcp import compute_mcp_features

        now = time.time()
        events = [
            {"event_type": "MCP_TOOL_CALL", "tool_name": "old_tool", "timestamp_epoch": now - 7200},  # 2h ago
            {"event_type": "MCP_TOOL_CALL", "tool_name": "recent_tool", "timestamp_epoch": now - 100},
        ]
        result = compute_mcp_features(events, now)
        assert result["mcp_tool_call_count_1h"] == 1.0
