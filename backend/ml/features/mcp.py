# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — MCP-Specific Features (J1 Hardening).

Features designed to detect malicious MCP (Model Context Protocol) tool server
interactions. Captures tool diversity per server, resource access patterns,
prompt-to-tool correlation ratios, and MCP-specific behavioral anomalies.

These features provide high-signal detection for:
- Malicious MCP servers (prompt injection via read_resource)
- Tool abuse via compromised MCP tool servers
- Unusual MCP interaction patterns (extraction, enumeration)
"""

from __future__ import annotations

from collections import Counter

from ml.features.registry import FeatureDefinition, register_feature

# ── Feature Definitions ──────────────────────────────────────────────────────

register_feature(
    FeatureDefinition(
        name="mcp_tool_call_count_1h",
        category="mcp",
        description="Number of MCP tool calls in the last 1 hour",
        window="1h",
    )
)

register_feature(
    FeatureDefinition(
        name="mcp_unique_tools_1h",
        category="mcp",
        description="Number of unique MCP tools invoked in the last 1 hour",
        window="1h",
    )
)

register_feature(
    FeatureDefinition(
        name="mcp_tool_diversity_ratio",
        category="mcp",
        description="Ratio of unique MCP tools to total MCP calls (1h). High = exploration/enumeration",
        window="1h",
    )
)

register_feature(
    FeatureDefinition(
        name="mcp_resource_read_count_1h",
        category="mcp",
        description="Number of MCP resource reads in the last 1 hour",
        window="1h",
    )
)

register_feature(
    FeatureDefinition(
        name="mcp_unique_resources_1h",
        category="mcp",
        description="Number of unique MCP resources read in the last 1 hour",
        window="1h",
    )
)

register_feature(
    FeatureDefinition(
        name="mcp_prompt_to_tool_ratio",
        category="mcp",
        description="Ratio of MCP get_prompt calls to tool_call events (1h). High = prompt injection probing",
        window="1h",
    )
)

register_feature(
    FeatureDefinition(
        name="mcp_list_tools_count_1h",
        category="mcp",
        description="Number of MCP list_tools calls (1h). High = server enumeration",
        window="1h",
    )
)

register_feature(
    FeatureDefinition(
        name="mcp_avg_tool_duration_ms",
        category="mcp",
        description="Average MCP tool call duration in milliseconds (1h)",
        window="1h",
    )
)

register_feature(
    FeatureDefinition(
        name="mcp_tool_error_rate",
        category="mcp",
        description="Fraction of MCP tool calls resulting in error responses (1h)",
        window="1h",
    )
)

register_feature(
    FeatureDefinition(
        name="mcp_top_tool_dominance",
        category="mcp",
        description="Fraction of MCP calls made to the most-used tool (1h). Low = scanning many tools",
        window="1h",
    )
)

# ── MCP Event Type Constants ─────────────────────────────────────────────────

_MCP_TOOL_CALL = "MCP_TOOL_CALL"
_MCP_RESOURCE_READ = "MCP_RESOURCE_READ"
_MCP_GET_PROMPT = "MCP_GET_PROMPT"
_MCP_LIST_TOOLS = "MCP_LIST_TOOLS"
_MCP_EVENT_TYPES = {_MCP_TOOL_CALL, _MCP_RESOURCE_READ, _MCP_GET_PROMPT, _MCP_LIST_TOOLS}

# Also match SDK-generated tool call/response events that may be MCP-routed
_TOOL_CALL = "TOOL_CALL"
_TOOL_RESPONSE = "TOOL_RESPONSE"

def compute_mcp_features(
    events: list[dict],
    now: float,
) -> dict[str, float]:
    """Compute MCP-specific features from recent events.

    Args:
        events: Event dicts sorted by timestamp_epoch ascending.
        now: Current epoch timestamp.

    Returns:
        Dict of feature_name → value.
    """
    cutoff = now - 3_600  # 1h window
    window_events = [e for e in events if e.get("timestamp_epoch", 0) >= cutoff]

    # Filter to MCP-related events
    mcp_events = []
    tool_call_events = []
    resource_events = []
    prompt_events = []
    list_events = []

    for e in window_events:
        etype = e.get("event_type", "")
        tool = e.get("tool_name", "")

        # Direct MCP event types
        if etype in _MCP_EVENT_TYPES:
            mcp_events.append(e)
            if etype == _MCP_TOOL_CALL:
                tool_call_events.append(e)
            elif etype == _MCP_RESOURCE_READ:
                resource_events.append(e)
            elif etype == _MCP_GET_PROMPT:
                prompt_events.append(e)
            elif etype == _MCP_LIST_TOOLS:
                list_events.append(e)
        # SDK tool calls that route through MCP (tool name starts with mcp_)
        elif etype in (_TOOL_CALL, _TOOL_RESPONSE) and tool.startswith("mcp_"):
            mcp_events.append(e)
            tool_call_events.append(e)

    # ── Tool call metrics ────────────────────────────────────────────────
    total_calls = len(tool_call_events)
    tool_names = [e.get("tool_name", "") for e in tool_call_events]
    tool_counter = Counter(tool_names)
    unique_tools = len(tool_counter)

    diversity_ratio = (unique_tools / total_calls) if total_calls > 0 else 0.0
    top_tool_count = tool_counter.most_common(1)[0][1] if tool_counter else 0
    top_dominance = (top_tool_count / total_calls) if total_calls > 0 else 0.0

    # ── Resource access metrics ──────────────────────────────────────────
    resource_count = len(resource_events)
    resource_names = {e.get("file_path", "") or e.get("tool_name", "") for e in resource_events}
    unique_resources = len(resource_names - {""})

    # ── Prompt-to-tool ratio ─────────────────────────────────────────────
    prompt_count = len(prompt_events)
    prompt_to_tool = (prompt_count / total_calls) if total_calls > 0 else 0.0

    # ── Duration metrics ─────────────────────────────────────────────────
    durations = []
    for e in tool_call_events:
        d = e.get("tool_duration_ms")
        if d is not None and isinstance(d, int | float) and d >= 0:
            durations.append(float(d))
    avg_duration = (sum(durations) / len(durations)) if durations else 0.0

    # ── Error rate (approximation: tool response with no duration = error) ──
    error_count = sum(
        1 for e in tool_call_events if e.get("tool_duration_ms") is not None and e.get("tool_duration_ms", 0) < 0
    )
    error_rate = (error_count / total_calls) if total_calls > 0 else 0.0

    return {
        "mcp_tool_call_count_1h": float(total_calls),
        "mcp_unique_tools_1h": float(unique_tools),
        "mcp_tool_diversity_ratio": min(diversity_ratio, 1.0),
        "mcp_resource_read_count_1h": float(resource_count),
        "mcp_unique_resources_1h": float(unique_resources),
        "mcp_prompt_to_tool_ratio": min(prompt_to_tool, 100.0),
        "mcp_list_tools_count_1h": float(len(list_events)),
        "mcp_avg_tool_duration_ms": min(avg_duration, 1_000_000.0),
        "mcp_tool_error_rate": min(error_rate, 1.0),
        "mcp_top_tool_dominance": min(top_dominance, 1.0),
    }
