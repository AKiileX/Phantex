# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Human-Readable Feature Description Templates (J5c).

Deterministic, template-based descriptions for feature values.
No LLM — auditable, no hallucination risk. Each feature category
has a template that converts raw values into natural language.
"""

from __future__ import annotations

from typing import Any

# -------------------------------------------------------------------
# Feature templates: {feature_name: description_template}
# Supports {value}, {baseline}, {z_score} placeholders.
# -------------------------------------------------------------------

_TEMPLATES: dict[str, str] = {
    # Volume features
    "syscall_count_1m": "{value:.0f} system calls in last minute (baseline: ~{baseline:.0f})",
    "syscall_count_5m": "{value:.0f} system calls in last 5 minutes (baseline: ~{baseline:.0f})",
    "file_read_count_1h": "{value:.0f} file reads in last hour (baseline: ~{baseline:.0f})",
    "file_write_count_1h": "{value:.0f} file writes in last hour (baseline: ~{baseline:.0f})",
    "network_connect_count_1h": "{value:.0f} network connections in last hour (baseline: ~{baseline:.0f})",
    "process_spawn_count_1h": "{value:.0f} processes spawned in last hour (baseline: ~{baseline:.0f})",
    # Velocity features
    "syscall_rate_1m": "System call rate: {value:.1f}/sec (baseline: ~{baseline:.1f}/sec)",
    "file_access_rate_5m": "File access rate: {value:.1f}/min ({z_score:.1f}σ above baseline)",
    "network_rate_5m": "Network connection rate: {value:.1f}/min ({z_score:.1f}σ above baseline)",
    # Diversity features
    "unique_file_paths_1h": "{value:.0f} unique file paths accessed (baseline: ~{baseline:.0f})",
    "unique_network_dests_1h": "{value:.0f} unique network destinations (baseline: ~{baseline:.0f})",
    "unique_syscalls_1h": "{value:.0f} distinct syscall types (baseline: ~{baseline:.0f})",
    "unique_tools_1h": "{value:.0f} unique tools invoked (baseline: ~{baseline:.0f})",
    # Behavioral features
    "sensitive_file_ratio": "{value:.1%} of file accesses target sensitive paths",
    "credential_access_count": "{value:.0f} credential store accesses",
    "privilege_escalation_attempts": "{value:.0f} privilege escalation attempts detected",
    "shell_command_count_1h": "{value:.0f} shell commands executed in last hour",
    "new_behavior_ratio": "{value:.1%} of actions are first-time behaviors for this agent",
    # Network features
    "outbound_bytes_1h": "{value:.0f} bytes sent outbound in last hour (baseline: ~{baseline:.0f})",
    "inbound_bytes_1h": "{value:.0f} bytes received in last hour",
    "dns_query_count_1h": "{value:.0f} DNS queries in last hour",
    "new_destination_count": "{value:.0f} never-before-seen network destinations",
    # Temporal features
    "hour_of_day": "Activity at hour {value:.0f} (UTC)",
    "time_since_last_activity": "{value:.0f}s since last activity (baseline: ~{baseline:.0f}s)",
    "burst_duration_s": "Activity burst lasting {value:.1f} seconds",
    # Sequence features
    "entropy_syscall_sequence": "Syscall sequence entropy: {value:.2f} (baseline: ~{baseline:.2f})",
    "longest_repeat_run": "Longest repeating syscall pattern: {value:.0f} calls",
    "rare_syscall_ratio": "{value:.1%} of syscalls are rarely seen for this agent",
    # MCP features
    "mcp_tool_call_count_1h": "{value:.0f} MCP tool calls in last hour (baseline: ~{baseline:.0f})",
    "mcp_tool_diversity_1h": "{value:.0f} distinct MCP tools used",
    "mcp_sensitive_tool_ratio": "{value:.1%} of MCP calls target sensitive tools",
    "mcp_prompt_injection_score": "Prompt injection risk score: {value:.2f}",
    "mcp_resource_access_breadth": "{value:.0f} distinct MCP resources accessed",
    "mcp_error_rate_1h": "{value:.1%} MCP call error rate",
    "mcp_chained_tool_depth": "MCP tool chain depth: {value:.0f} (baseline: ~{baseline:.0f})",
    "mcp_cross_server_calls": "{value:.0f} cross-server MCP calls",
    "mcp_unusual_hour_flag": "MCP activity at unusual hour (anomaly flag: {value:.0f})",
    "mcp_tool_velocity_5m": "MCP tool call velocity: {value:.1f}/min",
    # Trust features
    "trust_score": "Trust score: {value:.2f} (0=untrusted, 1=fully trusted)",
}

# Default template for unknown features
_DEFAULT_TEMPLATE = "{name}: {value:.4g}"

def get_feature_description(
    name: str,
    value: float,
    baseline: float = 0.0,
    z_score: float = 0.0,
) -> str:
    """Generate human-readable description for a feature value.

    Args:
        name: Feature name.
        value: Current feature value.
        baseline: Expected baseline value.
        z_score: Z-score deviation from baseline.

    Returns:
        Human-readable string describing the feature.
    """
    template = _TEMPLATES.get(name)
    if template is None:
        return _DEFAULT_TEMPLATE.format(name=name.replace("_", " "), value=value)

    try:
        return template.format(value=value, baseline=baseline, z_score=z_score)
    except (KeyError, ValueError):
        return _DEFAULT_TEMPLATE.format(name=name.replace("_", " "), value=value)

def enrich_features_with_descriptions(
    top_features: list[dict[str, Any]],
    baselines: dict[str, float] | None = None,
) -> list[dict[str, Any]]:
    """Add human_readable description to each feature dict.

    Args:
        top_features: List of feature dicts with 'name' and 'value' keys.
        baselines: Optional baseline values per feature.

    Returns:
        Same list with 'human_readable' key added.
    """
    baselines = baselines or {}

    for feat in top_features:
        name = feat.get("name", "")
        value = feat.get("value", 0.0)
        baseline = baselines.get(name, 0.0)
        z_score = feat.get("z_score", 0.0)
        feat["human_readable"] = get_feature_description(name, value, baseline, z_score)

    return top_features

def list_templates() -> dict[str, str]:
    """Return all registered feature templates (for documentation)."""
    return dict(_TEMPLATES)
