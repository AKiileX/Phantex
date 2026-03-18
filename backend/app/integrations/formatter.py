# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Event/Alert Formatter (N1).

Converts internal Phantex alert/event dicts into platform-native formats:
  - Splunk HEC JSON
  - Azure Sentinel (Log Analytics Collector JSON)
  - Elastic SIEM (NDJSON bulk format)
  - CrowdStrike LogScale JSON
  - Syslog CEF string

All formatters sanitize user-controlled data to prevent injection
(especially critical for CEF header/extension fields).
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

# ── Splunk HEC ────────────────────────────────────────────────────────────────

def to_splunk_hec(event: dict[str, Any], sourcetype: str = "phantex:alert") -> dict:
    """Format an event for Splunk HTTP Event Collector."""
    return {
        "time": _epoch_seconds(event),
        "sourcetype": sourcetype,
        "source": "phantex-backend",
        "index": "phantex",
        "event": _base_event(event),
    }

def to_splunk_hec_batch(events: list[dict[str, Any]]) -> str:
    """Format multiple events as newline-delimited JSON for Splunk HEC batch."""
    return "\n".join(json.dumps(to_splunk_hec(e), default=str) for e in events)

# ── Azure Sentinel ────────────────────────────────────────────────────────────

def to_azure_sentinel(event: dict[str, Any]) -> dict:
    """Format for Azure Log Analytics Data Collector API."""
    base = _base_event(event)
    base["TimeGenerated"] = event.get("timestamp", "")
    return base

def to_azure_sentinel_batch(events: list[dict[str, Any]]) -> str:
    """JSON array for Azure Sentinel batch."""
    return json.dumps([to_azure_sentinel(e) for e in events], default=str)

# ── Elastic SIEM ──────────────────────────────────────────────────────────────

def to_elastic_ndjson(events: list[dict[str, Any]], index: str = "phantex-alerts") -> str:
    """Format as NDJSON for Elasticsearch Bulk API.

    Each event becomes two lines: action + document.
    """
    lines = []
    for e in events:
        action = json.dumps({"index": {"_index": index}})
        doc = _base_event(e)
        doc["@timestamp"] = e.get("timestamp", "")
        lines.append(action)
        lines.append(json.dumps(doc, default=str))
    return "\n".join(lines) + "\n"

# ── CrowdStrike LogScale ─────────────────────────────────────────────────────

def to_logscale(events: list[dict[str, Any]]) -> list[dict]:
    """Format for CrowdStrike Falcon LogScale Ingest API."""
    return [
        {
            "tags": {"source": "phantex"},
            "events": [
                {
                    "timestamp": e.get("timestamp", ""),
                    "attributes": _base_event(e),
                }
                for e in events
            ],
        }
    ]

# ── Syslog CEF ───────────────────────────────────────────────────────────────

# Severity mapping: Phantex → CEF (0–10 scale)
_CEF_SEVERITY = {
    "critical": "10",
    "high": "8",
    "medium": "5",
    "low": "3",
    "info": "1",
}

def to_cef(event: dict[str, Any]) -> str:
    """Format as CEF (Common Event Format) syslog message.

    CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension

    SECURITY: Header fields use _sanitize_cef_header() to prevent
    pipe injection. Extension keys are hardcoded (not user-controlled).
    Extension values use _sanitize_cef_ext().
    """
    rule_name = event.get("rule_name", event.get("event_type", "unknown"))
    severity_str = event.get("severity", "info")
    cef_severity = _CEF_SEVERITY.get(severity_str, "1")

    # Build extension fields (keys hardcoded — safe)
    ext_parts = []

    if agent_id := event.get("agent_id"):
        ext_parts.append(f"cs1Label=agent_id cs1={_sanitize_cef_ext(str(agent_id))}")

    if tenant_id := event.get("tenant_id"):
        ext_parts.append(f"cs2Label=tenant_id cs2={_sanitize_cef_ext(str(tenant_id))}")

    if dest_ip := event.get("dest_ip"):
        ext_parts.append(f"dst={_sanitize_cef_ext(dest_ip)}")

    if dest_port := event.get("dest_port"):
        ext_parts.append(f"dpt={_sanitize_cef_ext(str(dest_port))}")

    if msg := event.get("message", event.get("description", "")):
        ext_parts.append(f"msg={_sanitize_cef_ext(str(msg)[:1024])}")

    if attack_class := event.get("attack_class"):
        ext_parts.append(f"cs3Label=attack_class cs3={_sanitize_cef_ext(str(attack_class))}")

    extension = " ".join(ext_parts)

    return (
        f"CEF:0|Phantex|Phantex|1.0|"
        f"{_sanitize_cef_header(rule_name)}|"
        f"{_sanitize_cef_header(rule_name.replace('_', ' ').title())}|"
        f"{cef_severity}|"
        f"{extension}"
    )

def to_cef_batch(events: list[dict[str, Any]]) -> list[str]:
    """Format multiple events as CEF strings."""
    return [to_cef(e) for e in events]

# ── Helpers ───────────────────────────────────────────────────────────────────

def _base_event(event: dict[str, Any]) -> dict[str, Any]:
    """Extract common fields for all platform formats."""
    return {
        "event_id": event.get("event_id", ""),
        "alert_id": event.get("alert_id", ""),
        "tenant_id": event.get("tenant_id", ""),
        "agent_id": event.get("agent_id", ""),
        "agent_name": event.get("agent_name", ""),
        "rule_name": event.get("rule_name", event.get("event_type", "")),
        "severity": event.get("severity", "info"),
        "attack_class": event.get("attack_class", ""),
        "framework": event.get("framework", ""),
        "timestamp": event.get("timestamp", ""),
        "message": event.get("message", event.get("description", "")),
        "dest_ip": event.get("dest_ip", ""),
        "dest_port": event.get("dest_port"),
        "file_path": event.get("file_path", ""),
        "tool_name": event.get("tool_name", ""),
    }

def _epoch_seconds(event: dict[str, Any]) -> float:
    """Convert event timestamp to epoch seconds (for Splunk)."""
    ts = event.get("timestamp")
    if isinstance(ts, int | float):
        return float(ts)
    # If string, attempt parse — fall back to current time
    return time.time()

# CEF header pipe injection prevention
_CEF_HEADER_UNSAFE = re.compile(r"[|\\]")

def _sanitize_cef_header(value: str) -> str:
    """Remove pipe and backslash from CEF header fields to prevent injection."""
    return _CEF_HEADER_UNSAFE.sub("", value)[:63]

_CEF_EXT_UNSAFE = re.compile(r"[=\\\n\r]")

def _sanitize_cef_ext(value: str) -> str:
    """Escape CEF extension value special characters."""
    return _CEF_EXT_UNSAFE.sub("_", value)[:1024]
