# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — OCSF v1.1 Event Mapper (L3).

Maps Phantex internal events/alerts to OCSF (Open Cybersecurity Schema
Framework) v1.1 JSON for interoperability with SIEMs, SOAR, data lakes.

Mapping table:
  PROCESS_EXEC  → Process Activity (1007)
  FILE_OPEN/READ → File Activity (1001)
  NETWORK_CONNECT → Network Activity (4001)
  TOOL_CALL       → API Activity (6003)
  DNS_QUERY       → DNS Activity (4003)
  Alert           → Security Finding (2001)

All public functions are pure — no DB, no network, no side effects.
"""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.schemas.ocsf import (
    OCSFAPI,
    OCSFActor,
    OCSFDns,
    OCSFEndpoint,
    OCSFEvent,
    OCSFFile,
    OCSFFinding,
    OCSFMetadata,
    OCSFProcess,
)
from app.utils.logging import get_logger

logger = get_logger("phantex.ocsf")

# ── Load Schema Definitions ──────────────────────────────────────────────────

_SCHEMA_PATH = Path(__file__).resolve().parent.parent / "data" / "ocsf_schema.json"

_schema_data: dict[str, Any] = {}

def _load_schema() -> dict[str, Any]:
    """Load OCSF schema definitions. Cached in module global."""
    global _schema_data
    if _schema_data:
        return _schema_data
    try:
        with open(_SCHEMA_PATH, encoding="utf-8") as f:
            _schema_data = json.load(f)
        logger.info("ocsf_schema_loaded", classes=len(_schema_data.get("classes", {})))
    except Exception:
        logger.exception("ocsf_schema_load_failed", path=str(_SCHEMA_PATH))
        _schema_data = {
            "classes": {},
            "event_type_mapping": {},
            "severity_mapping": {},
            "status_mapping": {},
            "pii_fields": [],
        }
    return _schema_data

def _schema() -> dict[str, Any]:
    if not _schema_data:
        _load_schema()
    return _schema_data

# ── Severity / Status Maps ───────────────────────────────────────────────────

def _severity_id(severity: str) -> int:
    """Map Phantex severity to OCSF severity_id (1–5)."""
    return _schema().get("severity_mapping", {}).get(severity.lower(), 1)

def _severity_name(severity_id: int) -> str:
    names = {1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}
    return names.get(severity_id, "Unknown")

def _status_id(status: str) -> int:
    return _schema().get("status_mapping", {}).get(status.lower(), 1)

# ── Timestamp Helpers ─────────────────────────────────────────────────────────

def _to_iso(ts: Any) -> str:
    """Convert various timestamp formats to ISO 8601."""
    if isinstance(ts, datetime):
        return ts.isoformat()
    if isinstance(ts, int | float):
        return datetime.fromtimestamp(ts, tz=UTC).isoformat()
    return str(ts) if ts else datetime.now(UTC).isoformat()

# ── PII Redaction ─────────────────────────────────────────────────────────────

def redact_pii(
    ocsf_event: dict[str, Any],
    fields_to_redact: list[str] | None = None,
) -> dict[str, Any]:
    """Redact PII fields from an OCSF event dict (returns new dict).

    Fields use dotted notation: ``src_endpoint.ip``, ``actor.user.email_addr``.
    """
    if not fields_to_redact:
        return ocsf_event

    result = copy.deepcopy(ocsf_event)
    for field_path in fields_to_redact:
        parts = field_path.split(".")
        _redact_nested(result, parts)
    return result

def _redact_nested(obj: dict, parts: list[str]) -> None:
    """Recursively redact a nested field."""
    if not parts or not isinstance(obj, dict):
        return
    key = parts[0]
    if key not in obj:
        return
    if len(parts) == 1:
        if obj[key] is not None:
            obj[key] = "***REDACTED***"
    else:
        if isinstance(obj[key], dict):
            _redact_nested(obj[key], parts[1:])

# ── Core Mapper ───────────────────────────────────────────────────────────────

def map_event(
    event: dict[str, Any],
    *,
    tenant_id: str | None = None,
) -> OCSFEvent:
    """Map a Phantex event dict to an OCSF v1.1 event.

    Accepts both raw ClickHouse/PG events and Kafka event dicts.
    The ``event_type`` field determines the OCSF class.
    """
    schema = _schema()
    event_type = _normalise_event_type(event)
    mapping = schema.get("event_type_mapping", {}).get(event_type, {})
    class_uid = mapping.get("class_uid", 0)
    class_info = schema.get("classes", {}).get(str(class_uid), {})

    raw_data = event.get("raw_data") or {}
    if isinstance(raw_data, str):
        try:
            raw_data = json.loads(raw_data)
        except (json.JSONDecodeError, TypeError):
            raw_data = {}
    if not isinstance(raw_data, dict):
        raw_data = {}

    sev = event.get("severity", "info")
    sev_id = _severity_id(sev)

    metadata = OCSFMetadata(
        original_time=_to_iso(event.get("timestamp")),
        uid=str(event.get("id", event.get("event_id", ""))),
        tenant_uid=tenant_id,
    )

    ocsf = OCSFEvent(
        metadata=metadata,
        class_uid=class_uid,
        class_name=class_info.get("name", "Unknown"),
        category_uid=class_info.get("category_uid", 0),
        category_name=class_info.get("category_name", "Unknown"),
        activity_id=mapping.get("activity_id", 0),
        activity_name=mapping.get("activity_name", "Unknown"),
        type_uid=mapping.get("type_uid", 0),
        severity_id=sev_id,
        severity=_severity_name(sev_id),
        time=_to_iso(event.get("timestamp")),
        message=_build_message(event, event_type),
    )

    # ── Class-specific enrichment ────────────────────────────────────────
    if event_type == "PROCESS_EXEC":
        ocsf.process = _build_process(raw_data)
        ocsf.actor = _build_actor(event, raw_data)

    elif event_type in ("FILE_OPEN", "FILE_READ", "FILE_WRITE"):
        ocsf.file = _build_file(raw_data)
        ocsf.actor = _build_actor(event, raw_data)

    elif event_type == "NETWORK_CONNECT":
        ocsf.src_endpoint = _build_src_endpoint(raw_data)
        ocsf.dst_endpoint = _build_dst_endpoint(raw_data)
        ocsf.actor = _build_actor(event, raw_data)

    elif event_type == "TOOL_CALL":
        ocsf.api = _build_api(raw_data)
        ocsf.actor = _build_actor(event, raw_data)

    elif event_type == "DNS_QUERY":
        ocsf.dns = _build_dns(raw_data)
        ocsf.actor = _build_actor(event, raw_data)

    elif event_type == "alert":
        ocsf.finding_info = _build_finding(event)
        ocsf.status_id = _status_id(event.get("status", "open"))
        ocsf.status = event.get("status", "open")

    # ── Unmapped fields (Phantex extensions) ─────────────────────────────
    unmapped: dict[str, Any] = {}
    for key in ("agent_id", "sensor_id", "rule_id", "attack_class"):
        val = event.get(key) or raw_data.get(key)
        if val:
            unmapped[key] = str(val)

    # ATLAS techniques
    atlas = event.get("atlas_techniques") or raw_data.get("atlas_techniques")
    if atlas:
        ocsf.enrichments = [
            {"name": t.get("id", ""), "value": t.get("name", ""), "provider": "MITRE ATLAS"}
            for t in (atlas if isinstance(atlas, list) else [])
        ]

    # Trust score
    trust = event.get("trust_score")
    if trust is not None:
        unmapped["trust_score"] = trust

    ocsf.unmapped = unmapped
    return ocsf

def map_alert(
    alert: dict[str, Any],
    *,
    tenant_id: str | None = None,
) -> OCSFEvent:
    """Map a Phantex alert dict to OCSF Security Finding (2001)."""
    alert_copy = dict(alert)
    alert_copy.setdefault("event_type", "alert")
    return map_event(alert_copy, tenant_id=tenant_id)

def map_batch(
    events: list[dict[str, Any]],
    *,
    tenant_id: str | None = None,
    pii_fields: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Map a batch of events to OCSF JSON dicts, optionally with PII redaction."""
    results = []
    for evt in events:
        try:
            ocsf = map_event(evt, tenant_id=tenant_id)
            d = ocsf.model_dump(mode="json", exclude_none=True)
            if pii_fields:
                d = redact_pii(d, pii_fields)
            results.append(d)
        except Exception as exc:
            logger.warning("ocsf_mapping_error", event_id=evt.get("id"), error=str(exc)[:200])
    return results

def to_jsonl(ocsf_events: list[dict[str, Any]]) -> str:
    """Serialize OCSF events to JSON Lines (one JSON object per line)."""
    return "\n".join(json.dumps(e, default=str) for e in ocsf_events) + "\n"

# ── Event Type Normalisation ─────────────────────────────────────────────────

def _normalise_event_type(event: dict[str, Any]) -> str:
    """Normalise event_type to match OCSF mapping keys."""
    et = event.get("event_type", "")
    # Handle alert-prefixed types from timeline service
    if et.startswith("alert:"):
        return "alert"
    # Uppercase for raw events
    upper = et.upper()
    if upper in ("PROCESS_EXEC", "FILE_OPEN", "FILE_READ", "FILE_WRITE", "NETWORK_CONNECT", "TOOL_CALL", "DNS_QUERY"):
        return upper
    # Check if this is an alert by presence of title/status
    if "title" in event and "status" in event:
        return "alert"
    return upper

# ── Field Builders ────────────────────────────────────────────────────────────

def _build_message(event: dict[str, Any], event_type: str) -> str:
    """Build human-readable message."""
    if event_type == "alert":
        title = event.get("title", "Security Alert")
        desc = event.get("description", "")
        return f"{title}: {desc}" if desc else title
    desc = event.get("description", "")
    if desc:
        return desc
    return f"Phantex {event_type} event"

def _build_process(raw: dict) -> OCSFProcess:
    return OCSFProcess(
        pid=raw.get("pid"),
        name=raw.get("comm") or raw.get("process_name"),
        cmd_line=raw.get("cmdline") or raw.get("cmd_line"),
        uid=raw.get("process_id"),
    )

def _build_file(raw: dict) -> OCSFFile:
    path = raw.get("path") or raw.get("filename") or raw.get("file_path")
    name = path.rsplit("/", 1)[-1] if path else raw.get("file_name")
    return OCSFFile(
        name=name,
        path=path,
        size=raw.get("size") or raw.get("bytes_read"),
    )

def _build_src_endpoint(raw: dict) -> OCSFEndpoint:
    return OCSFEndpoint(
        ip=raw.get("src_ip") or raw.get("source_ip"),
        port=raw.get("src_port") or raw.get("source_port"),
        hostname=raw.get("hostname"),
    )

def _build_dst_endpoint(raw: dict) -> OCSFEndpoint:
    return OCSFEndpoint(
        ip=raw.get("dst_ip") or raw.get("dest_ip") or raw.get("ip"),
        port=raw.get("dst_port") or raw.get("dest_port") or raw.get("port"),
        domain=raw.get("domain") or raw.get("hostname"),
    )

def _build_api(raw: dict) -> OCSFAPI:
    return OCSFAPI(
        operation=raw.get("tool_name") or raw.get("function") or raw.get("operation"),
        service={"name": raw.get("mcp_server", "unknown")} if raw.get("mcp_server") else None,
        request={"data": raw.get("input") or raw.get("arguments", {})}
        if raw.get("input") or raw.get("arguments")
        else None,
        response={"data": raw.get("output") or raw.get("result", {})}
        if raw.get("output") or raw.get("result")
        else None,
    )

def _build_dns(raw: dict) -> OCSFDns:
    query_name = raw.get("query") or raw.get("domain") or raw.get("hostname")
    return OCSFDns(
        query={"hostname": query_name, "type": raw.get("query_type", "A")} if query_name else None,
        answers=[{"rdata": a} for a in raw.get("answers", [])],
    )

def _build_actor(event: dict, raw: dict) -> OCSFActor:
    agent_id = event.get("agent_id") or raw.get("agent_id")
    return OCSFActor(
        session={"uid": str(agent_id)} if agent_id else None,
    )

def _build_finding(event: dict) -> OCSFFinding:
    context = event.get("context", {})
    if isinstance(context, str):
        try:
            context = json.loads(context)
        except (json.JSONDecodeError, TypeError):
            context = {}

    types = []
    attack_class = context.get("attack_class") or event.get("attack_class")
    if attack_class:
        types.append(attack_class)

    atlas = event.get("atlas_techniques") or context.get("atlas_techniques", [])
    for t in atlas if isinstance(atlas, list) else []:
        tid = t.get("id") if isinstance(t, dict) else str(t)
        if tid:
            types.append(f"ATLAS:{tid}")

    return OCSFFinding(
        uid=str(event.get("id", "")),
        title=event.get("title", ""),
        desc=event.get("description", ""),
        types=types,
    )

# ── Validation ────────────────────────────────────────────────────────────────

def validate_ocsf_event(ocsf_dict: dict[str, Any]) -> list[str]:
    """Validate an OCSF event dict against required fields.

    Returns a list of validation errors (empty = valid).
    """
    errors: list[str] = []
    required = _schema().get("required_base_fields", [])
    for field in required:
        if field not in ocsf_dict or ocsf_dict[field] is None:
            errors.append(f"Missing required field: {field}")

    # Type checks
    if "class_uid" in ocsf_dict and not isinstance(ocsf_dict["class_uid"], int):
        errors.append("class_uid must be an integer")
    if "severity_id" in ocsf_dict:
        sev = ocsf_dict["severity_id"]
        if not isinstance(sev, int) or sev < 1 or sev > 5:
            errors.append("severity_id must be 1–5")

    return errors

def get_supported_event_types() -> list[str]:
    """Return list of Phantex event types that have OCSF mappings."""
    return list(_schema().get("event_type_mapping", {}).keys())
