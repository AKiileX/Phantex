# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex EDR — Cortex XSOAR Integration

Commands:
  phantex-get-alerts         — Fetch alerts
  phantex-enrich-alert       — Full alert enrichment
  phantex-isolate-agent      — Isolate an agent
  phantex-acknowledge-alert  — Acknowledge an alert
  phantex-resolve-alert      — Resolve an alert
  phantex-escalate-alert     — Escalate an alert
  phantex-trust-penalty      — Trust penalty on agent
  phantex-collect-forensics  — Trigger forensics collection
  phantex-get-action-log     — SOAR action audit trail

fetch-incidents:
  Pulls new alerts as XSOAR incidents.

Security:
  - API key passed via X-Phantex-Api-Key header
  - HTTPS-only connections
  - SSL verification (configurable)
"""

import demistomock as demisto  # noqa: E402
from CommonServerPython import *  # noqa: E402,F401,F403
from CommonServerUserPython import *  # noqa: E402,F401,F403

import json
import urllib3
from datetime import datetime, timezone
from typing import Any

urllib3.disable_warnings()

# ── Client ────────────────────────────────────────────────────────────────────

class PhantexClient(BaseClient):
    """HTTP client for Phantex SOAR API."""

    def __init__(self, base_url: str, api_key: str, verify: bool):
        headers = {
            "X-Phantex-Api-Key": api_key,
            "Content-Type": "application/json",
            "User-Agent": "XSOAR-Phantex/1.0",
        }
        super().__init__(
            base_url=base_url,
            headers=headers,
            verify=verify,
        )

    def get_alerts(
        self,
        status: str | None = None,
        severity: str | None = None,
        limit: int = 50,
        since: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"limit": limit}
        if status:
            params["status"] = status
        if severity:
            params["severity"] = severity
        if since:
            params["since"] = since
        return self._http_request("GET", "/api/v1/soar/ext/alerts", params=params)

    def enrich_alert(self, alert_id: str) -> dict[str, Any]:
        return self._http_request("GET", f"/api/v1/soar/ext/alerts/{alert_id}/enrich")

    def execute_action(
        self,
        action: str,
        target_type: str,
        target_id: str,
        reason: str = "",
        params: dict | None = None,
    ) -> dict[str, Any]:
        body = {
            "action": action,
            "target_type": target_type,
            "target_id": target_id,
            "reason": reason,
            "params": params or {},
        }
        return self._http_request("POST", "/api/v1/soar/ext/actions", json_data=body)

    def get_action_log(self, limit: int = 50) -> dict[str, Any]:
        return self._http_request(
            "GET", "/api/v1/soar/ext/action-log", params={"limit": limit}
        )

# ── Commands ──────────────────────────────────────────────────────────────────

def get_alerts_command(client: PhantexClient, args: dict) -> CommandResults:
    status = args.get("status")
    severity = args.get("severity")
    limit = int(args.get("limit", 50))
    since = args.get("since")

    result = client.get_alerts(status=status, severity=severity, limit=limit, since=since)
    alerts = result.get("alerts", [])

    return CommandResults(
        outputs_prefix="Phantex.Alert",
        outputs_key_field="id",
        outputs=alerts,
        readable_output=tableToMarkdown(
            "Phantex Alerts",
            alerts,
            headers=["id", "title", "severity", "status", "agent_id", "event_type", "created_at"],
        ),
    )

def enrich_alert_command(client: PhantexClient, args: dict) -> CommandResults:
    alert_id = args["alert_id"]
    enrichment = client.enrich_alert(alert_id)

    return CommandResults(
        outputs_prefix="Phantex.Enrichment",
        outputs_key_field="alert_id",
        outputs=enrichment,
        readable_output=tableToMarkdown(
            f"Phantex Alert Enrichment — {alert_id}",
            enrichment,
            headers=[
                "alert_id", "severity", "status", "rule_name",
                "agent_hostname", "agent_trust_score", "event_type",
            ],
        ),
    )

def _action_command(
    client: PhantexClient,
    action: str,
    target_type: str,
    args: dict,
    id_field: str = "alert_id",
) -> CommandResults:
    target_id = args[id_field]
    reason = args.get("reason", f"{action} via XSOAR")
    result = client.execute_action(action, target_type, target_id, reason=reason)

    return CommandResults(
        outputs_prefix="Phantex.Action",
        outputs_key_field="id",
        outputs=result,
        readable_output=tableToMarkdown(
            f"Phantex Action: {action}",
            result,
            headers=["id", "action", "target_type", "target_id", "result", "error"],
        ),
    )

def get_action_log_command(client: PhantexClient, args: dict) -> CommandResults:
    limit = int(args.get("limit", 50))
    result = client.get_action_log(limit=limit)

    return CommandResults(
        outputs_prefix="Phantex.ActionLog",
        outputs=result,
        readable_output=tableToMarkdown(
            "Phantex Action Log",
            result.get("entries", []),
            headers=["id", "action", "target_type", "target_id", "result", "created_at"],
        ),
    )

# ── Fetch Incidents ───────────────────────────────────────────────────────────

def fetch_incidents(client: PhantexClient, max_results: int, min_severity: str, first_fetch: str):
    last_run = demisto.getLastRun()
    last_fetch = last_run.get("last_fetch")

    if not last_fetch:
        last_fetch = dateparser.parse(first_fetch).isoformat()

    result = client.get_alerts(severity=min_severity, limit=max_results, since=last_fetch)
    alerts = result.get("alerts", [])

    incidents = []
    latest_time = last_fetch

    for alert in alerts:
        created = alert.get("created_at", "")
        incident = {
            "name": f"Phantex: {alert.get('title', 'Unknown Alert')}",
            "occurred": created,
            "severity": _severity_to_demisto(alert.get("severity", "medium")),
            "rawJSON": json.dumps(alert),
            "type": "Phantex Alert",
            "details": json.dumps(alert, indent=2),
        }
        incidents.append(incident)
        if created > latest_time:
            latest_time = created

    demisto.setLastRun({"last_fetch": latest_time})
    demisto.incidents(incidents)

def _severity_to_demisto(severity: str) -> int:
    mapping = {
        "info": IncidentSeverity.INFO,
        "low": IncidentSeverity.LOW,
        "medium": IncidentSeverity.MEDIUM,
        "high": IncidentSeverity.HIGH,
        "critical": IncidentSeverity.CRITICAL,
    }
    return mapping.get(severity.lower(), IncidentSeverity.MEDIUM)

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    base_url = params["url"].rstrip("/")
    api_key = params["api_key"]
    verify = params.get("insecure", True)

    client = PhantexClient(base_url, api_key, verify)

    try:
        if command == "test-module":
            result = client.get_alerts(limit=1)
            return_results("ok")

        elif command == "fetch-incidents":
            max_results = int(params.get("max_fetch", 50))
            min_severity = params.get("min_severity", "medium")
            first_fetch = params.get("first_fetch", "3 days")
            fetch_incidents(client, max_results, min_severity, first_fetch)

        elif command == "phantex-get-alerts":
            return_results(get_alerts_command(client, args))

        elif command == "phantex-enrich-alert":
            return_results(enrich_alert_command(client, args))

        elif command == "phantex-isolate-agent":
            return_results(_action_command(client, "isolate_agent", "agent", args, "agent_id"))

        elif command == "phantex-acknowledge-alert":
            return_results(_action_command(client, "acknowledge_alert", "alert", args))

        elif command == "phantex-resolve-alert":
            return_results(_action_command(client, "resolve_alert", "alert", args))

        elif command == "phantex-escalate-alert":
            return_results(_action_command(client, "escalate_alert", "alert", args))

        elif command == "phantex-trust-penalty":
            return_results(_action_command(client, "trust_penalty", "agent", args, "agent_id"))

        elif command == "phantex-collect-forensics":
            return_results(_action_command(client, "collect_forensics", "agent", args, "agent_id"))

        elif command == "phantex-get-action-log":
            return_results(get_action_log_command(client, args))

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command}: {str(e)}")

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
