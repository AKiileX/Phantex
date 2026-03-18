# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex EDR — Splunk SOAR (Phantom) Connector

Provides bidirectional SOAR integration:
  - Alert ingestion + enrichment
  - Automated response actions (isolate, acknowledge, escalate, forensics)
  - Trust-based triage

Security:
  - API key stored in Phantom asset config (encrypted at rest)
  - HTTPS-only
  - SSL verification (configurable)
"""

import json
import requests

import phantom.app as phantom
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

class PhantexConnector(BaseConnector):
    """Splunk SOAR connector for Phantex EDR."""

    def __init__(self):
        super().__init__()
        self._base_url = None
        self._api_key = None
        self._verify = True
        self._session = None

    def initialize(self):
        config = self.get_config()
        self._base_url = config["base_url"].rstrip("/")
        self._api_key = config["api_key"]
        self._verify = config.get("verify_ssl", True)
        self._session = requests.Session()
        self._session.headers.update({
            "X-Phantex-Api-Key": self._api_key,
            "Content-Type": "application/json",
            "User-Agent": "Phantom-Phantex/1.0",
        })
        self._session.verify = self._verify
        return phantom.APP_SUCCESS

    def finalize(self):
        if self._session:
            self._session.close()
        return phantom.APP_SUCCESS

    # ── API helpers ──────────────────────────────────────────────────────────

    def _api_get(self, path: str, params: dict = None) -> dict:
        url = f"{self._base_url}{path}"
        resp = self._session.get(url, params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def _api_post(self, path: str, body: dict) -> dict:
        url = f"{self._base_url}{path}"
        resp = self._session.post(url, json=body, timeout=30)
        resp.raise_for_status()
        return resp.json()

    # ── Actions ──────────────────────────────────────────────────────────────

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Connecting to Phantex...")
        try:
            result = self._api_get("/api/v1/soar/ext/alerts", {"limit": 1})
            self.save_progress("Connected successfully")
            return action_result.set_status(phantom.APP_SUCCESS, "Connection successful")
        except Exception as e:
            self.save_progress(f"Connection failed: {e}")
            return action_result.set_status(phantom.APP_ERROR, str(e))

    def _handle_get_alerts(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        try:
            params = {"limit": param.get("limit", 50)}
            if param.get("severity"):
                params["severity"] = param["severity"]
            if param.get("status"):
                params["status"] = param["status"]

            result = self._api_get("/api/v1/soar/ext/alerts", params)
            for alert in result.get("alerts", []):
                action_result.add_data(alert)

            action_result.update_summary({"total_alerts": result.get("total", 0)})
            return action_result.set_status(phantom.APP_SUCCESS)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, str(e))

    def _handle_enrich_alert(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        try:
            alert_id = param["alert_id"]
            result = self._api_get(f"/api/v1/soar/ext/alerts/{alert_id}/enrich")
            action_result.add_data(result)
            action_result.update_summary({
                "trust_score": result.get("agent_trust_score"),
                "severity": result.get("severity"),
            })
            return action_result.set_status(phantom.APP_SUCCESS)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, str(e))

    def _execute_action(self, param, action: str, target_type: str, id_field: str):
        action_result = self.add_action_result(ActionResult(dict(param)))
        try:
            body = {
                "action": action,
                "target_type": target_type,
                "target_id": param[id_field],
                "reason": param.get("reason", f"{action} via Phantom"),
                "params": {},
            }
            result = self._api_post("/api/v1/soar/ext/actions", body)
            action_result.add_data(result)
            action_result.update_summary({"result": result.get("result")})
            return action_result.set_status(phantom.APP_SUCCESS)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, str(e))

    def _handle_isolate_agent(self, param):
        return self._execute_action(param, "isolate_agent", "agent", "agent_id")

    def _handle_acknowledge_alert(self, param):
        return self._execute_action(param, "acknowledge_alert", "alert", "alert_id")

    def _handle_resolve_alert(self, param):
        return self._execute_action(param, "resolve_alert", "alert", "alert_id")

    def _handle_escalate_alert(self, param):
        return self._execute_action(param, "escalate_alert", "alert", "alert_id")

    def _handle_collect_forensics(self, param):
        return self._execute_action(param, "collect_forensics", "agent", "agent_id")

    # ── Dispatcher ───────────────────────────────────────────────────────────

    def handle_action(self, param):
        action_id = self.get_action_identifier()
        handler = {
            "test_connectivity": self._handle_test_connectivity,
            "get_alerts": self._handle_get_alerts,
            "enrich_alert": self._handle_enrich_alert,
            "isolate_agent": self._handle_isolate_agent,
            "acknowledge_alert": self._handle_acknowledge_alert,
            "resolve_alert": self._handle_resolve_alert,
            "escalate_alert": self._handle_escalate_alert,
            "collect_forensics": self._handle_collect_forensics,
        }.get(action_id)

        if handler:
            return handler(param)
        else:
            return phantom.APP_ERROR

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("No test json specified")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        in_json = f.read()

    connector = PhantexConnector()
    connector.print_progress_message = True
    ret_val = connector._handle_action(json.loads(in_json), None)
    print(json.dumps(json.loads(connector.get_status_message()), indent=4))
    sys.exit(0)
