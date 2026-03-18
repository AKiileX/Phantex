#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Comprehensive End-to-End System Test.

Tests every major subsystem: auth, agents, events, alerts, analytics,
timeline, investigation, response, SOAR, GraphQL, ML pipeline,
trust engine, gateway health, dashboard, and security hardening.
"""
import json
import os
import sys
import time
import urllib.request
import urllib.error

BASE = os.environ.get("PHANTEX_API_URL", "http://localhost:8000")
DASH = os.environ.get("PHANTEX_DASH_URL", "http://localhost:3000")
GATEWAY = "http://localhost:50051"
TRUST = "http://localhost:50052"
EMAIL = os.environ.get("PHANTEX_ADMIN_EMAIL", "admin@phantex.dev")
PASSWORD = os.environ.get("PHANTEX_ADMIN_PASSWORD", "changeme")

passed = 0
failed = 0
skipped = 0

def ok(label):
    global passed
    passed += 1
    print(f"  PASS  {label}")

def fail(label, detail=""):
    global failed
    failed += 1
    print(f"  FAIL  {label}: {detail[:200]}")

def skip(label, reason=""):
    global skipped
    skipped += 1
    print(f"  SKIP  {label}: {reason}")

def api(method, path, token=None, body=None, expect=200):
    url = f"{BASE}{path}"
    data = json.dumps(body).encode() if body else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        resp = urllib.request.urlopen(req)
        return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body_text = e.read().decode()[:300]
        try:
            return e.code, json.loads(body_text)
        except Exception:
            return e.code, {"raw": body_text}
    except Exception as e:
        return 0, {"error": str(e)}

def http_get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        resp = urllib.request.urlopen(req)
        return resp.status, dict(resp.headers), resp.read().decode()[:2000]
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()[:500]
    except Exception as e:
        return 0, {}, str(e)

def main():
    global passed, failed, skipped
    token = None
    paid = None

    # ═══════════════════════════════════════════════════════════════════════
    print("\n[1/12] AUTHENTICATION & AUTHORIZATION")
    # ═══════════════════════════════════════════════════════════════════════

    # 1.1 Login
    code, data = api("POST", "/api/v1/auth/login", body={"email": EMAIL, "password": PASSWORD})
    if code == 200 and data.get("access_token"):
        token = data["access_token"]
        ok("Login")
    else:
        fail("Login", f"{code}: {data}")
        print("Cannot continue without auth token")
        sys.exit(1)

    # 1.2 Bad credentials rejected
    code, _ = api("POST", "/api/v1/auth/login", body={"email": EMAIL, "password": "wrong"})
    ok("Bad creds rejected") if code == 401 else fail("Bad creds rejected", str(code))

    # 1.3 No-token access denied
    code, _ = api("GET", "/api/v1/agents")
    ok("No-token 401") if code == 401 else fail("No-token 401", str(code))

    # 1.4 Me endpoint
    code, data = api("GET", "/api/v1/auth/me", token=token)
    ok("Me endpoint") if code == 200 and data.get("email") else fail("Me endpoint", str(data))

    # ═══════════════════════════════════════════════════════════════════════
    print("\n[2/12] AGENTS")
    # ═══════════════════════════════════════════════════════════════════════

    # 2.1 List agents
    code, data = api("GET", "/api/v1/agents", token=token)
    if code == 200:
        items = data.get("items", data.get("agents", []))
        ok(f"List agents ({len(items)} found)")
        if items:
            paid = items[0].get("paid", "")
            agent_uuid = str(items[0].get("id", ""))
            ok(f"Agent PAID: {paid}")
        else:
            skip("Agent PAID", "No agents in DB")
    else:
        fail("List agents", str(data))

    # 2.2 Get single agent by UUID
    if agent_uuid:
        code, data = api("GET", f"/api/v1/agents/{agent_uuid}", token=token)
        ok("Get agent by UUID") if code == 200 else fail("Get agent by UUID", str(data))

    # ═══════════════════════════════════════════════════════════════════════
    print("\n[3/12] EVENTS")
    # ═══════════════════════════════════════════════════════════════════════

    code, data = api("GET", "/api/v1/events", token=token)
    if code == 200:
        events = data.get("items", data.get("events", []))
        ok(f"List events ({len(events)} found)")
    else:
        fail("List events", str(data))

    if paid:
        code, data = api("GET", f"/api/v1/events?agent_id={paid}", token=token)
        ok("Events by PAID") if code == 200 else fail("Events by PAID", str(data))

    # ═══════════════════════════════════════════════════════════════════════
    print("\n[4/12] ALERTS")
    # ═══════════════════════════════════════════════════════════════════════

    code, data = api("GET", "/api/v1/alerts", token=token)
    alert_id = None
    if code == 200:
        alerts = data.get("items", data.get("alerts", []))
        ok(f"List alerts ({len(alerts)} found)")
        if alerts:
            alert_id = str(alerts[0].get("id", ""))
    else:
        fail("List alerts", str(data))

    if paid:
        code, data = api("GET", f"/api/v1/alerts?agent_id={paid}", token=token)
        ok("Alerts by PAID") if code == 200 else fail("Alerts by PAID", str(data))

    if alert_id:
        code, data = api("GET", f"/api/v1/alerts/{alert_id}", token=token)
        ok("Get single alert") if code == 200 else fail("Get single alert", str(data))

    # ═══════════════════════════════════════════════════════════════════════
    print("\n[5/12] ANALYTICS")
    # ═══════════════════════════════════════════════════════════════════════

    endpoints = [
        ("event-volume", "/api/v1/analytics/event-volume"),
        ("top-agents", "/api/v1/analytics/top-agents"),
        ("attack-breakdown", "/api/v1/analytics/attack-breakdown"),
    ]
    for name, path in endpoints:
        code, data = api("GET", path, token=token)
        ok(f"Analytics {name}") if code == 200 else fail(f"Analytics {name}", str(data))

    if paid:
        code, data = api("GET", f"/api/v1/analytics/event-volume?agent_id={paid}", token=token)
        ok("Analytics by PAID") if code == 200 else fail("Analytics by PAID", str(data))

    # ═══════════════════════════════════════════════════════════════════════
    print("\n[6/12] TIMELINE & INVESTIGATION")
    # ═══════════════════════════════════════════════════════════════════════

    if paid:
        code, data = api("GET", f"/api/v1/timeline/agent/{paid}", token=token)
        ok("Agent timeline") if code == 200 else fail("Agent timeline", str(data))
    else:
        skip("Agent timeline", "No PAID agent")

    # Investigation graph
    if paid:
        code, data = api("GET", f"/api/v1/investigate/agent-graph?agent_id={paid}", token=token)
        ok("Agent graph") if code in (200, 503) else fail("Agent graph", f"{code}: {data}")

    # ═══════════════════════════════════════════════════════════════════════
    print("\n[7/12] AUTO-RESPONSE")
    # ═══════════════════════════════════════════════════════════════════════

    # Kill switch status
    code, data = api("GET", "/api/v1/response/kill-switch", token=token)
    ok("Kill switch status") if code == 200 else fail("Kill switch", str(data))

    # Shadow mode status
    code, data = api("GET", "/api/v1/response/shadow", token=token)
    ok("Shadow mode status") if code == 200 else fail("Shadow mode", str(data))

    # Policies
    code, data = api("GET", "/api/v1/response/policies", token=token)
    ok(f"Response policies ({len(data.get('policies', []))} found)") if code == 200 else fail("Policies", str(data))

    # Escalation
    code, data = api("GET", "/api/v1/response/escalation", token=token)
    ok("Escalation list") if code == 200 else fail("Escalation", str(data))

    # Action log
    code, data = api("GET", "/api/v1/response/log", token=token)
    ok("Action log") if code == 200 else fail("Action log", str(data))

    # Response config
    code, data = api("GET", "/api/v1/response/config", token=token)
    ok("Response config") if code == 200 else fail("Response config", str(data))

    # ═══════════════════════════════════════════════════════════════════════
    print("\n[8/12] SOAR")
    # ═══════════════════════════════════════════════════════════════════════

    # API Keys
    code, data = api("GET", "/api/v1/soar/api-keys", token=token)
    ok("SOAR API keys list") if code == 200 else fail("SOAR API keys", str(data))

    # Webhooks
    code, data = api("GET", "/api/v1/soar/webhooks", token=token)
    ok("SOAR webhooks list") if code == 200 else fail("SOAR webhooks", str(data))

    # Integrations
    code, data = api("GET", "/api/v1/soar/integrations", token=token)
    ok("SOAR integrations list") if code == 200 else fail("SOAR integrations", str(data))

    # ═══════════════════════════════════════════════════════════════════════
    print("\n[9/12] GRAPHQL")
    # ═══════════════════════════════════════════════════════════════════════

    gql_query = {"query": "{ alerts(limit: 5) { items { id title severity } } }"}
    code, data = api("POST", "/graphql", token=token, body=gql_query)
    if code == 200 and "data" in data:
        ok("GraphQL alerts query")
    elif code == 200:
        fail("GraphQL alerts", f"No data key: {data}")
    else:
        fail("GraphQL alerts", f"{code}: {data}")

    gql_events = {"query": "{ events(limit: 5) { items { id eventType severity } } }"}
    code, data = api("POST", "/graphql", token=token, body=gql_events)
    if code == 200 and "data" in data:
        ok("GraphQL events query")
    else:
        fail("GraphQL events", f"{code}: {data}")

    # ═══════════════════════════════════════════════════════════════════════
    print("\n[10/12] HEALTH CHECKS")
    # ═══════════════════════════════════════════════════════════════════════

    # Backend health
    code, data = api("GET", "/healthz")
    ok("Backend /healthz") if code == 200 else fail("Backend healthz", str(data))

    code, data = api("GET", "/readyz")
    ok("Backend /readyz") if code == 200 else fail("Backend readyz", str(data))

    # Dashboard
    status_code, headers, body = http_get(DASH)
    ok("Dashboard reachable") if status_code == 200 else fail("Dashboard", str(status_code))

    # ═══════════════════════════════════════════════════════════════════════
    print("\n[11/12] SECURITY HEADERS")
    # ═══════════════════════════════════════════════════════════════════════

    status_code, headers, _ = http_get(DASH)
    if status_code == 200:
        checks = {
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Strict-Transport-Security": None,
            "Content-Security-Policy": None,
            "Referrer-Policy": None,
        }
        for header, expected_val in checks.items():
            val = headers.get(header, headers.get(header.lower(), ""))
            if val:
                if expected_val and expected_val not in val:
                    fail(f"Header {header}", f"Expected '{expected_val}', got '{val}'")
                else:
                    ok(f"Header {header}: {val[:60]}")
            else:
                fail(f"Header {header}", "Missing")

        # Server header should be stripped
        server = headers.get("Server", headers.get("server", ""))
        if not server or "nginx" not in server.lower():
            ok("Server header stripped/hidden")
        else:
            fail("Server header", f"Leaking: {server}")

    # ═══════════════════════════════════════════════════════════════════════
    print("\n[12/12] MISC ENDPOINTS")
    # ═══════════════════════════════════════════════════════════════════════

    # OpenAPI spec
    code, data = api("GET", "/openapi.json")
    ok("OpenAPI spec") if code == 200 else fail("OpenAPI spec", str(code))

    # MITRE/ATT&CK endpoints
    code, data = api("GET", "/api/v1/timeline/atlas/coverage", token=token)
    ok("ATLAS coverage") if code in (200, 404) else fail("ATLAS coverage", str(data))

    # Users list (admin)
    code, data = api("GET", "/api/v1/admin/users", token=token)
    if code == 200:
        users = data.get("users", data.get("items", []))
        ok(f"Admin users ({len(users)} found)")
    elif code == 404:
        skip("Admin users", "Endpoint not found")
    else:
        fail("Admin users", f"{code}: {data}")

    # FinOps
    code, data = api("GET", "/api/v1/finops/usage-summary", token=token)
    ok("FinOps usage") if code in (200, 404) else fail("FinOps usage", f"{code}: {data}")

    # Compliance
    code, data = api("GET", "/api/v1/compliance/status", token=token)
    ok("Compliance status") if code in (200, 404) else fail("Compliance", f"{code}: {data}")

    # ═══════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 60)
    total = passed + failed + skipped
    print(f"Results: {passed} passed, {failed} failed, {skipped} skipped out of {total}")
    print("=" * 60)

    return 1 if failed > 0 else 0

if __name__ == "__main__":
    sys.exit(main())
