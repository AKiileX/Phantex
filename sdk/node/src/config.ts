// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex SDK — Configuration.
 *
 * All configuration comes from environment variables — no secrets embedded.
 * Mirrors the Python SDK's config structure.
 */

export interface PhantexConfig {
  /** Auth token for sensor/gateway (from PHANTEX_TOKEN) */
  authToken: string;
  /** Tenant UUID (from PHANTEX_TENANT_ID) */
  tenantId: string;
  /** Agent PAID (from PHANTEX_AGENT_ID) */
  agentId: string;
  /** Transport mode: "auto" | "http" | "buffer" */
  transport: "auto" | "http" | "buffer";
  /** Gateway HTTP endpoint */
  gatewayAddr: string;
  /** Maximum events per batch */
  batchSize: number;
  /** Batch flush interval in ms */
  batchTimeoutMs: number;
  /** Max buffered events when transport unavailable */
  bufferSize: number;
  /** Which hooks to enable: "auto" | comma-separated | "none" */
  hooks: string;
  /** SDK enabled/disabled kill switch */
  enabled: boolean;
  /** Debug logging */
  debug: boolean;
}

/**
 * Build config from environment variables.
 * All prefixed with PHANTEX_.
 */
export function configFromEnv(): PhantexConfig {
  const env = process.env;
  return {
    authToken: env.PHANTEX_TOKEN ?? "",
    tenantId: env.PHANTEX_TENANT_ID ?? "",
    agentId: env.PHANTEX_AGENT_ID ?? "",
    transport: (env.PHANTEX_TRANSPORT as PhantexConfig["transport"]) ?? "auto",
    gatewayAddr: env.PHANTEX_GATEWAY_HTTP ?? "https://localhost:8443/api/v1/ingest",
    batchSize: parseInt(env.PHANTEX_BATCH_SIZE ?? "50", 10),
    batchTimeoutMs: parseInt(env.PHANTEX_BATCH_TIMEOUT_MS ?? "1000", 10),
    bufferSize: parseInt(env.PHANTEX_BUFFER_SIZE ?? "5000", 10),
    hooks: env.PHANTEX_HOOKS ?? "auto",
    enabled: env.PHANTEX_ENABLED !== "0",
    debug: env.PHANTEX_DEBUG === "1",
  };
}

let _config: PhantexConfig | null = null;

export function getConfig(): PhantexConfig {
  if (!_config) {
    _config = configFromEnv();
  }
  return _config;
}

export function setConfig(config: PhantexConfig): void {
  _config = config;
}
