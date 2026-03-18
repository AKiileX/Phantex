// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex SDK — Event Transport.
 *
 * Delivers captured events to the Phantex gateway or sensor.
 *
 * Supports:
 * - BufferTransport: in-memory (testing/fallback)
 * - HTTPTransport: HTTPS POST to gateway (JSON-L batches)
 *
 * Security:
 * - Auth token from env only (PHANTEX_TOKEN)
 * - TLS required by default
 * - No eval(), no Function() constructor
 */

import { createHash } from "node:crypto";
import type { PhantexConfig } from "./config.js";
import { getConfig } from "./config.js";

export interface PhantexEvent {
  event_type: string;
  tenant_id: string;
  agent_paid: string;
  tool_name: string;
  protocol: string;
  framework: string;
  trace_id: string;
  span_id: string;
  parent_span_id: string;
  timestamp_ns: number;
  [key: string]: unknown;
}

export interface Transport {
  send(event: PhantexEvent): void;
  flush(): Promise<void>;
  close(): Promise<void>;
}

// ── Buffer Transport ─────────────────────────────────────────────────────────

export class BufferTransport implements Transport {
  private readonly _buffer: PhantexEvent[] = [];
  private readonly _maxSize: number;

  constructor(maxSize = 5000) {
    this._maxSize = maxSize;
  }

  send(event: PhantexEvent): void {
    if (this._buffer.length >= this._maxSize) {
      this._buffer.shift(); // Drop oldest
    }
    this._buffer.push(event);
  }

  async flush(): Promise<void> {
    // No-op for buffer
  }

  async close(): Promise<void> {
    // No-op
  }

  /** Return and clear buffered events (for testing). */
  drain(): PhantexEvent[] {
    return this._buffer.splice(0);
  }

  /** Return buffered events without clearing. */
  peek(): PhantexEvent[] {
    return [...this._buffer];
  }

  get length(): number {
    return this._buffer.length;
  }
}

// ── HTTP Transport ───────────────────────────────────────────────────────────

export class HTTPTransport implements Transport {
  private _buffer: PhantexEvent[] = [];
  private readonly _endpoint: string;
  private readonly _authToken: string;
  private readonly _batchSize: number;
  private readonly _maxBuffer: number;
  private _flushTimer: ReturnType<typeof setInterval> | null = null;

  constructor(config?: Partial<PhantexConfig>) {
    const cfg = { ...getConfig(), ...config };
    this._endpoint = cfg.gatewayAddr;
    this._authToken = cfg.authToken;
    this._batchSize = cfg.batchSize;
    this._maxBuffer = cfg.bufferSize ?? 5000;

    // Periodic flush
    this._flushTimer = setInterval(() => {
      this.flush().catch(() => {});
    }, cfg.batchTimeoutMs);
  }

  send(event: PhantexEvent): void {
    if (this._buffer.length >= this._maxBuffer) {
      this._buffer.shift(); // Drop oldest to cap memory
    }
    this._buffer.push(event);
    if (this._buffer.length >= this._batchSize) {
      this.flush().catch(() => {});
    }
  }

  async flush(): Promise<void> {
    if (this._buffer.length === 0) return;

    const batch = this._buffer.splice(0, this._batchSize);
    const payload = batch.map((e) => JSON.stringify(e)).join("\n") + "\n";

    try {
      const resp = await fetch(this._endpoint, {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${this._authToken}`,
          "Content-Type": "application/x-ndjson",
          "User-Agent": "phantex-sdk-node/2.0.0",
        },
        body: payload,
      });

      if (!resp.ok) {
        // Re-buffer on failure
        this._buffer.unshift(...batch);
      }
    } catch {
      // Re-buffer on network error
      this._buffer.unshift(...batch);
    }
  }

  async close(): Promise<void> {
    if (this._flushTimer) {
      clearInterval(this._flushTimer);
      this._flushTimer = null;
    }
    await this.flush();
  }

  get length(): number {
    return this._buffer.length;
  }
}

// ── Transport Factory ────────────────────────────────────────────────────────

export function createTransport(config?: Partial<PhantexConfig>): Transport {
  const cfg = { ...getConfig(), ...config };

  if (cfg.transport === "buffer") {
    return new BufferTransport(cfg.bufferSize);
  }

  if (cfg.transport === "http" || cfg.transport === "auto") {
    // Use HTTP transport if we have an endpoint
    if (cfg.gatewayAddr && cfg.authToken) {
      return new HTTPTransport(cfg);
    }
  }

  // Fallback to buffer
  return new BufferTransport(cfg.bufferSize);
}

/** Hash a prompt (SHA-256, first 16 chars). Never store plaintext. */
export function hashPrompt(content: string): string {
  if (!content) return "";
  return createHash("sha256").update(content).digest("hex").slice(0, 16);
}
