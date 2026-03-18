// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex SDK for Node.js — Auto-instrumentation Entry Point.
 *
 * Usage:
 *   import '@phantex/sdk';  // Auto-instruments all detected frameworks
 *
 * Or manual:
 *   import { PhantexClient } from '@phantex/sdk';
 *   const client = new PhantexClient({ hooks: 'langchain,openai' });
 *   client.start();
 *
 * Configuration via environment variables:
 *   PHANTEX_TOKEN          Auth token for sensor/gateway
 *   PHANTEX_TENANT_ID      Tenant UUID
 *   PHANTEX_AGENT_ID       Agent PAID
 *   PHANTEX_TRANSPORT      auto|http|buffer (default: auto)
 *   PHANTEX_HOOKS          auto|langchain,openai,...|none (default: auto)
 *   PHANTEX_ENABLED        0|1 (default: 1)
 *   PHANTEX_DEBUG          0|1 (default: 0)
 */

import { type PhantexConfig, configFromEnv, getConfig, setConfig } from "./config.js";
import { type Transport, BufferTransport, HTTPTransport, createTransport } from "./transport.js";
import { installLangChainHooks } from "./hooks/langchain.js";
import { installVercelAIHooks } from "./hooks/vercel-ai.js";
import { installOpenAIHooks } from "./hooks/openai.js";
import { installAnthropicHooks } from "./hooks/anthropic.js";
import { installHTTPHooks } from "./hooks/http.js";
import { installMCPHooks } from "./hooks/mcp.js";

export { PhantexConfig, configFromEnv, getConfig, setConfig } from "./config.js";
export { Transport, BufferTransport, HTTPTransport, createTransport } from "./transport.js";
export { getContext, childContext, newTraceId, newSpanId } from "./context.js";

// ── Hook Registry ────────────────────────────────────────────────────────────

type HookInstaller = (transport: Transport) => boolean;

const HOOK_REGISTRY: Record<string, HookInstaller> = {
  langchain: installLangChainHooks,
  "vercel-ai": installVercelAIHooks,
  openai: installOpenAIHooks,
  anthropic: installAnthropicHooks,
  mcp: installMCPHooks,
  http: installHTTPHooks,
};

// ── Client ───────────────────────────────────────────────────────────────────

export class PhantexClient {
  private readonly _config: PhantexConfig;
  private readonly _transport: Transport;
  private _installedHooks: string[] = [];
  private _started = false;

  constructor(config?: Partial<PhantexConfig>, transport?: Transport) {
    this._config = { ...getConfig(), ...config };
    setConfig(this._config);
    this._transport = transport ?? createTransport(this._config);
  }

  get config(): PhantexConfig {
    return this._config;
  }
  get transport(): Transport {
    return this._transport;
  }
  get installedHooks(): string[] {
    return [...this._installedHooks];
  }
  get started(): boolean {
    return this._started;
  }

  start(): PhantexClient {
    if (this._started) return this;
    if (!this._config.enabled) return this;

    const hooksConfig = this._config.hooks.toLowerCase().trim();
    let hookNames: string[];

    if (hooksConfig === "auto") {
      hookNames = Object.keys(HOOK_REGISTRY);
    } else if (hooksConfig === "none") {
      hookNames = [];
    } else {
      hookNames = hooksConfig.split(",").map((h) => h.trim()).filter(Boolean);
    }

    for (const name of hookNames) {
      const installer = HOOK_REGISTRY[name];
      if (!installer) {
        if (this._config.debug) {
          console.warn(`[phantex] Unknown hook: ${name}`);
        }
        continue;
      }

      try {
        if (installer(this._transport)) {
          this._installedHooks.push(name);
        }
      } catch {
        // Hook installation failure must never crash user code
        if (this._config.debug) {
          console.warn(`[phantex] Hook '${name}' installation failed`);
        }
      }
    }

    this._started = true;

    if (this._config.debug) {
      console.log(
        `[phantex] SDK started — hooks: ${this._installedHooks.join(", ") || "none"}`
      );
    }

    return this;
  }

  async stop(): Promise<void> {
    if (!this._started) return;
    await this._transport.flush();
    await this._transport.close();
    this._started = false;
  }

  /** Get captured events (BufferTransport only). For testing. */
  getEvents(): unknown[] {
    if (this._transport instanceof BufferTransport) {
      return this._transport.peek();
    }
    return [];
  }
}

// ── Auto-Init ────────────────────────────────────────────────────────────────

let _client: PhantexClient | null = null;

export function init(config?: Partial<PhantexConfig>): PhantexClient {
  if (_client?.started) {
    _client.stop().catch(() => {});
  }
  _client = new PhantexClient(config);
  _client.start();
  return _client;
}

export async function stop(): Promise<void> {
  if (_client) {
    await _client.stop();
    _client = null;
  }
}

export function getClient(): PhantexClient | null {
  return _client;
}

// Auto-start if PHANTEX_ENABLED !== "0" and not in test mode
if (
  process.env.PHANTEX_ENABLED !== "0" &&
  process.env.PHANTEX_NO_AUTO_INIT !== "1" &&
  process.env.NODE_ENV !== "test"
) {
  try {
    _client = new PhantexClient();
    _client.start();
  } catch {
    // Never crash user's app during auto-init
  }
}
