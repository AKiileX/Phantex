// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex SDK — HTTP/fetch Hooks.
 *
 * Global intercept for:
 * - globalThis.fetch() → capture outgoing HTTP requests
 *
 * Filters for AI-related endpoints (OpenAI, Anthropic, Cohere, etc.)
 * to avoid noise from non-AI HTTP traffic.
 *
 * Security:
 * - Request body: never captured (may contain prompts)
 * - Only URL, method, status, duration, content-length captured
 * - No eval() or Function() constructor
 */

import type { Transport, PhantexEvent } from "../transport.js";
import { childContext } from "../context.js";
import { getConfig } from "../config.js";

const FRAMEWORK = "http";

/** AI API domains we specifically instrument. */
const AI_DOMAINS = [
  "api.openai.com",
  "api.anthropic.com",
  "api.cohere.ai",
  "api.cohere.com",
  "generativelanguage.googleapis.com",
  "api.mistral.ai",
  "api.groq.com",
  "api.together.xyz",
  "api.fireworks.ai",
  "api.perplexity.ai",
  "api.deepseek.com",
];

function isAIEndpoint(url: string): boolean {
  try {
    const parsed = new URL(url);
    return AI_DOMAINS.some((d) => parsed.hostname === d || parsed.hostname.endsWith(`.${d}`));
  } catch {
    return false;
  }
}

export function installHTTPHooks(transport: Transport): boolean {
  if (typeof globalThis.fetch !== "function") return false;
  if ((globalThis.fetch as any)._phantexPatched) return true;

  const originalFetch = globalThis.fetch;

  globalThis.fetch = async function phantexFetch(
    input: RequestInfo | URL,
    init?: RequestInit
  ): Promise<Response> {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;

    // Only instrument AI endpoints to reduce noise
    if (!isAIEndpoint(url)) {
      return originalFetch(input, init);
    }

    const ctx = childContext(FRAMEWORK);
    const method = init?.method ?? (input instanceof Request ? input.method : "GET");
    const startNs = Number(process.hrtime.bigint());

    // Extract just the path, not query params (may contain API keys)
    let safePath: string;
    try {
      const parsed = new URL(url);
      safePath = `${parsed.hostname}${parsed.pathname}`;
    } catch {
      safePath = "unknown";
    }

    transport.send({
      event_type: "TOOL_CALL",
      tenant_id: getConfig().tenantId,
      agent_paid: ctx.agentPaid,
      tool_name: `http:${method}:${safePath}`,
      protocol: "http_ai",
      framework: FRAMEWORK,
      trace_id: ctx.traceId,
      span_id: ctx.spanId,
      parent_span_id: ctx.parentSpanId,
      timestamp_ns: startNs,
    });

    try {
      const response = await originalFetch(input, init);
      const durationNs = Number(process.hrtime.bigint()) - startNs;

      transport.send({
        event_type: "TOOL_RESPONSE",
        tenant_id: getConfig().tenantId,
        agent_paid: ctx.agentPaid,
        tool_name: `http:${method}:${safePath}`,
        protocol: "http_ai",
        framework: FRAMEWORK,
        success: response.ok,
        duration_ns: durationNs,
        http_status: response.status,
        content_length: parseInt(response.headers.get("content-length") ?? "0", 10) || 0,
        trace_id: ctx.traceId,
        span_id: ctx.spanId,
        parent_span_id: ctx.parentSpanId,
        timestamp_ns: Number(process.hrtime.bigint()),
      });

      return response;
    } catch (err: any) {
      const durationNs = Number(process.hrtime.bigint()) - startNs;
      transport.send({
        event_type: "TOOL_RESPONSE",
        tenant_id: getConfig().tenantId,
        agent_paid: ctx.agentPaid,
        tool_name: `http:${method}:${safePath}`,
        protocol: "http_ai",
        framework: FRAMEWORK,
        success: false,
        duration_ns: durationNs,
        error_message: (err?.message ?? String(err)).slice(0, 500),
        trace_id: ctx.traceId,
        span_id: ctx.spanId,
        parent_span_id: ctx.parentSpanId,
        timestamp_ns: Number(process.hrtime.bigint()),
      });
      throw err;
    }
  };

  (globalThis.fetch as any)._phantexPatched = true;
  return true;
}
