// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex SDK — Async Context (trace propagation).
 *
 * Uses Node.js AsyncLocalStorage for correct context propagation
 * across async boundaries (callbacks, promises, await).
 */

import { AsyncLocalStorage } from "node:async_hooks";
import { randomUUID } from "node:crypto";

export interface TraceContext {
  traceId: string;
  spanId: string;
  parentSpanId: string;
  agentPaid: string;
  framework: string;
}

const _storage = new AsyncLocalStorage<TraceContext>();

/** Generate a new trace ID (UUID v4 hex, no dashes). */
export function newTraceId(): string {
  return randomUUID().replace(/-/g, "");
}

/** Generate a new span ID (first 16 chars of UUID). */
export function newSpanId(): string {
  return randomUUID().replace(/-/g, "").slice(0, 16);
}

/** Get or create the current trace context. */
export function getContext(): TraceContext {
  const ctx = _storage.getStore();
  if (ctx) return ctx;
  return {
    traceId: newTraceId(),
    spanId: "",
    parentSpanId: "",
    agentPaid: process.env.PHANTEX_AGENT_ID ?? "",
    framework: "",
  };
}

/** Run a function within a trace context. */
export function runWithContext<T>(ctx: TraceContext, fn: () => T): T {
  return _storage.run(ctx, fn);
}

/** Create a child context (new span, parent = current span). */
export function childContext(framework: string): TraceContext {
  const parent = getContext();
  return {
    traceId: parent.traceId || newTraceId(),
    spanId: newSpanId(),
    parentSpanId: parent.spanId,
    agentPaid: parent.agentPaid,
    framework,
  };
}
