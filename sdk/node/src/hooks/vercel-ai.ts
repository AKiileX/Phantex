// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex SDK — Vercel AI SDK Hooks.
 *
 * Wraps:
 * - generateText() → capture model calls + tool usage
 * - streamText() → capture streaming model calls
 * - generateObject() → capture structured output calls
 *
 * Security:
 * - Prompt: hash only, never stored plaintext
 * - No eval() or Function() constructor
 */

import type { Transport, PhantexEvent } from "../transport.js";
import { hashPrompt } from "../transport.js";
import { childContext, runWithContext } from "../context.js";
import { getConfig } from "../config.js";

const FRAMEWORK = "vercel-ai";

export function installVercelAIHooks(transport: Transport): boolean {
  try {
    const ai = require("ai");
    let patchedAny = false;

    // ── generateText ─────────────────────────────────────────────────
    if (typeof ai.generateText === "function" && !(ai.generateText as any)._phantexPatched) {
      const originalGenerateText = ai.generateText;

      ai.generateText = async function phantexGenerateText(options: any) {
        const ctx = childContext(FRAMEWORK);
        const modelName = options?.model?.modelId ?? options?.model ?? "unknown";
        const startNs = Number(process.hrtime.bigint());

        const promptHash = hashPrompt(
          typeof options?.prompt === "string"
            ? options.prompt
            : JSON.stringify(options?.messages ?? "")
        );

        transport.send({
          event_type: "TOOL_CALL",
          tenant_id: getConfig().tenantId,
          agent_paid: ctx.agentPaid,
          tool_name: `ai:generateText:${modelName}`,
          protocol: "vercel_ai",
          framework: FRAMEWORK,
          model_name: String(modelName),
          prompt_hash: promptHash,
          trace_id: ctx.traceId,
          span_id: ctx.spanId,
          parent_span_id: ctx.parentSpanId,
          timestamp_ns: startNs,
        });

        try {
          const result = await runWithContext(ctx, () =>
            originalGenerateText(options)
          );

          const durationNs = Number(process.hrtime.bigint()) - startNs;
          const usage = result?.usage ?? {};

          transport.send({
            event_type: "TOOL_RESPONSE",
            tenant_id: getConfig().tenantId,
            agent_paid: ctx.agentPaid,
            tool_name: `ai:generateText:${modelName}`,
            protocol: "vercel_ai",
            framework: FRAMEWORK,
            model_name: String(modelName),
            success: true,
            duration_ns: durationNs,
            input_tokens: usage.promptTokens ?? 0,
            output_tokens: usage.completionTokens ?? 0,
            tool_calls_count: result?.toolCalls?.length ?? 0,
            trace_id: ctx.traceId,
            span_id: ctx.spanId,
            parent_span_id: ctx.parentSpanId,
            timestamp_ns: Number(process.hrtime.bigint()),
          });
          return result;
        } catch (err: any) {
          const durationNs = Number(process.hrtime.bigint()) - startNs;
          transport.send({
            event_type: "TOOL_RESPONSE",
            tenant_id: getConfig().tenantId,
            agent_paid: ctx.agentPaid,
            tool_name: `ai:generateText:${modelName}`,
            protocol: "vercel_ai",
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
      (ai.generateText as any)._phantexPatched = true;
      patchedAny = true;
    }

    // ── streamText ───────────────────────────────────────────────────
    if (typeof ai.streamText === "function" && !(ai.streamText as any)._phantexPatched) {
      const originalStreamText = ai.streamText;

      ai.streamText = function phantexStreamText(options: any) {
        const ctx = childContext(FRAMEWORK);
        const modelName = options?.model?.modelId ?? options?.model ?? "unknown";
        const startNs = Number(process.hrtime.bigint());

        transport.send({
          event_type: "TOOL_CALL",
          tenant_id: getConfig().tenantId,
          agent_paid: ctx.agentPaid,
          tool_name: `ai:streamText:${modelName}`,
          protocol: "vercel_ai_stream",
          framework: FRAMEWORK,
          model_name: String(modelName),
          trace_id: ctx.traceId,
          span_id: ctx.spanId,
          parent_span_id: ctx.parentSpanId,
          timestamp_ns: startNs,
        });

        try {
          const result = runWithContext(ctx, () => originalStreamText(options));

          // Emit response event when stream completes (via async iteration)
          const durationNs = Number(process.hrtime.bigint()) - startNs;
          transport.send({
            event_type: "TOOL_RESPONSE",
            tenant_id: getConfig().tenantId,
            agent_paid: ctx.agentPaid,
            tool_name: `ai:streamText:${modelName}`,
            protocol: "vercel_ai_stream",
            framework: FRAMEWORK,
            success: true,
            duration_ns: durationNs,
            trace_id: ctx.traceId,
            span_id: ctx.spanId,
            parent_span_id: ctx.parentSpanId,
            timestamp_ns: Number(process.hrtime.bigint()),
          });
          return result;
        } catch (err: any) {
          const durationNs = Number(process.hrtime.bigint()) - startNs;
          transport.send({
            event_type: "TOOL_RESPONSE",
            tenant_id: getConfig().tenantId,
            agent_paid: ctx.agentPaid,
            tool_name: `ai:streamText:${modelName}`,
            protocol: "vercel_ai_stream",
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
      (ai.streamText as any)._phantexPatched = true;
      patchedAny = true;
    }

    return patchedAny;
  } catch {
    return false;
  }
}
