// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex SDK — Anthropic SDK Hooks.
 *
 * Proxies:
 * - anthropic.messages.create() → capture model calls + tool usage
 *
 * Security:
 * - Prompt: hash only, never stored plaintext
 * - No eval() or Function() constructor
 */

import type { Transport, PhantexEvent } from "../transport.js";
import { hashPrompt } from "../transport.js";
import { childContext, runWithContext } from "../context.js";
import { getConfig } from "../config.js";

const FRAMEWORK = "anthropic";

export function installAnthropicHooks(transport: Transport): boolean {
  try {
    const Anthropic = require("@anthropic-ai/sdk").default ?? require("@anthropic-ai/sdk");
    if (!Anthropic?.prototype) return false;

    const patchedSymbol = Symbol.for("phantex_anthropic_patched");
    if ((Anthropic as any)[patchedSymbol]) return true;

    let patchedAny = false;

    try {
      const testClient = new Anthropic({ apiKey: "test-key-for-patching" });
      const messages = testClient?.messages;

      if (messages && typeof messages.create === "function") {
        const proto = Object.getPrototypeOf(messages);
        if (proto && typeof proto.create === "function" && !(proto.create as any)._phantexPatched) {
          const originalCreate = proto.create;

          proto.create = async function phantexAnthropicCreate(
            this: any,
            body: any,
            ...args: any[]
          ) {
            const ctx = childContext(FRAMEWORK);
            const modelName = body?.model ?? "unknown";
            const startNs = Number(process.hrtime.bigint());

            const msgStr = JSON.stringify(body?.messages ?? []);
            const promptHash = hashPrompt(msgStr);

            transport.send({
              event_type: "TOOL_CALL",
              tenant_id: getConfig().tenantId,
              agent_paid: ctx.agentPaid,
              tool_name: `anthropic:messages:${modelName}`,
              protocol: "anthropic_messages",
              framework: FRAMEWORK,
              model_name: modelName,
              prompt_hash: promptHash,
              message_count: body?.messages?.length ?? 0,
              max_tokens: body?.max_tokens ?? 0,
              trace_id: ctx.traceId,
              span_id: ctx.spanId,
              parent_span_id: ctx.parentSpanId,
              timestamp_ns: startNs,
            });

            try {
              const result = await runWithContext(ctx, () =>
                originalCreate.call(this, body, ...args)
              );

              const durationNs = Number(process.hrtime.bigint()) - startNs;
              const usage = result?.usage ?? {};

              transport.send({
                event_type: "TOOL_RESPONSE",
                tenant_id: getConfig().tenantId,
                agent_paid: ctx.agentPaid,
                tool_name: `anthropic:messages:${modelName}`,
                protocol: "anthropic_messages",
                framework: FRAMEWORK,
                model_name: modelName,
                success: true,
                duration_ns: durationNs,
                input_tokens: usage.input_tokens ?? 0,
                output_tokens: usage.output_tokens ?? 0,
                stop_reason: result?.stop_reason ?? "",
                tool_use_count:
                  result?.content?.filter?.((b: any) => b.type === "tool_use")?.length ?? 0,
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
                tool_name: `anthropic:messages:${modelName}`,
                protocol: "anthropic_messages",
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
          (proto.create as any)._phantexPatched = true;
          patchedAny = true;
        }
      }
    } catch {
      // Instantiation may fail without API key — OK
    }

    (Anthropic as any)[patchedSymbol] = true;
    return patchedAny;
  } catch {
    return false;
  }
}
