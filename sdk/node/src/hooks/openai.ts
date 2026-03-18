// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex SDK — OpenAI SDK Hooks.
 *
 * Proxies:
 * - openai.chat.completions.create() → capture model calls + tool usage
 *
 * Security:
 * - Prompt: hash only, never stored plaintext
 * - No eval() or Function() constructor
 */

import type { Transport, PhantexEvent } from "../transport.js";
import { hashPrompt } from "../transport.js";
import { childContext, runWithContext } from "../context.js";
import { getConfig } from "../config.js";

const FRAMEWORK = "openai";

export function installOpenAIHooks(transport: Transport): boolean {
  try {
    const OpenAI = require("openai").default ?? require("openai");
    if (!OpenAI?.prototype) return false;

    // Patch the chat.completions.create method on the prototype's _client
    // OpenAI SDK v4+ uses: client.chat.completions.create(...)
    // We intercept at instance creation via constructor proxy

    const originalConstructor = OpenAI;

    // We can't easily monkey-patch nested objects in JS without proxying.
    // Instead, we wrap the constructor to proxy the returned instance.
    const patchedSymbol = Symbol.for("phantex_openai_patched");
    if ((OpenAI as any)[patchedSymbol]) return true;

    // Store reference for wrapping — we wrap create() on each instance
    const origModule = require("openai");
    const ChatCompletions = origModule.OpenAI?.Chat?.Completions ??
      origModule.default?.Chat?.Completions;

    // Approach: patch prototype of the Completions class if accessible
    // OpenAI v4 structure: OpenAI → .chat → .completions → .create()
    // The completions object is created lazily, so we patch after first access

    // Alternative: Patch at module level by intercepting create
    let patchedAny = false;

    // Try to find Completions prototype from an instance
    try {
      const testClient = new OpenAI({ apiKey: "test-key-for-patching" });
      const completions = testClient?.chat?.completions;
      if (completions && typeof completions.create === "function") {
        const proto = Object.getPrototypeOf(completions);
        if (proto && typeof proto.create === "function" && !(proto.create as any)._phantexPatched) {
          const originalCreate = proto.create;

          proto.create = async function phantexOpenAICreate(
            this: any,
            body: any,
            ...args: any[]
          ) {
            const ctx = childContext(FRAMEWORK);
            const modelName = body?.model ?? "unknown";
            const startNs = Number(process.hrtime.bigint());

            // Hash messages content
            const msgStr = JSON.stringify(body?.messages ?? []);
            const promptHash = hashPrompt(msgStr);

            transport.send({
              event_type: "TOOL_CALL",
              tenant_id: getConfig().tenantId,
              agent_paid: ctx.agentPaid,
              tool_name: `openai:chat:${modelName}`,
              protocol: "openai_chat",
              framework: FRAMEWORK,
              model_name: modelName,
              prompt_hash: promptHash,
              message_count: body?.messages?.length ?? 0,
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
                tool_name: `openai:chat:${modelName}`,
                protocol: "openai_chat",
                framework: FRAMEWORK,
                model_name: modelName,
                success: true,
                duration_ns: durationNs,
                input_tokens: usage.prompt_tokens ?? 0,
                output_tokens: usage.completion_tokens ?? 0,
                tool_calls_count: result?.choices?.[0]?.message?.tool_calls?.length ?? 0,
                finish_reason: result?.choices?.[0]?.finish_reason ?? "",
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
                tool_name: `openai:chat:${modelName}`,
                protocol: "openai_chat",
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
      // OpenAI client instantiation may fail — that's OK, user hasn't configured it yet
    }

    (OpenAI as any)[patchedSymbol] = true;
    return patchedAny;
  } catch {
    return false;
  }
}
