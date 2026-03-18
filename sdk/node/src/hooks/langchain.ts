// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex SDK — LangChain.js Hooks.
 *
 * Monkey-patches:
 * - BaseTool.invoke() → capture tool calls
 * - BaseChatModel.invoke() → capture LLM calls
 *
 * Security:
 * - Prompt content: hash only (SHA-256), never stored plaintext
 * - Tool input: serialized with size limit (4KB)
 * - No eval() or Function() constructor used
 */

import type { Transport, PhantexEvent } from "../transport.js";
import { hashPrompt } from "../transport.js";
import { childContext, runWithContext, getContext } from "../context.js";
import { getConfig } from "../config.js";

const FRAMEWORK = "langchain";
const MAX_INPUT_SIZE = 4096;

/** Safely serialize tool input to string, truncated. */
function safeSerialize(input: unknown): string {
  try {
    const s = typeof input === "string" ? input : JSON.stringify(input);
    return s.length > MAX_INPUT_SIZE ? s.slice(0, MAX_INPUT_SIZE) + "..." : s;
  } catch {
    return "[unserializable]";
  }
}

export function installLangChainHooks(transport: Transport): boolean {
  try {
    // Dynamic require — fails silently if langchain not installed
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const core = require("@langchain/core");
    const { StructuredTool } = require("@langchain/core/tools");
    const { BaseChatModel } = require("@langchain/core/language_models/chat_models");

    let patchedAny = false;

    // ── Patch BaseTool.invoke() ──────────────────────────────────────
    if (StructuredTool?.prototype?.invoke) {
      const originalInvoke = StructuredTool.prototype.invoke;

      if (!(originalInvoke as any)._phantexPatched) {
        StructuredTool.prototype.invoke = async function (
          this: any,
          input: any,
          ...args: any[]
        ) {
          const ctx = childContext(FRAMEWORK);
          const toolName = this.name ?? this.constructor?.name ?? "unknown_tool";
          const startNs = Number(process.hrtime.bigint());

          const callEvent: PhantexEvent = {
            event_type: "TOOL_CALL",
            tenant_id: getConfig().tenantId,
            agent_paid: ctx.agentPaid,
            tool_name: toolName,
            tool_input: safeSerialize(input),
            protocol: "langchain_tool",
            framework: FRAMEWORK,
            trace_id: ctx.traceId,
            span_id: ctx.spanId,
            parent_span_id: ctx.parentSpanId,
            timestamp_ns: startNs,
          };
          transport.send(callEvent);

          try {
            const result = await runWithContext(ctx, () =>
              originalInvoke.call(this, input, ...args)
            );

            const durationNs = Number(process.hrtime.bigint()) - startNs;
            const respEvent: PhantexEvent = {
              event_type: "TOOL_RESPONSE",
              tenant_id: getConfig().tenantId,
              agent_paid: ctx.agentPaid,
              tool_name: toolName,
              protocol: "langchain_tool",
              framework: FRAMEWORK,
              success: true,
              duration_ns: durationNs,
              output_size: String(result ?? "").length,
              trace_id: ctx.traceId,
              span_id: ctx.spanId,
              parent_span_id: ctx.parentSpanId,
              timestamp_ns: Number(process.hrtime.bigint()),
            };
            transport.send(respEvent);
            return result;
          } catch (err: any) {
            const durationNs = Number(process.hrtime.bigint()) - startNs;
            transport.send({
              event_type: "TOOL_RESPONSE",
              tenant_id: getConfig().tenantId,
              agent_paid: ctx.agentPaid,
              tool_name: toolName,
              protocol: "langchain_tool",
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
        (StructuredTool.prototype.invoke as any)._phantexPatched = true;
        patchedAny = true;
      }
    }

    // ── Patch BaseChatModel.invoke() ─────────────────────────────────
    if (BaseChatModel?.prototype?.invoke) {
      const originalModelInvoke = BaseChatModel.prototype.invoke;

      if (!(originalModelInvoke as any)._phantexPatched) {
        BaseChatModel.prototype.invoke = async function (
          this: any,
          input: any,
          ...args: any[]
        ) {
          const ctx = childContext(FRAMEWORK);
          const modelName =
            this.modelName ?? this._modelName ?? this.constructor?.name ?? "unknown_model";
          const startNs = Number(process.hrtime.bigint());

          // Hash prompt, never store plaintext
          const promptHash = hashPrompt(
            typeof input === "string" ? input : JSON.stringify(input)
          );

          transport.send({
            event_type: "TOOL_CALL",
            tenant_id: getConfig().tenantId,
            agent_paid: ctx.agentPaid,
            tool_name: `llm:${modelName}`,
            protocol: "langchain_llm",
            framework: FRAMEWORK,
            model_name: modelName,
            prompt_hash: promptHash,
            trace_id: ctx.traceId,
            span_id: ctx.spanId,
            parent_span_id: ctx.parentSpanId,
            timestamp_ns: startNs,
          });

          try {
            const result = await runWithContext(ctx, () =>
              originalModelInvoke.call(this, input, ...args)
            );

            const durationNs = Number(process.hrtime.bigint()) - startNs;
            const usage = result?.usage_metadata ?? {};

            transport.send({
              event_type: "TOOL_RESPONSE",
              tenant_id: getConfig().tenantId,
              agent_paid: ctx.agentPaid,
              tool_name: `llm:${modelName}`,
              protocol: "langchain_llm",
              framework: FRAMEWORK,
              model_name: modelName,
              success: true,
              duration_ns: durationNs,
              input_tokens: usage.input_tokens ?? 0,
              output_tokens: usage.output_tokens ?? 0,
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
              tool_name: `llm:${modelName}`,
              protocol: "langchain_llm",
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
        (BaseChatModel.prototype.invoke as any)._phantexPatched = true;
        patchedAny = true;
      }
    }

    return patchedAny;
  } catch {
    // LangChain not installed — silently skip
    return false;
  }
}
