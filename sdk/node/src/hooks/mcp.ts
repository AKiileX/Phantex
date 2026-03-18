// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex SDK — MCP (Model Context Protocol) Hook for Node.js.
 *
 * Monkey-patches the official @modelcontextprotocol/sdk Client to capture:
 *   - callTool()       → Tool invocations (primary attack surface)
 *   - readResource()   → Resource reads (exfiltration vector)
 *   - getPrompt()      → Prompt retrieval (injection vector)
 *   - listTools()      → Tool discovery (unexpected tool detection)
 *
 * Works with all MCP transports (stdio, SSE, streamable HTTP)
 * since they all flow through the Client class.
 *
 * Security relevance:
 *   MCP tools can read/write files, execute code, access DBs, make HTTP calls.
 *   Prompt injection via MCP: attacker poisons tool output → agent calls malicious tool.
 *   Data exfiltration via MCP: agent reads sensitive resource and sends to attacker.
 *   Tool confusion: unexpected tools appear at runtime → MCP server compromised.
 */

import type { Transport } from "../transport.js";
import { getContext } from "../context.js";

const _PATCHED = Symbol.for("phantex.mcp.patched");
const MAX_SERIALIZE = 4096;

function safeSerialize(v: unknown): string {
  try {
    const s = JSON.stringify(v);
    return s && s.length > MAX_SERIALIZE ? s.slice(0, MAX_SERIALIZE) + "…" : (s ?? "null");
  } catch {
    return "[unserializable]";
  }
}

function emit(transport: Transport, event: Record<string, unknown>): void {
  const ctx = getContext();
  const cfg = require("../config.js").getConfig();
  transport.send({
    ...event,
    tenant_id: cfg.tenantId ?? "",
    agent_paid: cfg.agentId ?? "",
    framework: "mcp",
    trace_id: ctx.traceId,
    span_id: ctx.spanId,
    timestamp: new Date().toISOString(),
  });
}

/**
 * Install MCP hooks by patching Client.prototype methods.
 * Returns true if the @modelcontextprotocol/sdk package is available.
 */
export function installMCPHooks(transport: Transport): boolean {
  let ClientProto: Record<string, unknown>;
  try {
    // The official MCP SDK for Node.js
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const sdk = require("@modelcontextprotocol/sdk/client/index.js");
    const Client = sdk.Client;
    if (!Client?.prototype) return false;
    ClientProto = Client.prototype;
  } catch {
    return false;
  }

  if ((ClientProto as any)[_PATCHED]) return true;

  let patched = false;

  // ── 1. callTool — primary attack surface ─────────────────────────────────

  const origCallTool = ClientProto.callTool as Function | undefined;
  if (typeof origCallTool === "function") {
    ClientProto.callTool = async function patchedCallTool(
      this: unknown,
      params: { name: string; arguments?: Record<string, unknown> },
      ...rest: unknown[]
    ) {
      const start = Date.now();
      emit(transport, {
        event_type: "mcp.tool_call",
        tool_name: params?.name ?? "unknown",
        tool_input: safeSerialize(params?.arguments),
        direction: "request",
      });

      try {
        const result = await origCallTool.apply(this, [params, ...rest]);
        emit(transport, {
          event_type: "mcp.tool_response",
          tool_name: params?.name ?? "unknown",
          tool_output: safeSerialize(result?.content),
          is_error: result?.isError ?? false,
          duration_ms: Date.now() - start,
          direction: "response",
        });
        return result;
      } catch (err: any) {
        emit(transport, {
          event_type: "mcp.tool_error",
          tool_name: params?.name ?? "unknown",
          error: err?.message?.slice(0, 256) ?? "unknown",
          duration_ms: Date.now() - start,
          direction: "response",
        });
        throw err;
      }
    };
    patched = true;
  }

  // ── 2. readResource — exfiltration vector ────────────────────────────────

  const origReadResource = ClientProto.readResource as Function | undefined;
  if (typeof origReadResource === "function") {
    ClientProto.readResource = async function patchedReadResource(
      this: unknown,
      params: { uri: string },
      ...rest: unknown[]
    ) {
      const start = Date.now();
      emit(transport, {
        event_type: "mcp.resource_read",
        resource_uri: params?.uri ?? "unknown",
        direction: "request",
      });

      try {
        const result = await origReadResource.apply(this, [params, ...rest]);
        const contents = Array.isArray(result?.contents) ? result.contents : [];
        emit(transport, {
          event_type: "mcp.resource_response",
          resource_uri: params?.uri ?? "unknown",
          content_count: contents.length,
          content_types: contents.map((c: any) => c?.mimeType ?? "unknown").slice(0, 10),
          duration_ms: Date.now() - start,
          direction: "response",
        });
        return result;
      } catch (err: any) {
        emit(transport, {
          event_type: "mcp.resource_error",
          resource_uri: params?.uri ?? "unknown",
          error: err?.message?.slice(0, 256) ?? "unknown",
          duration_ms: Date.now() - start,
          direction: "response",
        });
        throw err;
      }
    };
    patched = true;
  }

  // ── 3. getPrompt — prompt injection vector ──────────────────────────────

  const origGetPrompt = ClientProto.getPrompt as Function | undefined;
  if (typeof origGetPrompt === "function") {
    ClientProto.getPrompt = async function patchedGetPrompt(
      this: unknown,
      params: { name: string; arguments?: Record<string, string> },
      ...rest: unknown[]
    ) {
      const start = Date.now();
      emit(transport, {
        event_type: "mcp.prompt_get",
        prompt_name: params?.name ?? "unknown",
        argument_keys: params?.arguments ? Object.keys(params.arguments) : [],
        direction: "request",
      });

      try {
        const result = await origGetPrompt.apply(this, [params, ...rest]);
        const messages = Array.isArray(result?.messages) ? result.messages : [];
        emit(transport, {
          event_type: "mcp.prompt_response",
          prompt_name: params?.name ?? "unknown",
          message_count: messages.length,
          roles: messages.map((m: any) => m?.role ?? "unknown").slice(0, 20),
          duration_ms: Date.now() - start,
          direction: "response",
        });
        return result;
      } catch (err: any) {
        emit(transport, {
          event_type: "mcp.prompt_error",
          prompt_name: params?.name ?? "unknown",
          error: err?.message?.slice(0, 256) ?? "unknown",
          duration_ms: Date.now() - start,
          direction: "response",
        });
        throw err;
      }
    };
    patched = true;
  }

  // ── 4. listTools — unexpected tool detection ─────────────────────────────

  const origListTools = ClientProto.listTools as Function | undefined;
  if (typeof origListTools === "function") {
    ClientProto.listTools = async function patchedListTools(
      this: unknown,
      ...args: unknown[]
    ) {
      const start = Date.now();
      emit(transport, {
        event_type: "mcp.list_tools",
        direction: "request",
      });

      try {
        const result = await origListTools.apply(this, args);
        const tools = Array.isArray(result?.tools) ? result.tools : [];
        emit(transport, {
          event_type: "mcp.list_tools_response",
          tool_count: tools.length,
          tool_names: tools.map((t: any) => t?.name ?? "unknown").slice(0, 50),
          duration_ms: Date.now() - start,
          direction: "response",
        });
        return result;
      } catch (err: any) {
        emit(transport, {
          event_type: "mcp.list_tools_error",
          error: err?.message?.slice(0, 256) ?? "unknown",
          duration_ms: Date.now() - start,
          direction: "response",
        });
        throw err;
      }
    };
    patched = true;
  }

  if (patched) {
    (ClientProto as any)[_PATCHED] = true;
  }

  return patched;
}
