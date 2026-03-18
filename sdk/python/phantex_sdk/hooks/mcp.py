# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex SDK — MCP (Model Context Protocol) hooks.

Covers ALL MCP server types regardless of transport (stdio, SSE, streamable HTTP).
All MCP communication flows through ClientSession — we patch there.

Monkey-patches:
- ClientSession.call_tool()       → capture tool invocations (primary attack surface)
- ClientSession.read_resource()   → capture resource reads (exfiltration vector)
- ClientSession.get_prompt()      → capture prompt retrieval (injection vector)
- ClientSession.list_tools()      → capture tool discovery (unexpected tool detection)

Security relevance:
- MCP tools can read/write files, execute code, access DBs, make HTTP calls
- Prompt injection via MCP: attacker poisons tool output → agent calls malicious tool
- Data exfiltration via MCP: agent reads sensitive resource and sends to attacker
- Tool confusion: unexpected tools appear at runtime → MCP server compromised
"""

from __future__ import annotations

import logging
from typing import Any

from .base import BaseHook

logger = logging.getLogger("phantex.hooks.mcp")

class MCPHook(BaseHook):
    name = "mcp"
    framework = "mcp"

    def install(self) -> bool:
        """Install MCP hooks. Returns False if mcp package not installed."""
        try:
            from mcp import ClientSession  # noqa: F401
        except ImportError:
            logger.debug("mcp package not installed — skipping MCP hooks")
            return False

        patched_any = False

        # ── 1. call_tool — the main attack surface ──────────────────────
        patched_any |= self._patch_call_tool()

        # ── 2. read_resource — exfiltration vector ──────────────────────
        patched_any |= self._patch_read_resource()

        # ── 3. get_prompt — prompt injection vector ─────────────────────
        patched_any |= self._patch_get_prompt()

        # ── 4. list_tools — tool discovery monitoring ───────────────────
        patched_any |= self._patch_list_tools()

        self._installed = patched_any
        if patched_any:
            logger.info("MCP hooks installed (%d patches)", len(self._patches))
        return patched_any

    # ══════════════════════════════════════════════════════════════════════
    # call_tool — every MCP tool call goes through here
    # ══════════════════════════════════════════════════════════════════════

    def _patch_call_tool(self) -> bool:
        try:
            from mcp import ClientSession
        except ImportError:
            return False

        hook = self

        def make_wrapper(original):
            async def wrapper(
                self_session: Any,
                name: str,
                arguments: dict[str, Any] | None = None,
                *args: Any,
                **kwargs: Any,
            ) -> Any:
                # Serialize arguments for visibility (truncated for safety)
                tool_input = {
                    "tool_name": name,
                    "arguments": arguments or {},
                }

                span_id, start_ns = hook._emit_tool_call(
                    tool_name=f"mcp:call_tool:{name}",
                    tool_input=tool_input,
                    protocol="mcp_tool",
                )
                try:
                    result = await original(self_session, name, arguments, *args, **kwargs)

                    # Extract result metadata
                    is_error = getattr(result, "isError", False)
                    len(getattr(result, "content", []))
                    output_summary = _summarize_call_result(result)

                    hook._emit_tool_response(
                        tool_name=f"mcp:call_tool:{name}",
                        span_id=span_id,
                        start_ns=start_ns,
                        success=not is_error,
                        result=output_summary,
                        protocol="mcp_tool",
                    )
                    return result
                except Exception as e:
                    hook._emit_tool_response(
                        tool_name=f"mcp:call_tool:{name}",
                        span_id=span_id,
                        start_ns=start_ns,
                        success=False,
                        error=str(e),
                        protocol="mcp_tool",
                    )
                    raise

            return wrapper

        return self._patch(ClientSession, "call_tool", make_wrapper)

    # ══════════════════════════════════════════════════════════════════════
    # read_resource — data exfiltration vector
    # ══════════════════════════════════════════════════════════════════════

    def _patch_read_resource(self) -> bool:
        try:
            from mcp import ClientSession
        except ImportError:
            return False

        hook = self

        def make_wrapper(original):
            async def wrapper(
                self_session: Any,
                uri: Any,
                *args: Any,
                **kwargs: Any,
            ) -> Any:
                uri_str = str(uri)

                span_id, start_ns = hook._emit_tool_call(
                    tool_name="mcp:read_resource",
                    tool_input={"uri": uri_str},
                    protocol="mcp_resource",
                )
                try:
                    result = await original(self_session, uri, *args, **kwargs)

                    content_count = len(getattr(result, "contents", []))
                    total_size = _measure_resource_size(result)

                    hook._emit_tool_response(
                        tool_name="mcp:read_resource",
                        span_id=span_id,
                        start_ns=start_ns,
                        success=True,
                        result=f"uri={uri_str} contents={content_count} bytes={total_size}",
                        protocol="mcp_resource",
                    )
                    return result
                except Exception as e:
                    hook._emit_tool_response(
                        tool_name="mcp:read_resource",
                        span_id=span_id,
                        start_ns=start_ns,
                        success=False,
                        error=str(e),
                        protocol="mcp_resource",
                    )
                    raise

            return wrapper

        return self._patch(ClientSession, "read_resource", make_wrapper)

    # ══════════════════════════════════════════════════════════════════════
    # get_prompt — prompt injection vector
    # ══════════════════════════════════════════════════════════════════════

    def _patch_get_prompt(self) -> bool:
        try:
            from mcp import ClientSession
        except ImportError:
            return False

        hook = self

        def make_wrapper(original):
            async def wrapper(
                self_session: Any,
                name: str,
                arguments: dict[str, str] | None = None,
                *args: Any,
                **kwargs: Any,
            ) -> Any:
                span_id, start_ns = hook._emit_tool_call(
                    tool_name=f"mcp:get_prompt:{name}",
                    tool_input={"prompt_name": name, "arguments": arguments or {}},
                    protocol="mcp_prompt",
                    prompt_content=name,  # Hash the prompt name for tracking
                )
                try:
                    result = await original(self_session, name, arguments, *args, **kwargs)

                    msg_count = len(getattr(result, "messages", []))
                    # Hash prompt content from returned messages for injection detection
                    prompt_text = _extract_prompt_text(result)

                    hook._emit_tool_response(
                        tool_name=f"mcp:get_prompt:{name}",
                        span_id=span_id,
                        start_ns=start_ns,
                        success=True,
                        result=f"messages={msg_count} chars={len(prompt_text)}",
                        protocol="mcp_prompt",
                    )
                    return result
                except Exception as e:
                    hook._emit_tool_response(
                        tool_name=f"mcp:get_prompt:{name}",
                        span_id=span_id,
                        start_ns=start_ns,
                        success=False,
                        error=str(e),
                        protocol="mcp_prompt",
                    )
                    raise

            return wrapper

        return self._patch(ClientSession, "get_prompt", make_wrapper)

    # ══════════════════════════════════════════════════════════════════════
    # list_tools — tool discovery monitoring (detects unexpected tools)
    # ══════════════════════════════════════════════════════════════════════

    def _patch_list_tools(self) -> bool:
        try:
            from mcp import ClientSession
        except ImportError:
            return False

        hook = self

        def make_wrapper(original):
            async def wrapper(
                self_session: Any,
                *args: Any,
                **kwargs: Any,
            ) -> Any:
                span_id, start_ns = hook._emit_tool_call(
                    tool_name="mcp:list_tools",
                    protocol="mcp_discovery",
                )
                try:
                    result = await original(self_session, *args, **kwargs)

                    tools = getattr(result, "tools", [])
                    tool_names = [getattr(t, "name", "?") for t in tools]

                    hook._emit_tool_response(
                        tool_name="mcp:list_tools",
                        span_id=span_id,
                        start_ns=start_ns,
                        success=True,
                        result=f"tools={tool_names}",
                        protocol="mcp_discovery",
                    )
                    return result
                except Exception as e:
                    hook._emit_tool_response(
                        tool_name="mcp:list_tools",
                        span_id=span_id,
                        start_ns=start_ns,
                        success=False,
                        error=str(e),
                        protocol="mcp_discovery",
                    )
                    raise

            return wrapper

        return self._patch(ClientSession, "list_tools", make_wrapper)

# ══════════════════════════════════════════════════════════════════════════
# Helper functions — extract data from MCP result types safely
# ══════════════════════════════════════════════════════════════════════════

def _summarize_call_result(result: Any) -> str:
    """Summarize a CallToolResult for event logging."""
    try:
        is_error = getattr(result, "isError", False)
        contents = getattr(result, "content", [])

        parts = []
        for item in contents[:5]:  # Cap at 5 content items
            content_type = type(item).__name__
            if hasattr(item, "text"):
                text = str(item.text)[:200]
                parts.append(f"{content_type}:{len(text)}chars")
            elif hasattr(item, "data"):
                parts.append(f"{content_type}:blob")
            else:
                parts.append(content_type)

        status = "error" if is_error else "ok"
        return f"status={status} content=[{', '.join(parts)}]"
    except Exception:
        return "status=unknown"

def _measure_resource_size(result: Any) -> int:
    """Measure total size of resource contents in bytes."""
    try:
        total = 0
        for item in getattr(result, "contents", []):
            if hasattr(item, "text"):
                total += len(str(item.text).encode("utf-8", errors="replace"))
            elif hasattr(item, "blob"):
                total += len(item.blob) if item.blob else 0
        return total
    except Exception:
        return 0

def _extract_prompt_text(result: Any) -> str:
    """Extract text from GetPromptResult messages for hashing."""
    try:
        texts = []
        for msg in getattr(result, "messages", []):
            content = getattr(msg, "content", None)
            if isinstance(content, str):
                texts.append(content)
            elif hasattr(content, "text"):
                texts.append(str(content.text))
        return " ".join(texts)
    except Exception:
        return ""
