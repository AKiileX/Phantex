# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex Copilot — Investigation Assistant (U2).

NL-driven investigation using LLM tool calling against Phantex APIs.

Pipeline:
  User question → Firewall → LLM (with tools) → Tool execution → LLM summary → Firewall → Response

Tool functions query real Phantex data:
  - search_alerts     → DB query via alert_service
  - get_alert_detail  → DB query + timeline
  - search_events     → ClickHouse query
  - get_agent_info    → DB + trust graph
  - get_trust_score   → Trust engine gRPC
  - get_system_stats  → Nerve center probe

All tool results are tenant-scoped and RLS-enforced.
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.copilot.firewall import CopilotFirewall
from app.services.copilot.llm_provider import (
    COPILOT_TOOLS,
    LLMConfig,
    LLMProvider,
    UsageStats,
)
from app.services.copilot.memory import ConversationMessage, CopilotMemory

logger = logging.getLogger("phantex.copilot.investigator")

MAX_TOOL_ROUNDS = 12  # Max LLM ↔ Tool call rounds per conversation turn
MAX_HISTORY = 30  # Max messages kept in conversation context

# ── Tool executor ─────────────────────────────────────────────────────────────

async def execute_tool(
    name: str,
    arguments: dict[str, Any],
    db: AsyncSession,
    tenant_id: str,
) -> str:
    """
    Execute a copilot tool function against real Phantex data.

    All queries are tenant-scoped via RLS (app.current_tenant is already set
    on the session by enforce_tenant_isolation middleware).
    """
    try:
        if name == "search_alerts":
            return await _tool_search_alerts(db, tenant_id, **arguments)
        elif name == "get_alert_detail":
            return await _tool_get_alert_detail(db, tenant_id, **arguments)
        elif name == "search_events":
            return await _tool_search_events(db, tenant_id, **arguments)
        elif name == "get_agent_info":
            return await _tool_get_agent_info(db, tenant_id, **arguments)
        elif name == "get_trust_score":
            return await _tool_get_trust_score(tenant_id, **arguments)
        elif name == "get_system_stats":
            return await _tool_get_system_stats()
        else:
            return json.dumps({"error": f"Unknown tool: {name}"})
    except Exception as exc:
        logger.warning("copilot_tool_error: tool=%s error=%s", name, exc)
        return json.dumps({"error": f"Tool '{name}' failed: {str(exc)[:200]}"})

async def _tool_search_alerts(
    db: AsyncSession,
    tenant_id: str,
    severity: str | None = None,
    status: str | None = None,
    keyword: str | None = None,
    limit: int = 10,
) -> str:
    """Search alerts with optional filters."""
    conditions = []
    params: dict[str, Any] = {"lim": min(limit, 50)}

    if severity:
        conditions.append("severity = :severity")
        params["severity"] = severity
    if status:
        conditions.append("status = :status")
        params["status"] = status
    if keyword:
        conditions.append("(title ILIKE :kw OR description ILIKE :kw)")
        params["kw"] = f"%{keyword}%"

    where = " AND ".join(conditions) if conditions else "1=1"
    query = text(
        f"SELECT id, title, severity, status, created_at, agent_id "
        f"FROM alerts WHERE {where} "
        f"ORDER BY created_at DESC LIMIT :lim"
    )
    result = await db.execute(query, params)
    rows = result.mappings().all()

    alerts = [
        {
            "id": str(r["id"]),
            "title": r["title"],
            "severity": r["severity"],
            "status": r["status"],
            "created_at": str(r["created_at"]),
            "agent_id": str(r["agent_id"]) if r.get("agent_id") else None,
        }
        for r in rows
    ]
    return json.dumps({"alerts": alerts, "total": len(alerts)})

async def _tool_get_alert_detail(
    db: AsyncSession,
    tenant_id: str,
    alert_id: str,
) -> str:
    """Get full alert details."""
    query = text(
        "SELECT id, title, severity, status, description, created_at, "
        "rule_id, agent_id, context "
        "FROM alerts WHERE id = :aid"
    )
    result = await db.execute(query, {"aid": alert_id})
    row = result.mappings().first()
    if not row:
        return json.dumps({"error": f"Alert {alert_id} not found"})

    alert = {
        "id": str(row["id"]),
        "title": row["title"],
        "severity": row["severity"],
        "status": row["status"],
        "description": row.get("description", ""),
        "created_at": str(row["created_at"]),
        "rule_id": str(row["rule_id"]) if row.get("rule_id") else None,
        "agent_id": str(row["agent_id"]) if row.get("agent_id") else None,
    }
    return json.dumps({"alert": alert})

async def _tool_search_events(
    db: AsyncSession,
    tenant_id: str,
    event_type: str | None = None,
    agent_id: str | None = None,
    keyword: str | None = None,
    limit: int = 20,
) -> str:
    """Search events (from ClickHouse via postgres proxy or direct)."""
    conditions = []
    params: dict[str, Any] = {"lim": min(limit, 100)}

    if event_type:
        conditions.append("event_type = :etype")
        params["etype"] = event_type
    if agent_id:
        conditions.append("agent_id = :aid")
        params["aid"] = agent_id
    if keyword:
        conditions.append("raw_data::text ILIKE :kw")
        params["kw"] = f"%{keyword}%"

    where = " AND ".join(conditions) if conditions else "1=1"
    query = text(
        f"SELECT id, event_type, agent_id, timestamp, raw_data "
        f"FROM events WHERE {where} "
        f"ORDER BY timestamp DESC LIMIT :lim"
    )
    try:
        result = await db.execute(query, params)
        rows = result.mappings().all()
        events = [
            {
                "id": str(r["id"]),
                "event_type": r["event_type"],
                "agent_id": str(r["agent_id"]) if r.get("agent_id") else None,
                "timestamp": str(r["timestamp"]),
            }
            for r in rows
        ]
        return json.dumps({"events": events, "total": len(events)})
    except Exception:
        return json.dumps({"events": [], "total": 0, "note": "Event store unavailable"})

async def _tool_get_agent_info(
    db: AsyncSession,
    tenant_id: str,
    agent_id: str,
) -> str:
    """Get agent details."""
    query = text(
        "SELECT id, hostname, os, status, trust_score, last_seen, agent_version, "
        "ip_address, ai_app_name, ai_app_version "
        "FROM agents WHERE id::text = :aid OR hostname ILIKE :hname"
    )
    result = await db.execute(query, {"aid": agent_id, "hname": f"%{agent_id}%"})
    row = result.mappings().first()
    if not row:
        return json.dumps({"error": f"Agent '{agent_id}' not found"})

    agent = {
        "id": str(row["id"]),
        "hostname": row["hostname"],
        "os": row.get("os", ""),
        "status": row["status"],
        "trust_score": row.get("trust_score"),
        "last_seen": str(row["last_seen"]) if row.get("last_seen") else None,
        "version": row.get("agent_version"),
        "ip": row.get("ip_address"),
        "ai_app": row.get("ai_app_name"),
    }
    return json.dumps({"agent": agent})

async def _tool_get_trust_score(tenant_id: str, entity_id: str) -> str:
    """Get trust score from the trust engine."""
    try:
        from app.services.trust_client import get_trust_client

        client = get_trust_client()
        score = await client.get_score(entity_id=entity_id, tenant_id=tenant_id)
        return json.dumps(
            {
                "entity_id": entity_id,
                "trust_score": getattr(score, "score", 0.0),
                "risk_level": getattr(score, "risk_level", "unknown"),
                "factors": getattr(score, "factors", {}),
            }
        )
    except Exception as exc:
        return json.dumps({"entity_id": entity_id, "error": f"Trust engine unavailable: {str(exc)[:100]}"})

async def _tool_get_system_stats() -> str:
    """Get system health stats."""
    import time as _time

    from app.routers.nerve_center import _throughput

    uptime = max(1, _time.time() - _throughput["start_time"])
    return json.dumps(
        {
            "events_ingested": _throughput["events_ingested"],
            "events_processed": _throughput["events_processed"],
            "events_per_sec": round(_throughput["events_ingested"] / uptime, 2),
            "uptime_seconds": round(uptime),
        }
    )

# ── Investigation Assistant ───────────────────────────────────────────────────

class InvestigationAssistant:
    """
    NL-driven investigation assistant with tool calling.

    Manages conversation state and executes multi-round tool calls
    to gather data before producing a final answer.
    """

    def __init__(
        self,
        llm: LLMProvider | None = None,
        firewall: CopilotFirewall | None = None,
        memory: CopilotMemory | None = None,
    ) -> None:
        self._llm = llm or LLMProvider(LLMConfig.from_env())
        self._firewall = firewall or CopilotFirewall()
        self._memory = memory or CopilotMemory(llm=self._llm)

    # Truly useless inputs that should return guidance without hitting the LLM
    HELP_PATTERNS = {"help", "?", "test", "ping", "huh", "idk"}

    INVESTIGATE_HELP = (
        "**Phantex Copilot — Investigation Mode**\n\n"
        "Ask me specific questions about your environment and I'll query real data to answer. Examples:\n\n"
        '• "Show me all critical alerts from the last 24 hours"\n'
        '• "What\'s going on with agent `<hostname>`?"\n'
        '• "Explain alert `<alert-id>` — is it a true positive?"\n'
        '• "Find events related to suspicious outbound connections"\n'
        '• "What is the trust score of agent `<id>`?"\n'
        '• "Are there any brute-force patterns in recent alerts?"\n\n'
        "💡 **Tip:** Open an alert detail page first, then ask me — I'll automatically have the alert context."
    )

    async def investigate(
        self,
        user_message: str,
        history: list[dict[str, Any]],
        db: AsyncSession,
        tenant_id: str,
        *,
        context: dict[str, Any] | None = None,
        session_id: str | None = None,
    ) -> tuple[str, UsageStats, list[str]]:
        """
        Process an investigation query.

        Args:
            user_message: The user's natural language question
            history: Previous conversation messages
            db: Tenant-scoped database session
            tenant_id: Caller's tenant ID
            context: Optional page context (current alert, agent, etc.)

        Returns:
            (response_text, usage_stats, tool_calls_made)
        """
        # 0. Reject truly useless inputs — return guidance without calling LLM
        stripped = user_message.strip().rstrip("?!.").strip().lower()
        has_context = bool(context and any(context.get(k) for k in ("alert_id", "agent_id", "rule_id")))
        if stripped in self.HELP_PATTERNS and not has_context:
            return self.INVESTIGATE_HELP, UsageStats(), []

        # 1. Firewall: scan input
        input_verdict = self._firewall.scan_input(user_message)
        if not input_verdict.allowed:
            return (
                input_verdict.blocked_reason or "Message blocked by content firewall.",
                UsageStats(),
                [],
            )

        safe_input = input_verdict.sanitized_input or user_message

        # 1b. Load session history from memory (if session_id provided)
        memory_history: list[dict[str, Any]] = []
        if session_id and self._memory:
            memory_history = await self._memory.get_context_messages(
                tenant_id,
                session_id,
            )

        # 2. Build message chain — merge memory + client history, sanitize
        #    Memory history takes precedence (server-side, already scanned).
        #    Client history is used only as fallback if no session.
        raw_history = memory_history if memory_history else history

        sanitized_history: list[dict[str, Any]] = []
        for msg in raw_history[-MAX_HISTORY:]:
            if msg.get("role") == "system":
                continue  # Strip client-supplied system messages
            content = msg.get("content", "")
            if content and msg.get("role") == "user":
                h_verdict = self._firewall.scan_input(content)
                if not h_verdict.allowed:
                    continue
                content = h_verdict.sanitized_input or content
            sanitized_history.append({**msg, "content": content})

        messages = sanitized_history
        if context:
            safe_ctx = {k: v for k, v in (context or {}).items() if k in ("alert_id", "agent_id", "page", "rule_id")}
            if safe_ctx:
                # Auto-fetch data for context items so the LLM doesn't need tool calls
                enrichment_parts = []
                if "alert_id" in safe_ctx:
                    try:
                        alert_data = await execute_tool(
                            "get_alert_detail",
                            {"alert_id": safe_ctx["alert_id"]},
                            db,
                            tenant_id,
                        )
                        enrichment_parts.append(f"Alert details: {alert_data}")
                    except Exception:
                        pass
                if "agent_id" in safe_ctx:
                    try:
                        agent_data = await execute_tool(
                            "get_agent_info",
                            {"agent_id": safe_ctx["agent_id"]},
                            db,
                            tenant_id,
                        )
                        enrichment_parts.append(f"Agent details: {agent_data}")
                    except Exception:
                        pass
                ctx_text = f"[Current context: {json.dumps(safe_ctx, default=str)[:500]}]"
                if enrichment_parts:
                    ctx_text += "\n" + "\n".join(enrichment_parts)
                messages.append({"role": "system", "content": ctx_text})
        messages.append({"role": "user", "content": safe_input})

        # 3. Multi-round tool calling loop
        tool_calls_log: list[str] = []
        total_usage = UsageStats(model=self._llm._config.model, provider=self._llm._config.provider)

        for round_idx in range(MAX_TOOL_ROUNDS):
            response_text, usage = await self._llm.complete(messages, tools=COPILOT_TOOLS)
            total_usage.prompt_tokens += usage.prompt_tokens
            total_usage.completion_tokens += usage.completion_tokens
            total_usage.total_tokens += usage.total_tokens
            total_usage.latency_ms += usage.latency_ms

            # Check if LLM wants to call tools
            try:
                parsed = json.loads(response_text)
                if isinstance(parsed, dict) and "tool_calls" in parsed:
                    calls = parsed["tool_calls"]
                    content = parsed.get("content", "")

                    # Add assistant message with tool calls
                    messages.append(
                        {
                            "role": "assistant",
                            "content": content or None,
                            "tool_calls": calls,
                        }
                    )

                    # Execute each tool call
                    for tc in calls:
                        func = tc.get("function", {})
                        name = func.get("name", "")
                        args = json.loads(func.get("arguments", "{}"))
                        tool_calls_log.append(f"{name}({json.dumps(args)[:100]})")

                        logger.info("copilot_tool_call: tool=%s round=%d", name, round_idx)
                        result = await execute_tool(name, args, db, tenant_id)

                        messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": tc.get("id", f"call_{round_idx}"),
                                "content": result,
                            }
                        )

                    continue  # Let LLM process tool results
            except (json.JSONDecodeError, TypeError):
                pass

            # No tool calls — this is the final text response
            # 4. Firewall: scan output
            output_verdict = self._firewall.scan_output(response_text)
            final_response = output_verdict.redacted_output or response_text

            total_usage.estimate_cost()

            # 5. Persist to memory
            if session_id and self._memory:
                await self._memory.append_message(
                    tenant_id,
                    session_id,
                    ConversationMessage(role="user", content=safe_input),
                )
                await self._memory.append_message(
                    tenant_id,
                    session_id,
                    ConversationMessage(
                        role="assistant",
                        content=final_response,
                        tool_calls=tool_calls_log or None,
                    ),
                )

            return final_response, total_usage, tool_calls_log

        # Exceeded tool rounds — force a final summary from what we gathered
        logger.warning("copilot_tool_rounds_exceeded: rounds=%d calls=%s", MAX_TOOL_ROUNDS, tool_calls_log)
        messages.append(
            {
                "role": "user",
                "content": (
                    "You've gathered enough data. Provide your analysis now based on what you've collected. "
                    "Summarize your findings concisely — no more tool calls."
                ),
            }
        )
        try:
            summary_text, summary_usage = await self._llm.complete(messages)
            total_usage.prompt_tokens += summary_usage.prompt_tokens
            total_usage.completion_tokens += summary_usage.completion_tokens
            total_usage.total_tokens += summary_usage.total_tokens
            total_usage.latency_ms += summary_usage.latency_ms
            total_usage.estimate_cost()

            output_verdict = self._firewall.scan_output(summary_text)
            final_summary = output_verdict.redacted_output or summary_text

            # Persist to memory
            if session_id and self._memory:
                await self._memory.append_message(
                    tenant_id,
                    session_id,
                    ConversationMessage(role="user", content=safe_input),
                )
                await self._memory.append_message(
                    tenant_id,
                    session_id,
                    ConversationMessage(
                        role="assistant",
                        content=final_summary,
                        tool_calls=tool_calls_log or None,
                    ),
                )

            return final_summary, total_usage, tool_calls_log
        except Exception:
            total_usage.estimate_cost()
            return (
                "I collected data using the following tools but ran out of analysis rounds: "
                + ", ".join(tool_calls_log[:10])
                + ". Please try a more focused question or break it into smaller parts.",
                total_usage,
                tool_calls_log,
            )

    async def stream_investigate(
        self,
        user_message: str,
        history: list[dict[str, Any]],
        *,
        context: dict[str, Any] | None = None,
    ) -> AsyncIterator[str]:
        """
        Streaming investigation (no tool calling — direct stream).
        Used for simple questions that don't need data lookup.

        Buffers output and applies firewall scan before yielding.
        """
        # 1. Firewall: scan input
        input_verdict = self._firewall.scan_input(user_message)
        if not input_verdict.allowed:
            yield input_verdict.blocked_reason or "Message blocked."
            return

        safe_input = input_verdict.sanitized_input or user_message

        # 2. Scan history messages for injection attempts
        sanitized_history: list[dict[str, Any]] = []
        for msg in history[-MAX_HISTORY:]:
            if msg.get("role") == "system":
                continue  # Strip client-supplied system messages
            content = msg.get("content", "")
            if content and msg.get("role") == "user":
                h_verdict = self._firewall.scan_input(content)
                if not h_verdict.allowed:
                    continue  # Drop messages flagged by firewall
                content = h_verdict.sanitized_input or content
            sanitized_history.append({**msg, "content": content})

        messages = sanitized_history
        if context:
            # Allowlist expected context keys
            safe_ctx = {k: v for k, v in (context or {}).items() if k in ("alert_id", "agent_id", "page", "rule_id")}
            if safe_ctx:
                ctx_text = f"[Current context: {json.dumps(safe_ctx, default=str)[:500]}]"
                messages.append({"role": "system", "content": ctx_text})
        messages.append({"role": "user", "content": safe_input})

        # 3. Collect full response, then scan before yielding
        collected = ""
        async for chunk in self._llm.stream(messages):
            collected += chunk

        # 4. Firewall: scan output BEFORE delivering to client
        verdict = self._firewall.scan_output(collected)
        if verdict.findings:
            logger.warning("copilot_stream_output_findings: %s", verdict.findings)

        final_response = verdict.redacted_output or collected
        # Yield the scanned/redacted response as a single chunk
        yield final_response
