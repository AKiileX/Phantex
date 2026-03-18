# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex Copilot — Multi-Turn Memory (AB3).

Manages conversation context across multiple turns within a session:
  - Redis-backed session persistence (tenant-scoped keys)
  - Sliding window over message history (max messages + token budget)
  - Context summarisation when window is exceeded
  - Session lifecycle: create → append → summarise → expire

Key design decisions:
  - Keys: ``copilot:session:{tenant_id}:{session_id}`` — isolated per tenant
  - TTL: 4 hours (configurable) — sessions auto-expire
  - Summarisation: When message count exceeds threshold, older messages are
    compressed into a summary message via LLM (or simple truncation if LLM
    is unavailable)
  - In-memory fallback: If Redis is unavailable, sessions live in-process dict

Security:
  - Tenant isolation enforced at key level
  - No cross-tenant session access
  - Session data is ephemeral (TTL enforced)
  - All stored messages have been firewall-scanned at ingress
"""

from __future__ import annotations

import contextlib
import json
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger("phantex.copilot.memory")

# ── Configuration ─────────────────────────────────────────────────────────────

MAX_MESSAGES = 40  # Max messages kept before summarisation trigger
SUMMARY_TRIGGER = 30  # Summarise when history exceeds this count
KEEP_RECENT = 10  # Keep this many recent messages verbatim after summarisation
SESSION_TTL_SECONDS = 4 * 3600  # 4 hours
MAX_SESSIONS_PER_TENANT = 50  # Safety cap — prevent memory exhaustion

# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class ConversationMessage:
    role: str  # "user" | "assistant" | "system" | "tool"
    content: str
    timestamp: float = 0.0
    tool_calls: list[str] | None = None
    metadata: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"role": self.role, "content": self.content, "ts": self.timestamp}
        if self.tool_calls:
            d["tool_calls"] = self.tool_calls
        if self.metadata:
            d["meta"] = self.metadata
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ConversationMessage:
        return cls(
            role=d.get("role", "user"),
            content=d.get("content", ""),
            timestamp=d.get("ts", 0.0),
            tool_calls=d.get("tool_calls"),
            metadata=d.get("meta"),
        )

@dataclass
class Session:
    session_id: str
    tenant_id: str
    user_id: str
    title: str = "Investigation"
    messages: list[ConversationMessage] = field(default_factory=list)
    summary: str | None = None  # Compressed summary of older messages
    created_at: float = 0.0
    updated_at: float = 0.0

    def to_json(self) -> str:
        return json.dumps(
            {
                "sid": self.session_id,
                "tid": self.tenant_id,
                "uid": self.user_id,
                "title": self.title,
                "msgs": [m.to_dict() for m in self.messages],
                "summary": self.summary,
                "created": self.created_at,
                "updated": self.updated_at,
            }
        )

    @classmethod
    def from_json(cls, raw: str) -> Session:
        d = json.loads(raw)
        return cls(
            session_id=d["sid"],
            tenant_id=d["tid"],
            user_id=d["uid"],
            title=d.get("title", "Investigation"),
            messages=[ConversationMessage.from_dict(m) for m in d.get("msgs", [])],
            summary=d.get("summary"),
            created_at=d.get("created", 0.0),
            updated_at=d.get("updated", 0.0),
        )

# ── Memory Manager ────────────────────────────────────────────────────────────

class CopilotMemory:
    """
    Manage multi-turn conversation sessions.

    Uses Redis when available, falls back to in-memory dict.
    LLM is optional — used only for context summarisation.
    """

    def __init__(
        self,
        llm: Any | None = None,
    ) -> None:
        self._llm = llm  # LLMProvider (optional, for summarisation)
        self._redis: Any | None = None
        self._local: dict[str, Session] = {}  # In-memory fallback

    async def _get_redis(self) -> Any | None:
        """Lazy Redis acquisition."""
        if self._redis is not None:
            return self._redis
        try:
            from app.services.redis_client import get_redis

            self._redis = await get_redis()
        except Exception:
            pass
        return self._redis

    def _key(self, tenant_id: str, session_id: str) -> str:
        """Tenant-scoped Redis key."""
        return f"copilot:session:{tenant_id}:{session_id}"

    # ── Session CRUD ──────────────────────────────────────────────────────

    async def create_session(
        self,
        tenant_id: str,
        user_id: str,
        session_id: str,
        title: str = "Investigation",
    ) -> Session:
        """Create a new conversation session."""
        now = time.time()
        session = Session(
            session_id=session_id,
            tenant_id=tenant_id,
            user_id=user_id,
            title=title,
            created_at=now,
            updated_at=now,
        )
        await self._save(session)
        logger.info("session_created", tenant_id=tenant_id, session_id=session_id)
        return session

    async def get_session(
        self,
        tenant_id: str,
        session_id: str,
    ) -> Session | None:
        """Retrieve a session. Returns None if not found or expired."""
        redis = await self._get_redis()
        key = self._key(tenant_id, session_id)

        if redis is not None:
            try:
                raw = await redis.get(key)
                if raw is None:
                    return None
                return Session.from_json(raw if isinstance(raw, str) else raw.decode())
            except Exception as exc:
                logger.warning("session_get_redis_error", error=str(exc))

        # Fallback to local (with TTL enforcement)
        session = self._local.get(key)
        if session is not None and time.time() - session.updated_at > SESSION_TTL_SECONDS:
            self._local.pop(key, None)
            return None
        return session

    async def append_message(
        self,
        tenant_id: str,
        session_id: str,
        message: ConversationMessage,
    ) -> Session | None:
        """
        Append a message to an existing session.

        Triggers summarisation if message count exceeds threshold.
        """
        session = await self.get_session(tenant_id, session_id)
        if session is None:
            return None

        message.timestamp = message.timestamp or time.time()
        session.messages.append(message)
        session.updated_at = time.time()

        # Summarise if over threshold
        if len(session.messages) > SUMMARY_TRIGGER:
            session = await self._summarise(session)

        await self._save(session)
        return session

    async def get_context_messages(
        self,
        tenant_id: str,
        session_id: str,
    ) -> list[dict[str, Any]]:
        """
        Get the message list suitable for sending to the LLM.

        Returns summary (as system message) + recent messages.
        """
        session = await self.get_session(tenant_id, session_id)
        if session is None:
            return []

        messages: list[dict[str, Any]] = []

        # Inject summary as system context
        if session.summary:
            messages.append(
                {
                    "role": "system",
                    "content": f"[Previous conversation summary]\n{session.summary}",
                }
            )

        # Add recent messages
        for msg in session.messages[-MAX_MESSAGES:]:
            entry: dict[str, Any] = {"role": msg.role, "content": msg.content}
            if msg.tool_calls:
                entry["tool_calls"] = msg.tool_calls
            messages.append(entry)

        return messages

    async def delete_session(
        self,
        tenant_id: str,
        session_id: str,
    ) -> bool:
        """Delete a session."""
        key = self._key(tenant_id, session_id)
        redis = await self._get_redis()
        deleted = False

        if redis is not None:
            with contextlib.suppress(Exception):
                deleted = bool(await redis.delete(key))

        if key in self._local:
            del self._local[key]
            deleted = True

        if deleted:
            logger.info("session_deleted", tenant_id=tenant_id, session_id=session_id)
        return deleted

    async def list_sessions(
        self,
        tenant_id: str,
    ) -> list[dict[str, Any]]:
        """List active sessions for a tenant (metadata only, not full messages)."""
        prefix = f"copilot:session:{tenant_id}:"
        sessions: list[dict[str, Any]] = []

        redis = await self._get_redis()
        if redis is not None:
            try:
                keys = []
                async for key in redis.scan_iter(match=f"{prefix}*", count=100):
                    keys.append(key)
                    if len(keys) >= MAX_SESSIONS_PER_TENANT:
                        break
                for key in keys:
                    try:
                        raw = await redis.get(key)
                        if raw:
                            s = Session.from_json(raw if isinstance(raw, str) else raw.decode())
                            sessions.append(
                                {
                                    "session_id": s.session_id,
                                    "title": s.title,
                                    "message_count": len(s.messages),
                                    "has_summary": s.summary is not None,
                                    "created_at": s.created_at,
                                    "updated_at": s.updated_at,
                                }
                            )
                    except Exception:
                        continue
                return sessions
            except Exception as exc:
                logger.warning("session_list_redis_error", error=str(exc))

        # Fallback to local
        now = time.time()
        for key, s in list(self._local.items()):
            if not key.startswith(prefix):
                continue
            # Enforce TTL on in-memory fallback
            if now - s.updated_at > SESSION_TTL_SECONDS:
                self._local.pop(key, None)
                continue
            sessions.append(
                {
                    "session_id": s.session_id,
                    "title": s.title,
                    "message_count": len(s.messages),
                    "has_summary": s.summary is not None,
                    "created_at": s.created_at,
                    "updated_at": s.updated_at,
                }
            )
        return sessions

    # ── Internal ──────────────────────────────────────────────────────────

    async def _save(self, session: Session) -> None:
        """Persist session to Redis (with TTL) and local dict."""
        key = self._key(session.tenant_id, session.session_id)
        data = session.to_json()

        redis = await self._get_redis()
        if redis is not None:
            try:
                await redis.set(key, data, ex=SESSION_TTL_SECONDS)
            except Exception as exc:
                logger.warning("session_save_redis_error", error=str(exc))

        # Always keep local copy as fallback
        self._local[key] = session

        # Enforce local memory cap + TTL
        now = time.time()
        if len(self._local) > MAX_SESSIONS_PER_TENANT * 10:
            for k, s in list(self._local.items()):
                if now - s.updated_at > SESSION_TTL_SECONDS:
                    self._local.pop(k, None)
        if len(self._local) > MAX_SESSIONS_PER_TENANT * 10:
            oldest = sorted(self._local.values(), key=lambda s: s.updated_at)
            for s in oldest[: len(self._local) - MAX_SESSIONS_PER_TENANT]:
                self._local.pop(self._key(s.tenant_id, s.session_id), None)

    async def _summarise(self, session: Session) -> Session:
        """
        Compress older messages into a summary.

        Uses LLM if available, otherwise simple truncation.
        """
        if len(session.messages) <= KEEP_RECENT:
            return session

        old_messages = session.messages[:-KEEP_RECENT]
        recent_messages = session.messages[-KEEP_RECENT:]

        # Build text from old messages for summarisation
        old_text_parts: list[str] = []
        if session.summary:
            old_text_parts.append(f"Previous summary: {session.summary}")
        for m in old_messages:
            old_text_parts.append(f"{m.role}: {m.content[:500]}")
        old_text = "\n".join(old_text_parts)

        if self._llm is not None:
            try:
                summary_messages = [
                    {
                        "role": "system",
                        "content": (
                            "Summarise the following conversation history in 3-5 sentences. "
                            "Focus on: what the user investigated, key findings, and actions taken. "
                            "Preserve alert IDs, agent names, and important data points. Be concise."
                        ),
                    },
                    {"role": "user", "content": old_text[:8000]},
                ]
                summary_text, _ = await self._llm.complete(summary_messages)
                session.summary = summary_text[:2000]
                logger.info(
                    "session_summarised",
                    session_id=session.session_id,
                    mode="llm",
                    old_msg_count=len(old_messages),
                )
            except Exception as exc:
                logger.warning("session_summarise_llm_error", error=str(exc))
                # Fall through to simple truncation
                session.summary = old_text[:2000]
        else:
            # Simple truncation — keep the text of old messages
            session.summary = old_text[:2000]
            logger.info(
                "session_summarised",
                session_id=session.session_id,
                mode="truncation",
                old_msg_count=len(old_messages),
            )

        session.messages = recent_messages
        return session
