# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex SDK — AutoGen hooks.

Supports AG2 (autogen-agentchat >= 0.4) — the current AutoGen rewrite.
Falls back to legacy pyautogen (< 0.3) if AG2 not found.

Monkey-patches:
- BaseChatAgent.on_messages()   → capture agent responses (AG2)
- BaseChatAgent.run()           → capture agent task execution (AG2)
- RoundRobinGroupChat.run()     → capture team orchestration (AG2)
- ConversableAgent.generate_reply() → capture agent reply (legacy)
"""

from __future__ import annotations

import logging
from typing import Any

from .base import BaseHook

logger = logging.getLogger("phantex.hooks.autogen")

class AutoGenHook(BaseHook):
    name = "autogen"
    framework = "autogen"

    def install(self) -> bool:
        """Install AutoGen hooks. Tries AG2 first, falls back to legacy."""
        patched_any = False

        # ── Try AG2 (autogen-agentchat >= 0.4) ───────────────────────────
        ag2_available = False
        try:
            import autogen_agentchat  # noqa: F401

            ag2_available = True
        except ImportError:
            pass

        if ag2_available:
            patched_any |= self._patch_on_messages()
            patched_any |= self._patch_run()
            patched_any |= self._patch_team_run()
            if patched_any:
                logger.info("AutoGen AG2 hooks installed")
                self._installed = True
                return True

        # ── Fallback: legacy pyautogen (< 0.3) ───────────────────────────
        legacy_available = False
        try:
            from autogen import ConversableAgent  # noqa: F401

            legacy_available = True
        except ImportError:
            pass

        if legacy_available:
            patched_any |= self._patch_generate_reply_legacy()
            if patched_any:
                logger.info("AutoGen legacy hooks installed")
                self._installed = True
                return True

        logger.debug("Neither autogen-agentchat (AG2) nor legacy autogen found — skipping")
        return False

    # ══════════════════════════════════════════════════════════════════════
    # AG2 hooks (autogen-agentchat >= 0.4)
    # ══════════════════════════════════════════════════════════════════════

    @staticmethod
    def _all_subclasses(cls: type) -> list[type]:
        """Recursively find all loaded subclasses of a class."""
        result = []
        for subcls in cls.__subclasses__():
            result.append(subcls)
            result.extend(AutoGenHook._all_subclasses(subcls))
        return result

    def _patch_on_messages(self) -> bool:
        """Patch BaseChatAgent.on_messages() — main agent response path.
        Patches the base class AND all currently loaded subclasses
        (since subclasses like AssistantAgent override on_messages).
        """
        try:
            from autogen_agentchat.agents import BaseChatAgent
        except ImportError:
            return False

        hook = self

        def make_wrapper(original):
            async def wrapper(
                self_agent: Any, messages: Any, cancellation_token: Any = None, **kwargs: Any
            ) -> Any:
                agent_name = getattr(self_agent, "name", None) or type(self_agent).__name__
                msg_count = len(messages) if messages else 0

                # Extract last message content for prompt hashing
                prompt_text = ""
                if messages and msg_count > 0:
                    last = messages[-1]
                    content = getattr(last, "content", None)
                    if content:
                        prompt_text = str(content)

                span_id, start_ns = hook._emit_tool_call(
                    tool_name=f"agent:{agent_name}:on_messages",
                    tool_input={"message_count": msg_count},
                    protocol="autogen_agent",
                    prompt_content=prompt_text,
                )
                try:
                    result = await original(self_agent, messages, cancellation_token, **kwargs)
                    hook._emit_tool_response(
                        tool_name=f"agent:{agent_name}:on_messages",
                        span_id=span_id,
                        start_ns=start_ns,
                        success=True,
                        result=str(result)[:200] if result else "",
                        protocol="autogen_agent",
                    )
                    return result
                except Exception as e:
                    hook._emit_tool_response(
                        tool_name=f"agent:{agent_name}:on_messages",
                        span_id=span_id,
                        start_ns=start_ns,
                        success=False,
                        error=str(e),
                        protocol="autogen_agent",
                    )
                    raise

            return wrapper

        # Patch base class + all loaded subclasses (they override on_messages)
        patched = self._patch(BaseChatAgent, "on_messages", make_wrapper)
        for subcls in self._all_subclasses(BaseChatAgent):
            if "on_messages" in subcls.__dict__:  # Only if subclass defines its own
                patched |= self._patch(subcls, "on_messages", make_wrapper)
        return patched

    def _patch_run(self) -> bool:
        """Patch BaseChatAgent.run() — agent task execution."""
        try:
            from autogen_agentchat.agents import BaseChatAgent
        except ImportError:
            return False

        hook = self

        def make_wrapper(original):
            async def wrapper(self_agent: Any, *, task: Any = None, **kwargs: Any) -> Any:
                agent_name = getattr(self_agent, "name", None) or type(self_agent).__name__

                prompt_text = ""
                if isinstance(task, str):
                    prompt_text = task

                span_id, start_ns = hook._emit_tool_call(
                    tool_name=f"agent:{agent_name}:run",
                    tool_input={"task_type": type(task).__name__ if task else "none"},
                    protocol="autogen_run",
                    prompt_content=prompt_text,
                )
                try:
                    result = await original(self_agent, task=task, **kwargs)
                    hook._emit_tool_response(
                        tool_name=f"agent:{agent_name}:run",
                        span_id=span_id,
                        start_ns=start_ns,
                        success=True,
                        result=str(result)[:200] if result else "",
                        protocol="autogen_run",
                    )
                    return result
                except Exception as e:
                    hook._emit_tool_response(
                        tool_name=f"agent:{agent_name}:run",
                        span_id=span_id,
                        start_ns=start_ns,
                        success=False,
                        error=str(e),
                        protocol="autogen_run",
                    )
                    raise

            return wrapper

        # Patch base class + subclasses that override run()
        patched = self._patch(BaseChatAgent, "run", make_wrapper)
        for subcls in self._all_subclasses(BaseChatAgent):
            if "run" in subcls.__dict__:
                patched |= self._patch(subcls, "run", make_wrapper)
        return patched

    def _patch_team_run(self) -> bool:
        """Patch team run() — RoundRobinGroupChat and SelectorGroupChat."""
        patched = False
        try:
            from autogen_agentchat.teams import RoundRobinGroupChat

            patched |= self._patch_team_class(RoundRobinGroupChat, "round_robin")
        except ImportError:
            pass

        try:
            from autogen_agentchat.teams import SelectorGroupChat

            patched |= self._patch_team_class(SelectorGroupChat, "selector")
        except ImportError:
            pass

        return patched

    def _patch_team_class(self, team_cls: type, team_type: str) -> bool:
        hook = self

        def make_wrapper(original):
            async def wrapper(self_team: Any, *, task: Any = None, **kwargs: Any) -> Any:
                prompt_text = task if isinstance(task, str) else ""

                span_id, start_ns = hook._emit_tool_call(
                    tool_name=f"team:{team_type}:run",
                    tool_input={"task_type": type(task).__name__ if task else "none"},
                    protocol="autogen_team",
                    prompt_content=prompt_text,
                )
                try:
                    result = await original(self_team, task=task, **kwargs)
                    hook._emit_tool_response(
                        tool_name=f"team:{team_type}:run",
                        span_id=span_id,
                        start_ns=start_ns,
                        success=True,
                        result=str(result)[:200] if result else "",
                        protocol="autogen_team",
                    )
                    return result
                except Exception as e:
                    hook._emit_tool_response(
                        tool_name=f"team:{team_type}:run",
                        span_id=span_id,
                        start_ns=start_ns,
                        success=False,
                        error=str(e),
                        protocol="autogen_team",
                    )
                    raise

            return wrapper

        return self._patch(team_cls, "run", make_wrapper)

    # ══════════════════════════════════════════════════════════════════════
    # Legacy pyautogen (< 0.3) hooks
    # ══════════════════════════════════════════════════════════════════════

    def _patch_generate_reply_legacy(self) -> bool:
        try:
            from autogen import ConversableAgent
        except ImportError:
            return False

        hook = self

        def make_wrapper(original):
            def wrapper(self_agent: Any, *args: Any, **kwargs: Any) -> Any:
                agent_name = getattr(self_agent, "name", type(self_agent).__name__)
                messages = kwargs.get("messages") or (args[0] if args else None)

                prompt_text = ""
                if messages and isinstance(messages, list) and len(messages) > 0:
                    last_msg = messages[-1]
                    if isinstance(last_msg, dict):
                        prompt_text = last_msg.get("content", "")
                    else:
                        prompt_text = str(last_msg)

                span_id, start_ns = hook._emit_tool_call(
                    tool_name=f"agent:{agent_name}:generate_reply",
                    tool_input={"message_count": len(messages) if messages else 0},
                    protocol="autogen_agent",
                    prompt_content=prompt_text,
                )
                try:
                    result = original(self_agent, *args, **kwargs)
                    hook._emit_tool_response(
                        tool_name=f"agent:{agent_name}:generate_reply",
                        span_id=span_id,
                        start_ns=start_ns,
                        success=True,
                        result=result,
                        protocol="autogen_agent",
                    )
                    return result
                except Exception as e:
                    hook._emit_tool_response(
                        tool_name=f"agent:{agent_name}:generate_reply",
                        span_id=span_id,
                        start_ns=start_ns,
                        success=False,
                        error=str(e),
                        protocol="autogen_agent",
                    )
                    raise

            return wrapper

        return self._patch(ConversableAgent, "generate_reply", make_wrapper)
