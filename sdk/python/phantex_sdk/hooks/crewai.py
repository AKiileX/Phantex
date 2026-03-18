# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex SDK — CrewAI hooks.

Monkey-patches:
- Crew.kickoff()            → capture crew execution
- Task.execute()            → capture individual task execution (via _execute_core)
- Agent.execute_task()      → capture agent task execution
"""

from __future__ import annotations

import logging
from typing import Any

from .base import BaseHook

logger = logging.getLogger("phantex.hooks.crewai")

class CrewAIHook(BaseHook):
    name = "crewai"
    framework = "crewai"

    def install(self) -> bool:
        """Install CrewAI hooks. Returns False if crewai not installed."""
        try:
            import crewai  # noqa: F401
        except ImportError:
            logger.debug("crewai not installed — skipping CrewAI hooks")
            return False

        patched_any = False

        # ── 1. Crew.kickoff() ─────────────────────────────────────────────
        patched_any |= self._patch_crew_kickoff()

        # ── 2. Task._execute_core() or Task.execute() ────────────────────
        patched_any |= self._patch_task_execute()

        # ── 3. Agent.execute_task() ───────────────────────────────────────
        patched_any |= self._patch_agent_execute_task()

        self._installed = patched_any
        if patched_any:
            logger.info("CrewAI hooks installed")
        return patched_any

    # ── Crew.kickoff() ────────────────────────────────────────────────────

    def _patch_crew_kickoff(self) -> bool:
        try:
            from crewai import Crew
        except ImportError:
            return False

        hook = self

        def make_wrapper(original):
            def wrapper(self_crew: Any, *args: Any, **kwargs: Any) -> Any:
                crew_name = getattr(self_crew, "name", None) or type(self_crew).__name__
                task_count = len(getattr(self_crew, "tasks", []))
                agent_count = len(getattr(self_crew, "agents", []))

                span_id, start_ns = hook._emit_tool_call(
                    tool_name=f"crew:{crew_name}:kickoff",
                    tool_input={"tasks": task_count, "agents": agent_count},
                    protocol="crewai_crew",
                )
                try:
                    result = original(self_crew, *args, **kwargs)
                    hook._emit_tool_response(
                        tool_name=f"crew:{crew_name}:kickoff",
                        span_id=span_id,
                        start_ns=start_ns,
                        success=True,
                        result=result,
                        protocol="crewai_crew",
                    )
                    return result
                except Exception as e:
                    hook._emit_tool_response(
                        tool_name=f"crew:{crew_name}:kickoff",
                        span_id=span_id,
                        start_ns=start_ns,
                        success=False,
                        error=str(e),
                        protocol="crewai_crew",
                    )
                    raise

            return wrapper

        return self._patch(Crew, "kickoff", make_wrapper)

    # ── Task.execute() ────────────────────────────────────────────────────

    def _patch_task_execute(self) -> bool:
        try:
            from crewai import Task
        except ImportError:
            return False

        # CrewAI has changed internal method names across versions.
        # Try _execute_core first (newer), fall back to execute_sync.
        target_method = "execute_sync"
        if hasattr(Task, "_execute_core"):
            target_method = "_execute_core"

        hook = self

        def make_wrapper(original):
            def wrapper(self_task: Any, *args: Any, **kwargs: Any) -> Any:
                task_desc = getattr(self_task, "description", "") or ""
                task_name = task_desc[:80] if task_desc else type(self_task).__name__

                span_id, start_ns = hook._emit_tool_call(
                    tool_name=f"task:{task_name}",
                    protocol="crewai_task",
                )
                try:
                    result = original(self_task, *args, **kwargs)
                    hook._emit_tool_response(
                        tool_name=f"task:{task_name}",
                        span_id=span_id,
                        start_ns=start_ns,
                        success=True,
                        result=result,
                        protocol="crewai_task",
                    )
                    return result
                except Exception as e:
                    hook._emit_tool_response(
                        tool_name=f"task:{task_name}",
                        span_id=span_id,
                        start_ns=start_ns,
                        success=False,
                        error=str(e),
                        protocol="crewai_task",
                    )
                    raise

            return wrapper

        return self._patch(Task, target_method, make_wrapper)

    # ── Agent.execute_task() ──────────────────────────────────────────────

    def _patch_agent_execute_task(self) -> bool:
        try:
            from crewai import Agent
        except ImportError:
            return False

        hook = self

        def make_wrapper(original):
            def wrapper(self_agent: Any, task: Any, *args: Any, **kwargs: Any) -> Any:
                agent_role = getattr(self_agent, "role", "") or type(self_agent).__name__
                task_desc = getattr(task, "description", "")[:60] if task else ""

                span_id, start_ns = hook._emit_tool_call(
                    tool_name=f"agent:{agent_role}:execute_task",
                    tool_input={"task": task_desc},
                    protocol="crewai_agent",
                )
                try:
                    result = original(self_agent, task, *args, **kwargs)
                    hook._emit_tool_response(
                        tool_name=f"agent:{agent_role}:execute_task",
                        span_id=span_id,
                        start_ns=start_ns,
                        success=True,
                        result=result,
                        protocol="crewai_agent",
                    )
                    return result
                except Exception as e:
                    hook._emit_tool_response(
                        tool_name=f"agent:{agent_role}:execute_task",
                        span_id=span_id,
                        start_ns=start_ns,
                        success=False,
                        error=str(e),
                        protocol="crewai_agent",
                    )
                    raise

            return wrapper

        return self._patch(Agent, "execute_task", make_wrapper)
