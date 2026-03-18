# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex SDK hook base class.

All framework hooks inherit from this. Provides:
- Safe monkey-patching with original function preservation
- Event emission via the transport
- Timing measurement
- Error isolation (hook failure never breaks user code)
"""

from __future__ import annotations

import contextlib
import functools
import logging
import time
from collections.abc import Callable
from typing import Any

from ..config import PhantexConfig
from ..context import SpanContext, new_span_id, set_span_id
from ..events import (
    Severity,
    ToolCallEvent,
    ToolResponseEvent,
    _hash_prompt,
    _safe_serialize,
)
from ..transport import Transport

logger = logging.getLogger("phantex.hooks")

class BaseHook:
    """
    Base class for all framework hooks.

    Subclasses implement `install()` which monkey-patches target methods.
    """

    name: str = "base"
    framework: str = "unknown"

    def __init__(self, transport: Transport, config: PhantexConfig) -> None:
        self._transport = transport
        self._config = config
        self._patches: list[tuple[Any, str, Any]] = []  # (obj, attr_name, original_fn)
        self._installed = False

    @property
    def installed(self) -> bool:
        return self._installed

    def install(self) -> bool:
        """
        Install hooks. Returns True if successful, False if framework not available.
        Subclasses override this.
        """
        raise NotImplementedError

    def uninstall(self) -> None:
        """Restore all patched methods to their originals."""
        for obj, attr_name, original_fn in reversed(self._patches):
            try:
                setattr(obj, attr_name, original_fn)
            except Exception as e:
                logger.debug("Failed to restore %s.%s: %s", obj, attr_name, e)
        self._patches.clear()
        self._installed = False

    def _patch(self, obj: Any, method_name: str, wrapper_factory: Callable) -> bool:
        """
        Safely monkey-patch a method on an object/class.

        Args:
            obj: The class or module to patch
            method_name: Name of the method to patch
            wrapper_factory: Callable(original_fn) → wrapped_fn

        Returns True if patched, False if method doesn't exist.
        """
        original = getattr(obj, method_name, None)
        if original is None:
            logger.debug("Method %s.%s not found — skipping", obj, method_name)
            return False

        # Don't double-patch
        if getattr(original, "_phantex_patched", False):
            logger.debug("Method %s.%s already patched — skipping", obj, method_name)
            return True

        wrapped = wrapper_factory(original)
        wrapped._phantex_patched = True
        wrapped._phantex_original = original
        functools.update_wrapper(wrapped, original)

        self._patches.append((obj, method_name, original))
        setattr(obj, method_name, wrapped)
        logger.debug(
            "Patched %s.%s",
            type(obj).__name__ if not isinstance(obj, type) else obj.__name__,
            method_name,
        )
        return True

    def _emit_tool_call(
        self,
        tool_name: str,
        tool_input: Any = None,
        protocol: str = "",
        model_name: str = "",
        prompt_content: str = "",
    ) -> tuple[str, int]:
        """
        Emit a TOOL_CALL event. Returns (span_id, start_time_ns) for pairing with response.
        """
        span_id = new_span_id()
        set_span_id(span_id)
        ctx = SpanContext.current()
        start_ns = time.perf_counter_ns()

        event = ToolCallEvent(
            tenant_id=self._config.tenant_id,
            agent_paid=ctx.agent_paid,
            pid=ctx.pid,
            tool_name=tool_name,
            tool_input=_safe_serialize(tool_input) if tool_input is not None else "",
            protocol=protocol or f"{self.framework}_tool",
            framework=self.framework,
            model_name=model_name,
            prompt_hash=_hash_prompt(prompt_content) if prompt_content else "",
            trace_id=ctx.trace_id,
            span_id=span_id,
            parent_span_id=ctx.parent_span_id,
        )

        try:
            self._transport.send(event)
        except Exception as e:
            logger.debug("Failed to send tool_call event: %s", e)

        return span_id, start_ns

    def _emit_tool_response(
        self,
        tool_name: str,
        span_id: str,
        start_ns: int,
        success: bool = True,
        result: Any = None,
        error: str = "",
        model_name: str = "",
        input_tokens: int = 0,
        output_tokens: int = 0,
        protocol: str = "",
    ) -> None:
        """Emit a TOOL_RESPONSE event paired with a previous TOOL_CALL."""
        duration_ns = time.perf_counter_ns() - start_ns
        ctx = SpanContext.current()

        output_size = 0
        if result is not None:
            with contextlib.suppress(Exception):
                output_size = len(str(result).encode("utf-8", errors="replace"))

        event = ToolResponseEvent(
            tenant_id=self._config.tenant_id,
            agent_paid=ctx.agent_paid,
            pid=ctx.pid,
            tool_name=tool_name,
            protocol=protocol or f"{self.framework}_tool",
            framework=self.framework,
            success=success,
            duration_ns=duration_ns,
            output_size=output_size,
            error_message=error[:500] if error else "",
            model_name=model_name,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            trace_id=ctx.trace_id,
            span_id=span_id,
            parent_span_id=ctx.parent_span_id,
            severity=Severity.INFO if success else Severity.MEDIUM,
        )

        try:
            self._transport.send(event)
        except Exception as e:
            logger.debug("Failed to send tool_response event: %s", e)
