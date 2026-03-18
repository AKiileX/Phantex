# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex SDK — LangChain hooks.

Monkey-patches:
- BaseTool.run() / BaseTool.arun()       → capture tool calls
- BaseChatModel.generate() / .agenerate() → capture LLM calls
- Runnable.invoke() / .ainvoke()          → capture chain invocations
"""

from __future__ import annotations

import contextlib
import logging
from typing import Any

from .base import BaseHook

logger = logging.getLogger("phantex.hooks.langchain")

class LangChainHook(BaseHook):
    name = "langchain"
    framework = "langchain"

    def install(self) -> bool:
        """Install LangChain hooks. Returns False if langchain-core not installed."""
        try:
            # langchain-core is the minimum dependency (tools, models, runnables)
            import langchain_core  # noqa: F401
        except ImportError:
            logger.debug("langchain-core not installed — skipping LangChain hooks")
            return False

        patched_any = False

        # ── 1. BaseTool.run() — tool invocations ─────────────────────────
        patched_any |= self._patch_tool_run()

        # ── 2. BaseTool.arun() — async tool invocations ──────────────────
        patched_any |= self._patch_tool_arun()

        # ── 3. BaseChatModel.generate() — LLM calls ─────────────────────
        patched_any |= self._patch_chat_generate()

        # ── 4. BaseChatModel.agenerate() — async LLM calls ──────────────
        patched_any |= self._patch_chat_agenerate()

        # ── 5. Runnable.invoke() — chain invocations ────────────────────
        patched_any |= self._patch_runnable_invoke()

        # ── 6. Runnable.ainvoke() — async chain invocations ─────────────
        patched_any |= self._patch_runnable_ainvoke()

        self._installed = patched_any
        if patched_any:
            logger.info("LangChain hooks installed")
        return patched_any

    # ── Tool Hooks ────────────────────────────────────────────────────────

    def _patch_tool_run(self) -> bool:
        try:
            from langchain_core.tools import BaseTool
        except ImportError:
            return False

        hook = self

        def make_wrapper(original):
            def wrapper(self_tool: Any, tool_input: Any, *args: Any, **kwargs: Any) -> Any:
                tool_name = getattr(self_tool, "name", type(self_tool).__name__)
                span_id, start_ns = hook._emit_tool_call(
                    tool_name=tool_name,
                    tool_input=tool_input,
                    protocol="langchain_tool",
                )
                try:
                    result = original(self_tool, tool_input, *args, **kwargs)
                    hook._emit_tool_response(
                        tool_name=tool_name,
                        span_id=span_id,
                        start_ns=start_ns,
                        success=True,
                        result=result,
                    )
                    return result
                except Exception as e:
                    hook._emit_tool_response(
                        tool_name=tool_name,
                        span_id=span_id,
                        start_ns=start_ns,
                        success=False,
                        error=str(e),
                    )
                    raise

            return wrapper

        return self._patch(BaseTool, "run", make_wrapper)

    def _patch_tool_arun(self) -> bool:
        try:
            from langchain_core.tools import BaseTool
        except ImportError:
            return False

        hook = self

        def make_wrapper(original):
            async def wrapper(self_tool: Any, tool_input: Any, *args: Any, **kwargs: Any) -> Any:
                tool_name = getattr(self_tool, "name", type(self_tool).__name__)
                span_id, start_ns = hook._emit_tool_call(
                    tool_name=tool_name,
                    tool_input=tool_input,
                    protocol="langchain_tool",
                )
                try:
                    result = await original(self_tool, tool_input, *args, **kwargs)
                    hook._emit_tool_response(
                        tool_name=tool_name,
                        span_id=span_id,
                        start_ns=start_ns,
                        success=True,
                        result=result,
                    )
                    return result
                except Exception as e:
                    hook._emit_tool_response(
                        tool_name=tool_name,
                        span_id=span_id,
                        start_ns=start_ns,
                        success=False,
                        error=str(e),
                    )
                    raise

            return wrapper

        return self._patch(BaseTool, "arun", make_wrapper)

    # ── Chat Model Hooks ──────────────────────────────────────────────────

    def _patch_chat_generate(self) -> bool:
        try:
            from langchain_core.language_models.chat_models import BaseChatModel
        except ImportError:
            return False

        hook = self
        config = self._config

        def make_wrapper(original):
            def wrapper(self_model: Any, messages: Any, *args: Any, **kwargs: Any) -> Any:
                model_name = getattr(self_model, "model_name", "") or getattr(
                    self_model, "model", type(self_model).__name__
                )

                # Hash prompt content (never store plaintext)
                prompt_text = ""
                if messages:
                    with contextlib.suppress(Exception):
                        prompt_text = str(messages[-1]) if not config.record_prompts else ""

                span_id, start_ns = hook._emit_tool_call(
                    tool_name=f"llm:{model_name}",
                    protocol="langchain_llm",
                    model_name=model_name,
                    prompt_content=prompt_text,
                )
                try:
                    result = original(self_model, messages, *args, **kwargs)

                    # Extract token usage from LLM result
                    input_tokens = 0
                    output_tokens = 0
                    if hasattr(result, "llm_output") and result.llm_output:
                        usage = result.llm_output.get("token_usage", {})
                        input_tokens = usage.get("prompt_tokens", 0)
                        output_tokens = usage.get("completion_tokens", 0)

                    hook._emit_tool_response(
                        tool_name=f"llm:{model_name}",
                        span_id=span_id,
                        start_ns=start_ns,
                        success=True,
                        result=result,
                        model_name=model_name,
                        input_tokens=input_tokens,
                        output_tokens=output_tokens,
                        protocol="langchain_llm",
                    )
                    return result
                except Exception as e:
                    hook._emit_tool_response(
                        tool_name=f"llm:{model_name}",
                        span_id=span_id,
                        start_ns=start_ns,
                        success=False,
                        error=str(e),
                        model_name=model_name,
                        protocol="langchain_llm",
                    )
                    raise

            return wrapper

        return self._patch(BaseChatModel, "generate", make_wrapper)

    def _patch_chat_agenerate(self) -> bool:
        try:
            from langchain_core.language_models.chat_models import BaseChatModel
        except ImportError:
            return False

        hook = self
        config = self._config

        def make_wrapper(original):
            async def wrapper(self_model: Any, messages: Any, *args: Any, **kwargs: Any) -> Any:
                model_name = getattr(self_model, "model_name", "") or getattr(
                    self_model, "model", type(self_model).__name__
                )

                prompt_text = ""
                if messages:
                    with contextlib.suppress(Exception):
                        prompt_text = str(messages[-1]) if not config.record_prompts else ""

                span_id, start_ns = hook._emit_tool_call(
                    tool_name=f"llm:{model_name}",
                    protocol="langchain_llm",
                    model_name=model_name,
                    prompt_content=prompt_text,
                )
                try:
                    result = await original(self_model, messages, *args, **kwargs)

                    input_tokens = 0
                    output_tokens = 0
                    if hasattr(result, "llm_output") and result.llm_output:
                        usage = result.llm_output.get("token_usage", {})
                        input_tokens = usage.get("prompt_tokens", 0)
                        output_tokens = usage.get("completion_tokens", 0)

                    hook._emit_tool_response(
                        tool_name=f"llm:{model_name}",
                        span_id=span_id,
                        start_ns=start_ns,
                        success=True,
                        result=result,
                        model_name=model_name,
                        input_tokens=input_tokens,
                        output_tokens=output_tokens,
                        protocol="langchain_llm",
                    )
                    return result
                except Exception as e:
                    hook._emit_tool_response(
                        tool_name=f"llm:{model_name}",
                        span_id=span_id,
                        start_ns=start_ns,
                        success=False,
                        error=str(e),
                        model_name=model_name,
                        protocol="langchain_llm",
                    )
                    raise

            return wrapper

        return self._patch(BaseChatModel, "agenerate", make_wrapper)

    # ── Runnable Hooks (Chain invocations) ────────────────────────────────

    def _patch_runnable_invoke(self) -> bool:
        try:
            from langchain_core.runnables import Runnable
        except ImportError:
            return False

        hook = self

        def make_wrapper(original):
            def wrapper(self_runnable: Any, input: Any, *args: Any, **kwargs: Any) -> Any:
                chain_name = getattr(self_runnable, "name", None) or type(self_runnable).__name__
                span_id, start_ns = hook._emit_tool_call(
                    tool_name=f"chain:{chain_name}",
                    tool_input=input,
                    protocol="langchain_chain",
                )
                try:
                    result = original(self_runnable, input, *args, **kwargs)
                    hook._emit_tool_response(
                        tool_name=f"chain:{chain_name}",
                        span_id=span_id,
                        start_ns=start_ns,
                        success=True,
                        result=result,
                        protocol="langchain_chain",
                    )
                    return result
                except Exception as e:
                    hook._emit_tool_response(
                        tool_name=f"chain:{chain_name}",
                        span_id=span_id,
                        start_ns=start_ns,
                        success=False,
                        error=str(e),
                        protocol="langchain_chain",
                    )
                    raise

            return wrapper

        return self._patch(Runnable, "invoke", make_wrapper)

    def _patch_runnable_ainvoke(self) -> bool:
        try:
            from langchain_core.runnables import Runnable
        except ImportError:
            return False

        hook = self

        def make_wrapper(original):
            async def wrapper(self_runnable: Any, input: Any, *args: Any, **kwargs: Any) -> Any:
                chain_name = getattr(self_runnable, "name", None) or type(self_runnable).__name__
                span_id, start_ns = hook._emit_tool_call(
                    tool_name=f"chain:{chain_name}",
                    tool_input=input,
                    protocol="langchain_chain",
                )
                try:
                    result = await original(self_runnable, input, *args, **kwargs)
                    hook._emit_tool_response(
                        tool_name=f"chain:{chain_name}",
                        span_id=span_id,
                        start_ns=start_ns,
                        success=True,
                        result=result,
                        protocol="langchain_chain",
                    )
                    return result
                except Exception as e:
                    hook._emit_tool_response(
                        tool_name=f"chain:{chain_name}",
                        span_id=span_id,
                        start_ns=start_ns,
                        success=False,
                        error=str(e),
                        protocol="langchain_chain",
                    )
                    raise

            return wrapper

        return self._patch(Runnable, "ainvoke", make_wrapper)
