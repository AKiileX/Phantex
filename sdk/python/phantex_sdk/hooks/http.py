# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex SDK — HTTP client hooks.

Monkey-patches:
- requests.Session.send()   → capture all HTTP via requests library
- httpx.Client.send()       → capture all HTTP via httpx (sync)
- httpx.AsyncClient.send()  → capture all HTTP via httpx (async)

Detects LLM API calls by matching URLs against known LLM provider endpoints.
"""

from __future__ import annotations

import contextlib
import json
import logging
import re
from typing import Any

from .base import BaseHook

logger = logging.getLogger("phantex.hooks.http")

# ── LLM Provider Detection ───────────────────────────────────────────────────

# URL patterns that indicate LLM API calls
_LLM_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"api\.openai\.com"), "openai"),
    (re.compile(r"api\.anthropic\.com"), "anthropic"),
    (re.compile(r"generativelanguage\.googleapis\.com"), "google"),
    (re.compile(r"api\.cohere\.ai|api\.cohere\.com"), "cohere"),
    (re.compile(r"api-inference\.huggingface\.co"), "huggingface"),
    (re.compile(r"api\.mistral\.ai"), "mistral"),
    (re.compile(r"api\.together\.xyz|api\.together\.ai"), "together"),
    (re.compile(r"api\.fireworks\.ai"), "fireworks"),
    (re.compile(r"api\.groq\.com"), "groq"),
    (re.compile(r"api\.perplexity\.ai"), "perplexity"),
    (re.compile(r"api\.replicate\.com"), "replicate"),
    (re.compile(r"api\.deepseek\.com"), "deepseek"),
    (re.compile(r"openrouter\.ai"), "openrouter"),
    # Azure OpenAI uses custom subdomains
    (re.compile(r"\.openai\.azure\.com"), "azure_openai"),
    # AWS Bedrock
    (re.compile(r"bedrock-runtime\..*\.amazonaws\.com"), "aws_bedrock"),
]

def _detect_llm_provider(url: str) -> str | None:
    """Return LLM provider name if URL matches a known LLM API endpoint."""
    for pattern, provider in _LLM_PATTERNS:
        if pattern.search(url):
            return provider
    return None

def _extract_model_from_url(url: str) -> str:
    """Try to extract model name from URL path (e.g., /v1/chat/completions → "")."""
    # Model is usually in the request body, not URL. Return empty.
    return ""

def _extract_model_from_body(body: Any) -> str:
    """Extract model name from request body if it's JSON with a 'model' field."""
    if body is None:
        return ""
    try:
        if isinstance(body, str | bytes):
            data = json.loads(body)
        elif isinstance(body, dict):
            data = body
        else:
            return ""
        return str(data.get("model", ""))
    except Exception:
        return ""

def _extract_tokens_from_response(response_body: Any) -> tuple[int, int]:
    """Extract input/output token counts from LLM API response body."""
    try:
        if isinstance(response_body, str | bytes):
            data = json.loads(response_body)
        elif isinstance(response_body, dict):
            data = response_body
        else:
            return 0, 0

        usage = data.get("usage", {})
        input_tokens = usage.get("prompt_tokens", 0) or usage.get("input_tokens", 0)
        output_tokens = usage.get("completion_tokens", 0) or usage.get("output_tokens", 0)
        return int(input_tokens), int(output_tokens)
    except Exception:
        return 0, 0

# ── HTTP Hook ─────────────────────────────────────────────────────────────────

class HTTPHook(BaseHook):
    name = "http"
    framework = "http"

    def install(self) -> bool:
        """Install HTTP client hooks."""
        patched_any = False

        # ── 1. requests.Session.send() ────────────────────────────────────
        patched_any |= self._patch_requests()

        # ── 2. httpx.Client.send() ────────────────────────────────────────
        patched_any |= self._patch_httpx_sync()

        # ── 3. httpx.AsyncClient.send() ──────────────────────────────────
        patched_any |= self._patch_httpx_async()

        self._installed = patched_any
        if patched_any:
            logger.info("HTTP hooks installed")
        return patched_any

    # ── requests ──────────────────────────────────────────────────────────

    def _patch_requests(self) -> bool:
        try:
            import requests
        except ImportError:
            logger.debug("requests not installed — skipping requests hooks")
            return False

        hook = self
        config = self._config

        def make_wrapper(original):
            def wrapper(self_session: Any, request: Any, **kwargs: Any) -> Any:
                url = str(getattr(request, "url", ""))
                method = str(getattr(request, "method", "GET")).upper()
                provider = _detect_llm_provider(url)

                # If not an LLM call, pass through without instrumentation
                if provider is None:
                    return original(self_session, request, **kwargs)

                model = _extract_model_from_body(getattr(request, "body", None))
                tool_name = f"http:{provider}:{method}"

                # Hash the request body as "prompt" for LLM calls
                body_bytes = getattr(request, "body", None)
                prompt_text = ""
                if body_bytes and not config.record_prompts:
                    with contextlib.suppress(Exception):
                        prompt_text = (
                            body_bytes.decode("utf-8")
                            if isinstance(body_bytes, bytes)
                            else str(body_bytes)
                        )

                span_id, start_ns = hook._emit_tool_call(
                    tool_name=tool_name,
                    tool_input={"url": url, "method": method},
                    protocol="http",
                    model_name=model,
                    prompt_content=prompt_text,
                )
                try:
                    response = original(self_session, request, **kwargs)

                    # Extract token usage from response
                    input_tokens, output_tokens = 0, 0
                    if hasattr(response, "text") and response.text:
                        input_tokens, output_tokens = _extract_tokens_from_response(response.text)

                    hook._emit_tool_response(
                        tool_name=tool_name,
                        span_id=span_id,
                        start_ns=start_ns,
                        success=response.ok if hasattr(response, "ok") else True,
                        result=None,  # Don't capture response body
                        model_name=model,
                        input_tokens=input_tokens,
                        output_tokens=output_tokens,
                        protocol="http",
                    )
                    return response
                except Exception as e:
                    hook._emit_tool_response(
                        tool_name=tool_name,
                        span_id=span_id,
                        start_ns=start_ns,
                        success=False,
                        error=str(e),
                        model_name=model,
                        protocol="http",
                    )
                    raise

            return wrapper

        return self._patch(requests.Session, "send", make_wrapper)

    # ── httpx sync ────────────────────────────────────────────────────────

    def _patch_httpx_sync(self) -> bool:
        try:
            import httpx
        except ImportError:
            logger.debug("httpx not installed — skipping httpx sync hooks")
            return False

        hook = self
        config = self._config

        def make_wrapper(original):
            def wrapper(self_client: Any, request: Any, **kwargs: Any) -> Any:
                url = str(getattr(request, "url", ""))
                method = str(getattr(request, "method", "GET")).upper()
                provider = _detect_llm_provider(url)

                if provider is None:
                    return original(self_client, request, **kwargs)

                body_content = getattr(request, "content", None)
                model = _extract_model_from_body(body_content)
                tool_name = f"http:{provider}:{method}"

                prompt_text = ""
                if body_content and not config.record_prompts:
                    with contextlib.suppress(Exception):
                        prompt_text = (
                            body_content.decode("utf-8")
                            if isinstance(body_content, bytes)
                            else str(body_content)
                        )

                span_id, start_ns = hook._emit_tool_call(
                    tool_name=tool_name,
                    tool_input={"url": url, "method": method},
                    protocol="http",
                    model_name=model,
                    prompt_content=prompt_text,
                )
                try:
                    response = original(self_client, request, **kwargs)

                    input_tokens, output_tokens = 0, 0
                    with contextlib.suppress(Exception):
                        input_tokens, output_tokens = _extract_tokens_from_response(response.text)

                    hook._emit_tool_response(
                        tool_name=tool_name,
                        span_id=span_id,
                        start_ns=start_ns,
                        success=response.is_success if hasattr(response, "is_success") else True,
                        model_name=model,
                        input_tokens=input_tokens,
                        output_tokens=output_tokens,
                        protocol="http",
                    )
                    return response
                except Exception as e:
                    hook._emit_tool_response(
                        tool_name=tool_name,
                        span_id=span_id,
                        start_ns=start_ns,
                        success=False,
                        error=str(e),
                        model_name=model,
                        protocol="http",
                    )
                    raise

            return wrapper

        return self._patch(httpx.Client, "send", make_wrapper)

    # ── httpx async ───────────────────────────────────────────────────────

    def _patch_httpx_async(self) -> bool:
        try:
            import httpx
        except ImportError:
            return False

        hook = self
        config = self._config

        def make_wrapper(original):
            async def wrapper(self_client: Any, request: Any, **kwargs: Any) -> Any:
                url = str(getattr(request, "url", ""))
                method = str(getattr(request, "method", "GET")).upper()
                provider = _detect_llm_provider(url)

                if provider is None:
                    return await original(self_client, request, **kwargs)

                body_content = getattr(request, "content", None)
                model = _extract_model_from_body(body_content)
                tool_name = f"http:{provider}:{method}"

                prompt_text = ""
                if body_content and not config.record_prompts:
                    with contextlib.suppress(Exception):
                        prompt_text = (
                            body_content.decode("utf-8")
                            if isinstance(body_content, bytes)
                            else str(body_content)
                        )

                span_id, start_ns = hook._emit_tool_call(
                    tool_name=tool_name,
                    tool_input={"url": url, "method": method},
                    protocol="http",
                    model_name=model,
                    prompt_content=prompt_text,
                )
                try:
                    response = await original(self_client, request, **kwargs)

                    input_tokens, output_tokens = 0, 0
                    with contextlib.suppress(Exception):
                        input_tokens, output_tokens = _extract_tokens_from_response(response.text)

                    hook._emit_tool_response(
                        tool_name=tool_name,
                        span_id=span_id,
                        start_ns=start_ns,
                        success=response.is_success if hasattr(response, "is_success") else True,
                        model_name=model,
                        input_tokens=input_tokens,
                        output_tokens=output_tokens,
                        protocol="http",
                    )
                    return response
                except Exception as e:
                    hook._emit_tool_response(
                        tool_name=tool_name,
                        span_id=span_id,
                        start_ns=start_ns,
                        success=False,
                        error=str(e),
                        model_name=model,
                        protocol="http",
                    )
                    raise

            return wrapper

        return self._patch(httpx.AsyncClient, "send", make_wrapper)
