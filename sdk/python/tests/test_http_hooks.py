# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for HTTP hooks.

Validates:
- AC3: LLM API calls captured: model name, token count, prompt hash
- Non-LLM HTTP calls pass through without instrumentation
"""

from __future__ import annotations

import os

os.environ["PHANTEX_NO_AUTO_INIT"] = "1"
os.environ["PHANTEX_ENABLED"] = "1"

import contextlib

import pytest

from phantex_sdk import PhantexClient, PhantexConfig
from phantex_sdk.transport import BufferTransport

@pytest.fixture
def client():
    """Create a test client with buffer transport and HTTP hooks."""
    transport = BufferTransport()
    config = PhantexConfig(
        transport="buffer",
        hooks="http",
        tenant_id="test-tenant-001",
        agent_id="test-agent-001",
        enabled=True,
    )
    client = PhantexClient(config=config, transport=transport)
    client.start()
    yield client
    client.stop()

# ── Skip if requests not installed ────────────────────────────────────────────

try:
    import requests  # noqa: F401

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import httpx  # noqa: F401

    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

skip_no_requests = pytest.mark.skipif(not HAS_REQUESTS, reason="requests not installed")
skip_no_httpx = pytest.mark.skipif(not HAS_HTTPX, reason="httpx not installed")

# ── AC3: LLM API calls detected by URL matching ─────────────────────────────

def test_llm_url_detection():
    """LLM provider URLs are correctly detected."""
    from phantex_sdk.hooks.http import _detect_llm_provider

    assert _detect_llm_provider("https://api.openai.com/v1/chat/completions") == "openai"
    assert _detect_llm_provider("https://api.anthropic.com/v1/messages") == "anthropic"
    assert _detect_llm_provider("https://generativelanguage.googleapis.com/v1/models") == "google"
    assert _detect_llm_provider("https://api.groq.com/openai/v1/chat/completions") == "groq"
    assert _detect_llm_provider("https://api.deepseek.com/v1/chat/completions") == "deepseek"
    assert _detect_llm_provider("https://openrouter.ai/api/v1/chat/completions") == "openrouter"
    assert (
        _detect_llm_provider("https://myapp.openai.azure.com/openai/deployments/gpt-4")
        == "azure_openai"
    )
    assert (
        _detect_llm_provider("https://bedrock-runtime.us-east-1.amazonaws.com/model")
        == "aws_bedrock"
    )

    # Non-LLM URLs should return None
    assert _detect_llm_provider("https://www.google.com") is None
    assert _detect_llm_provider("https://api.github.com/repos") is None
    assert _detect_llm_provider("https://httpbin.org/get") is None

def test_model_extraction_from_body():
    """Model name is extracted from request body."""
    from phantex_sdk.hooks.http import _extract_model_from_body

    assert _extract_model_from_body('{"model": "gpt-4", "messages": []}') == "gpt-4"
    assert (
        _extract_model_from_body('{"model": "claude-3-opus-20240229"}') == "claude-3-opus-20240229"
    )
    assert _extract_model_from_body({"model": "gpt-3.5-turbo"}) == "gpt-3.5-turbo"
    assert _extract_model_from_body(None) == ""
    assert _extract_model_from_body("invalid json") == ""

def test_token_extraction_from_response():
    """Token counts are extracted from LLM API responses."""
    from phantex_sdk.hooks.http import _extract_tokens_from_response

    # OpenAI format
    inp, out = _extract_tokens_from_response(
        '{"usage": {"prompt_tokens": 100, "completion_tokens": 50}}'
    )
    assert inp == 100
    assert out == 50

    # Anthropic format
    inp, out = _extract_tokens_from_response(
        '{"usage": {"input_tokens": 200, "output_tokens": 80}}'
    )
    assert inp == 200
    assert out == 80

    # No usage info
    inp, out = _extract_tokens_from_response('{"choices": []}')
    assert inp == 0
    assert out == 0

# ── Non-LLM calls pass through ──────────────────────────────────────────────

@skip_no_requests
def test_non_llm_http_not_captured(client):
    """Non-LLM HTTP calls pass through without generating events."""
    import requests

    # This should NOT be captured (not an LLM URL)
    with contextlib.suppress(Exception):
        requests.get("http://localhost:1/nonexistent", timeout=0.1)

    events = client.drain_events()
    # No events should be captured for non-LLM URLs
    assert len(events) == 0, f"Non-LLM request generated events: {events}"

# ── Test prompt hash (never plaintext) ────────────────────────────────────────

def test_prompt_hashing():
    """Prompts are SHA-256 hashed, never stored as plaintext."""
    from phantex_sdk.events import _hash_prompt

    h = _hash_prompt("What is the meaning of life?")
    assert len(h) == 64  # SHA-256 hex digest
    assert h != "What is the meaning of life?"

    # Same input → same hash (deterministic)
    assert _hash_prompt("test") == _hash_prompt("test")
    # Different input → different hash
    assert _hash_prompt("a") != _hash_prompt("b")
