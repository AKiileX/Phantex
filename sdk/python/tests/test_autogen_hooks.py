# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for AutoGen hooks.

Tests both AG2 (autogen-agentchat >= 0.4) and graceful fallback.
"""

from __future__ import annotations

import asyncio
import os

os.environ["PHANTEX_NO_AUTO_INIT"] = "1"
os.environ["PHANTEX_ENABLED"] = "1"

import pytest

from phantex_sdk import PhantexConfig
from phantex_sdk.transport import BufferTransport

try:
    import autogen_agentchat  # noqa: F401

    HAS_AG2 = True
except ImportError:
    HAS_AG2 = False

skip_no_ag2 = pytest.mark.skipif(not HAS_AG2, reason="autogen-agentchat not installed")

def test_autogen_hook_skips_gracefully():
    """AutoGen hook reports status correctly based on availability."""
    from phantex_sdk.hooks.autogen import AutoGenHook

    transport = BufferTransport()
    config = PhantexConfig(transport="buffer", enabled=True)
    hook = AutoGenHook(transport=transport, config=config)

    if HAS_AG2:
        assert hook.install() is True
        assert hook.installed is True
        hook.uninstall()
    else:
        # Should return False without crashing when no autogen available
        assert hook.install() is False
        assert hook.installed is False

@skip_no_ag2
def test_autogen_hook_installs_patches():
    """AG2 hooks patch BaseChatAgent and its subclasses."""
    from autogen_agentchat.agents import AssistantAgent, BaseChatAgent

    from phantex_sdk.hooks.autogen import AutoGenHook

    transport = BufferTransport()
    config = PhantexConfig(
        transport="buffer", hooks="autogen", tenant_id="test-tenant", enabled=True
    )
    hook = AutoGenHook(transport=transport, config=config)

    assert hook.install() is True

    # AssistantAgent overrides on_messages, so it should be patched directly
    assert getattr(AssistantAgent.on_messages, "_phantex_patched", False) is True
    # BaseChatAgent should also be patched (for custom subclasses)
    assert getattr(BaseChatAgent.on_messages, "_phantex_patched", False) is True

    hook.uninstall()

    # Verify patches are removed
    assert getattr(AssistantAgent.on_messages, "_phantex_patched", False) is False
    assert getattr(BaseChatAgent.on_messages, "_phantex_patched", False) is False

@skip_no_ag2
def test_autogen_on_messages_captured():
    """AG2 BaseChatAgent.on_messages is captured via hook."""
    from autogen_agentchat.agents import BaseChatAgent

    from phantex_sdk.hooks.autogen import AutoGenHook

    transport = BufferTransport()
    config = PhantexConfig(
        transport="buffer",
        hooks="autogen",
        tenant_id="test-tenant",
        enabled=True,
    )

    # Install hook directly (not via client — avoids transport confusion)
    hook = AutoGenHook(transport=transport, config=config)
    assert hook.install() is True

    # Verify on_messages is patched
    assert getattr(BaseChatAgent.on_messages, "_phantex_patched", False) is True

    # Now create an agent and call the patched method
    from autogen_agentchat.agents import AssistantAgent
    from autogen_agentchat.messages import TextMessage

    agent = AssistantAgent(name="test_agent", model_client=None)

    async def run_test():
        try:
            msg = TextMessage(content="Hello there", source="user")
            await agent.on_messages([msg], cancellation_token=None)
        except Exception:
            pass  # Expected — no model client configured

    asyncio.new_event_loop().run_until_complete(run_test())

    events = transport.peek()
    # Hook fires tool_call on entry and tool_response on exit (even on error)
    assert len(events) >= 1, f"Expected events, got {len(events)}"

    # Verify the event content
    first = events[0]
    d = first.to_dict() if hasattr(first, "to_dict") else first
    assert "test_agent" in d["tool_name"]
    assert "on_messages" in d["tool_name"]

    hook.uninstall()

@skip_no_ag2
def test_autogen_team_patch():
    """AG2 team hooks patch RoundRobinGroupChat.run."""
    transport = BufferTransport()
    config = PhantexConfig(
        transport="buffer", hooks="autogen", tenant_id="test-tenant", enabled=True
    )

    from phantex_sdk.hooks.autogen import AutoGenHook

    hook = AutoGenHook(transport=transport, config=config)
    hook.install()

    try:
        from autogen_agentchat.teams import RoundRobinGroupChat

        assert getattr(RoundRobinGroupChat.run, "_phantex_patched", False) is True
    except ImportError:
        pass  # teams module might not be available

    hook.uninstall()
