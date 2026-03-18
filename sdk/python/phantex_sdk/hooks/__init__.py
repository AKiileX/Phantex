# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex SDK — Hook registry and auto-detection.

Discovers installed frameworks and activates the appropriate hooks.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..config import PhantexConfig
    from ..transport import Transport
    from .base import BaseHook

logger = logging.getLogger("phantex.hooks")

# Registry of all known hooks: name → class
_HOOK_CLASSES: dict[str, type[BaseHook]] = {}

def _register_hooks() -> None:
    """Lazy-register all hook classes (avoids import-time framework imports)."""
    if _HOOK_CLASSES:
        return

    from .autogen import AutoGenHook
    from .crewai import CrewAIHook
    from .http import HTTPHook
    from .langchain import LangChainHook
    from .mcp import MCPHook

    _HOOK_CLASSES["langchain"] = LangChainHook
    _HOOK_CLASSES["autogen"] = AutoGenHook
    _HOOK_CLASSES["crewai"] = CrewAIHook
    _HOOK_CLASSES["http"] = HTTPHook
    _HOOK_CLASSES["mcp"] = MCPHook

def install_hooks(transport: Transport, config: PhantexConfig) -> list[BaseHook]:
    """
    Detect installed frameworks and install hooks.

    Args:
        transport: Event transport for emitting captured events
        config: SDK configuration

    Returns:
        List of successfully installed hooks
    """
    _register_hooks()

    hooks_to_try: list[str]
    hooks_config = config.hooks.lower().strip()

    if hooks_config == "auto":
        # Try all hooks — each one silently skips if its framework isn't installed
        hooks_to_try = list(_HOOK_CLASSES.keys())
    elif hooks_config == "none":
        logger.debug("All hooks disabled by config")
        return []
    else:
        # Comma-separated list: "langchain,http"
        hooks_to_try = [h.strip() for h in hooks_config.split(",") if h.strip()]

    installed: list[BaseHook] = []

    for hook_name in hooks_to_try:
        hook_cls = _HOOK_CLASSES.get(hook_name)
        if hook_cls is None:
            logger.warning(
                "Unknown hook: %s (available: %s)", hook_name, list(_HOOK_CLASSES.keys())
            )
            continue

        hook = hook_cls(transport=transport, config=config)
        try:
            if hook.install():
                installed.append(hook)
                logger.debug("Hook '%s' installed successfully", hook_name)
            else:
                logger.debug("Hook '%s' skipped (framework not available)", hook_name)
        except Exception as e:
            # NEVER let a hook installation failure crash the user's app
            logger.warning("Hook '%s' failed to install: %s", hook_name, e)

    return installed

def uninstall_hooks(hooks: list[BaseHook]) -> None:
    """Restore all hooks to their original state."""
    for hook in hooks:
        try:
            hook.uninstall()
        except Exception as e:
            logger.warning("Failed to uninstall hook '%s': %s", hook.name, e)
