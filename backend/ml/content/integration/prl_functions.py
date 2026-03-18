# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — PRL Function Integration (JB6).

Registers 5 new built-in PRL functions that rules can use:
1. ``ml_score(classifier, content)``  →  float  (0.0–1.0)
2. ``data_classification(payload)``   →  str    (comma-separated labels)
3. ``tool_authorized(agent_id, tool)`` → bool
4. ``mcp_trust_level(server)``        →  str    ("verified", "unknown", etc.)
5. ``content_scan(response)``         →  str    (comma-separated finding types)

All functions are **read-only** (cannot modify content pipeline state).
"""

from __future__ import annotations

from typing import Any

from ml.content.analyzer import ContentAnalyzer
from ml.content.classifiers.data_classifier import SemanticDataClassifier
from ml.content.policy.mcp_registry import MCPServerRegistry
from ml.content.policy.tool_policy import ToolDecision, ToolPolicyEngine
from ml.content.scanners.output_scanner import OutputContentScanner

# ── Shared singletons (lazy-initialised) ─────────────────────────────────────
# These are module-level defaults.  In production, the gateway injects
# configured instances via ``configure_singletons()``.

_content_analyzer: ContentAnalyzer | None = None
_data_classifier: SemanticDataClassifier | None = None
_tool_policy: ToolPolicyEngine | None = None
_mcp_registry: MCPServerRegistry | None = None
_output_scanner: OutputContentScanner | None = None

def configure_singletons(
    content_analyzer: ContentAnalyzer | None = None,
    data_classifier: SemanticDataClassifier | None = None,
    tool_policy: ToolPolicyEngine | None = None,
    mcp_registry: MCPServerRegistry | None = None,
    output_scanner: OutputContentScanner | None = None,
) -> None:
    """Inject configured instances for PRL functions to use."""
    global _content_analyzer, _data_classifier, _tool_policy, _mcp_registry, _output_scanner
    if content_analyzer is not None:
        _content_analyzer = content_analyzer
    if data_classifier is not None:
        _data_classifier = data_classifier
    if tool_policy is not None:
        _tool_policy = tool_policy
    if mcp_registry is not None:
        _mcp_registry = mcp_registry
    if output_scanner is not None:
        _output_scanner = output_scanner

def _get_analyzer() -> ContentAnalyzer:
    global _content_analyzer
    if _content_analyzer is None:
        _content_analyzer = ContentAnalyzer()
    return _content_analyzer

def _get_classifier() -> SemanticDataClassifier:
    global _data_classifier
    if _data_classifier is None:
        _data_classifier = SemanticDataClassifier()
    return _data_classifier

def _get_tool_policy() -> ToolPolicyEngine:
    global _tool_policy
    if _tool_policy is None:
        _tool_policy = ToolPolicyEngine()
    return _tool_policy

def _get_mcp_registry() -> MCPServerRegistry:
    global _mcp_registry
    if _mcp_registry is None:
        _mcp_registry = MCPServerRegistry()
    return _mcp_registry

def _get_output_scanner() -> OutputContentScanner:
    global _output_scanner
    if _output_scanner is None:
        _output_scanner = OutputContentScanner()
    return _output_scanner

# ═══════════════════════════════════════════════════════════════════════
# ──  PRL Built-in Functions
# ═══════════════════════════════════════════════════════════════════════

# Max content length accepted by PRL functions (defence-in-depth)
_PRL_MAX_CONTENT = 65_536

def fn_ml_score(
    args: list[Any],
    ctx: dict[str, Any],
    func_ctx: Any,
) -> float:
    """ml_score(classifier_name, content) → float (0.0–1.0).

    Runs content analysis against *content* and returns the score.
    The *classifier_name* hint is reserved for future per-classifier routing.
    Returns 0.0 on error (graceful degradation).
    """
    if len(args) < 2:
        return 0.0
    # classifier_name = str(args[0])  — reserved for future routing
    content = str(args[1])[:_PRL_MAX_CONTENT]
    try:
        analyzer = _get_analyzer()
        verdict = analyzer.analyze(content)
        return verdict.score
    except Exception:
        return 0.0

def fn_data_classification(
    args: list[Any],
    ctx: dict[str, Any],
    func_ctx: Any,
) -> str:
    """data_classification(payload) → str (comma-separated labels).

    Classifies *payload* for PII/PHI/financial data and returns the
    label list as a comma-separated string usable in PRL ``contains``.
    Returns "" on error.
    """
    if len(args) < 1:
        return ""
    payload = str(args[0])[:_PRL_MAX_CONTENT]
    try:
        classifier = _get_classifier()
        result = classifier.classify(payload)
        return ",".join(result.labels)
    except Exception:
        return ""

def fn_tool_authorized(
    args: list[Any],
    ctx: dict[str, Any],
    func_ctx: Any,
) -> bool:
    """tool_authorized(agent_id, tool_name) → bool.

    Checks if *tool_name* is authorized for *agent_id* according to
    the tool policy engine.  Returns True (permissive) on error.
    """
    if len(args) < 2:
        return True
    agent_id = str(args[0])
    tool_name = str(args[1])
    tenant_id = ctx.get("tenant_id", "")
    try:
        engine = _get_tool_policy()
        verdict = engine.evaluate(tenant_id, agent_id, tool_name)
        return verdict.decision in (ToolDecision.ALLOW, ToolDecision.MONITOR)
    except Exception:
        return True  # Fail-open: don't block on error

def fn_mcp_trust_level(
    args: list[Any],
    ctx: dict[str, Any],
    func_ctx: Any,
) -> str:
    """mcp_trust_level(server_url) → str ("verified", "known", "unknown", etc.).

    Returns the trust level of an MCP server.
    Returns "unknown" on error or if server is not registered.
    """
    if len(args) < 1:
        return "unknown"
    server_url = str(args[0])
    tenant_id = ctx.get("tenant_id", "")
    try:
        registry = _get_mcp_registry()
        entry = registry.get(tenant_id, server_url)
        if entry is None:
            return "unknown"
        return entry.trust_level.value
    except Exception:
        return "unknown"

def fn_content_scan(
    args: list[Any],
    ctx: dict[str, Any],
    func_ctx: Any,
) -> str:
    """content_scan(response) → str (comma-separated finding types).

    Scans *response* for secrets, encoding anomalies, and internal leaks.
    Returns comma-separated finding types, e.g. "API_KEY,INTERNAL_IP".
    Returns "" on error.
    """
    if len(args) < 1:
        return ""
    response = str(args[0])[:_PRL_MAX_CONTENT]
    tenant_id = ctx.get("tenant_id", "")
    agent_id = ctx.get("agent_id", "")
    try:
        scanner = _get_output_scanner()
        result = scanner.scan(response, tenant_id=tenant_id, agent_id=agent_id)
        findings: list[str] = []
        for hit in result.secret_hits:
            findings.append(hit.pattern_name.upper())
        if result.prompt_leak:
            findings.append("PROMPT_LEAK")
        for hit in result.encoding_hits:
            findings.append(hit.pattern_name.upper())
        for hit in result.internal_leak_hits:
            findings.append(hit.pattern_name.upper())
        return ",".join(findings)
    except Exception:
        return ""

# ── Registration helper ──────────────────────────────────────────────────────

# PRL function signatures: (min_args, max_args)
PRL_CONTENT_FUNCTIONS: dict[str, tuple[int, int]] = {
    "ml_score": (2, 2),
    "data_classification": (1, 1),
    "tool_authorized": (2, 2),
    "mcp_trust_level": (1, 1),
    "content_scan": (1, 1),
}

# Function implementations
PRL_CONTENT_IMPLS: dict[str, Any] = {
    "ml_score": fn_ml_score,
    "data_classification": fn_data_classification,
    "tool_authorized": fn_tool_authorized,
    "mcp_trust_level": fn_mcp_trust_level,
    "content_scan": fn_content_scan,
}

def register_content_functions(registry: Any) -> None:
    """Register all JB content functions into a BuiltinRegistry.

    Call this during application startup:
    >>> from engine.evaluator.functions import BuiltinRegistry
    >>> registry = BuiltinRegistry()
    >>> register_content_functions(registry)
    """
    for name, impl in PRL_CONTENT_IMPLS.items():
        registry.register(name, impl)
