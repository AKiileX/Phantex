# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex GraphQL — Root Schema.

Assembles Query, Mutation, and Subscription types into the final
Strawberry schema with defense-in-depth extensions:

1. QueryDepthLimiter         — configurable max nesting depth
2. SessionCleanup            — auto-closes DB session after every request
3. ErrorSanitizer            — ALWAYS strips internal details (no env gate)
4. IntrospectionGuard        — blocks introspection unless explicitly opted in
5. AliasLimiter              — prevents alias-based DoS / batching attacks
6. QueryCostAnalyzer         — rejects expensive queries before execution

All security extensions enforce production-grade defaults regardless of
the ``environment`` setting.  Opt-in relaxation is controlled exclusively
via ``PHANTEX_GRAPHQL_*`` environment variables.
"""

from __future__ import annotations

import re

import strawberry
from strawberry.extensions import QueryDepthLimiter
from strawberry.extensions.base_extension import SchemaExtension

from app.config import get_settings
from app.graphql.resolvers import Mutation, Query
from app.graphql.subscriptions import Subscription
from app.utils.logging import get_logger

_settings = get_settings()
_logger = get_logger("phantex.graphql.schema")

# Pre-compiled patterns for alias/introspection detection
_ALIAS_PATTERN = re.compile(r"\b\w+\s*:\s*\w+", re.ASCII)
_INTROSPECTION_TOKENS = ("__schema", "__type")

# ── Extension: Auto-close DB session ─────────────────────────────────────────

class SessionCleanupExtension(SchemaExtension):
    """Commit + close the RLS DB session after every GraphQL request.

    Without this, sessions leak on every request.
    """

    async def on_execute(self):
        yield
        ctx = self.execution_context.context
        if ctx and hasattr(ctx, "close"):
            try:
                await ctx.close()
            except Exception as exc:
                _logger.warning("graphql_session_cleanup_error", error=str(exc))

# ── Extension: Error sanitization (ALWAYS active) ────────────────────────────

# User-facing error prefixes that are safe to pass through unmodified.
_SAFE_ERROR_PREFIXES = (
    "Not authenticated",
    "Token expired",
    "Insufficient permissions",
    "Introspection is disabled",
    "Query too complex",
    "Too many aliases",
)

class ErrorSanitizerExtension(SchemaExtension):
    """Strip internal error details — ALWAYS.

    Prevents leaking stack traces, DB schema, or file paths to clients
    regardless of the ``environment`` setting.  Only whitelisted prefixes
    are passed through; everything else becomes ``Internal server error``.
    """

    async def on_execute(self):
        result = yield
        if result and hasattr(result, "errors") and result.errors:
            for error in result.errors:
                original_msg = str(error.message) if error.message else ""

                if original_msg.startswith(_SAFE_ERROR_PREFIXES):
                    continue  # known user-facing — keep as-is

                _logger.error(
                    "graphql_error_sanitized",
                    original_message=original_msg,
                    path=error.path,
                )
                error.message = "Internal server error"

# ── Extension: Introspection Guard (off by default) ──────────────────────────

class IntrospectionGuardExtension(SchemaExtension):
    """Block ``__schema`` and ``__type`` introspection queries.

    Introspection leaks the full API surface area.  It is **disabled by
    default** regardless of environment.  To enable (e.g., for local dev
    with GraphiQL), set ``PHANTEX_GRAPHQL_INTROSPECTION_ENABLED=true``.
    """

    async def on_execute(self):
        if not _settings.graphql_introspection_enabled:
            query = self.execution_context.query
            if query and any(tok in query for tok in _INTROSPECTION_TOKENS):
                from graphql import GraphQLError

                _logger.warning("graphql_introspection_blocked")
                raise GraphQLError("Introspection is disabled")
        yield

# ── Extension: Alias Limiter ─────────────────────────────────────────────────

class AliasLimiterExtension(SchemaExtension):
    """Reject queries that exceed the configured alias count.

    Alias abuse allows attackers to multiply the cost of a single query
    (e.g., ``a1: alerts {...} a2: alerts {...} ...``).
    """

    async def on_execute(self):
        query = self.execution_context.query
        if query:
            alias_count = len(_ALIAS_PATTERN.findall(query))
            if alias_count > _settings.graphql_max_aliases:
                from graphql import GraphQLError

                _logger.warning(
                    "graphql_alias_limit_exceeded",
                    count=alias_count,
                    limit=_settings.graphql_max_aliases,
                )
                raise GraphQLError(f"Too many aliases ({alias_count}); limit is {_settings.graphql_max_aliases}")
        yield

# ── Extension: Query Cost Analyzer ───────────────────────────────────────────

# Rough cost weights for heuristic estimation.  Every top-level field
# costs 1 point, every nesting level multiplies inner cost × 5,
# and ``first``/``limit`` arguments act as multipliers.
_LIST_FIELD_TOKENS = {"alerts", "agents", "events", "rules"}
_COST_MULTIPLIER_RE = re.compile(r"(?:limit|first)\s*:\s*(\d+)", re.ASCII)

class QueryCostAnalyzerExtension(SchemaExtension):
    """Reject queries whose estimated cost exceeds the budget.

    Uses a lightweight heuristic on the raw query string so we can reject
    before parsing.  Not a replacement for a full cost model, but blocks
    the most common abuse patterns (deeply-nested pagination fan-out).
    """

    async def on_execute(self):
        query = self.execution_context.query
        if query:
            cost = self._estimate_cost(query)
            if cost > _settings.graphql_max_query_cost:
                from graphql import GraphQLError

                _logger.warning(
                    "graphql_query_cost_exceeded",
                    cost=cost,
                    limit=_settings.graphql_max_query_cost,
                )
                raise GraphQLError(
                    f"Query too complex (estimated cost {cost}; limit {_settings.graphql_max_query_cost})"
                )
        yield

    @staticmethod
    def _estimate_cost(query: str) -> int:
        """Heuristic cost estimator.

        - Each ``{`` nesting level increases the depth multiplier.
        - List fields (alerts, agents, events, rules) cost ``depth × page_size``.
        - Scalar fields cost 1 each.
        """
        cost = 0
        depth = 0
        # Extract all limit/first values
        limits = [int(m) for m in _COST_MULTIPLIER_RE.findall(query)]
        page_size = max(limits) if limits else 50  # default page size

        tokens = query.split()
        for token in tokens:
            stripped = token.strip("({,:")
            if "{" in token:
                depth += token.count("{")
            if "}" in token:
                depth = max(0, depth - token.count("}"))
            if stripped.lower() in _LIST_FIELD_TOKENS:
                cost += max(1, depth) * page_size
            elif stripped.isidentifier() and not stripped.startswith("$"):
                cost += 1

        return cost

# ── Assemble schema ──────────────────────────────────────────────────────────

schema = strawberry.Schema(
    query=Query,
    mutation=Mutation,
    subscription=Subscription,
    extensions=[
        QueryDepthLimiter(max_depth=_settings.graphql_max_depth),
        AliasLimiterExtension,
        QueryCostAnalyzerExtension,
        IntrospectionGuardExtension,
        SessionCleanupExtension,
        ErrorSanitizerExtension,  # must be last — catches errors from above
    ],
)
