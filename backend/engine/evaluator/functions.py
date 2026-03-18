# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
PRL Built-in Functions — implementations of count(), count_distinct(),
contains(), regex_match(), time_since(), in_allowlist().

These are the only functions callable from PRL rules.  Adding a new
function requires registering it in the BuiltinRegistry.

Security: regex patterns are compiled with re.compile (no eval/exec).
Patterns that take too long are not a concern at Phase 1 scale, but a
timeout guard can be added later.

count() uses a FunctionContext with a sliding window counter backed by
an in-memory deque of (timestamp, event_type) tuples.
count_distinct() additionally tracks unique field values within the window.
in_allowlist() checks a value against named, configurable allowlists.
"""

from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

# ── FunctionContext: sliding window state ─────────────────────────────────────

@dataclass
class FunctionContext:
    """
    Per-rule-engine state shared across function calls.

    Holds the sliding window event counters needed by count() and
    time_since().  Each distinct (tenant_id, event_type) gets its
    own deque of timestamps.

    The engine creates one FunctionContext on startup and passes it
    to every evaluate() call.
    """

    # key = (tenant_id, agent_id, event_type) → deque of float timestamps
    # Scoped per-tenant per-agent to prevent cross-tenant count pollution.
    event_windows: dict[str, deque[float]] = field(
        default_factory=lambda: defaultdict(lambda: deque(maxlen=100_000)),
    )

    # key = same composite key → deque of (timestamp, field_value) for count_distinct
    event_value_windows: dict[str, deque[tuple[float, str]]] = field(
        default_factory=lambda: defaultdict(lambda: deque(maxlen=100_000)),
    )

    # Named allowlists: name → set of allowed values
    # Populated from config file or environment at engine startup.
    allowlists: dict[str, set[str]] = field(default_factory=dict)

    # Maximum window entries to keep per key (safety cap)
    max_entries: int = 100_000

    @staticmethod
    def _window_key(event_type: str, tenant_id: str | None = None, agent_id: str | None = None) -> str:
        """Build a composite key scoped by tenant + agent + event_type."""
        t = tenant_id or "global"
        a = agent_id or "unknown"
        return f"{t}:{a}:{event_type}"

    def record_event(
        self,
        event_type: str,
        timestamp: float | None = None,
        tenant_id: str | None = None,
        agent_id: str | None = None,
        field_values: dict[str, str] | None = None,
    ) -> None:
        """Record that an event of `event_type` was seen at `timestamp`.

        Args:
            field_values: Optional dict of field_path → value for count_distinct.
                          e.g., {"raw_data.filename": "/etc/passwd"}
        """
        ts = timestamp or time.time()
        key = self._window_key(event_type, tenant_id, agent_id)
        dq = self.event_windows[key]
        dq.append(ts)

        # Store per-field values for count_distinct
        if field_values:
            for field_path, value in field_values.items():
                vkey = f"{key}:{field_path}"
                vdq = self.event_value_windows[vkey]
                vdq.append((ts, str(value)))

    def count_in_window(
        self,
        event_type: str,
        window_seconds: float,
        tenant_id: str | None = None,
        agent_id: str | None = None,
    ) -> int:
        """Count events of `event_type` within the last `window_seconds`."""
        cutoff = time.time() - window_seconds
        key = self._window_key(event_type, tenant_id, agent_id)
        dq = self.event_windows.get(key)
        if not dq:
            return 0

        # Purge expired entries from the left
        while dq and dq[0] < cutoff:
            dq.popleft()

        return len(dq)

    def time_since_last(
        self,
        event_type: str,
        tenant_id: str | None = None,
        agent_id: str | None = None,
    ) -> float | None:
        """Seconds since the last event of `event_type`, or None if never seen."""
        key = self._window_key(event_type, tenant_id, agent_id)
        dq = self.event_windows.get(key)
        if not dq:
            return None
        return time.time() - dq[-1]

    def count_distinct_in_window(
        self,
        event_type: str,
        field_path: str,
        window_seconds: float,
        tenant_id: str | None = None,
        agent_id: str | None = None,
    ) -> int:
        """Count distinct values of `field_path` for `event_type` within `window_seconds`."""
        cutoff = time.time() - window_seconds
        key = self._window_key(event_type, tenant_id, agent_id)
        vkey = f"{key}:{field_path}"
        vdq = self.event_value_windows.get(vkey)
        if not vdq:
            return 0

        # Purge expired entries from the left
        while vdq and vdq[0][0] < cutoff:
            vdq.popleft()

        # Count distinct values in the remaining window
        return len({v for _, v in vdq})

    def is_in_allowlist(self, value: str, list_name: str) -> bool:
        """Check if `value` is in the named allowlist.

        Supports two matching modes:
          - **Exact match**: value equals an entry (for domains, process names).
          - **Substring match**: any entry appears inside value (for file paths
            where entries like ``/etc/ssl/certs/`` should match
            ``/etc/ssl/certs/ca-bundle.pem``).

        Returns False when the allowlist is not configured (fail-closed).
        """
        al = self.allowlists.get(list_name)
        if al is None:
            return False  # Unconfigured allowlist = not-in-list (fail-closed)
        # Exact match first (fast O(1) set lookup)
        if value in al:
            return True
        # Substring / prefix match (for path-based allowlists)
        return any(entry in value for entry in al)

    def set_allowlist(self, list_name: str, values: set[str]) -> None:
        """Configure a named allowlist."""
        self.allowlists[list_name] = values

# ── Window Duration Parser ────────────────────────────────────────────────────

_DURATION_RE = re.compile(r"^(\d+)\s*(s|m|h|d)$", re.IGNORECASE)
_DURATION_MULTIPLIERS = {"s": 1, "m": 60, "h": 3600, "d": 86400}

def parse_duration(s: str) -> float:
    """
    Parse a duration string like "60s", "5m", "1h", "7d" into seconds.

    Raises ValueError if the format is invalid.
    """
    match = _DURATION_RE.match(s.strip())
    if not match:
        raise ValueError(f"Invalid duration format: {s!r}. Expected a number followed by s/m/h/d (e.g., '60s', '5m')")
    value = int(match.group(1))
    unit = match.group(2).lower()
    return float(value * _DURATION_MULTIPLIERS[unit])

# ── Compiled Regex Cache ──────────────────────────────────────────────────────

_regex_cache: dict[str, re.Pattern] = {}
_REGEX_CACHE_MAX = 1000

# ReDoS protection: detect nested quantifiers that cause catastrophic backtracking.
# Catches (a+)+, (a*)+, (a+)*, (a+){2,}, (a{2,})+ and similar.
_REDOS_PATTERN = re.compile(r"\([^)]*(?:[+*]|\{\d+,\d*\})[^)]*\)(?:[+*]|\{\d+,\d*\})")

def _get_compiled_regex(pattern: str) -> re.Pattern:
    """Get a compiled regex, caching for performance. Validates pattern complexity."""
    if pattern not in _regex_cache:
        # Limit pattern length to prevent abuse
        if len(pattern) > 1000:
            raise ValueError(f"Regex pattern too long ({len(pattern)} chars, max 1000).")
        if _REDOS_PATTERN.search(pattern):
            raise ValueError(
                f"Rejected regex pattern {pattern!r}: potential ReDoS "
                "(nested quantifiers detected). Simplify the pattern."
            )
        if len(_regex_cache) >= _REGEX_CACHE_MAX:
            # Evict oldest half when cache is full
            keys = list(_regex_cache.keys())
            for k in keys[: len(keys) // 2]:
                del _regex_cache[k]
        _regex_cache[pattern] = re.compile(pattern)
    return _regex_cache[pattern]

# ── Built-in Function Implementations ─────────────────────────────────────────

def fn_count(
    args: list[Any],
    ctx: dict[str, Any],
    func_ctx: FunctionContext | None,
) -> int:
    """
    count(event_type, window) → int

    Count events of `event_type` in the sliding window.
    window is a duration string like "60s", "5m".
    Scoped per tenant+agent from event context to prevent cross-tenant pollution.

    Example: count("TOOL_CALL", "60s") → 42
    """
    event_type = str(args[0])
    window_str = str(args[1])
    window_seconds = parse_duration(window_str)

    if func_ctx is None:
        return 0

    # Extract tenant_id and agent_id from evaluation context
    tenant_id = ctx.get("tenant_id")
    agent_id = ctx.get("event", {}).get("agent_id")
    return func_ctx.count_in_window(event_type, window_seconds, tenant_id, agent_id)

def fn_contains(
    args: list[Any],
    ctx: dict[str, Any],
    func_ctx: FunctionContext | None,
) -> bool:
    """
    contains(haystack, needle) → bool

    Check if `needle` is a substring of `haystack`.

    Example: contains(event.raw_data.tool_input, "password") → true
    """
    haystack = str(args[0])
    needle = str(args[1])
    return needle in haystack

def fn_regex_match(
    args: list[Any],
    ctx: dict[str, Any],
    func_ctx: FunctionContext | None,
) -> bool:
    """
    regex_match(pattern, text) → bool

    Check if `text` matches `pattern` (uses re.search, not re.fullmatch).

    Example: regex_match(".*password.*", event.raw_data.tool_input) → true
    """
    pattern = str(args[0])
    text = str(args[1])

    try:
        compiled = _get_compiled_regex(pattern)
        return compiled.search(text) is not None
    except re.error as e:
        raise ValueError(f"Invalid regex pattern {pattern!r}: {e}") from e

def fn_time_since(
    args: list[Any],
    ctx: dict[str, Any],
    func_ctx: FunctionContext | None,
) -> float:
    """
    time_since(event_type) → float (seconds)

    Return seconds since the last event of `event_type`.
    Returns 999999.0 if no such event has been seen (always passes > comparisons).
    Scoped per tenant+agent from event context.

    Example: time_since("HEARTBEAT") > 300  # No heartbeat in 5 minutes
    """
    event_type = str(args[0])

    if func_ctx is None:
        return 999999.0

    tenant_id = ctx.get("tenant_id")
    agent_id = ctx.get("event", {}).get("agent_id")
    result = func_ctx.time_since_last(event_type, tenant_id, agent_id)
    if result is None:
        return 999999.0
    return result

def fn_count_distinct(
    args: list[Any],
    ctx: dict[str, Any],
    func_ctx: FunctionContext | None,
) -> int:
    """
    count_distinct(event_type, field_path, window) → int

    Count distinct values of `field_path` for events of `event_type`
    within the sliding window.
    Scoped per tenant+agent from event context.

    Example: count_distinct("FILE_READ", "raw_data.filename", "60s") → 55
    """
    event_type = str(args[0])
    field_path = str(args[1])
    window_str = str(args[2])
    window_seconds = parse_duration(window_str)

    if func_ctx is None:
        return 0

    tenant_id = ctx.get("tenant_id")
    agent_id = ctx.get("event", {}).get("agent_id")
    return func_ctx.count_distinct_in_window(event_type, field_path, window_seconds, tenant_id, agent_id)

def fn_in_allowlist(
    args: list[Any],
    ctx: dict[str, Any],
    func_ctx: FunctionContext | None,
) -> bool:
    """
    in_allowlist(value, list_name) → bool

    Check if `value` is in the named allowlist.
    Allowlists are configured at engine startup from config.

    Returns False if the allowlist doesn't exist (fail-closed). This makes
    ``NOT in_allowlist(...)`` a no-op when no list is set — the rule fires
    normally and the allowlist only suppresses matches once configured.

    Returns True if the allowlist exists and the value is in it.
    Returns False if the allowlist exists and the value is NOT in it.

    Example: in_allowlist(event.raw_data.tool_name, "approved_mcp_servers")
    """
    value = str(args[0])
    list_name = str(args[1])

    if func_ctx is None:
        return False

    return func_ctx.is_in_allowlist(value, list_name)

# ── Registry ──────────────────────────────────────────────────────────────────

_BuiltinFunc = type(fn_count)  # callable signature

class BuiltinRegistry:
    """
    Registry of built-in PRL functions.

    Functions are looked up by name and called with (args, context, func_ctx).
    """

    def __init__(self) -> None:
        self._functions: dict[str, Any] = {
            "count": fn_count,
            "count_distinct": fn_count_distinct,
            "contains": fn_contains,
            "regex_match": fn_regex_match,
            "time_since": fn_time_since,
            "in_allowlist": fn_in_allowlist,
            "baseline_mode": fn_baseline_mode,
            "in_baseline_destinations": fn_in_baseline_destinations,
            "baseline_p95": fn_baseline_p95,
            "baseline_zscore": fn_baseline_zscore,
        }
        # Register JB6 content-analysis PRL functions
        self._register_content_functions()
        # Register K3 trust score function
        self._register_trust_functions()
        # Register AM5 sandbox PRL functions
        self._register_sandbox_functions()

    def call(
        self,
        name: str,
        args: list[Any],
        ctx: dict[str, Any],
        func_ctx: FunctionContext | None,
    ) -> Any:
        """Call a built-in function by name."""
        func = self._functions.get(name)
        if func is None:
            raise ValueError(f"Unknown function: {name!r}. Available: {', '.join(sorted(self._functions.keys()))}")
        return func(args, ctx, func_ctx)

    def register(self, name: str, func: Any) -> None:
        """Register a new built-in function (for testing/extensibility)."""
        self._functions[name] = func

    @property
    def names(self) -> list[str]:
        return sorted(self._functions.keys())

    def _register_content_functions(self) -> None:
        """Register JB6 content-analysis PRL functions (graceful if unavailable)."""
        try:
            from ml.content.integration.prl_functions import register_content_functions

            register_content_functions(self)
        except Exception:
            # Content analysis module not available — skip silently.
            # Functions will raise "Unknown function" if called.
            pass

    def _register_trust_functions(self) -> None:
        """Register K3 trust-score PRL function (graceful if unavailable)."""
        self._functions["trust_score"] = fn_trust_score

    def _register_sandbox_functions(self) -> None:
        """Register AM5 sandbox PRL functions (graceful if unavailable)."""
        try:
            from engine.sandbox.prl_extension import register_sandbox_functions

            register_sandbox_functions(self)
        except Exception:
            pass

# ── Baseline Built-in Functions (J4) ─────────────────────────────────────────

def fn_baseline_mode(
    args: list[Any],
    ctx: dict[str, Any],
    func_ctx: FunctionContext | None,
) -> str:
    """
    baseline_mode() → str

    Return the current baseline mode for the agent: "LEARNING", "ACTIVE", or "STALE".
    Always returns "LEARNING" if no baseline data is available yet.

    Example: baseline_mode() == "ACTIVE"
    """
    baseline_profiles = ctx.get("_baseline_profiles", {})
    tenant_id = ctx.get("tenant_id", "")
    agent_id = ctx.get("event", {}).get("agent_id", "")
    key = f"{tenant_id}:{agent_id}"
    profile = baseline_profiles.get(key)
    if profile is None:
        return "LEARNING"
    return profile.mode

def fn_in_baseline_destinations(
    args: list[Any],
    ctx: dict[str, Any],
    func_ctx: FunctionContext | None,
) -> bool:
    """
    in_baseline_destinations(ip) → bool

    Check whether an IP/hostname is in the agent's known baseline destinations.
    Returns False if no baseline exists (conservative — triggers the rule).

    Example: NOT in_baseline_destinations(event.dest_ip)
    """
    ip = str(args[0])
    baseline_profiles = ctx.get("_baseline_profiles", {})
    tenant_id = ctx.get("tenant_id", "")
    agent_id = ctx.get("event", {}).get("agent_id", "")
    key = f"{tenant_id}:{agent_id}"
    profile = baseline_profiles.get(key)
    if profile is None:
        return False
    return ip in profile.known_destinations

def fn_baseline_p95(
    args: list[Any],
    ctx: dict[str, Any],
    func_ctx: FunctionContext | None,
) -> float:
    """
    baseline_p95(metric_name) → float

    Return the P95 value of a metric from the agent's baseline.
    Returns 0.0 if no baseline or metric data is available.

    Example: event.bytes_sent > baseline_p95("bytes_sent_total_1h") * 3
    """
    metric = str(args[0])
    baseline_profiles = ctx.get("_baseline_profiles", {})
    tenant_id = ctx.get("tenant_id", "")
    agent_id = ctx.get("event", {}).get("agent_id", "")
    key = f"{tenant_id}:{agent_id}"
    profile = baseline_profiles.get(key)
    if profile is None:
        return 0.0
    mb = profile.metrics.get(metric)
    if mb is None:
        return 0.0
    return mb.p95

def fn_baseline_zscore(
    args: list[Any],
    ctx: dict[str, Any],
    func_ctx: FunctionContext | None,
) -> float:
    """
    baseline_zscore(metric_name, value) → float

    Return the z-score of a value relative to the agent's baseline for that metric.
    Returns 0.0 if no baseline or metric data is available, or std is 0.

    Example: baseline_zscore("event_count_1h", count("TOOL_CALL", "1h")) > 3.0
    """
    metric = str(args[0])
    value = float(args[1])
    baseline_profiles = ctx.get("_baseline_profiles", {})
    tenant_id = ctx.get("tenant_id", "")
    agent_id = ctx.get("event", {}).get("agent_id", "")
    key = f"{tenant_id}:{agent_id}"
    profile = baseline_profiles.get(key)
    if profile is None:
        return 0.0
    mb = profile.metrics.get(metric)
    if mb is None or mb.std == 0:
        return 0.0
    return (value - mb.mean) / mb.std

# ── Trust Score Built-in Function (K3) ───────────────────────────────────────

def fn_trust_score(
    args: list[Any],
    ctx: dict[str, Any],
    func_ctx: FunctionContext | None,
) -> float:
    """
    trust_score(entity_id, entity_type) → float

    Query the trust score for an entity from the Rust trust engine.
    Returns 0.5 (neutral) if the engine is unavailable — graceful degradation.

    entity_type: "agent", "tool", "resource", "network_dest"

    Example:
        trust_score(event.agent_id, "agent") < 0.3
        trust_score(event.tool_name, "tool") < 0.4
    """
    import asyncio

    if len(args) < 2:
        return 0.5  # neutral fallback

    entity_id = str(args[0])
    entity_type = str(args[1])
    tenant_id = ctx.get("tenant_id", "")

    if not entity_id or not tenant_id:
        return 0.5

    # Try to get the trust client from context (injected by engine).
    trust_client = ctx.get("_trust_client")

    if trust_client is None:
        try:
            from app.services.trust_client import get_trust_client

            trust_client = get_trust_client()
        except ImportError:
            return 0.5

    # ── Check pre-fetched cache first (populated by async consumer) ──
    trust_cache: dict[str, float] | None = ctx.get("_trust_scores")
    if trust_cache is not None:
        cache_key = f"{entity_id}:{entity_type}"
        if cache_key in trust_cache:
            return trust_cache[cache_key]

    # ── Async call from synchronous PRL evaluation context ──
    # The PRL evaluator is synchronous but typically invoked from an
    # async consumer running on an event loop.  Using
    # ``run_coroutine_threadsafe`` on the *same* loop and blocking
    # with ``future.result()`` deadlocks because the loop cannot
    # process the scheduled coroutine while the calling thread is
    # blocked.
    #
    # Fix: always spawn a *new* event loop in a worker thread via the
    # thread-pool executor so the calling thread is not the loop thread.
    try:
        import concurrent.futures

        def _fetch_score():
            """Run in a separate thread with its own event loop."""
            return asyncio.run(
                trust_client.get_trust_score(tenant_id, entity_id, entity_type),
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(_fetch_score)
            result = future.result(timeout=3.0)
    except Exception:
        return 0.5

    return result.trust_score
