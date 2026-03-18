# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Formal Verification Service

Exposes verification status and on-demand check execution for
TLA+, Alloy, and Z3 specs.  The Z3 checks run in-process (Python);
TLA+ and Alloy are external Java tools invoked as subprocesses.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

logger = logging.getLogger("phantex.verification")

# ── Path constants ───────────────────────────────────────────────────
# On host: backend/app/services/… → parents[3] = repo root
# In Docker: /app/app/services/… → parents[2] = /app
_REPO_ROOT = Path(__file__).resolve().parents[3]
if not (_REPO_ROOT / "verification").is_dir():
    _REPO_ROOT = Path(__file__).resolve().parents[2]
_VERIFICATION_DIR = _REPO_ROOT / "verification"
_TLA_DIR = _VERIFICATION_DIR / "tla"
_ALLOY_DIR = _VERIFICATION_DIR / "alloy"
_Z3_DIR = _VERIFICATION_DIR / "z3"

# Defence-in-depth: max file size for source/result reads (1 MB)
_MAX_READ_BYTES = 1_048_576

# Concurrency guard: at most 1 Z3 subprocess at a time (R2 — DoS prevention)
_z3_semaphore = asyncio.Semaphore(1)

# In-memory cache for last on-demand Z3 result (survives until restart)
_last_z3_result: dict | None = None

@dataclass
class SpecInfo:
    """Metadata about a single formal spec."""

    tool: str  # "tla+" | "alloy" | "z3"
    name: str
    file: str
    properties: list[str]
    description: str

@dataclass
class CheckResult:
    """Result of running a single spec check."""

    spec: str
    tool: str
    passed: bool
    checks_total: int
    checks_passed: int
    elapsed_ms: float
    details: list[dict] = field(default_factory=list)
    error: str | None = None

# ── Known specs ────────────────────────────────────────────────────
SPECS: list[SpecInfo] = [
    SpecInfo(
        tool="tla+",
        name="rule_evaluation",
        file="verification/tla/rule_evaluation.tla",
        properties=[
            "TypeOK",
            "NoSilentDrops",
            "MatchSetValid",
            "MatchCountBounded",
            "SnapshotIsolation",
            "EventualCompletion",
            "EvalTerminates",
        ],
        description="PRL rule evaluation pipeline — safety + liveness",
    ),
    SpecInfo(
        tool="tla+",
        name="policy_engine",
        file="verification/tla/policy_engine.tla",
        properties=[
            "TypeOK",
            "KillSwitchSupremacy",
            "ConsistentSnapshot",
            "VersionMonotonic",
            "EscalationMonotonic",
            "AuditComplete",
            "DeletedNeverMatch",
            "AlertEventualCompletion",
            "PipelineProgress",
        ],
        description="Auto-response policy engine — kill switch supremacy, audit completeness",
    ),
    SpecInfo(
        tool="alloy",
        name="sandbox_isolation",
        file="verification/alloy/sandbox_isolation.als",
        properties=[
            "ResourceContainment",
            "QuarantineCapture",
            "NoLateralMovement",
            "CrossTenantIsolation",
            "ToolMediationSafety",
        ],
        description="Agent sandbox isolation — containment, quarantine, no lateral movement",
    ),
    SpecInfo(
        tool="z3",
        name="trust_graph",
        file="verification/z3/trust_graph.py",
        properties=[
            "INV-1: Monotonic decrease under adversarial conditions",
            "INV-2: Tenant isolation in propagation",
            "INV-3: No trust manipulation via graph injection",
            "INV-4: Trust score boundedness [0,1]",
            "INV-5: Decay convergence to neutral",
        ],
        description="Trust graph scoring engine — invariants proven via SMT solver",
    ),
]

def list_specs() -> list[dict]:
    """Return metadata for all known formal specs."""
    return [asdict(s) for s in SPECS]

async def run_z3_checks() -> CheckResult:
    """Run Z3 trust graph verification in a subprocess (safe isolation)."""
    z3_script = _Z3_DIR / "trust_graph.py"
    if not z3_script.exists():
        return CheckResult(
            spec="trust_graph",
            tool="z3",
            passed=False,
            checks_total=0,
            checks_passed=0,
            elapsed_ms=0,
            error="Z3 verification script not found on server",
        )

    if not _z3_semaphore.locked():
        pass  # fast path
    else:
        logger.warning("Z3 check already in progress — waiting for semaphore")

    start = time.monotonic()
    async with _z3_semaphore:
        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable,
                str(z3_script),
                "--json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(_Z3_DIR),
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
            elapsed = (time.monotonic() - start) * 1000

            if proc.returncode is not None and proc.returncode != 0 and not stdout:
                return CheckResult(
                    spec="trust_graph",
                    tool="z3",
                    passed=False,
                    checks_total=0,
                    checks_passed=0,
                    elapsed_ms=round(elapsed, 2),
                    error=stderr.decode(errors="replace")[:500],
                )

            data = json.loads(stdout.decode())
            checks = data.get("checks", [])
            passed_count = sum(1 for c in checks if c.get("result") == "proved")

            result = CheckResult(
                spec="trust_graph",
                tool="z3",
                passed=data.get("passed", False),
                checks_total=len(checks),
                checks_passed=passed_count,
                elapsed_ms=round(elapsed, 2),
                details=checks,
            )
            # Cache for /results endpoint
            global _last_z3_result
            _last_z3_result = data
            return result
        except TimeoutError:
            return CheckResult(
                spec="trust_graph",
                tool="z3",
                passed=False,
                checks_total=0,
                checks_passed=0,
                elapsed_ms=60000,
                error="Z3 check timed out after 60s",
            )
        except Exception as exc:
            return CheckResult(
                spec="trust_graph",
                tool="z3",
                passed=False,
                checks_total=0,
                checks_passed=0,
                elapsed_ms=0,
                error=str(exc)[:500],
            )

def get_spec_source(spec_name: str) -> str | None:
    """Read the source of a spec file (for dashboard display)."""
    for s in SPECS:
        if s.name == spec_name:
            full_path = _REPO_ROOT / s.file
            if full_path.exists():
                if full_path.stat().st_size > _MAX_READ_BYTES:
                    return "(file too large to display)"
                return full_path.read_text(encoding="utf-8", errors="replace")
            return None
    return None

def get_last_results() -> dict:
    """Read cached CI results from results directories if available."""
    results = {}

    # TLA+ results
    tla_summary = _TLA_DIR / "results" / "summary.jsonl"
    if tla_summary.exists() and tla_summary.stat().st_size <= _MAX_READ_BYTES:
        tla_data = []
        for line in tla_summary.read_text().strip().splitlines():
            with contextlib.suppress(json.JSONDecodeError):
                tla_data.append(json.loads(line))
        results["tla+"] = tla_data

    # Z3 results — file first, then in-memory cache from on-demand runs
    z3_results = _Z3_DIR / "results.json"
    if z3_results.exists() and z3_results.stat().st_size <= _MAX_READ_BYTES:
        with contextlib.suppress(json.JSONDecodeError):
            results["z3"] = json.loads(z3_results.read_text())
    elif _last_z3_result is not None:
        results["z3"] = _last_z3_result

    # Alloy results (metadata only — no file content read)
    alloy_log = _ALLOY_DIR / "results" / "alloy_sandbox.log"
    if alloy_log.exists():
        log_size = alloy_log.stat().st_size
        results["alloy"] = {"log_exists": True, "log_size": min(log_size, _MAX_READ_BYTES)}

    return results
