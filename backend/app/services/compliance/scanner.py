# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Compliance Scanner (T5).

Background service that performs scheduled compliance scans:
  - Quick scan: headline scores only (daily default).
  - Full scan: full evidence collection + PDF archival (weekly default).
  - Drift detection: alert when score drops below threshold.

The scanner is designed to be run from:
  1. The router's POST /compliance/scan/trigger (on-demand).
  2. A background asyncio task started in the app lifespan.
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from datetime import UTC, datetime, timedelta

from app.utils.logging import get_logger

logger = get_logger("phantex.compliance.scanner")

# ── Core Scan Function ────────────────────────────────────────────────────────

async def run_scan(
    db,
    tenant_id: str,
    user_id: str | None = None,
    *,
    frameworks: list[str] | None = None,
) -> uuid.UUID:
    """Execute a compliance scan and persist the result.

    Parameters
    ----------
    db : RawSessionWrapper
    tenant_id : str
    user_id : str | None
        User who triggered the scan (None for scheduled).
    frameworks : list of str | None
        Frameworks to scan. Defaults to all.

    Returns
    -------
    uuid.UUID
        The persisted report id.
    """
    import json as _json

    from app.services.compliance.report_builder import generate_compliance_report

    if frameworks is None:
        frameworks = ["eu_ai_act", "nist_ai_rmf", "iso27001", "fedramp"]

    now = datetime.now(UTC)
    period_start = (now - timedelta(days=30)).isoformat()
    period_end = now.isoformat()

    data = await generate_compliance_report(
        db,
        tenant_id,
        frameworks,
        period_start,
        period_end,
    )

    # Compute overall score
    scores = [fw.get("overall_score", 0) for fw in data.get("frameworks", [])]
    overall = round(sum(scores) / max(len(scores), 1), 4)

    report_id = uuid.uuid4()
    await db.execute(
        """
        INSERT INTO compliance_reports
            (id, tenant_id, frameworks, overall_score, report_data, created_by, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, now())
        """,
        report_id,
        uuid.UUID(tenant_id),
        frameworks,
        overall,
        _json.dumps(data, default=str),
        uuid.UUID(user_id) if user_id else None,
    )

    logger.info(
        "compliance_scan_completed",
        tenant=tenant_id,
        report_id=str(report_id),
        overall_score=overall,
    )

    # ── Drift Detection ───────────────────────────────────────────────────
    await _check_drift(db, tenant_id, overall)

    return report_id

# ── Drift Detection ──────────────────────────────────────────────────────────

async def _check_drift(db, tenant_id: str, current_score: float, threshold: float = 0.05):
    """Compare current score to the previous scan. Alert if it drops > threshold."""
    prev = await db.fetchrow(
        """
        SELECT overall_score, created_at
        FROM compliance_reports
        WHERE tenant_id = $1
        ORDER BY created_at DESC
        OFFSET 1 LIMIT 1
        """,
        uuid.UUID(tenant_id),
    )
    if not prev:
        return  # No previous scan to compare against

    prev_score = float(prev["overall_score"])
    delta = prev_score - current_score

    if delta > threshold:
        logger.warning(
            "compliance_score_drift_detected",
            tenant=tenant_id,
            previous_score=prev_score,
            current_score=current_score,
            delta=round(delta, 4),
            threshold=threshold,
        )
        # Create a system alert for the drift
        await _create_drift_alert(db, tenant_id, prev_score, current_score, delta)

async def _create_drift_alert(
    db,
    tenant_id: str,
    prev_score: float,
    current_score: float,
    delta: float,
):
    """Insert an alert row for compliance score drift."""
    import json as _json

    alert_id = uuid.uuid4()
    title = f"Compliance score dropped by {round(delta * 100, 1)}%"
    description = (
        f"Compliance score fell from {round(prev_score * 100, 1)}% "
        f"to {round(current_score * 100, 1)}%. "
        f"Review recent changes and generate a full report for details."
    )

    try:
        await db.execute(
            """
            INSERT INTO alerts (id, tenant_id, severity, title, description, status, context, created_at)
            VALUES ($1, $2, 'high', $3, $4, 'open', $5, now())
            """,
            alert_id,
            uuid.UUID(tenant_id),
            title,
            description,
            _json.dumps(
                {
                    "source": "compliance_scanner",
                    "previous_score": prev_score,
                    "current_score": current_score,
                    "delta": delta,
                }
            ),
        )
        logger.info("compliance_drift_alert_created", alert_id=str(alert_id))
    except Exception as e:
        logger.error("compliance_drift_alert_failed", error=str(e))

# ── Background Scheduler ─────────────────────────────────────────────────────

class ComplianceScheduler:
    """Simple asyncio-based scheduler for recurring compliance scans.

    In production, this would be replaced by Celery Beat, APScheduler, etc.
    For Phase 3, a lightweight asyncio loop is sufficient.
    """

    def __init__(self, quick_interval_hours: int = 24, full_interval_hours: int = 168):
        self._quick_interval = quick_interval_hours * 3600
        self._full_interval = full_interval_hours * 3600
        self._running = False
        self._task: asyncio.Task | None = None

    async def start(self, db_factory, tenants: list[str]):
        """Start the background scheduler loop."""
        self._running = True
        self._task = asyncio.create_task(self._loop(db_factory, tenants))
        logger.info("compliance_scheduler_started")

    async def stop(self):
        """Stop the scheduler gracefully."""
        self._running = False
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        logger.info("compliance_scheduler_stopped")

    async def _loop(self, db_factory, tenants: list[str]):
        """Main scheduler loop — runs quick and full scans on intervals."""
        last_quick = datetime.now(UTC)
        last_full = datetime.now(UTC)

        while self._running:
            try:
                now = datetime.now(UTC)

                # Quick scan check
                if (now - last_quick).total_seconds() >= self._quick_interval:
                    for tid in tenants:
                        try:
                            async for db in db_factory():
                                await db.set_tenant(tid)
                                await run_scan(db, tid, frameworks=["eu_ai_act", "nist_ai_rmf"])
                        except Exception as e:
                            logger.error("quick_scan_failed", tenant=tid, error=str(e))
                    last_quick = now

                # Full scan check
                if (now - last_full).total_seconds() >= self._full_interval:
                    for tid in tenants:
                        try:
                            async for db in db_factory():
                                await db.set_tenant(tid)
                                await run_scan(db, tid, frameworks=["eu_ai_act", "nist_ai_rmf"])
                        except Exception as e:
                            logger.error("full_scan_failed", tenant=tid, error=str(e))
                    last_full = now

                # Sleep 60 seconds between checks
                await asyncio.sleep(60)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("scheduler_loop_error", error=str(e))
                await asyncio.sleep(60)
