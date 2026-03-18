# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Q2: Retrain Scheduler.

Monitors per-tenant label accumulation and triggers automatic model
retraining when sufficient new labeled data has arrived. Provides
rate limiting to prevent excessive retraining and manages concurrent
retrain limits.

Design principles:
  - Non-blocking: check() is fast and returns immediately
  - Thread-safe: safe to call from multiple consumers
  - Rate-limited: respects min_retrain_gap and max_concurrent limits
  - Fail-safe: if retrain fails, current model keeps serving
  - Auditable: all decisions are logged with structured context

Security:
  - No tenant can trigger more than one concurrent retrain
  - Label counts are validated (non-negative, bounded)
  - Scheduler state is local (no external persistence needed)
"""

from __future__ import annotations

import threading
import time
from typing import Any

import structlog

from ml.config import get_ml_config

logger = structlog.get_logger("phantex.ml.retrain.scheduler")

class RetrainTrigger:
    """Decision object from the scheduler."""

    __slots__ = ("should_retrain", "tenant_id", "new_labels", "reason", "total_labels")

    def __init__(
        self,
        should_retrain: bool,
        tenant_id: str,
        new_labels: int,
        reason: str,
        total_labels: int = 0,
    ) -> None:
        self.should_retrain = should_retrain
        self.tenant_id = tenant_id
        self.new_labels = new_labels
        self.reason = reason
        self.total_labels = total_labels

    def to_dict(self) -> dict[str, Any]:
        return {
            "should_retrain": self.should_retrain,
            "tenant_id": self.tenant_id,
            "new_labels": self.new_labels,
            "total_labels": self.total_labels,
            "reason": self.reason,
        }

class RetrainScheduler:
    """Monitor label accumulation and trigger retrains.

    Usage:
        scheduler = RetrainScheduler()

        # When new labels are confirmed:
        scheduler.record_labels(tenant_id, count=5)

        # Periodic check (e.g., from a background task):
        triggers = scheduler.check_all()
        for trigger in triggers:
            if trigger.should_retrain:
                pipeline.retrain(trigger.tenant_id)
                scheduler.mark_retrain_started(trigger.tenant_id)
    """

    def __init__(self) -> None:
        cfg = get_ml_config().auto_retrain
        self._min_new_labels = cfg.min_new_labels
        self._min_retrain_gap = cfg.min_retrain_gap_seconds
        self._max_concurrent = cfg.max_concurrent_retrains
        self._enabled = cfg.enabled

        self._lock = threading.Lock()

        # Per-tenant state
        self._new_label_counts: dict[str, int] = {}  # Labels since last retrain
        self._total_label_counts: dict[str, int] = {}  # Total historical labels
        self._last_retrain_time: dict[str, float] = {}  # Timestamp of last retrain
        self._active_retrains: set[str] = set()  # Currently retraining tenants

        # Defense-in-depth: cap tracked tenants to prevent unbounded growth
        self._MAX_TRACKED_TENANTS = 50_000
        # Cap per-call label count to prevent arithmetic abuse
        self._MAX_LABEL_BATCH = 10_000

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        self._enabled = value

    def record_labels(self, tenant_id: str, count: int = 1) -> None:
        """Record newly confirmed labels for a tenant.

        Called when an analyst confirms/rejects an alert (creating a training label).

        Args:
            tenant_id: Tenant identifier.
            count: Number of new labels (must be positive).
        """
        if count <= 0:
            return

        # Clamp to prevent arithmetic abuse
        count = min(count, self._MAX_LABEL_BATCH)

        with self._lock:
            # Evict oldest tenant if at capacity
            if tenant_id not in self._new_label_counts and len(self._new_label_counts) >= self._MAX_TRACKED_TENANTS:
                # Evict tenant with oldest last_retrain_time (or arbitrary if none)
                oldest_tid = min(
                    self._new_label_counts,
                    key=lambda t: self._last_retrain_time.get(t, 0.0),
                )
                self._new_label_counts.pop(oldest_tid, None)
                self._total_label_counts.pop(oldest_tid, None)
                self._last_retrain_time.pop(oldest_tid, None)

            self._new_label_counts[tenant_id] = self._new_label_counts.get(tenant_id, 0) + count
            self._total_label_counts[tenant_id] = self._total_label_counts.get(tenant_id, 0) + count

    def check(self, tenant_id: str) -> RetrainTrigger:
        """Check if a specific tenant should retrain.

        Returns a RetrainTrigger with the decision and reason.
        """
        with self._lock:
            if not self._enabled:
                return RetrainTrigger(
                    should_retrain=False,
                    tenant_id=tenant_id,
                    new_labels=self._new_label_counts.get(tenant_id, 0),
                    reason="auto_retrain_disabled",
                    total_labels=self._total_label_counts.get(tenant_id, 0),
                )

            new_labels = self._new_label_counts.get(tenant_id, 0)
            total_labels = self._total_label_counts.get(tenant_id, 0)

            # Check if already retraining
            if tenant_id in self._active_retrains:
                return RetrainTrigger(
                    should_retrain=False,
                    tenant_id=tenant_id,
                    new_labels=new_labels,
                    reason="retrain_already_in_progress",
                    total_labels=total_labels,
                )

            # Check concurrent retrain limit
            if len(self._active_retrains) >= self._max_concurrent:
                return RetrainTrigger(
                    should_retrain=False,
                    tenant_id=tenant_id,
                    new_labels=new_labels,
                    reason="max_concurrent_retrains_reached",
                    total_labels=total_labels,
                )

            # Check minimum label threshold
            if new_labels < self._min_new_labels:
                return RetrainTrigger(
                    should_retrain=False,
                    tenant_id=tenant_id,
                    new_labels=new_labels,
                    reason="insufficient_new_labels",
                    total_labels=total_labels,
                )

            # Check rate limit
            last_retrain = self._last_retrain_time.get(tenant_id, 0)
            if time.time() - last_retrain < self._min_retrain_gap:
                return RetrainTrigger(
                    should_retrain=False,
                    tenant_id=tenant_id,
                    new_labels=new_labels,
                    reason="rate_limited",
                    total_labels=total_labels,
                )

            # All checks passed — trigger retrain
            return RetrainTrigger(
                should_retrain=True,
                tenant_id=tenant_id,
                new_labels=new_labels,
                reason="threshold_met",
                total_labels=total_labels,
            )

    def check_all(self) -> list[RetrainTrigger]:
        """Check all tenants with accumulated labels.

        Returns list of RetrainTrigger for tenants that should retrain.
        """
        with self._lock:
            tenant_ids = list(self._new_label_counts.keys())

        triggers = []
        for tid in tenant_ids:
            trigger = self.check(tid)
            if trigger.should_retrain:
                triggers.append(trigger)
        return triggers

    def mark_retrain_started(self, tenant_id: str) -> None:
        """Mark that a retrain has been initiated for a tenant.

        Must be called BEFORE starting the retrain to prevent
        duplicate triggers.
        """
        with self._lock:
            self._active_retrains.add(tenant_id)
            logger.info(
                "retrain_started",
                tenant_id=tenant_id,
                new_labels=self._new_label_counts.get(tenant_id, 0),
            )

    def mark_retrain_completed(
        self,
        tenant_id: str,
        *,
        success: bool = True,
        reset_labels: bool = True,
    ) -> None:
        """Mark that a retrain has completed for a tenant.

        Args:
            tenant_id: Tenant that finished retraining.
            success: Whether the retrain succeeded.
            reset_labels: If True, resets the new_label_count to 0.
        """
        with self._lock:
            self._active_retrains.discard(tenant_id)
            self._last_retrain_time[tenant_id] = time.time()
            if success and reset_labels:
                self._new_label_counts[tenant_id] = 0

        logger.info(
            "retrain_completed",
            tenant_id=tenant_id,
            success=success,
        )

    def get_status(self, tenant_id: str) -> dict[str, Any]:
        """Get retrain status for a tenant."""
        with self._lock:
            return {
                "new_labels": self._new_label_counts.get(tenant_id, 0),
                "total_labels": self._total_label_counts.get(tenant_id, 0),
                "last_retrain": self._last_retrain_time.get(tenant_id),
                "is_retraining": tenant_id in self._active_retrains,
                "active_retrains": len(self._active_retrains),
                "max_concurrent": self._max_concurrent,
                "enabled": self._enabled,
            }

    def get_all_status(self) -> dict[str, dict[str, Any]]:
        """Get retrain status for all tracked tenants."""
        with self._lock:
            tenant_ids = set(self._new_label_counts.keys()) | set(self._total_label_counts.keys())
        return {tid: self.get_status(tid) for tid in sorted(tenant_ids)}
