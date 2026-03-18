# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Shadow Mode for Model Canary (J3).

When a new model is deployed, it runs in shadow mode for a configurable
period. During shadow mode:
  - Scores are computed but NOT acted on (no alerts created)
  - FPR is tracked against the existing model
  - If shadow FPR exceeds threshold → reject new model, keep old
"""

from __future__ import annotations

import time
from typing import Any

import structlog

from ml.config import get_ml_config

logger = structlog.get_logger("phantex.ml.serving.shadow")

class ShadowModeTracker:
    """Tracks shadow mode state for new model versions."""

    def __init__(self, max_scores_per_tenant: int = 50_000) -> None:
        cfg = get_ml_config().inference
        self._duration = cfg.shadow_duration_seconds
        self._max_fpr = get_ml_config().ensemble.shadow_fpr_max
        self._max_scores = max_scores_per_tenant

        # Per-tenant shadow state
        self._shadow_start: dict[str, float] = {}  # tenant → start timestamp
        self._shadow_version: dict[str, str] = {}  # tenant → model version
        self._shadow_scores: dict[str, list[float]] = {}  # tenant → list of scores
        self._shadow_alerts: dict[str, int] = {}  # tenant → alert count
        self._shadow_total: dict[str, int] = {}  # tenant → total scored

    def start_shadow(self, tenant_id: str, version: str) -> None:
        """Begin shadow mode for a new model version."""
        self._shadow_start[tenant_id] = time.time()
        self._shadow_version[tenant_id] = version
        self._shadow_scores[tenant_id] = []
        self._shadow_alerts[tenant_id] = 0
        self._shadow_total[tenant_id] = 0

        logger.info(
            "shadow_mode_started",
            tenant_id=tenant_id,
            version=version,
            duration_seconds=self._duration,
        )

    def is_in_shadow(self, tenant_id: str) -> bool:
        """Check if tenant is currently in shadow mode."""
        start = self._shadow_start.get(tenant_id)
        if start is None:
            return False
        return not time.time() - start > self._duration

    def record_score(self, tenant_id: str, score: float, should_alert: bool) -> None:
        """Record a shadow-mode score for fpr tracking."""
        if tenant_id not in self._shadow_scores:
            return
        self._shadow_scores[tenant_id].append(score)
        # HARD-03: Cap score list to prevent unbounded memory growth
        if len(self._shadow_scores[tenant_id]) > self._max_scores:
            self._shadow_scores[tenant_id] = self._shadow_scores[tenant_id][-self._max_scores :]
        self._shadow_total[tenant_id] = self._shadow_total.get(tenant_id, 0) + 1
        if should_alert:
            self._shadow_alerts[tenant_id] = self._shadow_alerts.get(tenant_id, 0) + 1

    def evaluate(self, tenant_id: str) -> dict[str, Any]:
        """Evaluate shadow mode results.

        Returns:
            Dict with 'passed', 'alert_rate', 'total_scored', 'version'.
            Note: alert_rate = alerts/total (not FPR, since we don't have
            ground truth labels at scoring time).
        """
        total = self._shadow_total.get(tenant_id, 0)
        alerts = self._shadow_alerts.get(tenant_id, 0)
        version = self._shadow_version.get(tenant_id, "unknown")

        alert_rate = (alerts / total) if total > 0 else 0.0
        passed = alert_rate <= self._max_fpr

        result = {
            "passed": passed,
            "alert_rate": alert_rate,
            "total_scored": total,
            "total_alerts": alerts,
            "version": version,
            "max_alert_rate": self._max_fpr,
        }

        if passed:
            logger.info("shadow_mode_passed", tenant_id=tenant_id, **result)
        else:
            logger.warning("shadow_mode_failed", tenant_id=tenant_id, **result)

        # Clean up shadow state
        self._shadow_start.pop(tenant_id, None)
        self._shadow_version.pop(tenant_id, None)
        self._shadow_scores.pop(tenant_id, None)
        self._shadow_alerts.pop(tenant_id, None)
        self._shadow_total.pop(tenant_id, None)

        return result
