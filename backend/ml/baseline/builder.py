# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Baseline Builder (J4).

Builds the initial baseline profile during the LEARNING phase.
Accumulates statistics (mean, std, p95, histograms) from feature
vectors over the learning window (default 7 days).
"""

from __future__ import annotations

import math
import time
from datetime import UTC
from typing import Any

import structlog

from ml.baseline.models import BaselineProfile, MetricBaseline
from ml.config import get_ml_config

logger = structlog.get_logger("phantex.ml.baseline.builder")

# Metrics to track in the baseline
BASELINE_METRICS = [
    "event_count_1h",
    "tool_call_count_1h",
    "file_read_count_1h",
    "network_connect_count_1h",
    "unique_tools_used_1h",
    "unique_files_accessed_1h",
    "unique_network_dests_1h",
    "bytes_sent_total_1h",
    "events_per_second_1m",
    "tool_calls_per_minute_1m",
]

class BaselineBuilder:
    """Build and manage per-agent behavioral baselines."""

    def __init__(self) -> None:
        self._cfg = get_ml_config().baseline

    def create_profile(self, tenant_id: str, agent_id: str) -> BaselineProfile:
        """Create a new baseline profile in LEARNING mode."""
        return BaselineProfile(
            agent_id=agent_id,
            tenant_id=tenant_id,
            mode="LEARNING",
        )

    def update_profile(
        self,
        profile: BaselineProfile,
        features: dict[str, float],
        event: dict[str, Any] | None = None,
        is_alert_flagged: bool = False,
    ) -> BaselineProfile:
        """Update a baseline profile with new feature data.

        In LEARNING mode: accumulates statistics.
        In ACTIVE mode: updates via exponential moving average.
        In STALE mode: resets to LEARNING.

        Args:
            profile: Current baseline profile.
            features: Feature vector dict.
            event: Raw event dict (for destination/histogram tracking).
            is_alert_flagged: True if this event triggered a PRL rule alert.
                When alert_aware_learning is enabled, flagged events are
                excluded from baseline metric computation during LEARNING
                (destinations/histograms still updated).
        """
        now = time.time()
        profile.last_event_at = now

        # Check for stale → learning transition
        if profile.mode == "STALE":
            profile = self.create_profile(profile.tenant_id, profile.agent_id)
            logger.info(
                "baseline_reset_from_stale",
                agent_id=profile.agent_id,
                tenant_id=profile.tenant_id,
            )

        # Check for learning → active transition
        if profile.mode == "LEARNING":
            learning_elapsed = now - profile.learning_start
            time_met = learning_elapsed >= self._cfg.learning_days * 86_400
            # Require minimum events across all tracked metrics
            min_count = self._get_min_metric_count(profile)
            events_met = min_count >= self._cfg.min_learning_events

            # Early graduation: if variance has stabilized and we have enough events
            early_grad = False
            if self._cfg.early_graduation and not time_met and min_count >= self._cfg.early_graduation_min_events:
                early_grad = self._check_variance_stability(profile)

            if (time_met and events_met) or early_grad:
                profile.mode = "ACTIVE"
                logger.info(
                    "baseline_activated",
                    agent_id=profile.agent_id,
                    tenant_id=profile.tenant_id,
                    learning_days=learning_elapsed / 86_400,
                    total_events=min_count,
                    early_graduation=early_grad,
                )

        # Skip metric updates for PRL-flagged events during LEARNING
        skip_metrics = is_alert_flagged and profile.mode == "LEARNING" and self._cfg.alert_aware_learning

        if not skip_metrics:
            # Update metric baselines
            for metric_name in BASELINE_METRICS:
                value = features.get(metric_name, 0.0)
                if metric_name not in profile.metrics:
                    profile.metrics[metric_name] = MetricBaseline()
                mb = profile.metrics[metric_name]

                if profile.mode == "LEARNING":
                    self._update_learning(mb, value)
                else:
                    self._update_ema(mb, value)

        # Always update network destinations and histograms (even for flagged events)
        if event:
            dest = event.get("dest_ip", "")
            if dest:
                profile.known_destinations.add(dest)

            # Update event type histogram
            etype = event.get("event_type", "")
            if etype:
                profile.event_type_histogram[etype] = profile.event_type_histogram.get(etype, 0) + 1

            # Update hour histogram
            from datetime import datetime

            dt = datetime.fromtimestamp(now, tz=UTC)
            profile.hour_histogram[dt.hour] = profile.hour_histogram.get(dt.hour, 0) + 1

        return profile

    def check_stale(self, profile: BaselineProfile) -> BaselineProfile:
        """Check if a profile should be marked as STALE."""
        if profile.mode == "STALE":
            return profile
        elapsed = time.time() - profile.last_event_at
        if elapsed > self._cfg.stale_days * 86_400:
            profile.mode = "STALE"
            logger.info(
                "baseline_stale",
                agent_id=profile.agent_id,
                tenant_id=profile.tenant_id,
                inactive_days=elapsed / 86_400,
            )
        return profile

    @staticmethod
    def _update_learning(mb: MetricBaseline, value: float) -> None:
        """Update metric during LEARNING phase (Welford's online algorithm)."""
        mb.count += 1
        n = mb.count

        if n == 1:
            mb.mean = value
            mb.std = 0.0
            mb.p95 = value
            mb.min_val = value
            mb.max_val = value
            return

        # Online mean + variance (Welford)
        old_mean = mb.mean
        mb.mean = old_mean + (value - old_mean) / n
        # Incremental variance: use running sum of squared differences
        # We track std directly, recalculate from running values
        old_var = mb.std**2
        new_var = old_var + ((value - old_mean) * (value - mb.mean) - old_var) / n
        mb.std = math.sqrt(max(new_var, 0.0))

        # p95 approximation: track max and use 95th rule of thumb
        mb.min_val = min(mb.min_val, value)
        mb.max_val = max(mb.max_val, value)
        # Rough p95 approximation: mean + 1.645 * std (for normal dist)
        mb.p95 = mb.mean + 1.645 * mb.std

    def _update_ema(self, mb: MetricBaseline, value: float) -> None:
        """Update metric during ACTIVE phase (exponential moving average).

        IMPORTANT: diff must be computed BEFORE updating the mean,
        otherwise variance is systematically underestimated which
        inflates z-scores and causes false alerts.
        """
        alpha = self._cfg.ema_alpha
        mb.count += 1
        # Compute residual against OLD mean (before update)
        diff = value - mb.mean
        # Update mean via EMA
        mb.mean = alpha * value + (1 - alpha) * mb.mean
        # Update variance via EMA using pre-update residual
        old_var = mb.std**2
        new_var = (1 - alpha) * (old_var + alpha * (diff**2))
        mb.std = math.sqrt(max(new_var, 0.0))
        mb.p95 = mb.mean + 1.645 * mb.std
        mb.min_val = min(mb.min_val, value)
        mb.max_val = max(mb.max_val, value)

    @staticmethod
    def _get_min_metric_count(profile: BaselineProfile) -> int:
        """Return the minimum observation count across all tracked metrics.

        If no metrics have been recorded yet, returns 0.
        """
        if not profile.metrics:
            return 0
        return min(mb.count for mb in profile.metrics.values())

    def _check_variance_stability(self, profile: BaselineProfile) -> bool:
        """Check if variance has stabilized across all metrics.

        Stability is defined as: for every metric with count >= early_graduation_min_events,
        the relative change in std over the last ~10% of observations is below threshold.

        We approximate this by checking if std/mean (coefficient of variation) is
        small enough that adding more data won't significantly change the profile.
        For metrics with zero mean, we check absolute std < 1.0.
        """
        threshold = self._cfg.variance_stability_threshold
        stable_count = 0
        total_metrics = 0

        for mb in profile.metrics.values():
            if mb.count < self._cfg.early_graduation_min_events:
                continue
            total_metrics += 1
            if mb.mean != 0:
                cv = mb.std / abs(mb.mean) if abs(mb.mean) > 1e-10 else 0.0
                # Low coefficient of variation = stable
                if cv < threshold or mb.std < 1.0:
                    stable_count += 1
            else:
                # Zero mean — stable if std is very small
                if mb.std < 1.0:
                    stable_count += 1

        # All tracked metrics must be stable
        return total_metrics > 0 and stable_count == total_metrics
