# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Baseline Comparator (J4).

Compares real-time feature values against the agent's established
behavioral baseline. Generates baseline deviation alerts when values
exceed configured thresholds (default: > mean + 3σ).
"""

from __future__ import annotations

import math
from datetime import UTC
from typing import Any

import structlog

from ml.baseline.builder import BASELINE_METRICS
from ml.baseline.models import BaselineProfile
from ml.config import get_ml_config

logger = structlog.get_logger("phantex.ml.baseline.comparator")

class BaselineComparator:
    """Compare real-time agent features against learned baselines."""

    def __init__(self) -> None:
        self._cfg = get_ml_config().baseline

    def compare(
        self,
        profile: BaselineProfile,
        features: dict[str, float],
        event: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Compare features against baseline and return deviation alerts.

        Only fires alerts when the profile is in ACTIVE mode.
        Returns a list of alert dicts (may be empty).
        """
        if profile.mode != "ACTIVE":
            return []

        alerts: list[dict[str, Any]] = []

        # ── Metric z-score checks ────────────────────────────────────
        for metric_name in BASELINE_METRICS:
            value = features.get(metric_name, 0.0)
            mb = profile.metrics.get(metric_name)
            if mb is None or mb.count < 10:
                continue

            z = self.zscore(mb.mean, mb.std, value)
            if z > self._cfg.sigma_threshold:
                # Determine severity based on z-score
                if z > 6.0:
                    severity = "critical"
                elif z > 4.5:
                    severity = "high"
                else:
                    severity = "medium"

                alerts.append(
                    {
                        "type": "baseline_deviation",
                        "metric": metric_name,
                        "value": value,
                        "baseline_mean": mb.mean,
                        "baseline_std": mb.std,
                        "z_score": z,
                        "severity": severity,
                        "message": (
                            f"{metric_name} = {value:.1f} is {z:.1f}σ above "
                            f"baseline (mean={mb.mean:.1f}, std={mb.std:.1f})"
                        ),
                    }
                )

        # ── P95 exceedance check ─────────────────────────────────────
        for metric_name in ("bytes_sent_total_1h",):
            value = features.get(metric_name, 0.0)
            mb = profile.metrics.get(metric_name)
            if mb is None or mb.p95 == 0:
                continue

            if value > mb.p95 * self._cfg.p95_multiplier:
                alerts.append(
                    {
                        "type": "baseline_p95_exceedance",
                        "metric": metric_name,
                        "value": value,
                        "baseline_p95": mb.p95,
                        "multiplier": self._cfg.p95_multiplier,
                        "severity": "high",
                        "message": (
                            f"{metric_name} = {value:.0f} exceeds "
                            f"{self._cfg.p95_multiplier}× baseline P95 ({mb.p95:.0f})"
                        ),
                    }
                )

        # ── New network destination check ────────────────────────────
        if event:
            dest = event.get("dest_ip", "")
            if dest and dest not in profile.known_destinations:
                alerts.append(
                    {
                        "type": "new_destination",
                        "dest_ip": dest,
                        "known_count": len(profile.known_destinations),
                        "severity": "medium",
                        "message": (
                            f"Agent connected to new destination {dest} "
                            f"(not in {len(profile.known_destinations)} known destinations)"
                        ),
                    }
                )

        # ── Event type distribution shift (Jensen-Shannon divergence) ─
        if event and profile.event_type_histogram:
            etype = event.get("event_type", "")
            if etype:
                js_div = self._js_divergence(profile.event_type_histogram, etype)
                if js_div > self._cfg.js_divergence_threshold:
                    alerts.append(
                        {
                            "type": "distribution_shift",
                            "js_divergence": js_div,
                            "threshold": self._cfg.js_divergence_threshold,
                            "severity": "medium",
                            "message": (f"Event type distribution shift detected (JS divergence = {js_div:.3f})"),
                        }
                    )

        # ── Active hours anomaly (activity outside normal hours) ─────
        if event and profile.hour_histogram:
            from datetime import datetime

            ts = event.get("timestamp_epoch")
            if ts:
                dt = datetime.fromtimestamp(float(ts), tz=UTC)
                hour = dt.hour
                total_events = sum(profile.hour_histogram.values())
                hour_count = profile.hour_histogram.get(hour, 0)
                # If this hour represents < 1% of historical activity
                # and we have enough data (100+ events), flag it
                if total_events >= 100 and hour_count / total_events < 0.01:
                    alerts.append(
                        {
                            "type": "unusual_hour",
                            "hour": hour,
                            "hour_fraction": hour_count / total_events,
                            "severity": "low",
                            "message": (
                                f"Activity at hour {hour:02d} UTC is unusual "
                                f"({hour_count}/{total_events} historical events = "
                                f"{100 * hour_count / total_events:.1f}%)"
                            ),
                        }
                    )

        # ── Novel tool-sequence bigram detection ─────────────────────
        if event and profile.top_bigrams:
            etype = event.get("event_type", "")
            if etype and hasattr(event, "__prev_event_type__"):
                # In production, previous event type would be tracked;
                # for now, check against the stored bigram distribution.
                pass
            # Simplified: check the event-type histogram as a proxy for
            # sequence novelty — if the event type itself is rare AND
            # we have bigram data, flag potential novel pattern.
            if etype and etype not in profile.top_bigrams:
                total_bigrams = sum(profile.top_bigrams.values())
                if total_bigrams >= 50:
                    alerts.append(
                        {
                            "type": "novel_sequence_pattern",
                            "event_type": etype,
                            "known_bigrams": len(profile.top_bigrams),
                            "severity": "low",
                            "message": (
                                f"Event type '{etype}' not seen in "
                                f"any tracked bigram patterns "
                                f"({len(profile.top_bigrams)} known bigrams)"
                            ),
                        }
                    )

        return alerts

    @staticmethod
    def zscore(mean: float, std: float, value: float) -> float:
        """Compute z-score. Returns 0 if std is 0."""
        if std == 0:
            return 0.0
        return (value - mean) / std

    @staticmethod
    def in_baseline_destinations(ip: str, profile: BaselineProfile) -> bool:
        """Check if an IP is in the agent's known destinations."""
        return ip in profile.known_destinations

    @staticmethod
    def baseline_p95(profile: BaselineProfile, metric: str) -> float:
        """Get the P95 value for a metric from the baseline."""
        mb = profile.metrics.get(metric)
        if mb is None:
            return 0.0
        return mb.p95

    def baseline_zscore(self, profile: BaselineProfile, metric: str, value: float) -> float:
        """Compute z-score of a value against the baseline."""
        mb = profile.metrics.get(metric)
        if mb is None:
            return 0.0
        return self.zscore(mb.mean, mb.std, value)

    @staticmethod
    def _js_divergence(histogram: dict[str, int], new_event_type: str) -> float:
        """Compute Jensen-Shannon divergence between historical distribution
        and a single new event type (simplified for real-time use).

        In production, this would compare windowed distributions.
        Here we use a proxy: information content of the new event type
        relative to the historical distribution.
        """
        total = sum(histogram.values())
        if total == 0:
            return 0.0

        # Probability of the new event type in historical data
        p = histogram.get(new_event_type, 0) / total

        if p == 0:
            # Never-seen event type — high divergence
            return 1.0

        # Information content: -log2(p) normalized by max possible
        max_info = math.log2(max(len(histogram), 2))
        if max_info == 0:
            return 0.0
        info = -math.log2(p) / max_info
        return min(info, 1.0)
