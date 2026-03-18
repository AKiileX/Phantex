# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Meta-Alert Router (J5d).

Routes meta-detection alerts to appropriate channels.
Meta-alerts go to Phantex ops team only (not customer-visible).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import structlog

logger = structlog.get_logger("phantex.ml.meta.alerter")

class MetaAlertSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"

class MetaAlertType(StrEnum):
    ACCURACY_DRIFT = "accuracy_drift"
    PREDICTION_DRIFT = "prediction_drift"
    FEATURE_DRIFT = "feature_drift"
    EVASION_PATTERN = "evasion_pattern"
    EXTRACTION_PROBE = "extraction_probe"
    POISONING_SIGNAL = "poisoning_signal"
    MODEL_STALE = "model_stale"
    LATENCY_SPIKE = "latency_spike"

# Routing table: alert type → (severity, channels)
_ROUTING: dict[MetaAlertType, tuple[MetaAlertSeverity, list[str]]] = {
    MetaAlertType.ACCURACY_DRIFT: (MetaAlertSeverity.WARNING, ["ops_team"]),
    MetaAlertType.PREDICTION_DRIFT: (MetaAlertSeverity.WARNING, ["ops_team"]),
    MetaAlertType.FEATURE_DRIFT: (MetaAlertSeverity.INFO, ["ml_team"]),
    MetaAlertType.EVASION_PATTERN: (MetaAlertSeverity.CRITICAL, ["ops_team", "customer_admin"]),
    MetaAlertType.EXTRACTION_PROBE: (MetaAlertSeverity.CRITICAL, ["ops_team"]),
    MetaAlertType.POISONING_SIGNAL: (MetaAlertSeverity.CRITICAL, ["ml_team"]),
    MetaAlertType.MODEL_STALE: (MetaAlertSeverity.WARNING, ["ml_team"]),
    MetaAlertType.LATENCY_SPIKE: (MetaAlertSeverity.WARNING, ["ops_team"]),
}

@dataclass
class MetaAlert:
    """A meta-detection alert (internal, not customer-facing)."""

    alert_type: MetaAlertType
    severity: MetaAlertSeverity
    channels: list[str]
    message: str
    details: dict[str, Any]
    timestamp: float = 0.0
    id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "alert_type": self.alert_type.value,
            "severity": self.severity.value,
            "channels": self.channels,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp,
        }

class MetaAlerter:
    """Routes and stores meta-detection alerts."""

    def __init__(self, max_alerts: int = 10_000) -> None:
        self._alerts: list[MetaAlert] = []
        self._counter = 0
        self._max_alerts = max_alerts

    def fire(
        self,
        alert_type: MetaAlertType,
        message: str,
        details: dict[str, Any] | None = None,
        severity_override: MetaAlertSeverity | None = None,
    ) -> MetaAlert:
        """Create and route a meta-alert.

        Args:
            alert_type: Type of meta-alert.
            message: Human-readable description.
            details: Additional context.
            severity_override: Override default severity.

        Returns:
            The created MetaAlert.
        """
        default_severity, channels = _ROUTING.get(alert_type, (MetaAlertSeverity.INFO, ["ops_team"]))
        severity = severity_override or default_severity

        self._counter += 1
        alert = MetaAlert(
            alert_type=alert_type,
            severity=severity,
            channels=channels,
            message=message,
            details=details or {},
            timestamp=time.time(),
            id=f"meta-{self._counter:06d}",
        )

        self._alerts.append(alert)

        # HARD-04: Evict oldest alerts when exceeding capacity
        if len(self._alerts) > self._max_alerts:
            self._alerts = self._alerts[-self._max_alerts :]

        logger.info(
            "meta_alert_fired",
            id=alert.id,
            type=alert_type.value,
            severity=severity.value,
            channels=channels,
        )

        return alert

    def get_alerts(
        self,
        *,
        alert_type: MetaAlertType | None = None,
        severity: MetaAlertSeverity | None = None,
        since: float | None = None,
        limit: int = 100,
    ) -> list[MetaAlert]:
        """Query meta-alerts with optional filters."""
        results = self._alerts

        if alert_type is not None:
            results = [a for a in results if a.alert_type == alert_type]

        if severity is not None:
            results = [a for a in results if a.severity == severity]

        if since is not None:
            results = [a for a in results if a.timestamp >= since]

        return results[-limit:]

    @property
    def alert_count(self) -> int:
        return len(self._alerts)

    def clear(self) -> None:
        """Clear all alerts (for testing)."""
        self._alerts.clear()
        self._counter = 0
