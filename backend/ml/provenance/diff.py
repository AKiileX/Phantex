# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Model-to-Model Diff (J5e).

Compares two model versions: accuracy delta, feature changes, and
parameter differences. Part of the provenance chain — every model
links to its predecessor with a computed diff.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import structlog

logger = structlog.get_logger("phantex.ml.provenance.diff")

@dataclass
class ModelVersionDiff:
    """Diff between two model versions."""

    model_a: str
    model_b: str
    accuracy_delta: dict[str, float]
    feature_changes: dict[str, list[str]]
    parameter_changes: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_a": self.model_a,
            "model_b": self.model_b,
            "accuracy_delta": self.accuracy_delta,
            "feature_changes": self.feature_changes,
            "parameter_changes": self.parameter_changes,
        }

def compute_diff(
    model_a_id: str,
    model_b_id: str,
    metrics_a: dict[str, float],
    metrics_b: dict[str, float],
    features_a: list[str],
    features_b: list[str],
    params_a: dict[str, Any] | None = None,
    params_b: dict[str, Any] | None = None,
) -> ModelVersionDiff:
    """Compute diff between two model versions.

    Args:
        model_a_id: ID of predecessor model.
        model_b_id: ID of new model.
        metrics_a: Validation metrics of model A.
        metrics_b: Validation metrics of model B.
        features_a: Feature names used by model A.
        features_b: Feature names used by model B.
        params_a: Hyperparameters of model A.
        params_b: Hyperparameters of model B.

    Returns:
        ModelVersionDiff with all differences.
    """
    # Metric deltas
    all_metrics = set(metrics_a.keys()) | set(metrics_b.keys())
    accuracy_delta = {}
    for metric in all_metrics:
        val_a = metrics_a.get(metric, 0.0)
        val_b = metrics_b.get(metric, 0.0)
        delta = val_b - val_a
        if abs(delta) > 1e-6:
            accuracy_delta[metric] = delta

    # Feature changes
    set_a = set(features_a)
    set_b = set(features_b)
    feature_changes = {
        "added": sorted(set_b - set_a),
        "removed": sorted(set_a - set_b),
        "unchanged": sorted(set_a & set_b),
    }

    # Parameter changes
    parameter_changes: dict[str, Any] = {}
    if params_a and params_b:
        all_keys = set(params_a.keys()) | set(params_b.keys())
        for key in all_keys:
            val_a = params_a.get(key)
            val_b = params_b.get(key)
            if val_a != val_b:
                parameter_changes[key] = {"old": val_a, "new": val_b}

    diff = ModelVersionDiff(
        model_a=model_a_id,
        model_b=model_b_id,
        accuracy_delta=accuracy_delta,
        feature_changes=feature_changes,
        parameter_changes=parameter_changes,
    )

    logger.info(
        "model_diff_computed",
        model_a=model_a_id,
        model_b=model_b_id,
        features_added=len(feature_changes["added"]),
        features_removed=len(feature_changes["removed"]),
        param_changes=len(parameter_changes),
    )

    return diff

def format_diff_summary(diff: ModelVersionDiff) -> str:
    """Generate human-readable diff summary."""
    parts = [f"Model diff: {diff.model_a} → {diff.model_b}"]

    if diff.accuracy_delta:
        for metric, delta in diff.accuracy_delta.items():
            sign = "+" if delta > 0 else ""
            parts.append(f"  {metric}: {sign}{delta:.4f}")

    added = diff.feature_changes.get("added", [])
    removed = diff.feature_changes.get("removed", [])
    if added:
        parts.append(f"  Features added: {', '.join(added)}")
    if removed:
        parts.append(f"  Features removed: {', '.join(removed)}")

    if diff.parameter_changes:
        for key, change in diff.parameter_changes.items():
            parts.append(f"  {key}: {change['old']} → {change['new']}")

    return "\n".join(parts)
