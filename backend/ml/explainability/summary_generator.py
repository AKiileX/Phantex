# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Template-Based Summary Generator (J5c).

Generates natural language alert summaries from top features.
Deterministic (no LLM): template + feature data → text.
"""

from __future__ import annotations

from typing import Any

from ml.explainability.templates import enrich_features_with_descriptions

# Summary template for attack classes
_ATTACK_SUMMARIES: dict[str, str] = {
    "credential_theft": "Agent exhibited credential theft behavior: {details}",
    "data_exfiltration": "Agent exhibited data exfiltration behavior: {details}",
    "dos": "Agent exhibited denial of service behavior: {details}",
    "lateral_movement": "Agent exhibited lateral movement behavior: {details}",
    "privilege_escalation": "Agent exhibited privilege escalation behavior: {details}",
    "prompt_injection": "Agent exhibited prompt injection behavior: {details}",
    "supply_chain": "Agent exhibited supply chain attack behavior: {details}",
}

_DEFAULT_SUMMARY = "Anomalous agent behavior detected (score {score:.2f}): {details}"

class SummaryGenerator:
    """Template-based alert summary generator."""

    def __init__(
        self,
        baselines: dict[str, float] | None = None,
    ) -> None:
        """
        Args:
            baselines: Baseline feature values for description context.
        """
        self._baselines = baselines or {}

    def generate(
        self,
        top_features: list[dict[str, Any]],
        score: float,
        attack_class: str = "unknown",
    ) -> str:
        """Generate a human-readable alert summary.

        Args:
            top_features: List of feature contributions (from explainer).
            score: Ensemble anomaly score.
            attack_class: Predicted attack class.

        Returns:
            Natural language summary string.
        """
        # Add human-readable descriptions
        enriched = enrich_features_with_descriptions(top_features[:3], self._baselines)

        # Compose detail string from feature descriptions
        details_parts = []
        for feat in enriched:
            desc = feat.get("human_readable", feat.get("name", "unknown"))
            details_parts.append(desc)

        details = "; ".join(details_parts) if details_parts else "multiple behavioral anomalies"

        # Pick template by attack class
        template = _ATTACK_SUMMARIES.get(attack_class, _DEFAULT_SUMMARY)

        try:
            return template.format(details=details, score=score)
        except KeyError:
            return _DEFAULT_SUMMARY.format(details=details, score=score)

    def generate_brief(
        self,
        top_features: list[dict[str, Any]],
        score: float,
    ) -> str:
        """Generate a brief one-line summary (for alert lists)."""
        if not top_features:
            return f"Anomaly (score {score:.2f})"

        primary = top_features[0]
        name = primary.get("name", "unknown").replace("_", " ")
        val = primary.get("value", 0)
        return f"Anomaly (score {score:.2f}): {name} = {val}"
