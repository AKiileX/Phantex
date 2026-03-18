# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Ensemble Explainer (J5c).

Assembles explanations from all 3 stages into a unified explanation
that accompanies every ML-generated alert.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger("phantex.ml.explainability.ensemble_explainer")

@dataclass
class EnsembleExplanation:
    """Unified explanation from all model stages."""

    score: float
    summary: str
    stage_contributions: dict[str, dict[str, float]]
    top_features: list[dict[str, Any]]
    confidence: str  # "high", "medium", "low"
    stage_explanations: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "summary": self.summary,
            "stage_contributions": self.stage_contributions,
            "top_features": self.top_features,
            "confidence": self.confidence,
            "stage_explanations": self.stage_explanations,
        }

class EnsembleExplainer:
    """Assemble per-stage explanations into unified alert explanation.

    Combines SHAP (XGBoost), path-perturbation (IF), and reconstruction
    error (Autoencoder) explanations into a single coherent output.
    """

    def __init__(
        self,
        isolation_explainer: Any | None = None,
        shap_explainer: Any | None = None,
        autoencoder_explainer: Any | None = None,
        summary_generator: Any | None = None,
    ) -> None:
        self._if_explainer = isolation_explainer
        self._shap_explainer = shap_explainer
        self._ae_explainer = autoencoder_explainer
        self._summary_gen = summary_generator

    def explain(
        self,
        features: dict[str, float],
        ordered_names: list[str],
        ensemble_result: dict[str, Any],
        top_k: int = 3,
    ) -> EnsembleExplanation:
        """Generate unified explanation for an ensemble prediction.

        Args:
            features: Feature dict.
            ordered_names: Feature names.
            ensemble_result: Output from EnsembleScorer.score().
            top_k: Number of top features to highlight.

        Returns:
            EnsembleExplanation with all stage contributions merged.
        """
        stage_scores = ensemble_result.get("stage_scores", {})
        score = ensemble_result.get("score", 0.0)

        # Compute stage contributions
        stage_contributions: dict[str, dict[str, float]] = {}
        weights = {"isolation_forest": 0.3, "xgboost": 0.5, "autoencoder": 0.2}

        for stage_name, stage_score in stage_scores.items():
            w = weights.get(stage_name, 0.0)
            stage_contributions[stage_name] = {
                "score": stage_score,
                "weight": w,
                "contribution": stage_score * w,
            }

        # Collect per-stage explanations
        stage_explanations: dict[str, Any] = {}
        all_features: dict[str, dict[str, Any]] = {}

        # Stage 1: Isolation Forest
        if self._if_explainer and "isolation_forest" in stage_scores:
            try:
                if_exp = self._if_explainer.explain(features, ordered_names, top_k=top_k * 2)
                stage_explanations["isolation_forest"] = if_exp.to_dict()
                for feat in if_exp.top_features:
                    name = feat["name"]
                    if name not in all_features:
                        all_features[name] = {
                            "name": name,
                            "value": feat.get("value", 0.0),
                            "importance": 0.0,
                        }
                    all_features[name]["importance"] += abs(feat.get("contribution", 0.0)) * 0.3
            except Exception as exc:
                logger.warning("if_explanation_failed", error=str(exc))

        # Stage 2: XGBoost (SHAP)
        if self._shap_explainer and "xgboost" in stage_scores:
            try:
                shap_exp = self._shap_explainer.explain(features, ordered_names, top_k=top_k * 2)
                stage_explanations["xgboost"] = shap_exp.to_dict()
                for feat in shap_exp.top_features:
                    name = feat["name"]
                    if name not in all_features:
                        all_features[name] = {
                            "name": name,
                            "value": feat.get("value", 0.0),
                            "importance": 0.0,
                        }
                    all_features[name]["importance"] += abs(feat.get("shap_value", 0.0)) * 0.5
                    all_features[name]["shap_value"] = feat.get("shap_value", 0.0)
            except Exception as exc:
                logger.warning("shap_explanation_failed", error=str(exc))

        # Stage 3: Autoencoder
        if self._ae_explainer and "autoencoder" in stage_scores:
            try:
                ae_exp = self._ae_explainer.explain(features, ordered_names, top_k=top_k * 2)
                stage_explanations["autoencoder"] = ae_exp.to_dict()
                for feat in ae_exp.top_features:
                    name = feat["name"]
                    if name not in all_features:
                        all_features[name] = {
                            "name": name,
                            "value": feat.get("value", 0.0),
                            "importance": 0.0,
                        }
                    all_features[name]["importance"] += feat.get("reconstruction_error", 0.0) * 0.2
            except Exception as exc:
                logger.warning("ae_explanation_failed", error=str(exc))

        # Rank features across all stages
        ranked_features = sorted(all_features.values(), key=lambda f: f["importance"], reverse=True)
        top_features = ranked_features[:top_k]

        # Determine confidence
        if score >= 0.85:
            confidence = "high"
        elif score >= 0.70:
            confidence = "medium"
        else:
            confidence = "low"

        # Generate summary
        summary = ""
        if self._summary_gen:
            try:
                summary = self._summary_gen.generate(
                    top_features=top_features,
                    score=score,
                    attack_class=ensemble_result.get("attack_class", "unknown"),
                )
            except Exception:
                summary = self._default_summary(top_features, score)
        else:
            summary = self._default_summary(top_features, score)

        return EnsembleExplanation(
            score=score,
            summary=summary,
            stage_contributions=stage_contributions,
            top_features=top_features,
            confidence=confidence,
            stage_explanations=stage_explanations,
        )

    @staticmethod
    def _default_summary(top_features: list[dict[str, Any]], score: float) -> str:
        """Generate a default text summary when no template generator is available."""
        if not top_features:
            return f"Anomaly detected with score {score:.2f}"

        parts = []
        for feat in top_features[:3]:
            name = feat["name"].replace("_", " ")
            val = feat.get("value", 0)
            parts.append(f"{name}={val}")

        feature_str = ", ".join(parts)
        return f"Anomaly detected (score {score:.2f}): primary factors — {feature_str}"
