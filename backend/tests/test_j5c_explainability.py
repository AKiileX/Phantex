# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for J5c — Model Explainability & Transparency.
"""

from __future__ import annotations

import numpy as np

# ---------------------------------------------------------------------------
# J5c: Templates
# ---------------------------------------------------------------------------

class TestFeatureTemplates:
    """Human-readable feature description templates."""

    def test_known_feature_description(self):
        from ml.explainability.templates import get_feature_description

        desc = get_feature_description("network_connect_count_1h", value=450, baseline=30, z_score=15)
        assert "450" in desc
        assert "30" in desc

    def test_unknown_feature_fallback(self):
        from ml.explainability.templates import get_feature_description

        desc = get_feature_description("totally_unknown", value=42.5)
        assert "42.5" in desc

    def test_enrich_features(self):
        from ml.explainability.templates import enrich_features_with_descriptions

        features = [
            {"name": "trust_score", "value": 0.31},
            {"name": "unknown_feat", "value": 7.0},
        ]
        enriched = enrich_features_with_descriptions(features)
        assert all("human_readable" in f for f in enriched)

    def test_list_templates_non_empty(self):
        from ml.explainability.templates import list_templates

        templates = list_templates()
        assert len(templates) > 20  # We defined 30+ templates

# ---------------------------------------------------------------------------
# J5c: Summary Generator
# ---------------------------------------------------------------------------

class TestSummaryGenerator:
    """Template-based natural language summary."""

    def test_generate_summary(self):
        from ml.explainability.summary_generator import SummaryGenerator

        gen = SummaryGenerator()
        summary = gen.generate(
            top_features=[
                {"name": "network_connect_count_1h", "value": 450},
                {"name": "trust_score", "value": 0.31},
            ],
            score=0.87,
            attack_class="credential_theft",
        )
        assert "credential theft" in summary.lower()

    def test_generate_unknown_attack_class(self):
        from ml.explainability.summary_generator import SummaryGenerator

        gen = SummaryGenerator()
        summary = gen.generate(
            top_features=[{"name": "x", "value": 1.0}],
            score=0.5,
            attack_class="totally_new",
        )
        assert "0.5" in summary or "anomal" in summary.lower()

    def test_brief_summary(self):
        from ml.explainability.summary_generator import SummaryGenerator

        gen = SummaryGenerator()
        brief = gen.generate_brief(
            [{"name": "syscall_count_1m", "value": 5000}],
            score=0.91,
        )
        assert "0.91" in brief
        assert "syscall" in brief.lower()

    def test_empty_features_summary(self):
        from ml.explainability.summary_generator import SummaryGenerator

        gen = SummaryGenerator()
        summary = gen.generate([], score=0.6)
        assert "0.6" in summary or "anomal" in summary.lower()

# ---------------------------------------------------------------------------
# J5c: Autoencoder Explainer
# ---------------------------------------------------------------------------

class TestAutoencoderExplainer:
    """Autoencoder explanation via reconstruction error."""

    def test_explain_returns_top_features(self):
        from ml.explainability.autoencoder_explainer import (
            AutoencoderExplainer,
            AutoencoderExplanation,
        )

        class MockAE:
            is_fitted = True

            def predict_single(self, features, names):
                return 0.8

            def reconstruction_errors_per_feature(self, features, names):
                return [(n, abs(features.get(n, 0))) for n in names]

        explainer = AutoencoderExplainer(MockAE())
        exp = explainer.explain(
            {"a": 10.0, "b": 0.5, "c": 5.0},
            ["a", "b", "c"],
            top_k=2,
        )
        assert isinstance(exp, AutoencoderExplanation)
        assert len(exp.top_features) == 2
        # 'a' should be top (highest error)
        assert exp.top_features[0]["name"] == "a"

# ---------------------------------------------------------------------------
# J5c: Isolation Forest Explainer
# ---------------------------------------------------------------------------

class TestIsolationExplainer:
    """IF explainer via feature perturbation."""

    def test_explain_returns_contributions(self):
        from ml.explainability.isolation_explainer import (
            IsolationExplanation,
            IsolationForestExplainer,
        )

        class MockIF:
            is_fitted = True

            def predict_score(self, X):
                return np.clip(X.sum(axis=1) * 0.1, 0, 1)

        explainer = IsolationForestExplainer(MockIF())
        exp = explainer.explain(
            {"f1": 5.0, "f2": 0.0, "f3": 0.0},
            ["f1", "f2", "f3"],
            top_k=2,
        )
        assert isinstance(exp, IsolationExplanation)
        assert len(exp.top_features) == 2

# ---------------------------------------------------------------------------
# J5c: Ensemble Explainer
# ---------------------------------------------------------------------------

class TestEnsembleExplainer:
    """Unified ensemble explanation assembly."""

    def test_explain_with_no_sub_explainers(self):
        from ml.explainability.ensemble_explainer import (
            EnsembleExplainer,
            EnsembleExplanation,
        )

        explainer = EnsembleExplainer()
        ensemble_result = {
            "score": 0.85,
            "stage_scores": {"isolation_forest": 0.9, "xgboost": 0.8},
        }
        exp = explainer.explain({"a": 1.0}, ["a"], ensemble_result)
        assert isinstance(exp, EnsembleExplanation)
        assert exp.confidence == "high"
        assert exp.score == 0.85

    def test_confidence_levels(self):
        from ml.explainability.ensemble_explainer import EnsembleExplainer

        explainer = EnsembleExplainer()

        high = explainer.explain({}, [], {"score": 0.90, "stage_scores": {}})
        assert high.confidence == "high"

        med = explainer.explain({}, [], {"score": 0.75, "stage_scores": {}})
        assert med.confidence == "medium"

        low = explainer.explain({}, [], {"score": 0.50, "stage_scores": {}})
        assert low.confidence == "low"

    def test_default_summary(self):
        from ml.explainability.ensemble_explainer import EnsembleExplainer

        result = EnsembleExplainer._default_summary(
            [{"name": "test_feat", "value": 42}],
            0.88,
        )
        assert "0.88" in result
        assert "test" in result.lower()
