# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — Feature Bridge (JB6).

Maps content analysis scores → normalized ML feature vector fields
so the ensemble models can incorporate semantic signals.
"""

from __future__ import annotations

from dataclasses import dataclass

from ml.content.verdict import ContentVerdict, Severity

@dataclass(frozen=True)
class ContentFeatureVector:
    """Eight normalized [0,1] features for ensemble consumption."""

    prompt_injection_score: float = 0.0
    tool_policy_violation: float = 0.0
    output_secret_detected: float = 0.0
    data_sensitivity_level: float = 0.0
    purpose_match_score: float = 0.0
    baseline_drift_score: float = 0.0
    embedding_similarity_score: float = 0.0  # JB8a
    trained_classifier_score: float = 0.0  # JB8b

    def to_dict(self) -> dict[str, float]:
        return {
            "prompt_injection_score": self.prompt_injection_score,
            "tool_policy_violation": self.tool_policy_violation,
            "output_secret_detected": self.output_secret_detected,
            "data_sensitivity_level": self.data_sensitivity_level,
            "purpose_match_score": self.purpose_match_score,
            "baseline_drift_score": self.baseline_drift_score,
            "embedding_similarity_score": self.embedding_similarity_score,
            "trained_classifier_score": self.trained_classifier_score,
        }

    def to_list(self) -> list[float]:
        return [
            self.prompt_injection_score,
            self.tool_policy_violation,
            self.output_secret_detected,
            self.data_sensitivity_level,
            self.purpose_match_score,
            self.baseline_drift_score,
            self.embedding_similarity_score,
            self.trained_classifier_score,
        ]

_SEVERITY_MAP: dict[Severity, float] = {
    Severity.INFO: 0.1,
    Severity.LOW: 0.3,
    Severity.MEDIUM: 0.5,
    Severity.HIGH: 0.8,
    Severity.CRITICAL: 1.0,
}

def _clamp(value: float) -> float:
    """Clamp to [0.0, 1.0]."""
    return max(0.0, min(1.0, value))

def build_feature_vector(
    *,
    prompt_injection_verdict: ContentVerdict | None = None,
    tool_policy_violation: bool = False,
    output_secrets_found: int = 0,
    data_sensitivity_severity: Severity | None = None,
    purpose_match: bool = True,
    baseline_drift_z: float = 0.0,
    embedding_similarity_score: float = 0.0,
    trained_classifier_score: float = 0.0,
) -> ContentFeatureVector:
    """Build a normalized [0, 1] feature vector from content signals.

    Parameters
    ----------
    prompt_injection_verdict:
        Verdict from prompt injection classifier (None → 0.0).
    tool_policy_violation:
        True if tool policy denied the call.
    output_secrets_found:
        Number of secrets found by output scanner.  Capped at 5 → 1.0.
    data_sensitivity_severity:
        Highest sensitivity severity from data classifier.
    purpose_match:
        True if content matches agent's declared purpose.
    baseline_drift_z:
        Z-score from baseline tracker.  Mapped via sigmoid-like curve.
    embedding_similarity_score:
        Max cosine similarity to known attack corpus (JB8a).  [0, 1].
    trained_classifier_score:
        P(malicious) from trained content classifier (JB8b).  [0, 1].
    """
    # 1. Prompt injection score — direct from verdict
    pi_score = 0.0
    if prompt_injection_verdict is not None:
        pi_score = _clamp(prompt_injection_verdict.score)

    # 2. Tool policy — binary
    tp_score = 1.0 if tool_policy_violation else 0.0

    # 3. Output secrets — 0-5 mapped to 0-1
    os_score = _clamp(output_secrets_found / 5.0)

    # 4. Data sensitivity — severity mapping
    ds_score = 0.0
    if data_sensitivity_severity is not None:
        ds_score = _SEVERITY_MAP.get(data_sensitivity_severity, 0.0)

    # 5. Purpose match — inverted (mismatch = high risk)
    pm_score = 0.0 if purpose_match else 1.0

    # 6. Baseline drift — sigmoid-ish: z / (z + 2) gives smooth 0→1
    bd_score = 0.0
    if baseline_drift_z > 0:
        bd_score = _clamp(baseline_drift_z / (baseline_drift_z + 2.0))

    return ContentFeatureVector(
        prompt_injection_score=round(pi_score, 4),
        tool_policy_violation=round(tp_score, 4),
        output_secret_detected=round(os_score, 4),
        data_sensitivity_level=round(ds_score, 4),
        purpose_match_score=round(pm_score, 4),
        baseline_drift_score=round(bd_score, 4),
        embedding_similarity_score=round(_clamp(embedding_similarity_score), 4),
        trained_classifier_score=round(_clamp(trained_classifier_score), 4),
    )
