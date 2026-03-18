# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Telemetry Anonymizer (Q3).

Transforms raw ML signals into privacy-safe telemetry payloads:
1. Anonymize tenant ID (HMAC-SHA256, irreversible)
2. Apply calibrated Laplacian noise to feature vectors (ε-DP)
3. Strip any PII or identifying metadata
4. Produce export-ready records

NOTHING in this module touches raw prompts, responses, or customer data.
Only feature vectors (statistical summaries) and attack classifications.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from ml.telemetry.config import TelemetryExportConfig

# ── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class TelemetryRecord:
    """A single anonymized telemetry record ready for export.

    Format per spec:
    {anonymized_tenant_hash, feature_vector[62], attack_class, confidence, timestamp}
    """

    anonymized_tenant_hash: str
    feature_vector: list[float]
    attack_class: str
    confidence: float
    timestamp: float
    # Internal tracking (not exported)
    created_at: float = field(default_factory=time.time)

    def to_export_dict(self) -> dict[str, Any]:
        """Serialize to the canonical export format."""
        return {
            "anonymized_tenant_hash": self.anonymized_tenant_hash,
            "feature_vector": self.feature_vector,
            "attack_class": self.attack_class,
            "confidence": round(self.confidence, 4),
            "timestamp": self.timestamp,
        }

# ── Tenant Anonymization ────────────────────────────────────────────────────

def anonymize_tenant_id(
    tenant_id: str,
    config: TelemetryExportConfig | None = None,
) -> str:
    """Hash a tenant ID using HMAC-SHA256.

    The hash is:
    - Deterministic (same tenant always maps to same hash)
    - Irreversible (cannot recover tenant ID from hash)
    - Collision-resistant (different tenants → different hashes)

    Args:
        tenant_id: Raw tenant UUID/string.
        config: Telemetry config (provides HMAC key).

    Returns:
        64-character hex string (HMAC-SHA256 digest).
    """
    if config is None:
        config = TelemetryExportConfig()
    key = config.tenant_hash_key.encode("utf-8")
    msg = tenant_id.encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()

# ── Differential Privacy Noise ───────────────────────────────────────────────

def _secure_laplace(scale: float) -> float:
    """Generate Laplace-distributed noise using cryptographic RNG.

    Uses inverse CDF: X = -b × sign(U) × ln(1 - 2|U|)
    where U ~ Uniform(-0.5, 0.5) drawn from secrets module.

    Same implementation as ml.privacy.noise but self-contained
    to avoid circular dependency and keep telemetry module isolated.
    """
    if scale <= 0:
        return 0.0

    # Re-sample on extreme tails to avoid zero-noise leakage
    for _ in range(10):
        u = secrets.randbelow(2**64) / (2**64) - 0.5
        if u != 0 and abs(u) < 0.5 - 1e-15:
            sign = 1.0 if u > 0 else -1.0
            return -scale * sign * math.log(1.0 - 2.0 * abs(u))

    # Fallback: return small noise rather than zero
    return scale * (1.0 if secrets.randbelow(2) == 0 else -1.0) * 0.01

def apply_dp_noise(
    feature_vector: list[float],
    epsilon: float = 2.0,
    sensitivity: float = 1.0,
) -> list[float]:
    """Apply calibrated Laplacian noise to a feature vector.

    Each dimension gets independent Laplace noise with scale = sensitivity / epsilon.
    This provides ε-differential privacy per vector.

    Args:
        feature_vector: Raw feature values (62 dimensions).
        epsilon: Privacy budget (lower = more noise/privacy).
        sensitivity: L1 sensitivity per feature dimension.

    Returns:
        Noised feature vector (same length).
    """
    if epsilon <= 0:
        raise ValueError("Epsilon must be positive")

    scale = sensitivity / epsilon
    noised = []
    for val in feature_vector:
        noise = _secure_laplace(scale)
        noised.append(val + noise)
    return noised

def verify_dp_noise_signature(
    feature_vector: list[float],
    n_features: int = 62,
) -> bool:
    """Validate that a feature vector plausibly has DP noise applied.

    Heuristic checks:
    1. Correct dimensionality
    2. Values are not all identical (would suggest no noise)
    3. No NaN/Inf values
    4. Values are within reasonable bounds

    This is a best-effort check — not cryptographic proof.
    """
    if len(feature_vector) != n_features:
        return False

    # Check for NaN/Inf
    for v in feature_vector:
        if not isinstance(v, int | float) or math.isnan(v) or math.isinf(v):
            return False

    # Check value range (features + noise should stay within reasonable bounds)
    if any(abs(v) > 1e9 for v in feature_vector):
        return False

    # Check that values aren't all identical (no noise applied)
    return not (len(set(round(v, 10) for v in feature_vector)) <= 1 and len(feature_vector) > 1)

# ── Record Builder ───────────────────────────────────────────────────────────

def build_telemetry_record(
    tenant_id: str,
    feature_vector: list[float],
    attack_class: str,
    confidence: float,
    timestamp: float | None = None,
    config: TelemetryExportConfig | None = None,
) -> TelemetryRecord:
    """Build a privacy-safe telemetry record from raw ML signals.

    This is the main entry point for Q3:
    1. Anonymizes tenant ID
    2. Applies DP noise to feature vector
    3. Returns export-ready record

    Args:
        tenant_id: Raw tenant UUID/string.
        feature_vector: Raw feature vector (62 dimensions).
        attack_class: Classification label (e.g. "prompt_injection", "normal").
        confidence: Model confidence [0, 1].
        timestamp: Event timestamp (epoch). Defaults to now.
        config: Telemetry export configuration.

    Returns:
        TelemetryRecord with anonymized tenant and noised features.

    Raises:
        ValueError: If feature vector has wrong dimensionality.
    """
    if config is None:
        config = TelemetryExportConfig()

    # Validate feature vector length
    if len(feature_vector) != config.n_features:
        raise ValueError(f"Feature vector must have {config.n_features} dimensions, got {len(feature_vector)}")

    # Step 1: Anonymize tenant ID
    anon_hash = anonymize_tenant_id(tenant_id, config)

    # Step 2: Apply differential privacy noise
    noised_vector = apply_dp_noise(
        feature_vector,
        epsilon=config.dp_epsilon,
        sensitivity=config.dp_sensitivity,
    )

    # Step 3: Clamp confidence to [0, 1]
    clamped_confidence = max(0.0, min(1.0, confidence))

    return TelemetryRecord(
        anonymized_tenant_hash=anon_hash,
        feature_vector=noised_vector,
        attack_class=attack_class,
        confidence=clamped_confidence,
        timestamp=timestamp or time.time(),
    )

def build_telemetry_batch(
    records: list[dict[str, Any]],
    config: TelemetryExportConfig | None = None,
) -> list[TelemetryRecord]:
    """Build a batch of telemetry records from raw inputs.

    Each dict should have: tenant_id, feature_vector, attack_class, confidence.
    Optional: timestamp.

    Invalid records are skipped with logging (no batch failure).
    """
    if config is None:
        config = TelemetryExportConfig()

    results = []
    for raw in records:
        try:
            record = build_telemetry_record(
                tenant_id=raw["tenant_id"],
                feature_vector=raw["feature_vector"],
                attack_class=raw.get("attack_class", "unknown"),
                confidence=raw.get("confidence", 0.0),
                timestamp=raw.get("timestamp"),
                config=config,
            )
            results.append(record)
        except (KeyError, ValueError, TypeError) as exc:
            import logging as _logging

            _logging.getLogger("phantex.ml.telemetry.anonymizer").debug(
                "Skipped malformed telemetry record: %s", type(exc).__name__
            )
            continue  # Skip malformed records
    return results
