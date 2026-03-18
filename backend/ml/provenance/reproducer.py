# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Reproducibility Verification (J5e).

Verifies that same data hash + same pipeline version + same random
seed + same hyperparameters = identical model (bit-for-bit).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

import numpy as np
import structlog
from numpy.typing import NDArray

logger = structlog.get_logger("phantex.ml.provenance.reproducer")

@dataclass
class ReproducibilityResult:
    """Result of reproducibility verification."""

    reproducible: bool
    hash_a: str
    hash_b: str
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "reproducible": self.reproducible,
            "hash_a": self.hash_a,
            "hash_b": self.hash_b,
            **self.details,
        }

def compute_data_hash(
    X: NDArray[np.floating],
    y: NDArray | None = None,
) -> str:
    """Compute SHA-256 hash of training data.

    Args:
        X: Feature matrix.
        y: Labels (optional).

    Returns:
        Hex-encoded SHA-256 hash.
    """
    h = hashlib.sha256()
    h.update(X.tobytes())
    if y is not None:
        h.update(y.tobytes())
    return h.hexdigest()

def compute_model_hash(model: Any) -> str:
    """Compute hash of model parameters for comparison.

    Supports: IsolationForestModel, XGBoostModel, AutoencoderModel.
    Falls back to str(model) for unknown types.
    """
    h = hashlib.sha256()

    # Try to get model internals
    if hasattr(model, "_model"):
        inner = model._model

        # sklearn IsolationForest — hash estimator params
        if hasattr(inner, "estimators_"):
            for est in inner.estimators_:
                if hasattr(est, "tree_"):
                    h.update(est.tree_.threshold.tobytes())
                    h.update(est.tree_.feature.tobytes())

        # XGBoost — hash booster data
        elif hasattr(inner, "get_booster"):
            try:
                raw = inner.get_booster().save_raw()
                h.update(raw)
            except Exception:
                h.update(str(inner.get_params()).encode())

        # PyTorch — hash state dict
        elif hasattr(inner, "state_dict"):
            for key, tensor in sorted(inner.state_dict().items()):
                h.update(key.encode())
                h.update(tensor.cpu().numpy().tobytes())

        else:
            h.update(str(inner).encode())
    else:
        h.update(str(model).encode())

    return h.hexdigest()

def verify_reproducibility(
    model_a: Any,
    model_b: Any,
) -> ReproducibilityResult:
    """Verify two models are identical (bit-for-bit).

    Args:
        model_a: First trained model.
        model_b: Second trained model (same data + seed + params).

    Returns:
        ReproducibilityResult.
    """
    hash_a = compute_model_hash(model_a)
    hash_b = compute_model_hash(model_b)

    match = hash_a == hash_b

    if not match:
        logger.warning(
            "reproducibility_failed",
            hash_a=hash_a[:16],
            hash_b=hash_b[:16],
        )

    return ReproducibilityResult(
        reproducible=match,
        hash_a=hash_a,
        hash_b=hash_b,
        details={"method": "parameter_hash"},
    )
