# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Differential Privacy Noise Mechanisms (J5f).

Laplace and Gaussian mechanisms for adding calibrated noise
to API responses. Uses cryptographically secure randomness
(secrets module, not random).
"""

from __future__ import annotations

import math
import secrets
from typing import Any

from ml.privacy.config import DEFAULT_DP_CONFIG, DPConfig

def _secure_laplace(scale: float) -> float:
    """Generate Laplace-distributed noise using cryptographic RNG.

    Uses inverse CDF: X = -b * sign(U) * ln(1 - 2|U|)
    where U ~ Uniform(-0.5, 0.5) drawn from secrets.
    """
    if scale <= 0:
        return 0.0

    # Generate 64-bit random integer, convert to uniform [0, 1)
    u = secrets.randbelow(2**64) / (2**64)
    # Shift to (-0.5, 0.5)
    u = u - 0.5

    if u == 0:
        return 0.0

    # Guard: |u| == 0.5 causes log(0) — practically impossible with
    # 2^64 quantization, but defend against it.
    if abs(u) >= 0.5 - 1e-15:
        return 0.0

    # Inverse CDF of Laplace distribution
    sign = 1.0 if u > 0 else -1.0
    noise = -scale * sign * math.log(1.0 - 2.0 * abs(u))
    return noise

def add_laplace_noise(
    value: float,
    sensitivity: float = 1.0,
    epsilon: float = 1.0,
    config: DPConfig = DEFAULT_DP_CONFIG,
) -> float:
    """Add calibrated Laplace noise to a value.

    Args:
        value: Raw value to protect.
        sensitivity: L1 sensitivity of the query.
        epsilon: Privacy parameter.
        config: DP configuration.

    Returns:
        Noisy value.
    """
    if config.development_mode:
        return value

    scale = sensitivity / epsilon
    noise = _secure_laplace(scale)
    return value + noise

def add_score_noise(
    score: float,
    config: DPConfig = DEFAULT_DP_CONFIG,
) -> float:
    """Add DP noise to a trust/ML score, clamped to [0, 1].

    Args:
        score: Raw score in [0, 1].
        config: DP configuration.

    Returns:
        Noisy score rounded to configured decimal places.
    """
    if config.development_mode:
        return round(score, config.score_decimal_places)

    noise = _secure_laplace(1.0 / config.score_epsilon) * config.score_noise_scale
    noisy = max(0.0, min(1.0, score + noise))
    return round(noisy, config.score_decimal_places)

def add_importance_noise(
    importances: list[dict[str, Any]],
    config: DPConfig = DEFAULT_DP_CONFIG,
) -> list[dict[str, Any]]:
    """Add DP noise to feature importance values.

    Args:
        importances: List of {name, importance} dicts.
        config: DP configuration.

    Returns:
        Same list with noised importance values.
    """
    if config.development_mode:
        return importances

    result = []
    for item in importances:
        noisy_imp = item["importance"] + _secure_laplace(config.importance_noise_scale / config.importance_epsilon)
        result.append({**item, "importance": max(0.0, noisy_imp)})

    # Re-sort after noising (order may change slightly)
    result.sort(key=lambda x: x["importance"], reverse=True)
    return result
