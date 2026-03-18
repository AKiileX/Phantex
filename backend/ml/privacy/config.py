# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Differential Privacy Configuration (J5f).

Centralized DP parameters. Epsilon is NOT configurable via API —
hardcoded, admin-only override.
"""

from __future__ import annotations

from dataclasses import dataclass

@dataclass(frozen=True)
class DPConfig:
    """Differential privacy configuration."""

    # Trust score noise
    score_epsilon: float = 1.0  # Privacy budget per query
    score_noise_scale: float = 0.01  # Scale factor for Laplace noise on scores

    # Feature importance noise
    importance_epsilon: float = 2.0  # Higher epsilon (less noise) for aggregated stats
    importance_noise_scale: float = 0.005

    # Budget tracking
    per_user_hourly_budget: float = 10.0  # Total ε budget per user per hour
    budget_reset_seconds: int = 3600  # 1 hour

    # Rounding (further reduces precision)
    score_decimal_places: int = 2

    # Development mode (disable noise)
    development_mode: bool = False

# Default configuration (immutable singleton)
DEFAULT_DP_CONFIG = DPConfig()

# Development configuration (no noise)
DEV_DP_CONFIG = DPConfig(development_mode=True)
