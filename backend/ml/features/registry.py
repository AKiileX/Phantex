# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Feature Registry (J1).

Central catalogue of all features computed by the extraction pipeline.
Each feature has a name, category, description, and calculator function.
Used by the extractor to compute the full feature vector, and by the
serving layer to know what inputs the model expects.
"""

from __future__ import annotations

from dataclasses import dataclass

@dataclass(frozen=True)
class FeatureDefinition:
    """Metadata for a single computed feature."""

    name: str
    category: str  # volume, velocity, diversity, behavioral, network, temporal, sequence
    description: str
    window: str | None  # e.g. "1m", "5m", "1h", "24h", None for instant features
    default: float = 0.0  # Value when no data is available

# Global feature catalogue — populated by each calculator module at import time
_REGISTRY: dict[str, FeatureDefinition] = {}

def register_feature(defn: FeatureDefinition) -> None:
    """Register a feature definition in the global catalogue."""
    _REGISTRY[defn.name] = defn

def get_feature(name: str) -> FeatureDefinition | None:
    return _REGISTRY.get(name)

def list_features() -> list[FeatureDefinition]:
    """Return all registered features, sorted by name."""
    return sorted(_REGISTRY.values(), key=lambda f: f.name)

def feature_names() -> list[str]:
    """Return sorted list of all feature names."""
    return sorted(_REGISTRY.keys())

def feature_defaults() -> dict[str, float]:
    """Return {name: default_value} for all features — used for missing data."""
    return {f.name: f.default for f in _REGISTRY.values()}
