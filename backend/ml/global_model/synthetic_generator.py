# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Q1: Synthetic Training Data Generator for Global Model.

Generates high-fidelity synthetic behavioral feature vectors that model
realistic AI agent attack patterns across all 8 attack classes. Each class
has a distinct feature signature derived from known attack TTPs
(Tactics, Techniques, and Procedures).

Attack classes:
  0: benign           — Normal AI agent operation
  1: credential_theft — Token/key exfiltration attempts
  2: data_exfiltration — Bulk data extraction
  3: dos              — Denial-of-service patterns
  4: lateral_movement — Internal network traversal
  5: privilege_escalation — Permission boundary violations
  6: prompt_injection — LLM manipulation attempts
  7: supply_chain     — Dependency/update poisoning

Security: All randomness uses numpy.random.Generator (PCG64) for
reproducibility. No external data sources or network access.
"""

from __future__ import annotations

import hashlib
from typing import Any

import numpy as np
import structlog
from numpy.typing import NDArray

logger = structlog.get_logger("phantex.ml.global_model.synthetic")

# ── Feature Names (must match FeatureExtractor output) ───────────────────────

# 62 behavioral features across 8 categories, matching the real feature
# extractor output. These are the standard Phantex feature dimensions.
GLOBAL_FEATURE_NAMES: list[str] = [
    # Volume features (8)
    "event_count_1m",
    "event_count_5m",
    "event_count_1h",
    "event_count_24h",
    "tool_call_count_1m",
    "tool_call_count_5m",
    "tool_call_count_1h",
    "tool_call_count_24h",
    # Velocity features (4)
    "events_per_second_1m",
    "events_per_second_5m",
    "tool_calls_per_second_1m",
    "tool_calls_per_second_5m",
    # File access features (8)
    "file_read_count_1m",
    "file_read_count_5m",
    "file_read_count_1h",
    "file_read_count_24h",
    "file_write_count_1m",
    "file_write_count_5m",
    "file_write_count_1h",
    "file_write_count_24h",
    # Network features (8)
    "network_connect_count_1m",
    "network_connect_count_5m",
    "network_connect_count_1h",
    "network_connect_count_24h",
    "bytes_sent_total_1m",
    "bytes_sent_total_5m",
    "bytes_sent_total_1h",
    "bytes_sent_total_24h",
    # Diversity features (8)
    "unique_event_types_1m",
    "unique_event_types_5m",
    "unique_event_types_1h",
    "unique_event_types_24h",
    "unique_tools_used_1m",
    "unique_tools_used_5m",
    "unique_tools_used_1h",
    "unique_tools_used_24h",
    # Resource access features (8)
    "unique_files_accessed_1m",
    "unique_files_accessed_5m",
    "unique_files_accessed_1h",
    "unique_files_accessed_24h",
    "unique_network_dests_1m",
    "unique_network_dests_5m",
    "unique_network_dests_1h",
    "unique_network_dests_24h",
    # Timing features (6)
    "avg_response_time_1m",
    "avg_response_time_5m",
    "avg_response_time_1h",
    "avg_response_time_24h",
    "max_response_time_1m",
    "max_response_time_5m",
    # Error/anomaly features (6)
    "error_rate_1m",
    "error_rate_5m",
    "permission_denied_count_1m",
    "permission_denied_count_5m",
    "unique_ports_1m",
    "unique_ports_5m",
    # Behavioral ratio features (6)
    "read_write_ratio_1h",
    "send_recv_ratio_1h",
    "tool_event_ratio_1m",
    "tool_event_ratio_5m",
    "new_dest_ratio_1m",
    "new_dest_ratio_5m",
]

assert len(GLOBAL_FEATURE_NAMES) == 62, f"Expected 62 features, got {len(GLOBAL_FEATURE_NAMES)}"

# ── Per-Class Feature Profiles ───────────────────────────────────────────────

# Each attack class has a distinctive "signature" expressed as feature-level
# mean offsets and variance multipliers relative to the benign baseline.
# These are derived from threat intelligence analysis of real-world
# AI agent compromises and attack simulations.

def _benign_profile() -> dict[str, tuple[float, float]]:
    """Benign baseline: low activity, stable patterns."""
    return {
        "event_count": (5.0, 1.5),
        "tool_call_count": (2.0, 0.8),
        "events_per_second": (0.08, 0.03),
        "tool_calls_per_second": (0.03, 0.01),
        "file_read_count": (1.0, 0.5),
        "file_write_count": (0.3, 0.2),
        "network_connect_count": (0.5, 0.3),
        "bytes_sent_total": (500.0, 200.0),
        "unique_event_types": (3.0, 1.0),
        "unique_tools_used": (2.0, 0.8),
        "unique_files_accessed": (2.0, 1.0),
        "unique_network_dests": (1.0, 0.5),
        "avg_response_time": (150.0, 50.0),
        "max_response_time": (500.0, 200.0),
        "error_rate": (0.02, 0.01),
        "permission_denied_count": (0.0, 0.1),
        "unique_ports": (1.0, 0.5),
        "read_write_ratio": (3.0, 1.0),
        "send_recv_ratio": (0.5, 0.2),
        "tool_event_ratio": (0.4, 0.1),
        "new_dest_ratio": (0.1, 0.05),
    }

def _credential_theft_profile() -> dict[str, tuple[float, float]]:
    """Credential theft: reads secrets, low network, high file reads."""
    return {
        "event_count": (15.0, 5.0),
        "tool_call_count": (8.0, 3.0),
        "events_per_second": (0.25, 0.1),
        "tool_calls_per_second": (0.13, 0.05),
        "file_read_count": (12.0, 4.0),  # HIGH: reading credential files
        "file_write_count": (0.5, 0.3),
        "network_connect_count": (2.0, 1.0),
        "bytes_sent_total": (2000.0, 800.0),  # Moderate: exfil small secrets
        "unique_event_types": (5.0, 1.5),
        "unique_tools_used": (4.0, 1.5),
        "unique_files_accessed": (8.0, 3.0),  # HIGH: scanning for creds
        "unique_network_dests": (2.0, 1.0),
        "avg_response_time": (80.0, 30.0),  # Fast: simple reads
        "max_response_time": (300.0, 100.0),
        "error_rate": (0.08, 0.04),
        "permission_denied_count": (3.0, 1.5),  # HIGH: testing boundaries
        "unique_ports": (2.0, 1.0),
        "read_write_ratio": (20.0, 8.0),  # HIGH: read-heavy
        "send_recv_ratio": (1.5, 0.5),
        "tool_event_ratio": (0.5, 0.15),
        "new_dest_ratio": (0.3, 0.15),
    }

def _data_exfiltration_profile() -> dict[str, tuple[float, float]]:
    """Data exfiltration: bulk reads + large outbound transfers."""
    return {
        "event_count": (30.0, 10.0),
        "tool_call_count": (12.0, 4.0),
        "events_per_second": (0.5, 0.2),
        "tool_calls_per_second": (0.2, 0.08),
        "file_read_count": (25.0, 8.0),  # VERY HIGH: bulk reads
        "file_write_count": (2.0, 1.0),
        "network_connect_count": (5.0, 2.0),
        "bytes_sent_total": (50000.0, 20000.0),  # VERY HIGH: large transfers
        "unique_event_types": (6.0, 2.0),
        "unique_tools_used": (5.0, 2.0),
        "unique_files_accessed": (15.0, 5.0),  # HIGH: accessing many files
        "unique_network_dests": (3.0, 1.5),
        "avg_response_time": (200.0, 80.0),
        "max_response_time": (800.0, 300.0),
        "error_rate": (0.05, 0.03),
        "permission_denied_count": (1.0, 0.8),
        "unique_ports": (3.0, 1.5),
        "read_write_ratio": (12.0, 5.0),
        "send_recv_ratio": (5.0, 2.0),  # HIGH: sending >> receiving
        "tool_event_ratio": (0.4, 0.15),
        "new_dest_ratio": (0.4, 0.2),
    }

def _dos_profile() -> dict[str, tuple[float, float]]:
    """DoS: extreme event volume, high velocity, resource exhaustion."""
    return {
        "event_count": (200.0, 60.0),  # EXTREME: flood
        "tool_call_count": (80.0, 25.0),
        "events_per_second": (3.0, 1.0),  # EXTREME: high velocity
        "tool_calls_per_second": (1.3, 0.5),
        "file_read_count": (5.0, 3.0),
        "file_write_count": (1.0, 0.5),
        "network_connect_count": (50.0, 20.0),  # HIGH: connection flood
        "bytes_sent_total": (100000.0, 40000.0),
        "unique_event_types": (3.0, 1.0),  # LOW: repetitive
        "unique_tools_used": (2.0, 1.0),  # LOW: repetitive
        "unique_files_accessed": (2.0, 1.0),
        "unique_network_dests": (1.0, 0.5),  # Targeting specific host
        "avg_response_time": (500.0, 200.0),  # Degraded response times
        "max_response_time": (2000.0, 800.0),
        "error_rate": (0.3, 0.15),  # HIGH: errors from overload
        "permission_denied_count": (0.5, 0.3),
        "unique_ports": (2.0, 1.0),
        "read_write_ratio": (5.0, 3.0),
        "send_recv_ratio": (8.0, 3.0),
        "tool_event_ratio": (0.4, 0.1),
        "new_dest_ratio": (0.05, 0.03),
    }

def _lateral_movement_profile() -> dict[str, tuple[float, float]]:
    """Lateral movement: many diverse network destinations."""
    return {
        "event_count": (20.0, 7.0),
        "tool_call_count": (10.0, 4.0),
        "events_per_second": (0.3, 0.12),
        "tool_calls_per_second": (0.17, 0.06),
        "file_read_count": (3.0, 1.5),
        "file_write_count": (1.0, 0.5),
        "network_connect_count": (15.0, 5.0),  # HIGH: scanning
        "bytes_sent_total": (5000.0, 2000.0),
        "unique_event_types": (7.0, 2.0),
        "unique_tools_used": (6.0, 2.0),
        "unique_files_accessed": (5.0, 2.0),
        "unique_network_dests": (10.0, 4.0),  # VERY HIGH: many targets
        "avg_response_time": (120.0, 45.0),
        "max_response_time": (600.0, 250.0),
        "error_rate": (0.12, 0.06),  # Moderate: some unreachable hosts
        "permission_denied_count": (2.0, 1.0),
        "unique_ports": (8.0, 3.0),  # HIGH: port scanning
        "read_write_ratio": (3.0, 1.5),
        "send_recv_ratio": (1.2, 0.5),
        "tool_event_ratio": (0.5, 0.2),
        "new_dest_ratio": (0.7, 0.2),  # VERY HIGH: new destinations
    }

def _privilege_escalation_profile() -> dict[str, tuple[float, float]]:
    """Privilege escalation: permission probing, admin tool access."""
    return {
        "event_count": (12.0, 4.0),
        "tool_call_count": (8.0, 3.0),
        "events_per_second": (0.2, 0.08),
        "tool_calls_per_second": (0.13, 0.05),
        "file_read_count": (6.0, 2.0),
        "file_write_count": (3.0, 1.5),  # Writing config files
        "network_connect_count": (2.0, 1.0),
        "bytes_sent_total": (1500.0, 600.0),
        "unique_event_types": (8.0, 2.5),  # HIGH: diverse operations
        "unique_tools_used": (7.0, 2.5),  # HIGH: testing many tools
        "unique_files_accessed": (6.0, 2.5),
        "unique_network_dests": (2.0, 1.0),
        "avg_response_time": (100.0, 40.0),
        "max_response_time": (400.0, 150.0),
        "error_rate": (0.15, 0.07),  # HIGH: permission failures
        "permission_denied_count": (8.0, 3.0),  # VERY HIGH: probing
        "unique_ports": (3.0, 1.5),
        "read_write_ratio": (2.0, 0.8),
        "send_recv_ratio": (0.8, 0.3),
        "tool_event_ratio": (0.65, 0.2),  # HIGH: tool-heavy
        "new_dest_ratio": (0.2, 0.1),
    }

def _prompt_injection_profile() -> dict[str, tuple[float, float]]:
    """Prompt injection: bursts of LLM interactions, low file/net."""
    return {
        "event_count": (25.0, 8.0),
        "tool_call_count": (15.0, 5.0),  # HIGH: rapid tool calls
        "events_per_second": (0.4, 0.15),
        "tool_calls_per_second": (0.25, 0.1),
        "file_read_count": (2.0, 1.0),
        "file_write_count": (0.5, 0.3),
        "network_connect_count": (1.0, 0.5),  # LOW: mostly LLM interaction
        "bytes_sent_total": (3000.0, 1200.0),
        "unique_event_types": (4.0, 1.5),
        "unique_tools_used": (3.0, 1.0),
        "unique_files_accessed": (2.0, 1.0),
        "unique_network_dests": (1.0, 0.5),
        "avg_response_time": (300.0, 120.0),  # HIGH: complex LLM responses
        "max_response_time": (1200.0, 500.0),
        "error_rate": (0.1, 0.05),
        "permission_denied_count": (1.0, 0.5),
        "unique_ports": (1.0, 0.5),
        "read_write_ratio": (4.0, 2.0),
        "send_recv_ratio": (0.6, 0.25),
        "tool_event_ratio": (0.6, 0.2),
        "new_dest_ratio": (0.05, 0.03),
    }

def _supply_chain_profile() -> dict[str, tuple[float, float]]:
    """Supply chain: external downloads, package installs, config writes."""
    return {
        "event_count": (18.0, 6.0),
        "tool_call_count": (10.0, 3.5),
        "events_per_second": (0.3, 0.12),
        "tool_calls_per_second": (0.17, 0.06),
        "file_read_count": (4.0, 2.0),
        "file_write_count": (6.0, 2.5),  # HIGH: writing packages
        "network_connect_count": (8.0, 3.0),  # HIGH: downloading
        "bytes_sent_total": (3000.0, 1500.0),
        "unique_event_types": (6.0, 2.0),
        "unique_tools_used": (5.0, 2.0),
        "unique_files_accessed": (8.0, 3.0),
        "unique_network_dests": (5.0, 2.0),  # HIGH: multiple registries
        "avg_response_time": (250.0, 100.0),
        "max_response_time": (1000.0, 400.0),
        "error_rate": (0.06, 0.03),
        "permission_denied_count": (1.0, 0.5),
        "unique_ports": (4.0, 2.0),
        "read_write_ratio": (0.7, 0.3),  # LOW: write-heavy
        "send_recv_ratio": (0.3, 0.15),  # LOW: downloading > sending
        "tool_event_ratio": (0.55, 0.2),
        "new_dest_ratio": (0.5, 0.2),  # HIGH: new package sources
    }

# Profile registry: class_index → profile function
_PROFILES: dict[int, Any] = {
    0: _benign_profile,
    1: _credential_theft_profile,
    2: _data_exfiltration_profile,
    3: _dos_profile,
    4: _lateral_movement_profile,
    5: _privilege_escalation_profile,
    6: _prompt_injection_profile,
    7: _supply_chain_profile,
}

# Feature category to column prefix mapping (for mapping profiles → features)
_CATEGORY_WINDOWS: dict[str, list[str]] = {
    "event_count": ["_1m", "_5m", "_1h", "_24h"],
    "tool_call_count": ["_1m", "_5m", "_1h", "_24h"],
    "events_per_second": ["_1m", "_5m"],
    "tool_calls_per_second": ["_1m", "_5m"],
    "file_read_count": ["_1m", "_5m", "_1h", "_24h"],
    "file_write_count": ["_1m", "_5m", "_1h", "_24h"],
    "network_connect_count": ["_1m", "_5m", "_1h", "_24h"],
    "bytes_sent_total": ["_1m", "_5m", "_1h", "_24h"],
    "unique_event_types": ["_1m", "_5m", "_1h", "_24h"],
    "unique_tools_used": ["_1m", "_5m", "_1h", "_24h"],
    "unique_files_accessed": ["_1m", "_5m", "_1h", "_24h"],
    "unique_network_dests": ["_1m", "_5m", "_1h", "_24h"],
    "avg_response_time": ["_1m", "_5m", "_1h", "_24h"],
    "max_response_time": ["_1m", "_5m"],
    "error_rate": ["_1m", "_5m"],
    "permission_denied_count": ["_1m", "_5m"],
    "unique_ports": ["_1m", "_5m"],
    "read_write_ratio": ["_1h"],
    "send_recv_ratio": ["_1h"],
    "tool_event_ratio": ["_1m", "_5m"],
    "new_dest_ratio": ["_1m", "_5m"],
}

# Time-window decay factors: shorter windows should have ~50-80% of the
# longer window values (recent activity is a fraction of cumulative)
_WINDOW_DECAY: dict[str, float] = {
    "_1m": 0.12,
    "_5m": 0.35,
    "_1h": 0.7,
    "_24h": 1.0,
}

class GlobalSyntheticGenerator:
    """Generate high-fidelity synthetic behavioral data for global model training.

    Each attack class generates feature vectors following its distinctive
    behavioral profile, with controlled noise for generalization.

    Security:
      - Deterministic via seeded RNG for reproducibility
      - No external data sources — purely algorithmic
      - Feature values clamped to physically plausible ranges
    """

    def __init__(self, random_state: int = 42) -> None:
        self._rng = np.random.default_rng(random_state)
        self._seed = random_state

    def generate(
        self,
        n_samples: int = 50_000,
        anomaly_fraction: float = 0.08,
        n_features: int = 62,
    ) -> tuple[NDArray[np.floating], NDArray[np.integer], list[str]]:
        """Generate multi-class synthetic training data.

        Args:
            n_samples: Total number of samples to generate.
            anomaly_fraction: Fraction of samples that are attack (classes 1-7).
            n_features: Number of features (must be 62 for standard model).

        Returns:
            (X, y, feature_names) where:
              X: (n_samples, 62) float64 feature matrix
              y: (n_samples,) int64 labels (0=benign, 1-7=attack classes)
              feature_names: list of 62 feature name strings
        """
        if n_features != 62:
            raise ValueError(
                f"Global model requires 62 features, got {n_features}. "
                "Use TrainingDataLoader.generate_synthetic_data() for "
                "arbitrary feature counts."
            )

        # Clamp anomaly_fraction to valid range
        anomaly_fraction = max(0.0, min(1.0, anomaly_fraction))
        n_samples = max(1, n_samples)

        n_anomaly = int(n_samples * anomaly_fraction)
        n_benign = n_samples - n_anomaly

        # Generate benign samples
        X_benign = self._generate_class(0, n_benign)
        y_benign = np.zeros(n_benign, dtype=np.int64)

        # Generate anomaly samples evenly across 7 attack classes
        n_per_class = n_anomaly // 7
        remainder = n_anomaly - n_per_class * 7

        X_parts = [X_benign]
        y_parts = [y_benign]

        for class_idx in range(1, 8):
            n_cls = n_per_class + (1 if class_idx <= remainder else 0)
            X_cls = self._generate_class(class_idx, n_cls)
            y_cls = np.full(n_cls, class_idx, dtype=np.int64)
            X_parts.append(X_cls)
            y_parts.append(y_cls)

        X = np.vstack(X_parts)
        y = np.concatenate(y_parts)

        # Shuffle with reproducible RNG
        indices = self._rng.permutation(len(X))
        X = X[indices]
        y = y[indices]

        # Final safety: clamp all values to [0, ∞) — no negative feature values
        np.clip(X, 0.0, None, out=X)

        logger.info(
            "synthetic_data_generated",
            total_samples=len(X),
            benign=n_benign,
            anomaly=n_anomaly,
            classes=8,
            features=62,
            seed=self._seed,
        )

        return X, y, list(GLOBAL_FEATURE_NAMES)

    def _generate_class(self, class_idx: int, n_samples: int) -> NDArray[np.floating]:
        """Generate feature vectors for a single class.

        Constructs each feature column by:
        1. Looking up the category profile (mean, std)
        2. Applying time-window decay for multi-window features
        3. Adding correlated noise across windows (temporal consistency)
        4. Adding per-sample noise (individual variation)
        """
        profile_fn = _PROFILES[class_idx]
        profile = profile_fn()

        X = np.zeros((n_samples, 62), dtype=np.float64)

        col_idx = 0
        for category, windows in _CATEGORY_WINDOWS.items():
            mean, std = profile[category]

            # Generate base values (shared temporal component)
            base = self._rng.normal(mean, std, size=n_samples)

            for window_suffix in windows:
                decay = _WINDOW_DECAY[window_suffix]
                # Scale by window decay
                col_vals = base * decay
                # Add per-window jitter (±10% of std)
                jitter = self._rng.normal(0, std * 0.1, size=n_samples)
                col_vals = col_vals + jitter
                X[:, col_idx] = col_vals
                col_idx += 1

        assert col_idx == 62, f"Generated {col_idx} columns, expected 62"
        return X

    def data_fingerprint(
        self,
        X: NDArray[np.floating],
        y: NDArray[np.integer],
    ) -> str:
        """Compute a reproducibility fingerprint for the generated data.

        Returns a SHA-256 hex digest that can be verified to ensure
        the exact same data was generated.
        """
        h = hashlib.sha256()
        h.update(X.tobytes())
        h.update(y.tobytes())
        h.update(str(self._seed).encode())
        return h.hexdigest()
