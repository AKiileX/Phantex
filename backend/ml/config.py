# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — ML Pipeline Configuration.

Central configuration for feature extraction windows, model parameters,
Redis key prefixes, and all tunable ML constants. Values are read from
environment (via app.config) where appropriate, with hardcoded safe defaults.
"""

from __future__ import annotations

import functools
import os
from dataclasses import dataclass, field

def _default_n_jobs() -> int:
    """Return sensible n_jobs default.

    - In tests (PYTEST_CURRENT_TEST or PHANTEX_TESTING set): 1 (single core).
    - Env override: PHANTEX_ML_N_JOBS (e.g. "4").
    - Production default: max(1, cpu_count // 2) — leave headroom for the
      API, Kafka consumers, and inference pipeline.

    NEVER use -1 ("all cores") — it starves co-located services and can
    push CPU to 100% in production.
    """
    # Explicit override always wins
    env = os.environ.get("PHANTEX_ML_N_JOBS")
    if env is not None:
        return max(1, int(env))
    # Test mode — single core to avoid pegging the machine
    if os.environ.get("PYTEST_CURRENT_TEST") or os.environ.get("PHANTEX_TESTING"):
        return 1
    # Production: half of available CPUs (minimum 1)
    cpu_count = os.cpu_count() or 2
    return max(1, cpu_count // 2)

# ── Feature Windows ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class FeatureWindow:
    """A named time window for feature computation."""

    name: str
    seconds: int

# Standard windows used by volume, velocity, diversity, network features
WINDOWS = [
    FeatureWindow("1m", 60),
    FeatureWindow("5m", 300),
    FeatureWindow("1h", 3_600),
    FeatureWindow("24h", 86_400),
]

ROLLING_WINDOWS = [
    FeatureWindow("1m", 60),
    FeatureWindow("5m", 300),
]

# ── Redis Key Scheme ─────────────────────────────────────────────────────────

REDIS_FEATURE_PREFIX = "ml:features"  # ml:features:{tenant_id}:{agent_id}
REDIS_EVENT_STREAM_PREFIX = "ml:events"  # ml:events:{tenant_id}:{agent_id}
REDIS_FEATURE_TTL = 86_400  # 24h — auto-cleanup of inactive agents
REDIS_EVENT_STREAM_MAXLEN = 10_000  # Max events kept per agent stream

# ── Feature Extraction ───────────────────────────────────────────────────────

@dataclass(frozen=True)
class FeatureExtractionConfig:
    """Configuration for the feature extraction consumer."""

    consumer_group: str = "ml-feature-extractor"
    batch_size: int = 1_000
    flush_interval_seconds: float = 1.0
    # Feature value bounds (clamp to prevent overflow / model poisoning)
    max_count: int = 1_000_000
    max_bytes: int = 10_000_000_000  # 10 GB
    max_rate: float = 100_000.0  # 100K events/sec ceiling

# ── Model Configuration ──────────────────────────────────────────────────────

@dataclass(frozen=True)
class IsolationForestConfig:
    """Stage 1: Isolation Forest hyperparameters."""

    n_estimators: int = 200
    contamination: float = 0.05
    max_features: float = 1.0
    random_state: int = 42
    n_jobs: int = -1  # Overridden at runtime — see MLConfig

    def __post_init__(self):
        if self.n_jobs == -1:
            object.__setattr__(self, "n_jobs", _default_n_jobs())

@dataclass(frozen=True)
class XGBoostConfig:
    """Stage 2: XGBoost hyperparameters."""

    max_depth: int = 8
    learning_rate: float = 0.1
    n_estimators: int = 500
    eval_metric: str = "logloss"
    tree_method: str = "hist"
    random_state: int = 42
    n_jobs: int = -1  # Overridden at runtime — see MLConfig

    def __post_init__(self):
        if self.n_jobs == -1:
            object.__setattr__(self, "n_jobs", _default_n_jobs())

@dataclass(frozen=True)
class AutoencoderConfig:
    """Stage 3: PyTorch Autoencoder hyperparameters."""

    hidden_dims: tuple[int, ...] = (64, 32, 16, 32, 64)
    epochs: int = 50
    learning_rate: float = 0.001
    batch_size: int = 256
    dropout: float = 0.1

    def __post_init__(self):
        # In test mode, cap epochs to avoid burning CPU on 50-epoch training
        if self.epochs == 50 and (os.environ.get("PYTEST_CURRENT_TEST") or os.environ.get("PHANTEX_TESTING")):
            object.__setattr__(self, "epochs", 3)

@dataclass(frozen=True)
class EnsembleConfig:
    """Ensemble scorer weights and thresholds."""

    weight_stage1: float = 0.3  # Isolation Forest
    weight_stage2: float = 0.5  # XGBoost
    weight_stage3: float = 0.2  # Autoencoder
    alert_threshold: float = 0.7
    shadow_fpr_max: float = 0.10  # Max FPR allowed in shadow mode

# ── Training Configuration ───────────────────────────────────────────────────

@dataclass(frozen=True)
class TrainingConfig:
    """Offline training pipeline configuration."""

    lookback_days: int = 30
    min_samples: int = 1_000
    validation_split: float = 0.2
    precision_threshold: float = 0.90
    recall_threshold: float = 0.80
    fpr_threshold: float = 0.05
    model_dir: str = "models"

    # Dev-mode isolation: when True, training data from dev/simulator tenants
    # is excluded from model training. Set PHANTEX_ML_DEV_MODE=true in dev.
    dev_mode: bool = False
    # Tenant IDs to exclude from training when dev_mode is active.
    # Default includes the seed-data dev tenant.
    dev_tenant_ids: tuple[str, ...] = ("a0000000-0000-0000-0000-000000000001",)

    def __post_init__(self):
        # Auto-enable from environment
        env = os.environ.get("PHANTEX_ML_DEV_MODE", "")
        if env.lower() in ("1", "true", "yes") and not self.dev_mode:
            object.__setattr__(self, "dev_mode", True)

# ── Baseline Configuration ───────────────────────────────────────────────────

@dataclass(frozen=True)
class BaselineConfig:
    """Per-agent behavioral baseline settings."""

    learning_days: int = 7
    min_learning_events: int = 1_000  # Minimum events before LEARNING → ACTIVE
    early_graduation: bool = True  # Graduate early if variance stabilizes
    early_graduation_min_events: int = 500  # Minimum events for early graduation check
    variance_stability_threshold: float = 0.05  # Relative variance change < 5% → stable
    alert_aware_learning: bool = True  # Exclude PRL-flagged events from baseline
    sigma_threshold: float = 3.0  # Alert when value > mean + Nσ
    ema_alpha: float = 0.1  # Exponential moving average decay
    stale_days: int = 30  # Mark stale after N days inactive
    p95_multiplier: float = 2.0  # Alert when value > p95 × N
    js_divergence_threshold: float = 0.15  # Jensen-Shannon divergence

# ── Inference Configuration ──────────────────────────────────────────────────

@dataclass(frozen=True)
class InferenceConfig:
    """Online inference pipeline settings."""

    model_poll_seconds: int = 300  # Check for new model every 5 min
    shadow_duration_seconds: int = 3_600  # 1h shadow mode for new models
    max_inference_ms: float = 20.0  # P99 target
    consumer_group: str = "ml-inference"
    batch_size: int = 500
    flush_interval_seconds: float = 1.0

# ── Q1: Global Starter Model Configuration ──────────────────────────────────

@dataclass(frozen=True)
class GlobalModelConfig:
    """Configuration for the global (tier-0) starter model.

    The global model provides day-1 protection before any tenant-specific
    model is trained. Tenant models progressively take over via ensemble
    fusion as they mature.
    """

    # Sentinel tenant_id for global model storage in the registry
    global_tenant_id: str = "__global__"
    # Path for pre-generated global model artifacts
    artifacts_dir: str = "models/__global__"
    # Minimum synthetic samples used to train the global model
    synthetic_samples: int = 50_000
    # Number of features the global model expects
    n_features: int = 62
    # Anomaly fraction in synthetic training data
    anomaly_fraction: float = 0.08

@dataclass(frozen=True)
class EnsembleFusionConfig:
    """Configuration for blending global + tenant models (Q1).

    The fusion weight shifts from fully-global to mostly-tenant as the
    tenant model accumulates training data and proven accuracy.

    final_score = w_global * global_score + w_tenant * tenant_score
    w_global + w_tenant = 1.0
    """

    # Initial global model weight (tenant has no model yet)
    initial_global_weight: float = 1.0
    # Minimum global weight (even with mature tenant model, keep floor)
    min_global_weight: float = 0.15
    # Number of tenant training samples at which fusion is 50/50
    crossover_samples: int = 5_000
    # Decay rate for sigmoid transition (higher = sharper transition)
    decay_rate: float = 0.0008
    # Minimum tenant model validation precision to start blending
    min_tenant_precision: float = 0.70

# ── Q2: Auto-Retrain Configuration ──────────────────────────────────────────

@dataclass(frozen=True)
class AutoRetrainConfig:
    """Configuration for the automatic retrain pipeline (Q2).

    Scheduler triggers retrain when enough new labeled data arrives.
    Quality gates ensure new models don't degrade performance.
    """

    # Minimum accumulated labels before triggering a retrain
    min_new_labels: int = 50
    # Retrain check interval in seconds (default: 6 hours)
    check_interval_seconds: int = 21_600
    # Maximum retrain frequency (don't retrain more often than this)
    min_retrain_gap_seconds: int = 3_600  # 1 hour minimum between retrains
    # Quality gate: new model must meet these thresholds relative to current
    precision_regression_tolerance: float = 0.02  # Allow 2% precision drop
    recall_regression_tolerance: float = 0.05  # Allow 5% recall drop
    fpr_max: float = 0.10  # Absolute FPR ceiling
    # Shadow validation duration before promotion (seconds)
    shadow_validation_seconds: int = 1_800  # 30 minutes
    # Maximum concurrent retrains across all tenants
    max_concurrent_retrains: int = 4
    # Enable/disable auto-retrain globally
    enabled: bool = True

# ── Convenience accessor ─────────────────────────────────────────────────────

@dataclass
class MLConfig:
    """Top-level container for all ML configuration."""

    features: FeatureExtractionConfig = field(default_factory=FeatureExtractionConfig)
    isolation_forest: IsolationForestConfig = field(default_factory=IsolationForestConfig)
    xgboost: XGBoostConfig = field(default_factory=XGBoostConfig)
    autoencoder: AutoencoderConfig = field(default_factory=AutoencoderConfig)
    ensemble: EnsembleConfig = field(default_factory=EnsembleConfig)
    training: TrainingConfig = field(default_factory=TrainingConfig)
    baseline: BaselineConfig = field(default_factory=BaselineConfig)
    inference: InferenceConfig = field(default_factory=InferenceConfig)
    global_model: GlobalModelConfig = field(default_factory=GlobalModelConfig)
    ensemble_fusion: EnsembleFusionConfig = field(default_factory=EnsembleFusionConfig)
    auto_retrain: AutoRetrainConfig = field(default_factory=AutoRetrainConfig)

    # Q3/Q4 — Telemetry export configs (lazy import to avoid circular deps)
    @property
    def telemetry_export(self):
        from ml.telemetry.config import TelemetryExportConfig

        return TelemetryExportConfig()

    @property
    def cloud_ingestion(self):
        from ml.telemetry.config import CloudIngestionConfig

        return CloudIngestionConfig()

@functools.lru_cache(maxsize=1)
def get_ml_config() -> MLConfig:
    """Return the (cached) default ML configuration."""
    return MLConfig()
