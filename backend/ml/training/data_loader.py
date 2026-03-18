# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Training Data Loader (J2).

Load feature vectors from ClickHouse for model training.
Supports loading by date range, tenant isolation, and label joins.
"""

from __future__ import annotations

import numpy as np
import structlog
from numpy.typing import NDArray

logger = structlog.get_logger("phantex.ml.training.data_loader")

# ── Column mapping: ClickHouse ml_features_hourly → feature names ────────────
_CH_COLUMN_MAP = {
    "event_count": "event_count_1h",
    "tool_call_count": "tool_call_count_1h",
    "file_read_count": "file_read_count_1h",
    "network_connect_count": "network_connect_count_1h",
    "bytes_sent_total": "bytes_sent_total_1h",
    "bytes_recv_total": "bytes_recv_total_1h",
    "unique_dest_ips": "unique_network_dests_1h",
    "unique_dest_ports": "unique_ports_1h",
    "unique_event_types": "unique_event_types_1h",
    "unique_tools": "unique_tools_used_1h",
    "unique_files": "unique_files_accessed_1h",
    "avg_duration_ms": "avg_response_time_1h",
    "max_duration_ms": "max_response_time_1h",
}

# Columns to SELECT from ClickHouse (order matters for array indexing)
_CH_SELECT_COLUMNS = list(_CH_COLUMN_MAP.keys())
_FEATURE_NAMES = list(_CH_COLUMN_MAP.values())

class TrainingDataLoader:
    """Load feature matrices from ClickHouse for offline training.

    In Phase 2, models are trained per-tenant (no cross-tenant data).
    """

    def __init__(self, clickhouse_client=None) -> None:
        self._ch = clickhouse_client

    async def load_features(
        self,
        tenant_id: str,
        lookback_days: int = 30,
        feature_names: list[str] | None = None,
    ) -> tuple[NDArray[np.floating], list[str], list[str]]:
        """Load feature vectors from ClickHouse ml_features_hourly table.

        Returns:
            Tuple of (X matrix, feature_names list, agent_ids list).

        Dev-mode safety:
            When ``MLConfig.training.dev_mode`` is active and the requested
            tenant_id is in the dev_tenant_ids exclusion list, this method
            returns an empty dataset to prevent simulator/test data from
            contaminating production models.
        """
        # ── Dev-mode guard: skip training on simulator/test tenants ──
        from ml.config import get_ml_config

        ml_cfg = get_ml_config()
        if ml_cfg.training.dev_mode and tenant_id in ml_cfg.training.dev_tenant_ids:
            logger.warning(
                "dev_mode_training_skipped",
                tenant_id=tenant_id,
                reason="Tenant is in dev_tenant_ids exclusion list. Set PHANTEX_ML_DEV_MODE=false to include.",
            )
            return np.empty((0, 0)), _FEATURE_NAMES, []

        if self._ch is None:
            logger.warning("clickhouse_not_available", action="returning_empty")
            return np.empty((0, 0)), [], []

        logger.info(
            "loading_training_data",
            tenant_id=tenant_id,
            lookback_days=lookback_days,
        )

        cols = ", ".join(_CH_SELECT_COLUMNS)
        query = f"""
            SELECT
                agent_id,
                {cols}
            FROM phantex.ml_features_hourly
            WHERE tenant_id = {{tenant_id:UUID}}
              AND hour >= now() - INTERVAL {{lookback_days:UInt32}} DAY
            ORDER BY agent_id, hour
        """

        try:
            result = await self._ch.query(
                query,
                parameters={
                    "tenant_id": tenant_id,
                    "lookback_days": lookback_days,
                },
            )
        except Exception:
            logger.exception("clickhouse_query_failed", tenant_id=tenant_id)
            return np.empty((0, 0)), [], []

        rows = result.result_rows
        if not rows:
            logger.info("no_training_data", tenant_id=tenant_id)
            return np.empty((0, 0)), _FEATURE_NAMES, []

        # Parse rows: column 0 = agent_id, columns 1..N = features
        agent_ids = [str(row[0]) for row in rows]
        X = np.array(
            [[float(row[i + 1]) for i in range(len(_CH_SELECT_COLUMNS))] for row in rows],
            dtype=np.float64,
        )

        # Guard: replace NaN/Inf with 0
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

        used_names = feature_names if feature_names else _FEATURE_NAMES

        logger.info(
            "training_data_loaded",
            tenant_id=tenant_id,
            rows=len(rows),
            features=len(used_names),
            unique_agents=len(set(agent_ids)),
        )

        return X, used_names, agent_ids

    # ── Sync loading (for synchronous training pipelines) ─────────────

    def load_features_sync(
        self,
        tenant_id: str,
        lookback_days: int = 30,
    ) -> tuple[NDArray[np.floating], list[str], list[str]]:
        """Load feature vectors from ClickHouse using the **sync** client.

        Used by ``TrainingPipeline.train_all()`` which runs in a
        synchronous context.  Falls back to empty arrays if the client
        is not configured.

        Returns:
            Tuple of (X matrix, feature_names list, agent_ids list).
        """
        if self._ch is None:
            logger.warning("clickhouse_not_available_sync", action="returning_empty")
            return np.empty((0, 0)), [], []

        logger.info(
            "loading_training_data_sync",
            tenant_id=tenant_id,
            lookback_days=lookback_days,
        )

        cols = ", ".join(_CH_SELECT_COLUMNS)
        query = f"""
            SELECT
                agent_id,
                {cols}
            FROM phantex.ml_features_hourly
            WHERE tenant_id = %(tenant_id)s
              AND hour >= now() - INTERVAL %(lookback_days)s DAY
            ORDER BY agent_id, hour
        """

        try:
            result = self._ch.query(
                query,
                parameters={
                    "tenant_id": tenant_id,
                    "lookback_days": lookback_days,
                },
            )
        except Exception:
            logger.exception("clickhouse_sync_query_failed", tenant_id=tenant_id)
            return np.empty((0, 0)), _FEATURE_NAMES, []

        rows = result.result_rows
        if not rows:
            logger.info("no_training_data_sync", tenant_id=tenant_id)
            return np.empty((0, 0)), _FEATURE_NAMES, []

        agent_ids = [str(row[0]) for row in rows]
        X = np.array(
            [[float(row[i + 1]) for i in range(len(_CH_SELECT_COLUMNS))] for row in rows],
            dtype=np.float64,
        )
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

        logger.info(
            "training_data_loaded_sync",
            tenant_id=tenant_id,
            rows=len(rows),
            features=len(_FEATURE_NAMES),
            unique_agents=len(set(agent_ids)),
        )

        return X, _FEATURE_NAMES, agent_ids

    def generate_synthetic_data(
        self,
        n_samples: int = 10_000,
        n_features: int = 30,
        anomaly_fraction: float = 0.05,
        random_state: int = 42,
    ) -> tuple[NDArray[np.floating], NDArray[np.integer], list[str]]:
        """Generate synthetic training data for development/testing.

        Returns:
            Tuple of (X, y, feature_names).
            y: 0 = benign, 1..7 = attack classes.
        """
        rng = np.random.RandomState(random_state)

        feature_names = [f"feature_{i}" for i in range(n_features)]

        n_anomaly = int(n_samples * anomaly_fraction)
        n_normal = n_samples - n_anomaly

        # Normal samples: centered at origin, low variance
        X_normal = rng.randn(n_normal, n_features) * 0.3
        y_normal = np.zeros(n_normal, dtype=np.int64)  # class 0 = benign

        # Anomaly samples: offset from origin, higher variance
        X_anomaly = rng.randn(n_anomaly, n_features) * 1.5 + 2.0
        # Assign to random attack classes (1..7)
        y_anomaly = rng.randint(1, 8, size=n_anomaly).astype(np.int64)

        X = np.vstack([X_normal, X_anomaly])
        y = np.concatenate([y_normal, y_anomaly])

        # Shuffle
        indices = rng.permutation(n_samples)
        X = X[indices]
        y = y[indices]

        return X, y, feature_names
