# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Stage 3: Autoencoder Anomaly Detector (J2).

PyTorch autoencoder that learns normal behavioral embeddings.
Anomalies are detected by high reconstruction error.

Architecture: input → encoder → bottleneck → decoder → output
Loss: MSE between input and output.
"""

from __future__ import annotations

import pickle
from pathlib import Path
from typing import Any

import numpy as np
from numpy.typing import NDArray

from ml.config import get_ml_config

try:
    import torch
    import torch.nn as nn
except ImportError:
    torch = None  # type: ignore[assignment]
    nn = None  # type: ignore[assignment]

def _build_autoencoder(input_dim: int, hidden_dims: tuple[int, ...], dropout: float):
    """Build a symmetric autoencoder as nn.Sequential."""
    layers = []
    prev_dim = input_dim
    for h in hidden_dims:
        layers.append(nn.Linear(prev_dim, h))
        layers.append(nn.ReLU())
        layers.append(nn.Dropout(dropout))
        prev_dim = h
    # Output layer — reconstruct original input
    layers.append(nn.Linear(prev_dim, input_dim))
    return nn.Sequential(*layers)

class AutoencoderModel:
    """PyTorch autoencoder for anomaly detection via reconstruction error."""

    def __init__(self, input_dim: int | None = None) -> None:
        if torch is None:
            raise ImportError("PyTorch is required: pip install torch")

        cfg = get_ml_config().autoencoder
        self._config = cfg
        self._input_dim = input_dim
        self._model: nn.Module | None = None
        self._is_fitted = False
        self._feature_names: list[str] = []
        self._train_mean: NDArray | None = None
        self._train_std: NDArray | None = None
        self._threshold: float = 0.5  # Reconstruction error threshold

        if input_dim is not None:
            self._model = _build_autoencoder(input_dim, cfg.hidden_dims, cfg.dropout)

    @property
    def is_fitted(self) -> bool:
        return self._is_fitted

    def fit(
        self,
        X: NDArray[np.floating],
        feature_names: list[str] | None = None,
    ) -> dict[str, Any]:
        """Train autoencoder on normal data.

        Args:
            X: (n_samples, n_features) — ONLY normal/benign samples.
            feature_names: Feature column names.

        Returns:
            Training metadata dict.
        """
        self._feature_names = feature_names or []
        self._input_dim = X.shape[1]
        cfg = self._config

        # Normalize training data
        self._train_mean = X.mean(axis=0)
        self._train_std = X.std(axis=0)
        self._train_std[self._train_std == 0] = 1.0  # Avoid division by zero
        X_norm = (X - self._train_mean) / self._train_std

        # Build model
        self._model = _build_autoencoder(self._input_dim, cfg.hidden_dims, cfg.dropout)
        device = torch.device("cpu")
        self._model.to(device)

        optimizer = torch.optim.Adam(self._model.parameters(), lr=cfg.learning_rate)
        criterion = nn.MSELoss()

        # Convert to torch tensor
        X_tensor = torch.FloatTensor(X_norm).to(device)
        dataset = torch.utils.data.TensorDataset(X_tensor, X_tensor)
        loader = torch.utils.data.DataLoader(dataset, batch_size=cfg.batch_size, shuffle=True)

        # Training loop
        self._model.train()
        final_loss = 0.0
        for _epoch in range(cfg.epochs):
            epoch_loss = 0.0
            for batch_x, _ in loader:
                optimizer.zero_grad()
                output = self._model(batch_x)
                loss = criterion(output, batch_x)
                loss.backward()
                optimizer.step()
                epoch_loss += loss.item()
            final_loss = epoch_loss / max(len(loader), 1)

        # Compute threshold from training data reconstruction errors
        self._model.eval()
        with torch.no_grad():
            reconstructed = self._model(X_tensor)
            errors = torch.mean((X_tensor - reconstructed) ** 2, dim=1).numpy()
            # Set threshold at 95th percentile of training errors
            self._threshold = float(np.percentile(errors, 95))

        self._is_fitted = True
        return {
            "n_samples": X.shape[0],
            "n_features": X.shape[1],
            "epochs": cfg.epochs,
            "final_loss": final_loss,
            "threshold_p95": self._threshold,
        }

    def predict_score(self, X: NDArray[np.floating]) -> NDArray[np.floating]:
        """Return anomaly scores in [0, 1] based on reconstruction error.

        Higher score = more anomalous (higher reconstruction error).
        """
        if not self._is_fitted or self._model is None:
            raise RuntimeError("Model not fitted")

        # Normalize
        X_norm = (X - self._train_mean) / self._train_std

        self._model.eval()
        with torch.no_grad():
            X_tensor = torch.FloatTensor(X_norm)
            reconstructed = self._model(X_tensor)
            errors = torch.mean((X_tensor - reconstructed) ** 2, dim=1).numpy()

        # Normalize to [0, 1] using the training threshold as calibration
        # scores = errors / (2 * threshold) capped at 1.0
        scores = errors / (2 * self._threshold) if self._threshold > 0 else errors
        return np.clip(scores, 0.0, 1.0)

    def predict_single(self, features: dict[str, float], ordered_names: list[str]) -> float:
        """Score a single feature vector. Returns anomaly score [0, 1]."""
        X = np.array([[features.get(n, 0.0) for n in ordered_names]])
        return float(self.predict_score(X)[0])

    def reconstruction_errors_per_feature(
        self, features: dict[str, float], ordered_names: list[str]
    ) -> list[tuple[str, float]]:
        """Return per-feature reconstruction error for explainability."""
        if not self._is_fitted or self._model is None:
            return []

        X = np.array([[features.get(n, 0.0) for n in ordered_names]])
        X_norm = (X - self._train_mean) / self._train_std

        self._model.eval()
        with torch.no_grad():
            X_tensor = torch.FloatTensor(X_norm)
            reconstructed = self._model(X_tensor)
            per_feature_errors = ((X_tensor - reconstructed) ** 2).numpy()[0]

        return sorted(
            zip(ordered_names, per_feature_errors.tolist(), strict=False),
            key=lambda x: x[1],
            reverse=True,
        )

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "state_dict": self._model.state_dict() if self._model else None,
            "input_dim": self._input_dim,
            "config": self._config,
            "is_fitted": self._is_fitted,
            "feature_names": self._feature_names,
            "train_mean": self._train_mean,
            "train_std": self._train_std,
            "threshold": self._threshold,
        }
        with open(path, "wb") as f:
            pickle.dump(data, f, protocol=pickle.HIGHEST_PROTOCOL)

    @classmethod
    def load(cls, path: str | Path) -> AutoencoderModel:
        with open(path, "rb") as f:
            data = pickle.load(f)  # noqa: S301
        obj = cls.__new__(cls)
        obj._config = data["config"]
        obj._input_dim = data["input_dim"]
        obj._is_fitted = data["is_fitted"]
        obj._feature_names = data.get("feature_names", [])
        obj._train_mean = data.get("train_mean")
        obj._train_std = data.get("train_std")
        obj._threshold = data.get("threshold", 0.5)
        if data.get("state_dict") and obj._input_dim:
            obj._model = _build_autoencoder(obj._input_dim, obj._config.hidden_dims, obj._config.dropout)
            obj._model.load_state_dict(data["state_dict"])
            obj._model.eval()
        else:
            obj._model = None
        return obj
