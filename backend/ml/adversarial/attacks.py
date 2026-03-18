# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Adversarial Attack Implementations (J5a).

Provides FGSM, PGD, and feature-perturbation attacks for robustness testing.
All attacks operate on NumPy arrays and target the autoencoder's gradient
(Stage 3) or the XGBoost/IF decision boundary (Stage 2/1).

These are INTERNAL testing tools — never exposed via API.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import numpy as np
import structlog
from numpy.typing import NDArray

logger = structlog.get_logger("phantex.ml.adversarial.attacks")

try:
    import torch
    import torch.nn as nn

    _TORCH = True
except ImportError:
    _TORCH = False

# ── Attack Result ────────────────────────────────────────────────────────────

@dataclass
class AttackResult:
    """Result of an adversarial attack run."""

    attack_name: str
    epsilon: float
    total_samples: int
    evaded_samples: int
    evasion_rate: float
    mean_perturbation: float
    details: dict[str, Any] = field(default_factory=dict)

# ── FGSM (Fast Gradient Sign Method) ────────────────────────────────────────

def fgsm_attack(
    model: nn.Module,
    X: NDArray[np.floating],
    epsilon: float = 0.1,
    threshold: float = 0.5,
    train_mean: NDArray | None = None,
    train_std: NDArray | None = None,
) -> AttackResult:
    """Fast Gradient Sign Method against the autoencoder.

    Single-step gradient perturbation to maximize reconstruction error for
    samples that should be flagged (positive) or minimize error for anomalies.

    Strategy: for each sample classified as anomalous, perturb to reduce
    reconstruction error (evade detection).

    Args:
        model: PyTorch autoencoder (nn.Module).
        X: Input samples (n_samples, n_features) — raw feature scale.
        epsilon: Maximum perturbation magnitude (L∞ norm).
        threshold: Reconstruction error threshold for anomaly.
        train_mean: Training set mean (for normalization).
        train_std: Training set std (for normalization).

    Returns:
        AttackResult with evasion rate and details.
    """
    if not _TORCH:
        raise ImportError("PyTorch required for FGSM attack")

    model.eval()

    # Normalize
    X_norm = (X - train_mean) / train_std if train_mean is not None and train_std is not None else X.copy()

    X_t = torch.tensor(X_norm, dtype=torch.float32, requires_grad=True)

    # Forward pass
    with torch.enable_grad():
        recon = model(X_t)
        loss = nn.MSELoss(reduction="none")(recon, X_t).mean(dim=1)

    # Get samples that are currently flagged as anomalous
    errors = loss.detach().numpy()
    anomalous_mask = errors > threshold

    if anomalous_mask.sum() == 0:
        return AttackResult(
            attack_name="fgsm",
            epsilon=epsilon,
            total_samples=len(X),
            evaded_samples=0,
            evasion_rate=0.0,
            mean_perturbation=0.0,
            details={"no_anomalous_samples": True},
        )

    # Compute gradients for the loss
    loss.sum().backward()
    grad = X_t.grad.data  # type: ignore[union-attr]

    # FGSM: perturb in the direction that REDUCES loss (evade detection)
    perturbation = -epsilon * grad.sign()
    X_adv = X_t.data + perturbation

    # Evaluate adversarial samples
    with torch.no_grad():
        recon_adv = model(X_adv)
        loss_adv = nn.MSELoss(reduction="none")(recon_adv, X_adv).mean(dim=1)

    adv_errors = loss_adv.numpy()
    # Evasion: sample was anomalous before, now below threshold
    evaded = (anomalous_mask) & (adv_errors <= threshold)
    evaded_count = int(evaded.sum())

    perturbation_norms = np.abs(perturbation.numpy()).mean()

    return AttackResult(
        attack_name="fgsm",
        epsilon=epsilon,
        total_samples=int(anomalous_mask.sum()),
        evaded_samples=evaded_count,
        evasion_rate=evaded_count / max(int(anomalous_mask.sum()), 1),
        mean_perturbation=float(perturbation_norms),
        details={
            "pre_attack_mean_error": float(errors[anomalous_mask].mean()),
            "post_attack_mean_error": float(adv_errors[anomalous_mask].mean()),
        },
    )

# ── PGD (Projected Gradient Descent) ────────────────────────────────────────

def pgd_attack(
    model: nn.Module,
    X: NDArray[np.floating],
    epsilon: float = 0.05,
    step_size: float = 0.01,
    num_steps: int = 20,
    threshold: float = 0.5,
    train_mean: NDArray | None = None,
    train_std: NDArray | None = None,
) -> AttackResult:
    """Projected Gradient Descent — multi-step iterative FGSM.

    Stronger than FGSM: takes multiple small gradient steps, projecting back
    to the ε-ball after each step.

    Args:
        model: PyTorch autoencoder.
        X: Input samples.
        epsilon: L∞ perturbation budget.
        step_size: Step size per iteration (α).
        num_steps: Number of PGD iterations.
        threshold: Anomaly threshold.
        train_mean: Training mean.
        train_std: Training std.

    Returns:
        AttackResult with evasion rate.
    """
    if not _TORCH:
        raise ImportError("PyTorch required for PGD attack")

    model.eval()

    X_norm = (X - train_mean) / train_std if train_mean is not None and train_std is not None else X.copy()

    X_orig = torch.tensor(X_norm, dtype=torch.float32)

    # Get initially anomalous samples
    with torch.no_grad():
        recon = model(X_orig)
        errors = nn.MSELoss(reduction="none")(recon, X_orig).mean(dim=1).numpy()
    anomalous_mask = errors > threshold

    if anomalous_mask.sum() == 0:
        return AttackResult(
            attack_name="pgd",
            epsilon=epsilon,
            total_samples=len(X),
            evaded_samples=0,
            evasion_rate=0.0,
            mean_perturbation=0.0,
            details={"no_anomalous_samples": True},
        )

    # Initialize adversarial perturbation (random start within ε-ball)
    delta = torch.zeros_like(X_orig)
    delta.uniform_(-epsilon, epsilon)
    delta = torch.clamp(delta, -epsilon, epsilon)
    delta.requires_grad_(True)

    for _step in range(num_steps):
        X_adv = X_orig + delta

        recon = model(X_adv)
        # Minimize reconstruction error to evade
        loss = nn.MSELoss(reduction="none")(recon, X_adv).mean(dim=1).sum()

        loss.backward()

        with torch.no_grad():
            # Step in negative gradient direction (reduce error)
            delta.data -= step_size * delta.grad.sign()  # type: ignore[union-attr]
            # Project back to ε-ball
            delta.data = torch.clamp(delta.data, -epsilon, epsilon)

        if delta.grad is not None:
            delta.grad.zero_()

    # Evaluate
    with torch.no_grad():
        X_final = X_orig + delta
        recon_final = model(X_final)
        adv_errors = nn.MSELoss(reduction="none")(recon_final, X_final).mean(dim=1).numpy()

    evaded = (anomalous_mask) & (adv_errors <= threshold)
    evaded_count = int(evaded.sum())

    return AttackResult(
        attack_name="pgd",
        epsilon=epsilon,
        total_samples=int(anomalous_mask.sum()),
        evaded_samples=evaded_count,
        evasion_rate=evaded_count / max(int(anomalous_mask.sum()), 1),
        mean_perturbation=float(torch.abs(delta).mean()),
        details={
            "num_steps": num_steps,
            "step_size": step_size,
            "pre_attack_mean_error": float(errors[anomalous_mask].mean()),
            "post_attack_mean_error": float(adv_errors[anomalous_mask].mean()),
        },
    )

# ── Feature Perturbation (Model-Agnostic) ───────────────────────────────────

def feature_perturbation_attack(
    predict_fn,
    X: NDArray[np.floating],
    y_pred: NDArray[np.integer],
    perturbation_pct: float = 0.20,
    top_k: int = 5,
    feature_importances: NDArray | None = None,
    random_state: int = 42,
) -> AttackResult:
    """Perturb top-K features by ±perturbation_pct to flip predictions.

    Model-agnostic: works on any predict_fn that takes X and returns labels.

    Args:
        predict_fn: Callable(X) → labels (int array).
        X: Input samples.
        y_pred: Current predictions.
        perturbation_pct: Fractional perturbation (0.20 = ±20%).
        top_k: Number of most important features to perturb.
        feature_importances: Feature importance scores (higher = more important).
            If None, perturb random features.
        random_state: RNG seed.

    Returns:
        AttackResult with prediction flip rate.
    """
    rng = np.random.RandomState(random_state)
    n_samples, n_features = X.shape

    # Select top-K features to perturb
    if feature_importances is not None:
        top_indices = np.argsort(feature_importances)[-top_k:]
    else:
        top_indices = rng.choice(n_features, size=min(top_k, n_features), replace=False)

    X_adv = X.copy()

    for idx in top_indices:
        col = X_adv[:, idx]
        col_range = np.abs(col) * perturbation_pct
        col_range = np.maximum(col_range, 0.01)  # Minimum perturbation for zero values
        noise = rng.uniform(-col_range, col_range)
        X_adv[:, idx] = col + noise

    y_adv = predict_fn(X_adv)
    flipped = y_pred != y_adv
    flip_count = int(flipped.sum())

    mean_perturb = float(np.abs(X_adv - X).mean())

    return AttackResult(
        attack_name="feature_perturbation",
        epsilon=perturbation_pct,
        total_samples=n_samples,
        evaded_samples=flip_count,
        evasion_rate=flip_count / max(n_samples, 1),
        mean_perturbation=mean_perturb,
        details={
            "top_k": top_k,
            "perturbed_features": top_indices.tolist(),
        },
    )
