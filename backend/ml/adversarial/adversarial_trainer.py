# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Adversarial Training Wrapper (J5a).

Augments training data with adversarial examples (FGSM + PGD variants)
so models learn to be robust against perturbation attacks.

Strategy: 50% clean + 50% adversarial samples during training.
Adversarial samples keep their ORIGINAL label (an attack is still an attack
even if perturbed).
"""

from __future__ import annotations

import numpy as np
import structlog
from numpy.typing import NDArray

logger = structlog.get_logger("phantex.ml.adversarial.adversarial_trainer")

try:
    import torch
    import torch.nn as nn

    _TORCH = True
except ImportError:
    _TORCH = False

def generate_adversarial_samples(
    model: nn.Module,
    X: NDArray[np.floating],
    epsilon: float = 0.1,
    method: str = "fgsm",
    num_steps: int = 10,
    step_size: float = 0.01,
    train_mean: NDArray | None = None,
    train_std: NDArray | None = None,
) -> NDArray[np.floating]:
    """Generate adversarial variants of input samples.

    Args:
        model: PyTorch autoencoder.
        X: Clean input samples (raw feature scale).
        epsilon: Max perturbation (L∞).
        method: "fgsm" or "pgd".
        num_steps: PGD steps (ignored for FGSM).
        step_size: PGD step size (ignored for FGSM).
        train_mean: Training mean for normalization.
        train_std: Training std for normalization.

    Returns:
        Adversarial samples (same shape as X, raw feature scale).
    """
    if not _TORCH:
        raise ImportError("PyTorch required for adversarial training")

    model.eval()

    X_norm = (X - train_mean) / train_std if train_mean is not None and train_std is not None else X.copy()

    X_t = torch.tensor(X_norm, dtype=torch.float32)

    if method == "fgsm":
        X_adv_norm = _fgsm_generate(model, X_t, epsilon)
    elif method == "pgd":
        X_adv_norm = _pgd_generate(model, X_t, epsilon, step_size, num_steps)
    else:
        raise ValueError(f"Unknown method: {method}. Use 'fgsm' or 'pgd'.")

    X_adv = X_adv_norm.detach().numpy()

    # Denormalize back to raw scale
    if train_mean is not None and train_std is not None:
        X_adv = X_adv * train_std + train_mean

    return X_adv.astype(X.dtype)

def _fgsm_generate(
    model: nn.Module,
    X_t: torch.Tensor,
    epsilon: float,
) -> torch.Tensor:
    """Single-step FGSM adversarial generation."""
    X_input = X_t.clone().requires_grad_(True)
    recon = model(X_input)
    loss = nn.MSELoss()(recon, X_input)
    loss.backward()
    grad = X_input.grad.data  # type: ignore[union-attr]
    # Perturb to INCREASE reconstruction error (make harder for model)
    X_adv = X_input.data + epsilon * grad.sign()
    return X_adv

def _pgd_generate(
    model: nn.Module,
    X_t: torch.Tensor,
    epsilon: float,
    step_size: float,
    num_steps: int,
) -> torch.Tensor:
    """Multi-step PGD adversarial generation."""
    delta = torch.zeros_like(X_t).uniform_(-epsilon, epsilon)
    delta = torch.clamp(delta, -epsilon, epsilon)

    for _ in range(num_steps):
        delta.requires_grad_(True)
        X_adv = X_t + delta
        recon = model(X_adv)
        loss = nn.MSELoss()(recon, X_adv)
        loss.backward()
        with torch.no_grad():
            delta = delta + step_size * delta.grad.sign()  # type: ignore[union-attr]
            delta = torch.clamp(delta, -epsilon, epsilon)
        delta = delta.detach()

    return X_t + delta

def augment_training_data(
    model: nn.Module,
    X_train: NDArray[np.floating],
    y_train: NDArray | None = None,
    epsilon: float = 0.1,
    adversarial_ratio: float = 0.5,
    methods: list[str] | None = None,
    train_mean: NDArray | None = None,
    train_std: NDArray | None = None,
    random_state: int = 42,
) -> tuple[NDArray[np.floating], NDArray | None]:
    """Augment training data with adversarial examples.

    Creates a mixed dataset of clean + adversarial samples.
    Adversarial samples retain their original labels.

    Args:
        model: Trained autoencoder model.
        X_train: Clean training data.
        y_train: Labels (optional — preserved for adversarial copies).
        epsilon: Perturbation budget.
        adversarial_ratio: Fraction of adversarial samples (0.5 = 50/50).
        methods: List of attack methods to use. Default: ["fgsm", "pgd"].
        train_mean: Training mean.
        train_std: Training std.
        random_state: RNG seed.

    Returns:
        (X_augmented, y_augmented) — shuffled mix of clean + adversarial.
    """
    rng = np.random.RandomState(random_state)
    methods = methods or ["fgsm", "pgd"]

    n_samples = len(X_train)
    n_adv = int(n_samples * adversarial_ratio)

    # Select samples to create adversarial versions of
    adv_indices = rng.choice(n_samples, size=n_adv, replace=False)
    X_subset = X_train[adv_indices]

    # Generate adversarial samples using alternating methods
    adv_batches = []
    batch_size = max(1, n_adv // len(methods))

    for i, method in enumerate(methods):
        start = i * batch_size
        end = min(start + batch_size, n_adv) if i < len(methods) - 1 else n_adv
        if start >= end:
            continue
        batch = generate_adversarial_samples(
            model=model,
            X=X_subset[start:end],
            epsilon=epsilon,
            method=method,
            train_mean=train_mean,
            train_std=train_std,
        )
        adv_batches.append(batch)

    X_adv = np.vstack(adv_batches) if adv_batches else np.empty((0, X_train.shape[1]))

    # Combine clean + adversarial
    X_augmented = np.vstack([X_train, X_adv])

    y_augmented = None
    if y_train is not None:
        y_adv = y_train[adv_indices[: len(X_adv)]]
        y_augmented = np.concatenate([y_train, y_adv])

    # Shuffle
    perm = rng.permutation(len(X_augmented))
    X_augmented = X_augmented[perm]
    if y_augmented is not None:
        y_augmented = y_augmented[perm]

    logger.info(
        "adversarial_augmentation_complete",
        clean_samples=n_samples,
        adversarial_samples=len(X_adv),
        total_samples=len(X_augmented),
        methods=methods,
    )

    return X_augmented, y_augmented
