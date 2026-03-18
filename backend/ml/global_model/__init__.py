# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Q1: Global Starter Model.

Provides day-1 ML protection before any tenant-specific model is trained.
The global model is trained on synthetic attack patterns derived from
threat intelligence and security research, delivering baseline detection
for all 8 attack classes from the first event.

Architecture:
  - GlobalSyntheticGenerator: Produces realistic multi-class attack data
  - GlobalModelTrainer: Trains IF + XGBoost + AE on synthetic data
  - GlobalModelManager: Loads/caches the global ensemble, handles fallback
  - EnsembleFusion: Blends global + tenant models with adaptive weighting
"""
