# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Q2: Auto-Retrain Pipeline.

Automated model retraining system that monitors label accumulation,
triggers retraining when thresholds are met, validates new models
against quality gates, and performs hot-swap deployment via shadow mode.

Components:
  - RetrainScheduler: Monitors label counts and triggers retrains
  - RetrainPipeline: Orchestrates training, validation, and deployment
  - QualityGate: Ensures new models don't degrade performance
  - HotSwapper: Atomic model replacement in the serving layer
"""
