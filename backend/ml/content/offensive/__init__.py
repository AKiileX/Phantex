# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — Offensive Output & Campaign Detection

Sub-modules:

- **exploit_patterns**: 70+ regex patterns for offensive tool signatures
- **exploit_scanner**: ``BaseClassifier`` implementation that detects exploit code
- **campaign_tracker**: Cross-session behavioural accumulation (slow-burn attack detection)
- **trust_boundary**: Scanner for trust-boundary files that coding agents auto-parse
"""

from ml.content.offensive.campaign_tracker import CampaignTracker
from ml.content.offensive.exploit_scanner import ExploitCodeScanner
from ml.content.offensive.trust_boundary import TrustBoundaryScanner

__all__ = [
    "ExploitCodeScanner",
    "CampaignTracker",
    "TrustBoundaryScanner",
]
