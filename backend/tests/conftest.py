# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Shared test fixtures and path configuration.

Adds the workspace root to sys.path so that the `rules` package
(which lives at the project root, not inside backend/) is importable.
"""

import os
import sys
from pathlib import Path

# ── Mark test mode BEFORE any ML config is imported ──────────────────────────
# This ensures n_jobs=1, reduced epochs, etc. via ml.config._default_n_jobs()
os.environ["PHANTEX_TESTING"] = "1"

# Workspace root: backend/tests/../../ → PHANTEX/
_workspace_root = str(Path(__file__).resolve().parent.parent.parent)
if _workspace_root not in sys.path:
    sys.path.insert(0, _workspace_root)

# Clear the ML config LRU cache so test-mode defaults take effect
try:
    from ml.config import get_ml_config

    get_ml_config.cache_clear()
except ImportError:
    pass
