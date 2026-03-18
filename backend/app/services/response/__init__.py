# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Automated Response Engine (Decision Layer).

Subpackage providing:
  - policy_engine   — PRL-condition matching: alert → response policy → action
  - dispatcher      — routes actions to enforcement subsystems
  - escalation      — progressive response ladder per agent
  - shadow          — log-only mode for safe rollout

Wired into the alert pipeline via rule_engine._create_alerts().
"""
