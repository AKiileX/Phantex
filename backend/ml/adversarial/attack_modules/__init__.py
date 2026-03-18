# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Attack Modules Package.

Pluggable attack modules for all 14 attack classes defined in Section 30.2
of the Phantex blueprint.  Each module implements the BaseAttackModule
interface and can be executed independently by the Red Team Simulator.

Attack classes:
  1. Direct Prompt Injection
  2. Indirect Prompt Injection
  3. Agent Lateral Movement
  4. Tool Poisoning
  5. MCP Supply Chain Attack
  6. Data Exfiltration
  7. Agent Impersonation
  8. Privilege Escalation
  9. Memory Poisoning
  10. Model Extraction
  11. Denial of Service
  12. Compliance Violation
  13. Credential Theft
  14. Supply Chain (Dependencies)
"""

from engine.sandbox.quarantine import ActionType  # noqa: F401  — re-export for convenience
