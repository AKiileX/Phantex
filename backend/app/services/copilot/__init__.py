# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex Copilot — Service Package.

Sub-modules:
  firewall       — Content firewall (prompt injection + output scanning)
  llm_provider   — LLM provider abstraction (OpenAI, Anthropic, Ollama/LM Studio)
  investigator   — Investigation assistant with tool calling
  triage         — Alert triage assistant
  rule_generator — NL → PRL rule suggestion engine
  briefing       — Threat briefing generator (AB1)
  playbooks      — IR playbook service (AB2)
  memory         — Multi-turn conversation memory (AB3)
"""
