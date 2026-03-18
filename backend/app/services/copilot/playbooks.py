# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex Copilot — IR Playbooks (AB2).

Pre-built incident-response playbooks keyed by attack class.  Each playbook
provides a structured 5-phase guide:

  1. **Detect**      — How the alert was triggered, key indicators.
  2. **Contain**     — Immediate containment actions (may auto-invoke Response Engine).
  3. **Investigate** — Deeper analysis steps, what to look for.
  4. **Remediate**   — Fix & harden (patch, rotate creds, update rules).
  5. **Post-Incident** — Lessons learned, metric capture.

Playbooks are static knowledge (no LLM required) but can optionally be
contextualised by the LLM against a specific alert.

LLM contextualisation pipeline:
  playbook template + alert data → LLM → contextualised playbook → firewall → response
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

from app.services.copilot.firewall import CopilotFirewall
from app.services.copilot.llm_provider import LLMProvider, UsageStats

logger = structlog.get_logger("phantex.copilot.playbooks")

# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class PlaybookStep:
    action: str
    detail: str
    automated: bool = False  # Can the Response Engine execute this?
    response_action: str | None = None  # Response Engine action key (if automated)

@dataclass
class PlaybookPhase:
    name: str  # detect / contain / investigate / remediate / post_incident
    description: str
    steps: list[PlaybookStep] = field(default_factory=list)

@dataclass
class Playbook:
    attack_class: str
    title: str
    severity_default: str  # typical severity for this class
    description: str
    phases: list[PlaybookPhase] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    def to_markdown(self) -> str:
        """Render the playbook as human-readable Markdown."""
        lines: list[str] = []
        lines.append(f"# IR Playbook — {self.title}")
        lines.append(f"**Attack Class:** `{self.attack_class}` | **Default Severity:** {self.severity_default}")
        lines.append("")
        lines.append(self.description)
        lines.append("")

        for phase in self.phases:
            lines.append(f"## Phase: {phase.name.replace('_', ' ').title()}")
            lines.append(phase.description)
            lines.append("")
            for i, step in enumerate(phase.steps, 1):
                auto = " 🤖 *(automated)*" if step.automated else ""
                lines.append(f"{i}. **{step.action}**{auto}")
                lines.append(f"   {step.detail}")
                if step.response_action:
                    lines.append(f"   → Response Engine action: `{step.response_action}`")
            lines.append("")

        if self.references:
            lines.append("## References")
            for ref in self.references:
                lines.append(f"- {ref}")

        return "\n".join(lines)

# ── Playbook Registry ────────────────────────────────────────────────────────

_PLAYBOOKS: dict[str, Playbook] = {}

def _register(pb: Playbook) -> None:
    _PLAYBOOKS[pb.attack_class] = pb

# ── Prompt Injection ──────────────────────────────────────────────────────────
_register(
    Playbook(
        attack_class="prompt_injection",
        title="Prompt Injection Response",
        severity_default="critical",
        description=(
            "An AI agent received input containing prompt injection patterns — "
            "attempts to manipulate the agent's system prompt, override safety "
            "instructions, or exfiltrate internal data via crafted prompts."
        ),
        phases=[
            PlaybookPhase(
                name="detect",
                description="Identify the prompt injection attempt.",
                steps=[
                    PlaybookStep(
                        "Review alert details",
                        "Open the alert and inspect the flagged input payload. Look for phrases like 'ignore previous instructions', role impersonation, or encoded payloads.",
                    ),
                    PlaybookStep(
                        "Check content firewall logs",
                        "Review the content firewall verdict: was the injection blocked, or did it reach the agent?",
                    ),
                    PlaybookStep(
                        "Assess agent trust score",
                        "Check whether the source agent's trust score has degraded recently.",
                    ),
                ],
            ),
            PlaybookPhase(
                name="contain",
                description="Limit blast radius immediately.",
                steps=[
                    PlaybookStep(
                        "Quarantine the agent",
                        "Place the agent in quarantine mode to prevent further tool execution.",
                        automated=True,
                        response_action="quarantine_agent",
                    ),
                    PlaybookStep(
                        "Revoke agent tokens",
                        "Invalidate any active API tokens for the affected agent.",
                        automated=True,
                        response_action="revoke_tokens",
                    ),
                    PlaybookStep(
                        "Block source IP/endpoint",
                        "If injections originate from an external source, block at the network level.",
                    ),
                ],
            ),
            PlaybookPhase(
                name="investigate",
                description="Determine scope and root cause.",
                steps=[
                    PlaybookStep(
                        "Trace the injection source",
                        "Follow the event timeline backward: which user/API call submitted the malicious input?",
                    ),
                    PlaybookStep(
                        "Review tool call history",
                        "Check all tool calls made after the injection — were any unauthorised actions taken?",
                    ),
                    PlaybookStep(
                        "Search for similar patterns",
                        "Use Copilot to search for similar injection patterns across all agents in the last 7 days.",
                    ),
                    PlaybookStep(
                        "Check data exfiltration",
                        "Verify no sensitive data was included in outbound tool calls or network connections.",
                    ),
                ],
            ),
            PlaybookPhase(
                name="remediate",
                description="Fix the vulnerability and harden defenses.",
                steps=[
                    PlaybookStep(
                        "Update content firewall rules",
                        "Add the injection pattern to the firewall's fast-path regex if it's a new variant.",
                    ),
                    PlaybookStep(
                        "Retrain ML classifiers",
                        "Submit the sample to the prompt injection classifier retraining pipeline.",
                    ),
                    PlaybookStep(
                        "Patch agent configuration",
                        "Ensure the agent's system prompt includes injection-resistant framing.",
                    ),
                    PlaybookStep(
                        "Rotate affected credentials",
                        "If any secrets were potentially exposed, rotate them immediately.",
                    ),
                ],
            ),
            PlaybookPhase(
                name="post_incident",
                description="Document and improve.",
                steps=[
                    PlaybookStep(
                        "Create incident report", "Document the timeline, impact, and response actions taken."
                    ),
                    PlaybookStep(
                        "Update detection rules", "Create or refine PRL rules to catch this injection variant earlier."
                    ),
                    PlaybookStep(
                        "Review trust score impact",
                        "Verify the agent's trust score reflects the incident appropriately.",
                    ),
                ],
            ),
        ],
        references=[
            "OWASP Top 10 for LLM Applications — LLM01: Prompt Injection",
            "MITRE ATLAS — AML.T0051: LLM Prompt Injection",
        ],
    )
)

# ── Data Exfiltration ─────────────────────────────────────────────────────────
_register(
    Playbook(
        attack_class="exfiltration",
        title="Data Exfiltration Response",
        severity_default="high",
        description=(
            "An agent is transferring abnormally large volumes of data to external "
            "endpoints, or accessing an unusually high number of files in a short "
            "time period — potential data theft or bulk reconnaissance."
        ),
        phases=[
            PlaybookPhase(
                name="detect",
                description="Identify the exfiltration pattern.",
                steps=[
                    PlaybookStep(
                        "Review network connections",
                        "Inspect outbound connections: destination IPs, ports, data volume, and timing.",
                    ),
                    PlaybookStep(
                        "Check file access logs",
                        "Look at file read events — were sensitive files (credentials, configs, PII) accessed?",
                    ),
                    PlaybookStep(
                        "Compare to baseline",
                        "Check whether the data transfer volume is anomalous vs the agent's normal behavior.",
                    ),
                ],
            ),
            PlaybookPhase(
                name="contain",
                description="Stop active exfiltration.",
                steps=[
                    PlaybookStep(
                        "Block agent network access",
                        "Restrict the agent to internal-only network communication.",
                        automated=True,
                        response_action="restrict_network",
                    ),
                    PlaybookStep(
                        "Quarantine the agent",
                        "Place the agent in quarantine mode.",
                        automated=True,
                        response_action="quarantine_agent",
                    ),
                    PlaybookStep("Snapshot current state", "Capture the agent's current state for forensic analysis."),
                ],
            ),
            PlaybookPhase(
                name="investigate",
                description="Determine what was exfiltrated and where.",
                steps=[
                    PlaybookStep(
                        "Enumerate accessed files", "List all files accessed by the agent in the incident window."
                    ),
                    PlaybookStep(
                        "Check destination reputation",
                        "Look up destination IPs/domains against threat intelligence feeds.",
                    ),
                    PlaybookStep(
                        "Review tool call chain",
                        "Trace the sequence of tool calls to understand the exfiltration method.",
                    ),
                    PlaybookStep(
                        "Check for command injection",
                        "Verify whether the exfiltration was triggered by a prior injection attack.",
                    ),
                ],
            ),
            PlaybookPhase(
                name="remediate",
                description="Close the vulnerability.",
                steps=[
                    PlaybookStep(
                        "Revoke compromised credentials",
                        "If credential files were accessed, rotate ALL affected secrets.",
                    ),
                    PlaybookStep(
                        "Update network policies", "Add the destination to the blocklist and tighten egress rules."
                    ),
                    PlaybookStep(
                        "Strengthen file access controls", "Restrict the agent's file access scope in its PRL policy."
                    ),
                ],
            ),
            PlaybookPhase(
                name="post_incident",
                description="Document and improve detection.",
                steps=[
                    PlaybookStep(
                        "Quantify data exposure",
                        "Determine the scope: how much data, what sensitivity level, who is affected.",
                    ),
                    PlaybookStep(
                        "Notify stakeholders", "If PII/PHI was exfiltrated, follow breach notification procedures."
                    ),
                    PlaybookStep(
                        "Update detection thresholds",
                        "Refine PRL rules for file read counts and outbound transfer limits.",
                    ),
                ],
            ),
        ],
        references=[
            "MITRE ATT&CK — T1041: Exfiltration Over C2 Channel",
            "MITRE ATLAS — AML.T0024: Exfiltration via ML Inference API",
        ],
    )
)

# ── Credential Theft ──────────────────────────────────────────────────────────
_register(
    Playbook(
        attack_class="credential_theft",
        title="Credential Theft Response",
        severity_default="critical",
        description=(
            "An agent has exposed or attempted to expose credentials — API keys, "
            "tokens, private keys, or passwords — in tool call arguments, outputs, "
            "or network traffic."
        ),
        phases=[
            PlaybookPhase(
                name="detect",
                description="Identify the credential exposure.",
                steps=[
                    PlaybookStep(
                        "Review flagged content",
                        "Inspect the alert payload: what credential type was detected and where?",
                    ),
                    PlaybookStep("Check credential scope", "Determine what the exposed credential grants access to."),
                    PlaybookStep(
                        "Verify if credential is valid",
                        "Check if the credential is still active (without using it externally).",
                    ),
                ],
            ),
            PlaybookPhase(
                name="contain",
                description="Revoke and restrict immediately.",
                steps=[
                    PlaybookStep(
                        "Rotate the credential",
                        "Immediately rotate or revoke the compromised key/token.",
                        automated=True,
                        response_action="rotate_credential",
                    ),
                    PlaybookStep(
                        "Quarantine the agent",
                        "Isolate the agent that exposed the credential.",
                        automated=True,
                        response_action="quarantine_agent",
                    ),
                    PlaybookStep(
                        "Invalidate active sessions",
                        "Revoke all sessions authenticated with the compromised credential.",
                    ),
                ],
            ),
            PlaybookPhase(
                name="investigate",
                description="Determine exposure scope.",
                steps=[
                    PlaybookStep(
                        "Trace access chain",
                        "How did the agent obtain the credential? Was it from file access, environment variables, or another tool?",
                    ),
                    PlaybookStep(
                        "Check for lateral use", "Was the credential used to access other systems before detection?"
                    ),
                    PlaybookStep(
                        "Search for similar exposures",
                        "Scan all agents for the same credential pattern in recent tool calls.",
                    ),
                ],
            ),
            PlaybookPhase(
                name="remediate",
                description="Harden credential management.",
                steps=[
                    PlaybookStep(
                        "Move secrets to Vault", "Ensure all secrets are managed by HashiCorp Vault, not in plaintext."
                    ),
                    PlaybookStep("Update agent permissions", "Restrict the agent's access to credential stores."),
                    PlaybookStep(
                        "Enhance output scanning",
                        "Add the credential pattern to the content firewall if it's a new format.",
                    ),
                ],
            ),
            PlaybookPhase(
                name="post_incident",
                description="Audit and document.",
                steps=[
                    PlaybookStep("Audit credential rotation", "Confirm all affected credentials have been rotated."),
                    PlaybookStep(
                        "Update secret management policy", "Document the gap and update credential handling procedures."
                    ),
                ],
            ),
        ],
        references=[
            "MITRE ATT&CK — T1552: Unsecured Credentials",
            "CIS Controls v8 — Control 6: Access Control Management",
        ],
    )
)

# ── Supply Chain (MCP) ────────────────────────────────────────────────────────
_register(
    Playbook(
        attack_class="supply_chain",
        title="MCP Supply Chain Attack Response",
        severity_default="high",
        description=(
            "An agent connected to an MCP server that is unknown, unverified, or "
            "flagged as malicious — potential tool poisoning, dependency confusion, "
            "or compromised upstream supply chain."
        ),
        phases=[
            PlaybookPhase(
                name="detect",
                description="Identify the supply chain risk.",
                steps=[
                    PlaybookStep(
                        "Review MCP server details",
                        "Check the MCP server name, version, and hash against the known-good registry.",
                    ),
                    PlaybookStep(
                        "Check tool manifest",
                        "Review the tools exposed by this MCP server — are any unexpected or code-execution capable?",
                    ),
                    PlaybookStep("Verify SBOM", "Check the Agent Bill of Materials for unexpected dependencies."),
                ],
            ),
            PlaybookPhase(
                name="contain",
                description="Block the untrusted MCP server.",
                steps=[
                    PlaybookStep(
                        "Disconnect from MCP server",
                        "Sever the agent's connection to the flagged MCP server.",
                        automated=True,
                        response_action="block_mcp_server",
                    ),
                    PlaybookStep(
                        "Quarantine affected agents",
                        "Isolate all agents that connected to this MCP server.",
                        automated=True,
                        response_action="quarantine_agent",
                    ),
                ],
            ),
            PlaybookPhase(
                name="investigate",
                description="Assess the supply chain compromise.",
                steps=[
                    PlaybookStep("Enumerate affected agents", "Find all agents that used tools from this MCP server."),
                    PlaybookStep(
                        "Review tool call results", "Check if any tool calls returned unexpected/malicious payloads."
                    ),
                    PlaybookStep(
                        "Compare tool implementations",
                        "Diff the current tool manifest against the last known-good version.",
                    ),
                    PlaybookStep(
                        "Check for code execution", "Verify whether the MCP server's tools executed arbitrary code."
                    ),
                ],
            ),
            PlaybookPhase(
                name="remediate",
                description="Restore to known-good state.",
                steps=[
                    PlaybookStep("Add to blocklist", "Permanently block the compromised MCP server hash."),
                    PlaybookStep("Update MCP registry", "Add the verified hash to your approved server list."),
                    PlaybookStep(
                        "Rebuild agent configs", "Redeploy affected agents with clean MCP server configurations."
                    ),
                ],
            ),
            PlaybookPhase(
                name="post_incident",
                description="Improve supply chain controls.",
                steps=[
                    PlaybookStep(
                        "Update MCP verification policy",
                        "Require hash verification + code signing for all MCP servers.",
                    ),
                    PlaybookStep(
                        "Enable continuous ABOM scanning",
                        "Turn on drift detection to catch future supply chain changes.",
                    ),
                ],
            ),
        ],
        references=[
            "MITRE ATT&CK — T1195: Supply Chain Compromise",
            "OWASP Top 10 for LLM Applications — LLM05: Supply-Chain Vulnerabilities",
        ],
    )
)

# ── Lateral Movement ──────────────────────────────────────────────────────────
_register(
    Playbook(
        attack_class="lateral_movement",
        title="Lateral Movement Response",
        severity_default="high",
        description=(
            "An agent spawned shells, reverse connections, or attack tools — "
            "indicators of lateral movement or post-exploitation activity."
        ),
        phases=[
            PlaybookPhase(
                name="detect",
                description="Identify the lateral movement indicators.",
                steps=[
                    PlaybookStep(
                        "Review process spawn events",
                        "Check which processes were spawned: shells, scripting engines, known attack tools.",
                    ),
                    PlaybookStep(
                        "Check network connections",
                        "Look for new outbound connections to unusual ports (e.g., reverse shells).",
                    ),
                    PlaybookStep(
                        "Correlate with trust score", "Did the agent's trust score drop before or after the spawns?"
                    ),
                ],
            ),
            PlaybookPhase(
                name="contain",
                description="Isolate the compromised agent.",
                steps=[
                    PlaybookStep(
                        "Kill the spawned processes",
                        "Terminate any rogue processes immediately.",
                        automated=True,
                        response_action="kill_process",
                    ),
                    PlaybookStep(
                        "Quarantine the agent",
                        "Full network isolation for the compromised agent.",
                        automated=True,
                        response_action="quarantine_agent",
                    ),
                    PlaybookStep(
                        "Block lateral paths", "Restrict network access between the compromised agent and other agents."
                    ),
                ],
            ),
            PlaybookPhase(
                name="investigate",
                description="Map the attack chain.",
                steps=[
                    PlaybookStep(
                        "Build attack timeline", "Use the event timeline to reconstruct the sequence of actions."
                    ),
                    PlaybookStep(
                        "Check for persistence",
                        "Look for scheduled tasks, cron jobs, or startup entries created by the attacker.",
                    ),
                    PlaybookStep(
                        "Identify initial access",
                        "Trace back to the initial compromise — was it prompt injection, supply chain, or external?",
                    ),
                    PlaybookStep(
                        "Enumerate accessed systems",
                        "Check which other hosts/agents the compromised agent communicated with.",
                    ),
                ],
            ),
            PlaybookPhase(
                name="remediate",
                description="Eliminate the threat.",
                steps=[
                    PlaybookStep(
                        "Remove persistence mechanisms", "Clean up any scheduled tasks, cron jobs, or registry entries."
                    ),
                    PlaybookStep("Patch the entry vector", "Fix the vulnerability that allowed initial access."),
                    PlaybookStep(
                        "Reset agent credentials", "Rotate all credentials accessible to the compromised agent."
                    ),
                ],
            ),
            PlaybookPhase(
                name="post_incident",
                description="Improve detection.",
                steps=[
                    PlaybookStep(
                        "Update process spawn rules", "Add new PRL rules for detected attack tool signatures."
                    ),
                    PlaybookStep(
                        "Run red team simulation",
                        "Use the adversarial simulator to test detection of similar attack chains.",
                    ),
                ],
            ),
        ],
        references=[
            "MITRE ATT&CK — T1021: Remote Services",
            "MITRE ATT&CK — T1059: Command and Scripting Interpreter",
        ],
    )
)

# ── DoS / Runaway Agent ────────────────────────────────────────────────────────
_register(
    Playbook(
        attack_class="dos",
        title="Denial of Service / Runaway Agent Response",
        severity_default="high",
        description=(
            "An agent is making an abnormally high number of tool calls — either a "
            "runaway loop, resource exhaustion attack, or deliberate DoS against "
            "backend services."
        ),
        phases=[
            PlaybookPhase(
                name="detect",
                description="Identify the DoS pattern.",
                steps=[
                    PlaybookStep(
                        "Review tool call rate",
                        "Check the agent's tool call frequency — is it exceeding the 100/60s threshold?",
                    ),
                    PlaybookStep("Check for loops", "Look for repeated identical tool calls (loop detection)."),
                    PlaybookStep(
                        "Assess system impact", "Check backend service latency, CPU, and memory during the spike."
                    ),
                ],
            ),
            PlaybookPhase(
                name="contain",
                description="Rate-limit or stop the agent.",
                steps=[
                    PlaybookStep(
                        "Apply rate limit",
                        "Engage per-agent rate limiting to throttle tool calls.",
                        automated=True,
                        response_action="rate_limit_agent",
                    ),
                    PlaybookStep(
                        "Suspend the agent",
                        "Temporarily suspend the agent if rate limiting is insufficient.",
                        automated=True,
                        response_action="suspend_agent",
                    ),
                ],
            ),
            PlaybookPhase(
                name="investigate",
                description="Determine root cause.",
                steps=[
                    PlaybookStep("Check agent configuration", "Is the agent's loop/retry logic configured correctly?"),
                    PlaybookStep("Review prompt/input", "Was the agent given input that caused an infinite loop?"),
                    PlaybookStep(
                        "Check for external triggers", "Is another agent or user deliberately triggering the runaway?"
                    ),
                ],
            ),
            PlaybookPhase(
                name="remediate",
                description="Fix and prevent recurrence.",
                steps=[
                    PlaybookStep(
                        "Fix agent loop logic", "Update the agent's configuration to include proper loop guards."
                    ),
                    PlaybookStep("Enforce rate limits", "Set hard per-agent rate limits in the policy."),
                    PlaybookStep("Add circuit breakers", "Implement circuit breaker patterns for tool call backends."),
                ],
            ),
            PlaybookPhase(
                name="post_incident",
                description="Document and improve.",
                steps=[
                    PlaybookStep("Document the trigger", "Record what caused the runaway for future reference."),
                    PlaybookStep("Update DoS detection rules", "Refine thresholds based on observed patterns."),
                ],
            ),
        ],
        references=[
            "MITRE ATT&CK — T1499: Endpoint Denial of Service",
            "OWASP Top 10 for LLM Applications — LLM04: Model Denial of Service",
        ],
    )
)

# ── Behavioral Anomaly ────────────────────────────────────────────────────────
_register(
    Playbook(
        attack_class="behavioral_anomaly",
        title="Behavioral Anomaly Response",
        severity_default="medium",
        description=(
            "An agent is exhibiting behavior outside its established baseline — "
            "new network connections, unusual tool usage patterns, or unexpected "
            "data access. May indicate compromise, drift, or misconfiguration."
        ),
        phases=[
            PlaybookPhase(
                name="detect",
                description="Characterize the anomaly.",
                steps=[
                    PlaybookStep(
                        "Review ML anomaly score",
                        "Check the anomaly detection model's score and which features deviated.",
                    ),
                    PlaybookStep("Compare to baseline", "What is the agent's normal behavior profile vs current?"),
                    PlaybookStep(
                        "Check recent changes",
                        "Was the agent updated, reconfigured, or given new permissions recently?",
                    ),
                ],
            ),
            PlaybookPhase(
                name="contain",
                description="Monitor closely or restrict.",
                steps=[
                    PlaybookStep("Increase monitoring", "Enable extended recording (Level 2) for the agent."),
                    PlaybookStep(
                        "Restrict scope if risky",
                        "If the anomaly involves sensitive resources, restrict the agent's tool access.",
                        automated=True,
                        response_action="restrict_tools",
                    ),
                ],
            ),
            PlaybookPhase(
                name="investigate",
                description="Root-cause the deviation.",
                steps=[
                    PlaybookStep(
                        "Review event timeline", "Trace the sequence of events that triggered the anomaly detection."
                    ),
                    PlaybookStep(
                        "Check drift status", "Is this a legitimate configuration drift? Check the ABOM for changes."
                    ),
                    PlaybookStep("Correlate with other agents", "Are other agents showing similar behavior changes?"),
                    PlaybookStep(
                        "Triage with Copilot",
                        "Use Copilot triage to classify: true anomaly, configuration change, or false positive.",
                    ),
                ],
            ),
            PlaybookPhase(
                name="remediate",
                description="Resolve based on classification.",
                steps=[
                    PlaybookStep(
                        "If drift — update baseline", "Accept the new behavior as baseline if it's a legitimate change."
                    ),
                    PlaybookStep(
                        "If malicious — quarantine",
                        "Isolate the agent and follow the appropriate attack-specific playbook.",
                    ),
                    PlaybookStep("If FP — tune model", "Submit feedback to improve ML anomaly detection accuracy."),
                ],
            ),
            PlaybookPhase(
                name="post_incident",
                description="Refine detection.",
                steps=[
                    PlaybookStep("Update anomaly thresholds", "Adjust sensitivity based on this case."),
                    PlaybookStep(
                        "Add contextual rules", "Create PRL rules for the specific behavioral pattern if warranted."
                    ),
                ],
            ),
        ],
        references=[
            "MITRE ATLAS — AML.T0031: Erode ML Model Integrity",
            "NIST AI 100-2: Adversarial Machine Learning",
        ],
    )
)

# ── Unauthorized Access ───────────────────────────────────────────────────────
_register(
    Playbook(
        attack_class="unauthorized_access",
        title="Unauthorized Access Response",
        severity_default="high",
        description=(
            "An agent accessed sensitive files (credentials, configs, PII) beyond "
            "its authorized scope — potential misconfiguration or deliberate "
            "privilege abuse."
        ),
        phases=[
            PlaybookPhase(
                name="detect",
                description="Identify the unauthorized access.",
                steps=[
                    PlaybookStep("Review file access event", "What file was accessed and by which agent?"),
                    PlaybookStep(
                        "Check agent permissions", "Does the agent's policy authorize access to this file path?"
                    ),
                    PlaybookStep(
                        "Verify file sensitivity", "Classify the file: credential, configuration, PII, or other?"
                    ),
                ],
            ),
            PlaybookPhase(
                name="contain",
                description="Restrict the agent's file access.",
                steps=[
                    PlaybookStep(
                        "Restrict file access",
                        "Narrow the agent's file access policy immediately.",
                        automated=True,
                        response_action="restrict_file_access",
                    ),
                    PlaybookStep("Monitor for data egress", "Watch for any outbound transfer of the accessed data."),
                ],
            ),
            PlaybookPhase(
                name="investigate",
                description="Assess impact.",
                steps=[
                    PlaybookStep(
                        "Check file contents sensitivity",
                        "Was PII, credentials, or other regulated data in the accessed file?",
                    ),
                    PlaybookStep(
                        "Review agent activity post-access",
                        "Did the agent do anything with the file contents (e.g., send to external endpoint)?",
                    ),
                    PlaybookStep(
                        "Check policy configuration",
                        "Was the access policy too permissive, or did the agent bypass it?",
                    ),
                ],
            ),
            PlaybookPhase(
                name="remediate",
                description="Tighten access controls.",
                steps=[
                    PlaybookStep(
                        "Update agent file policy", "Apply principle of least privilege to file access paths."
                    ),
                    PlaybookStep("Rotate exposed secrets", "If credential files were accessed, rotate them."),
                    PlaybookStep(
                        "Enable file access auditing", "Turn on detailed file access logging for sensitive paths."
                    ),
                ],
            ),
            PlaybookPhase(
                name="post_incident",
                description="Strengthen access management.",
                steps=[
                    PlaybookStep(
                        "Review all agent file policies",
                        "Audit file access policies across all agents for similar gaps.",
                    ),
                    PlaybookStep(
                        "Add sensitive path rules", "Create PRL rules for additional sensitive file patterns."
                    ),
                ],
            ),
        ],
        references=[
            "MITRE ATT&CK — T1083: File and Directory Discovery",
            "CIS Controls v8 — Control 3: Data Protection",
        ],
    )
)

# ── Trust Degradation ─────────────────────────────────────────────────────────
_register(
    Playbook(
        attack_class="trust_degradation",
        title="Trust Score Degradation Response",
        severity_default="high",
        description=(
            "An agent's trust score has dropped significantly — indicating "
            "sustained malicious or anomalous behavior detected by the trust "
            "engine. Could be a slow-burn attack or accumulated policy violations."
        ),
        phases=[
            PlaybookPhase(
                name="detect",
                description="Understand the trust score drop.",
                steps=[
                    PlaybookStep(
                        "Review trust score history", "Check the trust score trend: was the drop sudden or gradual?"
                    ),
                    PlaybookStep(
                        "Check trust factors",
                        "Which factors contributed most to the drop? (behavior, network, file access, etc.)",
                    ),
                    PlaybookStep(
                        "Correlate with alerts",
                        "Are there related alerts (injection, exfiltration, etc.) in the same time window?",
                    ),
                ],
            ),
            PlaybookPhase(
                name="contain",
                description="Restrict based on trust level.",
                steps=[
                    PlaybookStep(
                        "Apply trust-based restrictions",
                        "Enforce policy restrictions for the agent's current trust tier.",
                        automated=True,
                        response_action="apply_trust_policy",
                    ),
                    PlaybookStep(
                        "Quarantine if critical",
                        "If trust < 0.3, fully quarantine the agent.",
                        automated=True,
                        response_action="quarantine_agent",
                    ),
                ],
            ),
            PlaybookPhase(
                name="investigate",
                description="Identify the root cause.",
                steps=[
                    PlaybookStep(
                        "Review contributing events", "List all events that negatively impacted the trust score."
                    ),
                    PlaybookStep(
                        "Check for attack chain",
                        "Is this trust degradation the result of an ongoing multi-stage attack?",
                    ),
                    PlaybookStep(
                        "Verify agent identity",
                        "Confirm the agent hasn't been compromised or replaced (check hardware identity if available).",
                    ),
                ],
            ),
            PlaybookPhase(
                name="remediate",
                description="Restore trust or decommission.",
                steps=[
                    PlaybookStep("Fix underlying issues", "Address the root causes identified during investigation."),
                    PlaybookStep("Request trust recalculation", "After fixes, trigger a trust score recalculation."),
                    PlaybookStep(
                        "Decommission if irrecoverable",
                        "If the agent is confirmed compromised, decommission and replace.",
                    ),
                ],
            ),
            PlaybookPhase(
                name="post_incident",
                description="Improve trust model.",
                steps=[
                    PlaybookStep(
                        "Review trust factor weights",
                        "Were the trust factors appropriately weighted for this scenario?",
                    ),
                    PlaybookStep(
                        "Document the degradation pattern", "Create a case study for similar slow-burn attack patterns."
                    ),
                ],
            ),
        ],
        references=[
            "NIST SP 800-207 — Zero Trust Architecture",
            "PHANTEX Trust Engine Documentation — Trust Factor Weights",
        ],
    )
)

# ── Privilege Escalation ──────────────────────────────────────────────────────
_register(
    Playbook(
        attack_class="privilege_escalation",
        title="Privilege Escalation Response",
        severity_default="high",
        description=(
            "A low-trust agent attempted to escalate its permissions — requesting "
            "higher-privilege tool access, admin operations, or policy modifications "
            "beyond its authorization level."
        ),
        phases=[
            PlaybookPhase(
                name="detect",
                description="Identify the escalation attempt.",
                steps=[
                    PlaybookStep("Review permission request", "What permission or action did the agent attempt?"),
                    PlaybookStep("Check current trust tier", "What is the agent's trust score and identity level?"),
                    PlaybookStep("Verify policy enforcement", "Did the ABAC system correctly block the request?"),
                ],
            ),
            PlaybookPhase(
                name="contain",
                description="Lock down the agent.",
                steps=[
                    PlaybookStep(
                        "Deny escalation", "Ensure the escalation attempt was denied (verify ABAC enforcement)."
                    ),
                    PlaybookStep(
                        "Reduce agent permissions",
                        "Temporarily lower the agent's permission ceiling.",
                        automated=True,
                        response_action="reduce_permissions",
                    ),
                    PlaybookStep("Enable enhanced logging", "Turn on Level 2 extended recording for the agent."),
                ],
            ),
            PlaybookPhase(
                name="investigate",
                description="Determine intent.",
                steps=[
                    PlaybookStep(
                        "Check request context",
                        "Was the escalation requested by a user action or autonomously by the agent?",
                    ),
                    PlaybookStep(
                        "Review prior behavior", "Is this the first escalation attempt, or part of a pattern?"
                    ),
                    PlaybookStep(
                        "Correlate with other attacks",
                        "Is this escalation part of a larger attack chain (e.g., post-injection)?",
                    ),
                ],
            ),
            PlaybookPhase(
                name="remediate",
                description="Harden authorization.",
                steps=[
                    PlaybookStep(
                        "Review ABAC policies", "Ensure policies correctly reflect the principle of least privilege."
                    ),
                    PlaybookStep("Update trust tier thresholds", "Adjust permission tier boundaries if needed."),
                    PlaybookStep("Add escalation alerting", "Create PRL rules for specific escalation patterns."),
                ],
            ),
            PlaybookPhase(
                name="post_incident",
                description="Audit and improve.",
                steps=[
                    PlaybookStep("Audit all agent permissions", "Review permission assignments across all agents."),
                    PlaybookStep(
                        "Run privilege escalation simulation", "Use the red team simulator to test escalation defenses."
                    ),
                ],
            ),
        ],
        references=[
            "MITRE ATT&CK — T1548: Abuse Elevation Control Mechanism",
            "CIS Controls v8 — Control 6: Access Control Management",
        ],
    )
)

# ── Service ───────────────────────────────────────────────────────────────────

class PlaybookService:
    """Serve and optionally contextualise IR playbooks."""

    def __init__(
        self,
        llm: LLMProvider | None = None,
        firewall: CopilotFirewall | None = None,
    ) -> None:
        self._llm = llm
        self._firewall = firewall or CopilotFirewall()

    @staticmethod
    def list_playbooks() -> list[dict[str, str]]:
        """Return metadata for all registered playbooks."""
        return [
            {
                "attack_class": pb.attack_class,
                "title": pb.title,
                "severity_default": pb.severity_default,
                "description": pb.description,
                "phase_count": len(pb.phases),
            }
            for pb in _PLAYBOOKS.values()
        ]

    @staticmethod
    def get_playbook(attack_class: str) -> Playbook | None:
        """Get a playbook by attack class."""
        return _PLAYBOOKS.get(attack_class)

    async def get_contextualised(
        self,
        attack_class: str,
        alert_data: dict[str, Any],
        db: Any | None = None,
        tenant_id: str | None = None,
    ) -> tuple[str, UsageStats]:
        """
        Return a playbook contextualised against a specific alert using LLM.

        If the LLM is unavailable, returns the static playbook Markdown.
        """
        playbook = _PLAYBOOKS.get(attack_class)
        if playbook is None:
            logger.warning("playbook_not_found", attack_class=attack_class)
            return f"No playbook found for attack class: `{attack_class}`", UsageStats()

        static_md = playbook.to_markdown()

        if self._llm is None:
            return static_md, UsageStats()

        t0 = time.monotonic()
        try:
            messages = [
                {
                    "role": "system",
                    "content": (
                        "You are a senior incident responder. You have a standard IR playbook "
                        "and a specific alert. Contextualise the playbook for this specific "
                        "incident: replace generic steps with concrete actions based on the "
                        "alert data (agent name, IPs, file paths, timestamps). Keep the same "
                        "5-phase structure. Output Markdown. Be concise and actionable."
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        f"## Playbook\n\n{static_md}\n\n"
                        f"## Alert Data\n\n```json\n{json.dumps(alert_data, default=str, indent=2)[:4000]}\n```\n\n"
                        "Contextualise this playbook for the specific alert above."
                    ),
                },
            ]
            response_text, usage = await self._llm.complete(messages)

            # Firewall scan
            verdict = self._firewall.scan_output(response_text)
            final = verdict.redacted_output or response_text

            usage.latency_ms = (time.monotonic() - t0) * 1000
            logger.info(
                "playbook_contextualised",
                attack_class=attack_class,
                tokens=usage.total_tokens,
                latency_ms=round(usage.latency_ms, 1),
            )
            return final, usage

        except Exception as exc:
            logger.warning("playbook_llm_fallback", error=str(exc))
            return static_md, UsageStats(latency_ms=(time.monotonic() - t0) * 1000)
