# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex Copilot — Rule Suggestion Engine (U4).

Generates Phantex Rule Language (PRL) detection rules from natural language
descriptions. Human approval required before activation.

Pipeline:
  NL description → LLM → PRL rule → Validate → Return for review

PRL syntax reference (embedded in system prompt for the LLM):
  RULE "name" {
    SEVERITY critical|high|medium|low|info
    MATCH event_type == "PROCESS_EXEC" AND process.name IN ["curl", "wget"]
    WHERE agent.trust_score < 0.5
    WITHIN 5m
    ALERT "Suspicious download tool on low-trust agent"
  }
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import structlog

from app.services.copilot.llm_provider import LLMConfig, LLMProvider, UsageStats

logger = structlog.get_logger("phantex.copilot.rule_generator")

PRL_REFERENCE = """
Phantex Rule Language (PRL) Quick Reference:

RULE "<name>" {
    SEVERITY critical|high|medium|low|info
    MATCH <condition> [AND|OR <condition>]*
    WHERE <additional_filter>
    WITHIN <time_window>      # e.g. 5m, 1h, 30s
    COUNT <n>                 # trigger after N matches
    ALERT "<alert_message>"
    TAG "<tag1>", "<tag2>"
}

Available event types:
  PROCESS_EXEC, NETWORK_CONNECT, FILE_ACCESS, FILE_WRITE, DNS_QUERY,
  TOOL_CALL, MCP_REQUEST, PROMPT_INJECTION, SENSITIVE_FILE_ACCESS,
  REGISTRY_WRITE, MODULE_LOAD, SOCKET_LISTEN

Available fields:
  event_type, process.name, process.path, process.cmdline, process.pid
  network.dest_ip, network.dest_port, network.protocol, network.domain
  file.path, file.name, file.operation
  agent.hostname, agent.os, agent.trust_score, agent.id
  tool.name, tool.server_id, tool.arguments
  mcp.server_name, mcp.tool_name, mcp.trust_level

Operators:
  ==, !=, <, >, <=, >=, IN [...], NOT IN [...], MATCHES /regex/,
  STARTS_WITH "...", ENDS_WITH "...", CONTAINS "..."

Examples:
  MATCH event_type == "NETWORK_CONNECT" AND network.dest_port IN [4444, 5555, 8888]
  MATCH event_type == "PROCESS_EXEC" AND process.name MATCHES /^(nc|ncat|netcat)$/
  MATCH event_type == "TOOL_CALL" AND mcp.trust_level == "unknown"
  WHERE agent.trust_score < 0.3
  WITHIN 10m
  COUNT 3
"""

VALID_EVENT_TYPES = frozenset(
    {
        "PROCESS_EXEC",
        "NETWORK_CONNECT",
        "FILE_ACCESS",
        "FILE_WRITE",
        "DNS_QUERY",
        "TOOL_CALL",
        "MCP_REQUEST",
        "PROMPT_INJECTION",
        "SENSITIVE_FILE_ACCESS",
        "REGISTRY_WRITE",
        "MODULE_LOAD",
        "SOCKET_LISTEN",
    }
)

RULE_GEN_SYSTEM_PROMPT = f"""You are a detection rule engineer for the Phantex security platform.

Your task: Convert natural language security detection descriptions into valid Phantex Rule Language (PRL) rules.

{PRL_REFERENCE}

IMPORTANT — PHANTEX MONITORS AI AGENT BEHAVIOR, NOT TRADITIONAL IT EVENTS:
Phantex sensors observe what AI agents do: process execution, network connections,
file access, tool calls, MCP requests, DNS queries, and module loads.
Phantex does NOT have these traditional SIEM event types:
  - Authentication / login events (no AUTH_FAILURE, LOGIN_FAILED, etc.)
  - Windows Event Log events (no EventID, Security Log, etc.)
  - Firewall logs, VPN logs, email logs, Active Directory events
  - Application-layer auth (no OAuth, SAML, SSO events)

IF the user asks for a rule that requires event types Phantex does not have,
you MUST respond with EXACTLY this text and nothing else:
  CANNOT_DETECT: <brief reason why this is outside Phantex telemetry scope>

Examples of requests that require CANNOT_DETECT:
  - "Detect failed logins" → CANNOT_DETECT: Phantex monitors AI agent behavior, not authentication events. Failed login detection requires a SIEM integration.
  - "Alert on VPN disconnections" → CANNOT_DETECT: Phantex does not collect VPN/firewall logs.
  - "Detect brute force attacks" → CANNOT_DETECT: Phantex has no authentication event type.

STRICT PRL syntax rules — you MUST follow these exactly:
1. Always wrap the rule in a RULE "..." {{ ... }} block
2. SEVERITY is required — match it to the threat level described
3. MATCH is required — specify the event pattern to detect
4. WHERE is optional — for additional context filters
5. WITHIN is optional — for time-windowed correlation
6. COUNT is optional — for threshold-based detection
7. ALERT is required — clear, actionable alert message
8. TAG is optional but recommended — for categorization
9. Use ONLY field names from the reference above — do NOT invent fields
10. Generate defensive rules — never offensive/exploit rules
11. event_type MUST be one of: PROCESS_EXEC, NETWORK_CONNECT, FILE_ACCESS, FILE_WRITE,
    DNS_QUERY, TOOL_CALL, MCP_REQUEST, PROMPT_INJECTION, SENSITIVE_FILE_ACCESS,
    REGISTRY_WRITE, MODULE_LOAD, SOCKET_LISTEN — do NOT invent event types
12. Values inside IN [...] lists are string literals (like filenames or IPs), NOT field names

COMPACTNESS — keep rules short to avoid token truncation:
- Keep MATCHES regex SHORT: use /^10\\./ not /^(10\\.\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}})$/
- Prefer IN ["10.0.0.1", "192.168.1.1"] with a few representative IPs over long regex
- Use simple patterns: /^192\\.168\\./ not /^(192\\.168\\.\\d{{1,3}}\\.\\d{{1,3}})$/
- Keep the entire rule under 15 lines — be concise
- ALERT messages should be one short sentence

FORBIDDEN (will fail validation):
- NO comments (no # or // lines)
- NO CIDR notation (10.0.0.0/8 is invalid) — use exact IPs or regex: MATCHES /^10\\\\./
- NO markdown, no explanation text, no backticks around the rule
- Strings use double quotes only: "value"
- IN/NOT IN lists use square brackets: IN ["a", "b"]
- Do NOT use IP ranges or subnet masks in string lists
- For IP range matching use: MATCHES /^10\\\\./ or MATCHES /^192\\\\.168\\\\./
- Do NOT use process names like cmd.exe, login.exe to represent login events

Respond with ONLY the PRL rule (or CANNOT_DETECT if outside scope). No explanation, no comments, no markdown fences."""

@dataclass
class RuleSuggestion:
    """A generated PRL rule suggestion."""

    rule_text: str  # The PRL rule text
    name: str  # Extracted rule name
    severity: str  # Extracted severity
    description: str  # NL description of what the rule detects
    is_valid: bool  # Basic syntax validation passed
    validation_errors: list[str]  # Any syntax issues found
    confidence: float  # 0.0 - 1.0 LLM confidence in the rule

class RuleSuggestionEngine:
    """
    NL → PRL rule generator with syntax validation.

    Usage::

        engine = RuleSuggestionEngine()
        suggestion, usage = await engine.generate(
            "Detect when curl or wget runs on a low-trust agent"
        )
        if suggestion.is_valid:
            print(suggestion.rule_text)
    """

    def __init__(self, llm: LLMProvider | None = None) -> None:
        self._llm = llm or LLMProvider(LLMConfig.from_env())

    # Common non-description inputs that should return guidance
    HELP_PATTERNS = {"help", "?", "hi", "hello", "hey", "test", "ping", "what", "how", "why"}

    async def generate(
        self,
        description: str,
        *,
        severity_hint: str | None = None,
        examples: list[str] | None = None,
    ) -> tuple[RuleSuggestion, UsageStats]:
        """
        Generate a PRL rule from a natural language description.

        Args:
            description: What the rule should detect
            severity_hint: Optional severity level hint
            examples: Optional example events to include

        Returns:
            (RuleSuggestion, usage_stats)
        """
        # Input validation: reject trivial/non-descriptive inputs
        stripped = description.strip().rstrip("?!.").strip().lower()
        words = stripped.split()
        if stripped in self.HELP_PATTERNS or len(words) < 3:
            return RuleSuggestion(
                rule_text="",
                name="",
                severity="",
                description=description,
                is_valid=False,
                validation_errors=["Input too short or vague — describe what the rule should detect."],
                confidence=0.0,
            ), UsageStats()

        # ── Pre-screen: reject requests clearly outside PHANTEX scope ──
        scope_error = self._detect_hallucinated_scope("", description)
        if scope_error:
            return RuleSuggestion(
                rule_text="",
                name="",
                severity="",
                description=description,
                is_valid=False,
                validation_errors=[scope_error],
                confidence=0.0,
            ), UsageStats()

        # Build prompt
        user_msg = f"Generate a PRL detection rule for:\n\n{description}"
        if severity_hint:
            user_msg += f"\n\nSeverity should be: {severity_hint}"
        if examples:
            user_msg += "\n\nExample events:\n" + "\n".join(f"- {e}" for e in examples[:5])

        messages = [{"role": "user", "content": user_msg}]

        response, usage = await self._llm.complete(
            messages,
            system_prompt=RULE_GEN_SYSTEM_PROMPT,
        )

        # ── Check if the LLM correctly refused ──────────────────────
        refusal = self._detect_refusal(response)
        if refusal:
            return RuleSuggestion(
                rule_text="",
                name="",
                severity="",
                description=description,
                is_valid=False,
                validation_errors=[refusal],
                confidence=0.0,
            ), usage

        # Extract PRL from response
        rule_text = self._extract_prl(response)

        # ── Detect truncated output (LLM hit token limit) ──────────
        if rule_text and not rule_text.rstrip().endswith("}"):
            return RuleSuggestion(
                rule_text=rule_text,
                name=self._extract_field(rule_text, "RULE"),
                severity=self._extract_field(rule_text, "SEVERITY") or "medium",
                description=description,
                is_valid=False,
                validation_errors=[
                    "Rule was truncated — the model ran out of tokens before finishing. "
                    "Try a shorter, more specific description so the rule stays compact."
                ],
                confidence=0.1,
            ), usage

        name = self._extract_field(rule_text, "RULE")
        severity = self._extract_field(rule_text, "SEVERITY") or "medium"
        is_valid, errors = self._validate_prl(rule_text)

        # ── Confidence degrades with errors ─────────────────────────
        if is_valid:
            confidence = 0.85
        elif len(errors) == 1:
            confidence = 0.35
        elif len(errors) <= 3:
            confidence = 0.2
        else:
            confidence = 0.1

        suggestion = RuleSuggestion(
            rule_text=rule_text,
            name=name,
            severity=severity,
            description=description,
            is_valid=is_valid,
            validation_errors=errors,
            confidence=confidence,
        )

        return suggestion, usage

    def _extract_prl(self, response: str) -> str:
        """Extract PRL rule from LLM response (may be in a code block)."""
        # Try code block extraction
        match = re.search(r"```(?:prl|phantex)?\s*(RULE\s.*?)```", response, re.DOTALL | re.I)
        if match:
            raw = match.group(1).strip()
        else:
            # Try finding RULE block directly
            match = re.search(r"(RULE\s+\".*?\"\s*\{.*?\})", response, re.DOTALL | re.I)
            raw = match.group(1).strip() if match else response.strip()

        # Post-process: strip comment lines (# or //)
        lines = raw.splitlines()
        cleaned = [ln for ln in lines if not ln.strip().startswith("#") and not ln.strip().startswith("//")]
        return "\n".join(cleaned).strip()

    def _extract_field(self, rule_text: str, field: str) -> str:
        """Extract a named field value from PRL text."""
        if field == "RULE":
            match = re.search(r'RULE\s+"([^"]+)"', rule_text, re.I)
            return match.group(1) if match else "unnamed_rule"
        match = re.search(rf"{field}\s+(\S+)", rule_text, re.I)
        return match.group(1) if match else ""

    # Known PRL fields for validation
    VALID_FIELDS = {
        "event_type",
        "process.name",
        "process.path",
        "process.cmdline",
        "process.pid",
        "network.dest_ip",
        "network.dest_port",
        "network.protocol",
        "network.domain",
        "file.path",
        "file.name",
        "file.operation",
        "agent.hostname",
        "agent.os",
        "agent.trust_score",
        "agent.id",
        "tool.name",
        "tool.server_id",
        "tool.arguments",
        "mcp.server_name",
        "mcp.tool_name",
        "mcp.trust_level",
    }

    def _validate_prl(self, rule_text: str) -> tuple[bool, list[str]]:
        """PRL syntax validation — catches structural and semantic issues."""
        errors: list[str] = []

        if not re.search(r'RULE\s+"[^"]+"', rule_text, re.I):
            errors.append("Missing RULE declaration with name")

        if not re.search(r"\{", rule_text):
            errors.append("Missing opening brace {")
        if not re.search(r"\}", rule_text):
            errors.append("Missing closing brace }")

        if not re.search(r"MATCH\s+", rule_text, re.I):
            errors.append("Missing MATCH clause")

        if not re.search(r"ALERT\s+", rule_text, re.I):
            errors.append("Missing ALERT clause")

        if not re.search(r"SEVERITY\s+(critical|high|medium|low|info)", rule_text, re.I):
            errors.append("Missing or invalid SEVERITY (must be critical|high|medium|low|info)")

        # Check for CIDR notation in string lists (e.g. "10.0.0.0/8") — invalid in PRL
        cidr_in_list = re.findall(r"\"[\d.]+/\d+\"", rule_text)
        if cidr_in_list:
            errors.append(
                f"CIDR notation ({', '.join(cidr_in_list[:3])}) is not valid in PRL. "
                "Use MATCHES /^10\\./ for IP range matching instead."
            )

        # Check for comments (# or //) — not valid PRL
        if re.search(r"^\s*#", rule_text, re.MULTILINE):
            errors.append("PRL does not support # comments — remove comment lines")
        if re.search(r"^\s*//", rule_text, re.MULTILINE):
            errors.append("PRL does not support // comments — remove comment lines")

        # Validate event_type values used in MATCH clause
        event_type_values = re.findall(r'event_type\s*==\s*"([^"]+)"', rule_text, re.I)
        for et in event_type_values:
            if et.upper() not in VALID_EVENT_TYPES:
                errors.append(f"Unknown event_type '{et}' — valid types: " + ", ".join(sorted(VALID_EVENT_TYPES)))

        # Validate field names used in MATCH/WHERE clauses.
        # Strip out string literals first so "cmd.exe" doesn't match as a field.
        text_no_strings = re.sub(r'"[^"]*"', '""', rule_text.lower())
        # Also strip IN [...] list contents (values, not fields)
        text_no_lists = re.sub(r"\[[^\]]*\]", "[]", text_no_strings)
        used_fields = re.findall(r"\b([a-z_]+\.[a-z_]+)\b", text_no_lists)
        for f in set(used_fields):
            if f not in self.VALID_FIELDS and not f.startswith("agent.") and not f.startswith("network."):
                errors.append(f"Unknown field '{f}' — check PRL field reference")

        # Check WITHIN format (should be like 5m, 1h, 30s)
        within_match = re.search(r"WITHIN\s+(\S+)", rule_text, re.I)
        if within_match:
            val = within_match.group(1)
            if not re.match(r"^\d+[smhd]$", val, re.I):
                errors.append(f"Invalid WITHIN value '{val}' — use format like 5m, 1h, 30s")

        return len(errors) == 0, errors

    # ── Refusal / hallucination detection ──────────────────────────────────

    # Phrases that indicate the LLM tried to refuse but hallucinated a rule anyway
    _HALLUCINATION_INDICATORS = re.compile(
        r"(?i)"
        r"(failed\s+login|login\s+fail|brute\s*force|auth(entication)?\s+(fail|event|log)"
        r"|vpn\s+(disconnect|log)|firewall\s+log|windows\s+event\s+log"
        r"|active\s+directory|siem|event\s*id)"
    )

    @staticmethod
    def _detect_refusal(response: str) -> str | None:
        """
        Detect if the LLM correctly refused (CANNOT_DETECT) or produced a
        non-PRL response that indicates it can't generate the rule.
        Returns the refusal message, or None if the response is a rule.
        """
        stripped = response.strip()

        # Explicit CANNOT_DETECT from the LLM
        if stripped.upper().startswith("CANNOT_DETECT"):
            reason = stripped.split(":", 1)[1].strip() if ":" in stripped else stripped
            return reason

        # LLM apologized or explained instead of producing a rule
        lower = stripped.lower()
        refusal_phrases = [
            "i cannot",
            "i can't",
            "not possible",
            "outside the scope",
            "phantex does not",
            "not supported",
            "no event type",
            "sorry",
            "unfortunately",
            "i'm unable",
        ]
        if any(phrase in lower for phrase in refusal_phrases) and "RULE" not in stripped:
            # Extract the first sentence as the reason
            first_sentence = stripped.split(".")[0].strip()
            return first_sentence[:300]

        return None

    def _detect_hallucinated_scope(self, rule_text: str, description: str) -> str | None:
        """
        Detect when the LLM hallucinated a rule for something outside PHANTEX scope.
        E.g., user asked for "failed logins" and LLM used PROMPT_INJECTION event type.
        Returns an error message, or None if the rule scope looks correct.
        """
        desc_lower = description.lower()
        # Check if the description mentions concepts outside PHANTEX telemetry
        outside_scope_patterns = {
            r"\b(failed|fail)\s+(login|logon|auth)\w*\b": "failed login/authentication events",
            r"\bbrute\s*force\b": "brute force authentication attacks",
            r"\b(vpn|firewall)\s+(log|event|disconnect)\w*\b": "VPN/firewall logs",
            r"\bactive\s+directory\b": "Active Directory events",
            r"\b(sso|saml|oauth|oidc)\s+(fail|event|log)\w*\b": "SSO/SAML authentication events",
            r"\bevent\s*id\b": "Windows Event Log IDs",
            r"\b(email|spam|phishing)\s+(log|event|alert)\w*\b": "email security logs",
        }
        for pattern, concept in outside_scope_patterns.items():
            if re.search(pattern, desc_lower):
                return (
                    f"Phantex monitors AI agent behavior (process exec, network, file, tool calls, MCP), "
                    f"not {concept}. This detection requires a SIEM integration or a different event source."
                )
        return None

    async def refine(
        self,
        original_rule: str,
        feedback: str,
    ) -> tuple[RuleSuggestion, UsageStats]:
        """
        Refine a previously generated rule based on analyst feedback.

        Args:
            original_rule: The PRL rule to refine
            feedback: Analyst's feedback on what to change

        Returns:
            (refined RuleSuggestion, usage_stats)
        """
        messages = [
            {"role": "user", "content": f"Here is an existing PRL rule:\n\n```prl\n{original_rule}\n```"},
            {"role": "assistant", "content": "I have the rule. What would you like me to change?"},
            {"role": "user", "content": feedback},
        ]

        response, usage = await self._llm.complete(
            messages,
            system_prompt=RULE_GEN_SYSTEM_PROMPT,
        )

        rule_text = self._extract_prl(response)
        name = self._extract_field(rule_text, "RULE")
        severity = self._extract_field(rule_text, "SEVERITY") or "medium"
        is_valid, errors = self._validate_prl(rule_text)

        return RuleSuggestion(
            rule_text=rule_text,
            name=name,
            severity=severity,
            description=f"Refined: {feedback[:200]}",
            is_valid=is_valid,
            validation_errors=errors,
            confidence=0.8 if is_valid else 0.3,
        ), usage
