# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — Prompt Injection Regex Patterns.

40+ patterns organised into 7 categories covering known prompt-injection
signature families.  Every pattern has been tested for ReDoS resistance
(no unbounded repetition inside repetition).

Usage::

    from ml.content.patterns.injection_patterns import scan_fast
    hits = scan_fast(normalised_text)
    # hits → list of (pattern_name, matched_text)

The patterns are case-insensitive and operate on *normalised* text
(after encoding_utils.normalize).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

@dataclass(frozen=True)
class InjectionPattern:
    """A single injection-detection regex."""

    name: str
    category: str
    pattern: re.Pattern[str]
    weight: float = 1.0  # Higher → more indicative of injection
    description: str = ""

# ── Category 1: Role Override ────────────────────────────────────────────────

_CAT1_ROLE_OVERRIDE: list[InjectionPattern] = [
    InjectionPattern(
        name="role_you_are_now",
        category="role_override",
        pattern=re.compile(r"you\s+are\s+now\b", re.I),
        weight=0.8,
        description="'You are now X' — attempts to reassign agent identity",
    ),
    InjectionPattern(
        name="role_act_as",
        category="role_override",
        pattern=re.compile(r"\bact\s+as\b", re.I),
        weight=0.6,
        description="'Act as X' — role reassignment",
    ),
    InjectionPattern(
        name="role_new_role",
        category="role_override",
        pattern=re.compile(r"\bnew\s+role\s*:", re.I),
        weight=0.9,
        description="'New role:' — explicit role override",
    ),
    InjectionPattern(
        name="role_forget_instructions",
        category="role_override",
        pattern=re.compile(r"forget\s+(your|all|previous)\s+(previous\s+)?instructions", re.I),
        weight=1.0,
        description="'Forget your instructions' — memory wipe attempt",
    ),
    InjectionPattern(
        name="role_from_now_on",
        category="role_override",
        pattern=re.compile(r"from\s+now\s+on\s+you\s+will", re.I),
        weight=0.9,
        description="'From now on you will' — persistent role change",
    ),
    InjectionPattern(
        name="role_new_task",
        category="role_override",
        pattern=re.compile(r"your\s+new\s+task\s+is", re.I),
        weight=0.8,
        description="'Your new task is' — task reassignment",
    ),
    InjectionPattern(
        name="role_pretend_to_be",
        category="role_override",
        pattern=re.compile(r"pretend\s+(to\s+be|you\s*(?:are|'re))", re.I),
        weight=0.7,
        description="'Pretend to be X' — identity hijack",
    ),
]

# ── Category 2: Instruction Override ─────────────────────────────────────────

_CAT2_INSTRUCTION_OVERRIDE: list[InjectionPattern] = [
    InjectionPattern(
        name="instr_ignore_previous",
        category="instruction_override",
        pattern=re.compile(r"ignore\s+(all\s+)?(previous|above|prior)\s+(instructions|rules|context)", re.I),
        weight=1.0,
        description="'Ignore previous instructions' — classic injection",
    ),
    InjectionPattern(
        name="instr_disregard",
        category="instruction_override",
        pattern=re.compile(r"disregard\s+(the\s+)?(above|previous|prior|initial)\b", re.I),
        weight=1.0,
        description="'Disregard above' — instruction override",
    ),
    InjectionPattern(
        name="instr_override",
        category="instruction_override",
        pattern=re.compile(r"\boverride\s*:", re.I),
        weight=0.8,
        description="'Override:' — explicit override marker",
    ),
    InjectionPattern(
        name="instr_system_prefix",
        category="instruction_override",
        pattern=re.compile(r"^\s*system\s*:", re.I | re.M),
        weight=0.9,
        description="'System:' at line start — attempts to inject system message",
    ),
    InjectionPattern(
        name="instr_new_instructions",
        category="instruction_override",
        pattern=re.compile(r"(?:new|actual|real|true)\s+instructions?\s*:", re.I),
        weight=1.0,
        description="'New instructions:' — replacement instruction block",
    ),
    InjectionPattern(
        name="instr_do_not_follow",
        category="instruction_override",
        pattern=re.compile(r"do\s+not\s+follow\s+(your|the|any)\s+(original|previous|initial)", re.I),
        weight=1.0,
        description="'Do not follow your original instructions'",
    ),
]

# ── Category 3: Information Extraction ───────────────────────────────────────

_CAT3_EXTRACTION: list[InjectionPattern] = [
    InjectionPattern(
        name="extract_repeat_above",
        category="extraction",
        pattern=re.compile(r"repeat\s+(the\s+)?(text\s+)?above\b", re.I),
        weight=0.8,
        description="'Repeat the above' — system prompt extraction",
    ),
    InjectionPattern(
        name="extract_show_system_prompt",
        category="extraction",
        pattern=re.compile(
            r"(show|display|print|output|reveal|tell\s+me)\s+(your\s+)?(system\s+prompt|initial\s+prompt|instructions|configuration)",
            re.I,
        ),
        weight=1.0,
        description="'Show your system prompt' — direct extraction",
    ),
    InjectionPattern(
        name="extract_what_are_your",
        category="extraction",
        pattern=re.compile(r"what\s+are\s+your\s+(instructions|rules|guidelines|system\s+prompt)", re.I),
        weight=0.9,
        description="'What are your instructions' — probing",
    ),
    InjectionPattern(
        name="extract_output_config",
        category="extraction",
        pattern=re.compile(r"output\s+(your\s+)?(config|configuration|setup|initialization)", re.I),
        weight=0.9,
        description="'Output your configuration' — config extraction",
    ),
    InjectionPattern(
        name="extract_verbatim",
        category="extraction",
        pattern=re.compile(
            r"(copy|paste|reproduce)\s+(the\s+)?(entire|full|complete)\s+(prompt|instructions|message)", re.I
        ),
        weight=1.0,
        description="'Reproduce the entire prompt' — verbatim extraction",
    ),
]

# ── Category 4: Delimiter Injection ──────────────────────────────────────────

_CAT4_DELIMITER: list[InjectionPattern] = [
    InjectionPattern(
        name="delim_triple_hash",
        category="delimiter",
        pattern=re.compile(r"#{3,}\s*(new|system|actual|real|override|admin)", re.I),
        weight=0.9,
        description="'### NEW' — delimiter injection with keyword",
    ),
    InjectionPattern(
        name="delim_triple_dash_keyword",
        category="delimiter",
        pattern=re.compile(r"-{3,}\s*(system|actual|real|override|new\s+instructions)", re.I),
        weight=0.9,
        description="'--- system' — delimiter injection",
    ),
    InjectionPattern(
        name="delim_im_start",
        category="delimiter",
        pattern=re.compile(r"<\|im_start\|>", re.I),
        weight=1.0,
        description="ChatML-style <|im_start|> injection",
    ),
    InjectionPattern(
        name="delim_system_bracket",
        category="delimiter",
        pattern=re.compile(r"\[\[(?:SYSTEM|ADMIN|ROOT|INTERNAL)\]\]", re.I),
        weight=1.0,
        description="'[[SYSTEM]]' — bracket-delimited role injection",
    ),
    InjectionPattern(
        name="delim_xml_system",
        category="delimiter",
        pattern=re.compile(r"<(?:system|instruction|admin|root)>", re.I),
        weight=0.8,
        description="'<system>' — XML-style role injection",
    ),
    InjectionPattern(
        name="delim_backtick_fence",
        category="delimiter",
        pattern=re.compile(r"`{3,}\s*(?:system|override|admin|instructions)", re.I),
        weight=0.8,
        description="'```system' — code-fence role injection",
    ),
]

# ── Category 5: Encoding Evasion ─────────────────────────────────────────────
# These detect RESIDUAL encoding artifacts that survive normalisation but
# indicate the *intent* to evade.

_CAT5_ENCODING: list[InjectionPattern] = [
    InjectionPattern(
        name="enc_html_entity_cluster",
        category="encoding_evasion",
        pattern=re.compile(r"(?:&#\d{2,4};){4,}", re.I),
        weight=0.7,
        description="Cluster of HTML numeric entities — encoding evasion attempt",
    ),
    InjectionPattern(
        name="enc_unicode_escape_cluster",
        category="encoding_evasion",
        pattern=re.compile(r"(?:\\u[0-9a-f]{4}){4,}", re.I),
        weight=0.7,
        description="Cluster of \\uXXXX escapes — encoding evasion",
    ),
    InjectionPattern(
        name="enc_percent_encoding_cluster",
        category="encoding_evasion",
        pattern=re.compile(r"(?:%[0-9a-f]{2}){6,}", re.I),
        weight=0.6,
        description="Excessive percent-encoding — URL evasion attempt",
    ),
]

# ── Category 6: Multi-turn / Context Manipulation ────────────────────────────

_CAT6_MULTITURN: list[InjectionPattern] = [
    InjectionPattern(
        name="mt_remember_this",
        category="multi_turn",
        pattern=re.compile(r"remember\s+this\s+for\s+(later|future|next)", re.I),
        weight=0.6,
        description="'Remember this for later' — planting future instruction",
    ),
    InjectionPattern(
        name="mt_in_next_message",
        category="multi_turn",
        pattern=re.compile(r"in\s+(the\s+)?next\s+message\s*,?\s*(you\s+)?(should|must|will|always)", re.I),
        weight=0.8,
        description="'In the next message, you must' — deferred injection",
    ),
    InjectionPattern(
        name="mt_always_output",
        category="multi_turn",
        pattern=re.compile(r"always\s+(output|respond|say|start\s+with)\b", re.I),
        weight=0.5,
        description="'Always output X' — persistent behaviour modification",
    ),
    InjectionPattern(
        name="mt_when_asked_about",
        category="multi_turn",
        pattern=re.compile(r"whenever\s+(you\s+are\s+)?asked\s+about\b", re.I),
        weight=0.5,
        description="'Whenever asked about X, do Y' — conditional injection",
    ),
]

# ── Category 7: Indirect Injection (embedded in data/documents) ──────────────

_CAT7_INDIRECT: list[InjectionPattern] = [
    InjectionPattern(
        name="indirect_hidden_instruction",
        category="indirect",
        pattern=re.compile(r"(?:hidden|embedded|secret)\s+instructions?\s*:", re.I),
        weight=1.0,
        description="'Hidden instructions:' — indirect injection marker",
    ),
    InjectionPattern(
        name="indirect_agent_please",
        category="indirect",
        pattern=re.compile(r"(?:dear|hey|attention)\s+(?:ai|agent|assistant|model|gpt|claude|llm)\b", re.I),
        weight=0.7,
        description="'Dear AI/agent' — content addressing the agent directly",
    ),
    InjectionPattern(
        name="indirect_tool_call_instruction",
        category="indirect",
        pattern=re.compile(r"(?:please|now)\s+(?:call|use|invoke|execute)\s+(?:the\s+)?(?:tool|function|api)\b", re.I),
        weight=0.8,
        description="'Please call the tool' — embedded tool invocation",
    ),
    InjectionPattern(
        name="indirect_ignore_and_do",
        category="indirect",
        pattern=re.compile(r"ignore\s+(?:this|the)\s+(?:document|text|content|file)\s+and\b", re.I),
        weight=1.0,
        description="'Ignore this document and do X' — indirect override",
    ),
    InjectionPattern(
        name="indirect_important_override",
        category="indirect",
        pattern=re.compile(
            r"(?:IMPORTANT|URGENT|CRITICAL|PRIORITY)\s*[:\-!]\s*(?:ignore|override|disregard|new\s+instruction)",
            re.I,
        ),
        weight=1.0,
        description="'IMPORTANT: ignore' — urgency-based indirect injection",
    ),
    InjectionPattern(
        name="indirect_note_to_ai",
        category="indirect",
        pattern=re.compile(r"(?:note|message)\s+(?:to|for)\s+(?:the\s+)?(?:ai|agent|assistant|model)\b", re.I),
        weight=0.7,
        description="'Note to the AI' — embedded instructions in documents",
    ),
    InjectionPattern(
        name="indirect_begin_new_conversation",
        category="indirect",
        pattern=re.compile(r"begin\s+(?:a\s+)?new\s+conversation", re.I),
        weight=0.8,
        description="'Begin a new conversation' — context reset attempt",
    ),
    InjectionPattern(
        name="indirect_you_must_obey",
        category="indirect",
        pattern=re.compile(r"you\s+must\s+(?:obey|comply|follow|listen)\b", re.I),
        weight=0.8,
        description="'You must obey' — authoritative command injection",
    ),
    InjectionPattern(
        name="indirect_end_of_prompt",
        category="indirect",
        pattern=re.compile(r"(?:end|stop)\s+(?:of\s+)?(?:system\s+)?prompt\b", re.I),
        weight=0.9,
        description="'End of system prompt' — boundary marker injection",
    ),
]

# ── All Patterns ─────────────────────────────────────────────────────────────

ALL_PATTERNS: tuple[InjectionPattern, ...] = tuple(
    _CAT1_ROLE_OVERRIDE
    + _CAT2_INSTRUCTION_OVERRIDE
    + _CAT3_EXTRACTION
    + _CAT4_DELIMITER
    + _CAT5_ENCODING
    + _CAT6_MULTITURN
    + _CAT7_INDIRECT
)

PATTERN_COUNT = len(ALL_PATTERNS)  # 40+

# ── Fast scan function ───────────────────────────────────────────────────────

@dataclass(frozen=True)
class PatternHit:
    """A single pattern match result."""

    name: str
    category: str
    weight: float
    matched_text: str

def scan_fast(text: str) -> list[PatternHit]:
    """Run all injection patterns against *text* and return hits.

    Returns a (possibly empty) list of ``PatternHit`` sorted by weight
    descending.  Runs all patterns sequentially (total < 1 ms on typical
    prompts under 4 KB).
    """
    hits: list[PatternHit] = []
    for pat in ALL_PATTERNS:
        m = pat.pattern.search(text)
        if m:
            hits.append(
                PatternHit(
                    name=pat.name,
                    category=pat.category,
                    weight=pat.weight,
                    matched_text=m.group(0)[:120],  # cap match length in result
                ),
            )
    # Sort by weight descending so highest-confidence matches come first
    hits.sort(key=lambda h: h.weight, reverse=True)
    return hits

def compute_heuristic_score(text: str) -> float:
    """Compute a 0.0–1.0 heuristic injection score from text statistics.

    Signals:
    - Imperative verb density
    - Instruction keyword density
    - Dramatic shift in sentence style (narrative → imperative)
    - Short-text dampening to avoid false positives
    """
    if not text:
        return 0.0

    words = text.lower().split()
    if not words:
        return 0.0

    total = len(words)

    # Count imperative/instruction keywords
    _IMPERATIVE = {
        "ignore",
        "override",
        "forget",
        "disregard",
        "bypass",
        "always",
        "never",
        "must",
        "execute",
        "call",
        "output",
        "print",
        "repeat",
        "reveal",
        "display",
        "respond",
        "act",
        "pretend",
        "become",
        "switch",
        "transform",
    }
    imperative_count = sum(1 for w in words if w in _IMPERATIVE)
    imperative_density = imperative_count / total

    # Count role/instruction keywords
    _ROLE_KEYWORDS = {
        "system",
        "instructions",
        "prompt",
        "role",
        "configuration",
        "override",
        "admin",
        "internal",
        "secret",
        "hidden",
    }
    role_count = sum(1 for w in words if w in _ROLE_KEYWORDS)
    role_density = role_count / total

    # Raw combine (weighted)
    raw = min(1.0, imperative_density * 4.0 + role_density * 5.0)

    # Dampen for short texts: a single keyword in 5 words shouldn't
    # score high.  Require ≥2 keyword hits total for meaningful signal.
    keyword_total = imperative_count + role_count
    if keyword_total < 2:
        raw *= 0.25  # heavy dampening for single-keyword matches
    elif keyword_total < 3:
        raw *= 0.5

    return round(raw, 4)
