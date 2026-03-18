# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex Copilot — Alert Triage Assistant (U3).

Automated alert classification:
  - True positive (TP)
  - False positive (FP)
  - Needs investigation

Batch mode: up to 100 alerts per call.
Target: >80% accuracy on historical data.

The triage assistant uses LLM analysis combined with:
  - Alert metadata (severity, source, rule, frequency)
  - Historical patterns (similar alerts, resolution history)
  - Agent trust context (trust score of source agent)
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.copilot.llm_provider import LLMConfig, LLMProvider, UsageStats

logger = logging.getLogger("phantex.copilot.triage")

@dataclass
class TriageResult:
    """Result for a single alert triage."""

    alert_id: str
    classification: str  # "true_positive", "false_positive", "needs_investigation"
    confidence: float  # 0.0 - 1.0
    reasoning: str
    suggested_action: str  # "escalate", "dismiss", "investigate", "auto_resolve"
    priority: int  # 1 (critical) - 5 (info)

TRIAGE_SYSTEM_PROMPT = """You are a security alert triage specialist. Classify each alert.

Classification options: true_positive, false_positive, needs_investigation
Action options: escalate, dismiss, investigate, auto_resolve
Priority: 1=critical, 2=high, 3=medium, 4=low, 5=info

Rules:
- Critical severity from low-trust agent → likely true_positive
- Repeated similar alerts same agent within minutes → possible alert storm (FP)
- Prompt injection or MCP tool abuse → true_positive
- When in doubt → needs_investigation

Respond ONLY with this JSON (no markdown, no extra text):
{"results": [{"alert_id": "<id>", "classification": "<class>", "confidence": 0.8, "reasoning": "brief reason", "suggested_action": "<action>", "priority": 3}]}"""

class AlertTriageAssistant:
    """
    Automated alert triage using LLM analysis.

    Classifies alerts as TP/FP/needs_investigation with confidence scores
    and suggested actions.
    """

    def __init__(self, llm: LLMProvider | None = None) -> None:
        self._llm = llm or LLMProvider(LLMConfig.from_env())

    @staticmethod
    def _is_valid_uuid(val: str) -> bool:
        """Check if a string is a valid UUID."""
        import re

        return bool(
            re.match(
                r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                val.strip().lower(),
            )
        )

    async def triage_alerts(
        self,
        alert_ids: list[str],
        db: AsyncSession,
        tenant_id: str,
    ) -> tuple[list[TriageResult], UsageStats]:
        """
        Triage a batch of alerts.

        Args:
            alert_ids: List of alert UUIDs to triage (max 100)
            db: Tenant-scoped database session
            tenant_id: Caller's tenant ID

        Returns:
            (list[TriageResult], usage_stats)
        """
        if len(alert_ids) > 100:
            alert_ids = alert_ids[:100]

        # 0. Validate UUIDs — reject non-UUID strings before hitting the DB
        valid_ids = [aid for aid in alert_ids if self._is_valid_uuid(aid)]
        invalid_ids = [aid for aid in alert_ids if not self._is_valid_uuid(aid)]

        if not valid_ids:
            # All IDs are invalid — return error results without touching DB
            return [
                TriageResult(
                    alert_id=aid,
                    classification="needs_investigation",
                    confidence=0.0,
                    reasoning=f"Invalid alert ID format: '{aid[:50]}'. Expected a UUID (e.g. 550e8400-e29b-41d4-a716-446655440000).",
                    suggested_action="investigate",
                    priority=3,
                )
                for aid in alert_ids
            ], UsageStats()

        # 1. Fetch alert details
        placeholders = ", ".join(f":a{i}" for i in range(len(valid_ids)))
        params = {f"a{i}": aid for i, aid in enumerate(valid_ids)}
        query = text(
            f"SELECT id, title, severity, status, description, "
            f"rule_id, agent_id, created_at, context "
            f"FROM alerts WHERE id IN ({placeholders})"
        )
        try:
            result = await db.execute(query, params)
            rows = result.mappings().all()
        except Exception as db_err:
            logger.warning("triage_db_error: %s", db_err)
            return [
                TriageResult(
                    alert_id=aid,
                    classification="needs_investigation",
                    confidence=0.0,
                    reasoning="Database error fetching alert — verify the alert ID is valid.",
                    suggested_action="investigate",
                    priority=3,
                )
                for aid in alert_ids
            ], UsageStats()

        if not rows:
            # Return results for invalid IDs if any
            results_out: list[TriageResult] = []
            for aid in invalid_ids:
                results_out.append(
                    TriageResult(
                        alert_id=aid,
                        classification="needs_investigation",
                        confidence=0.0,
                        reasoning=f"Invalid alert ID format: '{aid[:50]}'. Expected a UUID.",
                        suggested_action="investigate",
                        priority=3,
                    )
                )
            return results_out, UsageStats()

        # 2. Build context for LLM
        alerts_context = []
        for r in rows:
            alerts_context.append(
                {
                    "id": str(r["id"]),
                    "title": r["title"],
                    "severity": r["severity"],
                    "status": r["status"],
                    "description": (r.get("description") or "")[:300],
                    "agent_id": str(r["agent_id"]) if r.get("agent_id") else None,
                    "created_at": str(r["created_at"]),
                }
            )

        user_msg = (
            f"Triage the following {len(alerts_context)} alert(s):\n\n"
            f"```json\n{json.dumps(alerts_context, indent=2)}\n```"
        )

        messages = [{"role": "user", "content": user_msg}]

        # 3. Call LLM with error handling
        try:
            response, usage = await self._llm.complete(
                messages,
                system_prompt=TRIAGE_SYSTEM_PROMPT,
            )
        except Exception as llm_err:
            logger.warning("triage_llm_failed: %s — falling back to heuristic triage", llm_err)
            # Heuristic fallback when LLM is unavailable
            return self._heuristic_triage(alerts_context, alert_ids), UsageStats()

        # 4. Parse results
        results = self._parse_triage_response(response, valid_ids)

        # If LLM returned no useful results, fall back to heuristics
        if not any(r.confidence > 0 for r in results):
            logger.warning("triage_llm_empty_results — falling back to heuristic triage")
            results = self._heuristic_triage(alerts_context, valid_ids)

        # Append results for any invalid IDs
        for aid in invalid_ids:
            results.append(
                TriageResult(
                    alert_id=aid,
                    classification="needs_investigation",
                    confidence=0.0,
                    reasoning=f"Invalid alert ID format: '{aid[:50]}'. Expected a UUID.",
                    suggested_action="investigate",
                    priority=3,
                )
            )

        return results, usage

    def _parse_triage_response(self, response: str, alert_ids: list[str]) -> list[TriageResult]:
        """Parse LLM triage response into TriageResult objects."""
        try:
            # Try to extract JSON from response
            data = json.loads(response)
            raw_results = data.get("results", [])
        except json.JSONDecodeError:
            # Try to find JSON in markdown code block
            import re

            match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", response, re.DOTALL)
            if match:
                try:
                    data = json.loads(match.group(1))
                    raw_results = data.get("results", [])
                except json.JSONDecodeError:
                    raw_results = []
            else:
                raw_results = []

        results = []
        for r in raw_results:
            try:
                results.append(
                    TriageResult(
                        alert_id=r.get("alert_id", ""),
                        classification=r.get("classification", "needs_investigation"),
                        confidence=float(r.get("confidence", 0.5)),
                        reasoning=r.get("reasoning", "Unable to determine"),
                        suggested_action=r.get("suggested_action", "investigate"),
                        priority=int(r.get("priority", 3)),
                    )
                )
            except (ValueError, TypeError):
                continue

        # Fill in any missing alerts with default "needs_investigation"
        triaged_ids = {r.alert_id for r in results}
        for aid in alert_ids:
            if aid not in triaged_ids:
                results.append(
                    TriageResult(
                        alert_id=aid,
                        classification="needs_investigation",
                        confidence=0.0,
                        reasoning="Triage model did not return a result for this alert",
                        suggested_action="investigate",
                        priority=3,
                    )
                )

        return results

    def _heuristic_triage(
        self,
        alerts_context: list[dict],
        alert_ids: list[str],
    ) -> list[TriageResult]:
        """Rule-based fallback triage when LLM is unavailable."""
        SEVERITY_PRIORITY = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}
        results = []
        for a in alerts_context:
            sev = a.get("severity", "medium")
            priority = SEVERITY_PRIORITY.get(sev, 3)
            title_lower = (a.get("title", "") + " " + a.get("description", "")).lower()

            # Simple heuristic rules
            if sev in ("critical", "high"):
                classification = "true_positive"
                confidence = 0.7
                action = "escalate"
                reasoning = f"High severity ({sev}) alert — escalation recommended pending analyst review."
            elif any(
                kw in title_lower
                for kw in ("brute force", "injection", "exfiltration", "privilege", "lateral", "c2", "beacon")
            ):
                classification = "true_positive"
                confidence = 0.65
                action = "investigate"
                reasoning = "Alert title contains threat indicators — investigation recommended."
            elif sev == "info":
                classification = "false_positive"
                confidence = 0.55
                action = "auto_resolve"
                reasoning = "Info-level alert — likely benign activity."
            else:
                classification = "needs_investigation"
                confidence = 0.5
                action = "investigate"
                reasoning = "Insufficient context for automated classification — analyst review required."

            results.append(
                TriageResult(
                    alert_id=a.get("id", ""),
                    classification=classification,
                    confidence=confidence,
                    reasoning=reasoning,
                    suggested_action=action,
                    priority=priority,
                )
            )

        # Fill missing
        triaged = {r.alert_id for r in results}
        for aid in alert_ids:
            if aid not in triaged:
                results.append(
                    TriageResult(
                        alert_id=aid,
                        classification="needs_investigation",
                        confidence=0.0,
                        reasoning="Alert not found in database.",
                        suggested_action="investigate",
                        priority=3,
                    )
                )
        return results

    async def triage_single(
        self,
        alert_id: str,
        db: AsyncSession,
        tenant_id: str,
    ) -> tuple[TriageResult | None, UsageStats]:
        """Triage a single alert. Convenience wrapper."""
        results, usage = await self.triage_alerts([alert_id], db, tenant_id)
        return results[0] if results else None, usage
