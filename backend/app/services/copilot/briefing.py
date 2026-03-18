# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex Copilot — Threat Briefing Service (AB1).

Generates executive-readable NL summaries of the last 24h:
  - Alert counts by severity + trend deltas vs previous 24h
  - Top attack classes with percentage changes
  - Most active / riskiest agents
  - Anomaly highlights (spike detection)
  - Actionable recommendations

Pipeline:
  ClickHouse aggregations → structured data → LLM summarisation → firewall scan → response

LLM is optional: if unavailable the service returns a structured-data-only briefing.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog

from app.services.copilot.firewall import CopilotFirewall
from app.services.copilot.llm_provider import LLMProvider, UsageStats

logger = structlog.get_logger("phantex.copilot.briefing")

# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class SeverityCounts:
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

@dataclass
class TrendDelta:
    """Comparison of current vs previous period."""

    current: int = 0
    previous: int = 0

    @property
    def change_pct(self) -> float:
        if self.previous == 0:
            return 100.0 if self.current > 0 else 0.0
        return round((self.current - self.previous) / self.previous * 100, 1)

    @property
    def direction(self) -> str:
        if self.current > self.previous:
            return "up"
        if self.current < self.previous:
            return "down"
        return "flat"

@dataclass
class AttackClassSummary:
    attack_class: str
    count: int
    severity_breakdown: dict[str, int] = field(default_factory=dict)
    trend: TrendDelta = field(default_factory=TrendDelta)

@dataclass
class AgentRisk:
    agent_id: str
    hostname: str
    event_count: int
    alert_count: int
    trust_score: float | None = None

@dataclass
class BriefingData:
    """Structured threat briefing data (pre-LLM)."""

    generated_at: str = ""
    period_start: str = ""
    period_end: str = ""

    total_alerts: TrendDelta = field(default_factory=TrendDelta)
    severity: SeverityCounts = field(default_factory=SeverityCounts)
    previous_severity: SeverityCounts = field(default_factory=SeverityCounts)

    top_attack_classes: list[AttackClassSummary] = field(default_factory=list)
    riskiest_agents: list[AgentRisk] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)

    total_events: TrendDelta = field(default_factory=TrendDelta)
    resolved_alerts: int = 0
    mean_time_to_respond_min: float | None = None

# ── Prompts ───────────────────────────────────────────────────────────────────

BRIEFING_SYSTEM_PROMPT = """\
You are a senior security analyst writing a concise threat briefing for the \
SOC team. You will receive a JSON blob with structured alert/event data from \
the last 24 hours.

Produce a Markdown briefing with these sections:
1. **Executive Summary** — 2-3 sentences: what happened, is the trend up/down, \
any critical issues.
2. **Alert Overview** — Table with severity counts, trend arrows (↑/↓/→), and \
deltas vs prior 24h.
3. **Top Threats** — Bullet list of the top attack classes with counts and trend.
4. **Riskiest Agents** — Highlight agents with highest alert volume or lowest trust.
5. **Anomalies** — Any spikes, new attack classes, or unusual patterns.
6. **Recommendations** — 2-4 actionable next steps for the SOC team.

Rules:
- Be factual: cite numbers from the data. Do not invent data.
- Keep it under 500 words.
- Use ↑ ↓ → for trend arrows.
- If no data for a section, say "No data for this period."
"""

# ── Service ───────────────────────────────────────────────────────────────────

class ThreatBriefingService:
    """Generate daily threat briefings from ClickHouse + LLM summarisation."""

    def __init__(
        self,
        llm: LLMProvider | None = None,
        firewall: CopilotFirewall | None = None,
    ) -> None:
        self._llm = llm
        self._firewall = firewall or CopilotFirewall()

    # ── Data gathering (DB queries) ───────────────────────────────────────

    async def _gather_data(
        self,
        db: Any,
        tenant_id: str,
        *,
        hours: int = 24,
    ) -> BriefingData:
        """
        Pull aggregated alert + event data for the briefing.

        Uses the RLS-scoped *db* session so every query is tenant-isolated.
        Falls back gracefully if tables/columns are missing.
        """
        from sqlalchemy import text

        now = datetime.now(UTC)
        period_start = now - timedelta(hours=hours)
        prev_start = period_start - timedelta(hours=hours)

        data = BriefingData(
            generated_at=now.isoformat(),
            period_start=period_start.isoformat(),
            period_end=now.isoformat(),
        )

        # ── Current-period alert counts by severity ──────────────────────
        try:
            r = await db.execute(
                text("SELECT severity, COUNT(*) AS cnt FROM alerts WHERE created_at >= :since GROUP BY severity"),
                {"since": period_start},
            )
            for row in r.mappings():
                sev = (row["severity"] or "").lower()
                cnt = row["cnt"]
                if hasattr(data.severity, sev):
                    setattr(data.severity, sev, cnt)
            data.total_alerts.current = (
                data.severity.critical
                + data.severity.high
                + data.severity.medium
                + data.severity.low
                + data.severity.info
            )
        except Exception as exc:
            logger.warning("briefing_alert_severity_query_failed", error=str(exc))

        # ── Previous-period alert counts ─────────────────────────────────
        try:
            r = await db.execute(
                text(
                    "SELECT severity, COUNT(*) AS cnt "
                    "FROM alerts "
                    "WHERE created_at >= :prev AND created_at < :cur "
                    "GROUP BY severity"
                ),
                {"prev": prev_start, "cur": period_start},
            )
            for row in r.mappings():
                sev = (row["severity"] or "").lower()
                cnt = row["cnt"]
                if hasattr(data.previous_severity, sev):
                    setattr(data.previous_severity, sev, cnt)
            data.total_alerts.previous = (
                data.previous_severity.critical
                + data.previous_severity.high
                + data.previous_severity.medium
                + data.previous_severity.low
                + data.previous_severity.info
            )
        except Exception as exc:
            logger.warning("briefing_previous_alert_query_failed", error=str(exc))

        # ── Attack class breakdown (current period) ──────────────────────
        try:
            r = await db.execute(
                text(
                    "SELECT COALESCE(a.attack_class, 'unknown') AS attack_class, "
                    "       a.severity, COUNT(*) AS cnt "
                    "FROM alerts a "
                    "WHERE a.created_at >= :since "
                    "  AND a.attack_class IS NOT NULL "
                    "GROUP BY a.attack_class, a.severity "
                    "ORDER BY cnt DESC"
                ),
                {"since": period_start},
            )
            class_map: dict[str, AttackClassSummary] = {}
            for row in r.mappings():
                cls_name = row["attack_class"]
                if cls_name not in class_map:
                    class_map[cls_name] = AttackClassSummary(attack_class=cls_name, count=0)
                class_map[cls_name].count += row["cnt"]
                class_map[cls_name].severity_breakdown[row["severity"]] = row["cnt"]
            data.top_attack_classes = sorted(class_map.values(), key=lambda x: x.count, reverse=True)[:10]
        except Exception as exc:
            logger.warning("briefing_attack_class_query_failed", error=str(exc))

        # ── Attack class previous period (for trend) ─────────────────────
        try:
            r = await db.execute(
                text(
                    "SELECT COALESCE(attack_class, 'unknown') AS attack_class, "
                    "       COUNT(*) AS cnt "
                    "FROM alerts "
                    "WHERE created_at >= :prev AND created_at < :cur "
                    "  AND attack_class IS NOT NULL "
                    "GROUP BY attack_class"
                ),
                {"prev": prev_start, "cur": period_start},
            )
            prev_counts: dict[str, int] = {}
            for row in r.mappings():
                prev_counts[row["attack_class"]] = row["cnt"]
            for ac in data.top_attack_classes:
                ac.trend = TrendDelta(
                    current=ac.count,
                    previous=prev_counts.get(ac.attack_class, 0),
                )
        except Exception as exc:
            logger.warning("briefing_attack_trend_query_failed", error=str(exc))

        # ── Riskiest agents ──────────────────────────────────────────────
        try:
            r = await db.execute(
                text(
                    "SELECT a.agent_id, ag.hostname, "
                    "       COUNT(*) AS alert_count, "
                    "       ag.trust_score "
                    "FROM alerts a "
                    "LEFT JOIN agents ag ON ag.id = a.agent_id "
                    "WHERE a.created_at >= :since "
                    "GROUP BY a.agent_id, ag.hostname, ag.trust_score "
                    "ORDER BY alert_count DESC "
                    "LIMIT 5"
                ),
                {"since": period_start},
            )
            for row in r.mappings():
                data.riskiest_agents.append(
                    AgentRisk(
                        agent_id=str(row["agent_id"]) if row["agent_id"] else "unknown",
                        hostname=row["hostname"] or "unknown",
                        event_count=0,
                        alert_count=row["alert_count"],
                        trust_score=float(row["trust_score"]) if row["trust_score"] is not None else None,
                    )
                )
        except Exception as exc:
            logger.warning("briefing_risky_agents_query_failed", error=str(exc))

        # ── Resolved alerts + MTTR ───────────────────────────────────────
        try:
            r = await db.execute(
                text(
                    "SELECT COUNT(*) AS resolved, "
                    "       AVG(EXTRACT(EPOCH FROM (resolved_at - created_at)) / 60) AS mttr "
                    "FROM alerts "
                    "WHERE status = 'resolved' "
                    "  AND resolved_at >= :since"
                ),
                {"since": period_start},
            )
            row = r.mappings().first()
            if row:
                data.resolved_alerts = row["resolved"] or 0
                if row["mttr"] is not None:
                    data.mean_time_to_respond_min = round(float(row["mttr"]), 1)
        except Exception as exc:
            logger.warning("briefing_mttr_query_failed", error=str(exc))

        # ── Total events (current + previous) ────────────────────────────
        try:
            r = await db.execute(
                text("SELECT COUNT(*) FROM events WHERE created_at >= :since"),
                {"since": period_start},
            )
            data.total_events.current = r.scalar() or 0
        except Exception:
            pass  # events table may live in ClickHouse — best effort
        try:
            r = await db.execute(
                text("SELECT COUNT(*) FROM events WHERE created_at >= :prev AND created_at < :cur"),
                {"prev": prev_start, "cur": period_start},
            )
            data.total_events.previous = r.scalar() or 0
        except Exception:
            pass

        # ── Anomaly detection (simple spike heuristic) ───────────────────
        if data.total_alerts.change_pct > 50:
            data.anomalies.append(
                f"Alert volume spike: {data.total_alerts.change_pct:+.0f}% vs previous period "
                f"({data.total_alerts.previous} → {data.total_alerts.current})"
            )
        for ac in data.top_attack_classes:
            if ac.trend.change_pct > 100:
                data.anomalies.append(
                    f"Attack class '{ac.attack_class}' surged {ac.trend.change_pct:+.0f}% "
                    f"({ac.trend.previous} → {ac.trend.current})"
                )
        for ag in data.riskiest_agents:
            if ag.trust_score is not None and ag.trust_score < 0.3:
                data.anomalies.append(f"Agent '{ag.hostname}' has critically low trust score ({ag.trust_score:.2f})")

        return data

    # ── Format structured-data-only briefing ──────────────────────────────

    def _format_structured(self, data: BriefingData) -> str:
        """Markdown briefing without LLM — just formatted data."""
        lines: list[str] = []
        lines.append(f"# Threat Briefing — {data.period_start[:10]}")
        lines.append("")
        lines.append(f"**Period:** {data.period_start} → {data.period_end}")
        lines.append("")

        # Alert overview
        delta = data.total_alerts
        arrow = {"up": "↑", "down": "↓", "flat": "→"}[delta.direction]
        lines.append("## Alert Overview")
        lines.append(f"Total alerts: **{delta.current}** ({arrow} {delta.change_pct:+.0f}% vs prior 24h)")
        lines.append("")
        lines.append("| Severity | Current | Previous |")
        lines.append("|----------|---------|----------|")
        for sev in ("critical", "high", "medium", "low", "info"):
            cur = getattr(data.severity, sev, 0)
            prev = getattr(data.previous_severity, sev, 0)
            lines.append(f"| {sev.title()} | {cur} | {prev} |")
        lines.append("")

        # Top attack classes
        if data.top_attack_classes:
            lines.append("## Top Attack Classes")
            for ac in data.top_attack_classes[:5]:
                arrow = {"up": "↑", "down": "↓", "flat": "→"}[ac.trend.direction]
                lines.append(f"- **{ac.attack_class}**: {ac.count} alerts ({arrow} {ac.trend.change_pct:+.0f}%)")
            lines.append("")

        # Riskiest agents
        if data.riskiest_agents:
            lines.append("## Riskiest Agents")
            for ag in data.riskiest_agents[:5]:
                ts = f" (trust: {ag.trust_score:.2f})" if ag.trust_score is not None else ""
                lines.append(f"- **{ag.hostname}**: {ag.alert_count} alerts{ts}")
            lines.append("")

        # Anomalies
        if data.anomalies:
            lines.append("## Anomalies")
            for a in data.anomalies:
                lines.append(f"- ⚠️ {a}")
            lines.append("")

        # Operational metrics
        lines.append("## Operational Metrics")
        lines.append(f"- Resolved alerts: {data.resolved_alerts}")
        if data.mean_time_to_respond_min is not None:
            lines.append(f"- Mean time to respond: {data.mean_time_to_respond_min:.0f} min")
        ev_arrow = {"up": "↑", "down": "↓", "flat": "→"}[data.total_events.direction]
        lines.append(f"- Total events: {data.total_events.current} ({ev_arrow} {data.total_events.change_pct:+.0f}%)")

        return "\n".join(lines)

    # ── Public API ────────────────────────────────────────────────────────

    async def generate_briefing(
        self,
        db: Any,
        tenant_id: str,
        *,
        hours: int = 24,
        use_llm: bool = True,
    ) -> tuple[str, BriefingData, UsageStats]:
        """
        Generate a threat briefing.

        Returns:
            (markdown_text, structured_data, usage_stats)
        """
        t0 = time.monotonic()
        data = await self._gather_data(db, tenant_id, hours=hours)
        gather_ms = (time.monotonic() - t0) * 1000

        logger.info(
            "briefing_data_gathered",
            tenant_id=tenant_id,
            hours=hours,
            total_alerts=data.total_alerts.current,
            gather_ms=round(gather_ms, 1),
        )

        # Try LLM summarisation; fall back to structured if unavailable
        if use_llm and self._llm is not None:
            try:
                data_json = json.dumps(asdict(data), default=str, indent=2)
                messages = [
                    {"role": "system", "content": BRIEFING_SYSTEM_PROMPT},
                    {
                        "role": "user",
                        "content": f"Generate a threat briefing from this data:\n\n```json\n{data_json}\n```",
                    },
                ]
                response_text, usage = await self._llm.complete(messages)

                # Firewall scan output
                verdict = self._firewall.scan_output(response_text)
                final_text = verdict.redacted_output or response_text

                usage.latency_ms = (time.monotonic() - t0) * 1000
                logger.info(
                    "briefing_generated",
                    tenant_id=tenant_id,
                    mode="llm",
                    tokens=usage.total_tokens,
                    latency_ms=round(usage.latency_ms, 1),
                )
                return final_text, data, usage

            except Exception as exc:
                logger.warning("briefing_llm_fallback", error=str(exc))

        # Structured-only fallback
        structured_text = self._format_structured(data)
        usage = UsageStats(latency_ms=(time.monotonic() - t0) * 1000)
        logger.info(
            "briefing_generated",
            tenant_id=tenant_id,
            mode="structured",
            latency_ms=round(usage.latency_ms, 1),
        )
        return structured_text, data, usage
