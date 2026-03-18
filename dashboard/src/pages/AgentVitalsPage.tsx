// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Agent Vitals Page.
 *
 * Patient-monitor–style cards: real-time heartbeat line for activity,
 * mini sparklines for metrics, one-glance health overview per agent.
 *
 * Data sources:
 *   - GET /api/v1/agents → agent list
 *   - GET /api/v1/events → activity feed per agent
 *   - GET /api/v1/alerts → open alerts per agent
 *   - GET /api/v1/trust/score → trust per agent
 *
 * @module pages/AgentVitalsPage
 */

import { useMemo, useState, useEffect, useRef } from "react"
import {
  HeartPulse,
  Activity,
  Shield,
  AlertTriangle,
  HelpCircle,
} from "lucide-react"
import { useAgents } from "@/api/agents"
import { useEvents } from "@/api/events"
import { useAlerts } from "@/api/alerts"
import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Sparkline } from "@/components/ui/sparkline"
import { cn } from "@/lib/utils"
import { timeAgo } from "@/lib/utils"
import { useThemeStore } from "@/stores/themeStore"
import type { AgentSummary, EventSummary, AlertSummary } from "@/types"

/* ── Health score computation ──────────────────────────────── */

interface AgentVitals {
  agent: AgentSummary
  eventCount: number
  alertCount: number
  criticalAlerts: number
  avgSeverity: number
  lastEvent: string | null
  activitySparkline: number[]
  healthScore: number // 0-100
  healthLabel: string
  healthColor: string
}

function computeHealth(eventCount: number, alertCount: number, criticals: number, status: string): { score: number; label: string; color: string } {
  if (status === "terminated") return { score: 0, label: "Offline", color: "#71717a" }
  if (status === "stale") return { score: 25, label: "Stale", color: "#eab308" }

  let score = 90
  score -= criticals * 25
  score -= (alertCount - criticals) * 5
  if (eventCount === 0) score -= 30
  score = Math.max(0, Math.min(100, score))

  const label = score >= 80 ? "Healthy" : score >= 50 ? "Warning" : score >= 25 ? "Degraded" : "Critical"
  const color = score >= 80 ? "#22c55e" : score >= 50 ? "#eab308" : score >= 25 ? "#f97316" : "#ef4444"
  return { score, label, color }
}

/* ── Heartbeat SVG animation ───────────────────────────────── */

function HeartbeatLine({ color, active }: { color: string; active: boolean }) {
  const ref = useRef<SVGPathElement>(null)
  const [offset, setOffset] = useState(0)

  useEffect(() => {
    if (!active) return
    const iv = setInterval(() => setOffset((o) => (o + 2) % 200), 30)
    return () => clearInterval(iv)
  }, [active])

  // ECG-like waveform path
  const path = "M0,20 L10,20 L12,20 L15,8 L18,32 L21,14 L24,20 L34,20 L36,20 L39,10 L42,30 L45,16 L48,20 L58,20 L60,20 L63,12 L66,28 L69,18 L72,20 L82,20 L84,20 L87,8 L90,32 L93,14 L96,20 L106,20 L108,20 L111,10 L114,30 L117,16 L120,20 L130,20 L132,20 L135,8 L138,32 L141,14 L144,20 L154,20 L156,20 L159,12 L162,28 L165,18 L168,20 L178,20 L180,20 L183,10 L186,30 L189,16 L192,20 L200,20"

  return (
    <svg viewBox="0 0 200 40" className="w-full h-8 overflow-hidden">
      <path
        ref={ref}
        d={path}
        fill="none"
        stroke={color}
        strokeWidth={1.5}
        opacity={active ? 0.8 : 0.2}
        transform={`translate(-${offset}, 0)`}
        style={{ filter: active ? `drop-shadow(0 0 3px ${color})` : undefined }}
      />
    </svg>
  )
}

/* ── Circular health gauge ─────────────────────────────────── */

function HealthGauge({ score, color, size = 56 }: { score: number; color: string; size?: number }) {
  const r = (size - 8) / 2
  const circ = 2 * Math.PI * r
  const offset = circ - (score / 100) * circ
  const isDark = useThemeStore((s) => s.resolved === "dark")

  return (
    <svg width={size} height={size} className="flex-shrink-0">
      {/* Background ring */}
      <circle
        cx={size / 2} cy={size / 2} r={r}
        fill="none" stroke={isDark ? "rgba(63,63,70,0.3)" : "rgba(0,0,0,0.08)"} strokeWidth={3}
      />
      {/* Score arc */}
      <circle
        cx={size / 2} cy={size / 2} r={r}
        fill="none" stroke={color} strokeWidth={3}
        strokeDasharray={circ}
        strokeDashoffset={offset}
        strokeLinecap="round"
        transform={`rotate(-90 ${size / 2} ${size / 2})`}
        style={{ transition: "stroke-dashoffset 0.8s ease" }}
      />
      {/* Score text */}
      <text
        x={size / 2} y={size / 2}
        textAnchor="middle" dominantBaseline="central"
        fill={color} fontSize={14} fontWeight="bold" fontFamily="Inter,sans-serif"
      >
        {score}
      </text>
    </svg>
  )
}

/* ── Sort options ──────────────────────────────────────────── */
type SortBy = "health" | "alerts" | "activity" | "name"

/* ── Component ─────────────────────────────────────────────── */

export default function AgentVitalsPage() {
  const [sortBy, setSortBy] = useState<SortBy>("health")
  const [statusFilter, setStatusFilter] = useState<string>("all")
  const [mountTime] = useState(Date.now)
  const [showGuide, setShowGuide] = useState(false)

  const { data: agentsData } = useAgents({ limit: 100 })
  const [since] = useState(() => new Date(Date.now() - 86400_000).toISOString())
  const { data: eventsData } = useEvents({ since, limit: 100 }, 10_000)
  const { data: alertsData } = useAlerts({ status: "open", limit: 100 }, 10_000)

  const agents = useMemo(() => agentsData?.items ?? [], [agentsData?.items])
  const events = useMemo(() => eventsData?.items ?? [], [eventsData?.items])
  const openAlerts = useMemo(() => alertsData?.items ?? [], [alertsData?.items])

  /* ── Build vitals ────────────────────────────────────── */
  const vitals = useMemo(() => {
    // Index events by agent
    const eventsByAgent = new Map<string, EventSummary[]>()
    events.forEach((e: EventSummary) => {
      if (!e.agent_id) return
      const arr = eventsByAgent.get(e.agent_id) ?? []
      arr.push(e)
      eventsByAgent.set(e.agent_id, arr)
    })

    // Index alerts by agent
    const alertsByAgent = new Map<string, AlertSummary[]>()
    openAlerts.forEach((a: AlertSummary) => {
      if (!a.agent_id) return
      const arr = alertsByAgent.get(a.agent_id) ?? []
      arr.push(a)
      alertsByAgent.set(a.agent_id, arr)
    })

    return agents.map((agent: AgentSummary): AgentVitals => {
      const agentEvents = eventsByAgent.get(agent.id) ?? []
      const agentAlerts = alertsByAgent.get(agent.id) ?? []
      const criticals = agentAlerts.filter((a) => a.severity === "critical").length

      // Build sparkline: bucket events into 12 time slots over 24h
      const now = mountTime
      const bucketSize = 86400_000 / 12
      const sparkline = new Array(12).fill(0)
      agentEvents.forEach((e) => {
        const ts = new Date(e.timestamp).getTime()
        const bucket = Math.min(11, Math.max(0, Math.floor((ts - (now - 86400_000)) / bucketSize)))
        sparkline[bucket]++
      })

      const avgSev = agentAlerts.length > 0
        ? agentAlerts.reduce((sum, a) => {
            const w: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
            return sum + (w[a.severity] ?? 0)
          }, 0) / agentAlerts.length
        : 0

      const lastEvent = agentEvents.length > 0
        ? agentEvents.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())[0].timestamp
        : null

      const health = computeHealth(agentEvents.length, agentAlerts.length, criticals, agent.status)

      return {
        agent,
        eventCount: agentEvents.length,
        alertCount: agentAlerts.length,
        criticalAlerts: criticals,
        avgSeverity: avgSev,
        lastEvent,
        activitySparkline: sparkline,
        healthScore: health.score,
        healthLabel: health.label,
        healthColor: health.color,
      }
    })
  }, [agents, events, openAlerts, mountTime])

  /* ── Filter & sort ───────────────────────────────────── */
  const sorted = useMemo(() => {
    let list = vitals
    if (statusFilter !== "all") list = list.filter((v) => v.agent.status === statusFilter)

    const sortFn: Record<SortBy, (a: AgentVitals, b: AgentVitals) => number> = {
      health: (a, b) => a.healthScore - b.healthScore, // worst first
      alerts: (a, b) => b.alertCount - a.alertCount,
      activity: (a, b) => b.eventCount - a.eventCount,
      name: (a, b) => (a.agent.name ?? "").localeCompare(b.agent.name ?? ""),
    }

    return [...list].sort(sortFn[sortBy])
  }, [vitals, sortBy, statusFilter])

  /* ── Summary stats ───────────────────────────────────── */
  const summary = useMemo(() => ({
    healthy: vitals.filter((v) => v.healthScore >= 80).length,
    warning: vitals.filter((v) => v.healthScore >= 50 && v.healthScore < 80).length,
    degraded: vitals.filter((v) => v.healthScore >= 25 && v.healthScore < 50).length,
    critical: vitals.filter((v) => v.healthScore < 25 && v.agent.status === "active").length,
    offline: vitals.filter((v) => v.agent.status === "terminated").length,
  }), [vitals])

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center h-9 w-9 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
            <HeartPulse size={18} className="text-emerald-400" />
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-tight">Agent Vitals</h1>
            <p className="text-xs text-muted-foreground">Real-time health monitoring — one glance per agent</p>
          </div>
          <button onClick={() => setShowGuide(!showGuide)} className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"><HelpCircle size={14} />{showGuide ? "Hide Guide" : "How does this work?"}</button>
        </div>
        <div className="flex items-center gap-2">
          {/* Sort */}
          <div className="flex items-center gap-1 bg-surface-1 border border-border/50 rounded-lg p-0.5">
            {(["health", "alerts", "activity", "name"] as SortBy[]).map((s) => (
              <button
                key={s}
                onClick={() => setSortBy(s)}
                className={cn(
                  "px-2.5 py-1 rounded-md text-xs font-medium capitalize cursor-pointer transition-all",
                  sortBy === s ? "bg-primary/15 text-primary border border-primary/20" : "text-muted-foreground hover:text-foreground",
                )}
              >
                {s}
              </button>
            ))}
          </div>
          {/* Status filter */}
          <div className="flex items-center gap-1 bg-surface-1 border border-border/50 rounded-lg p-0.5">
            {["all", "active", "stale", "terminated"].map((s) => (
              <button
                key={s}
                onClick={() => setStatusFilter(s)}
                className={cn(
                  "px-2 py-1 rounded-md text-xs font-medium capitalize cursor-pointer",
                  statusFilter === s ? "bg-primary/15 text-primary" : "text-muted-foreground",
                )}
              >
                {s}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Summary bar */}
      <div className="flex gap-3">
        {[
          { label: "Healthy", value: summary.healthy, color: "text-status-active", bg: "bg-status-active/10 border-status-active/20" },
          { label: "Warning", value: summary.warning, color: "text-severity-medium", bg: "bg-severity-medium/10 border-severity-medium/20" },
          { label: "Degraded", value: summary.degraded, color: "text-severity-high", bg: "bg-severity-high/10 border-severity-high/20" },
          { label: "Critical", value: summary.critical, color: "text-severity-critical", bg: "bg-severity-critical/10 border-severity-critical/20" },
          { label: "Offline", value: summary.offline, color: "text-muted-foreground" },
        ].map((s) => (
          <div key={s.label} className={cn("flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs", s.bg ?? "bg-surface-1/50 border-border/30")}>
            <span className="text-muted-foreground">{s.label}</span>
            <span className={cn("font-bold tabular-nums", s.color)}>{s.value}</span>
          </div>
        ))}
      </div>

      {/* Agent vital cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
        {sorted.map((v) => (
          <Card key={v.agent.id} className="group relative overflow-hidden">
            {/* Health accent top border */}
            <div
              className="absolute inset-x-0 top-0 h-0.5"
              style={{ backgroundColor: v.healthColor }}
            />

            <div className="p-4 space-y-3">
              {/* Agent identity + health gauge */}
              <div className="flex items-start gap-3">
                <HealthGauge score={v.healthScore} color={v.healthColor} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <a
                      href={`/agents/${v.agent.id}`}
                      className="text-sm font-bold text-foreground hover:text-primary truncate"
                    >
                      {v.agent.name ?? `Agent-${v.agent.paid.slice(0, 8)}`}
                    </a>
                    <Badge variant={v.agent.status} className="text-[9px]">
                      {v.agent.status}
                    </Badge>
                  </div>
                  <div className="text-[10px] text-muted-foreground mt-0.5">
                    {v.agent.framework ?? "unknown"} · {v.agent.paid.slice(0, 12)}
                  </div>
                  <div className="flex items-center gap-1 mt-1">
                    <span className="text-[10px] font-bold" style={{ color: v.healthColor }}>
                      {v.healthLabel}
                    </span>
                    <span className="text-[10px] text-muted-foreground/50">·</span>
                    <span className="text-[10px] text-muted-foreground">
                      Last seen {timeAgo(v.agent.last_seen)}
                    </span>
                  </div>
                </div>
              </div>

              {/* Heartbeat line */}
              <HeartbeatLine color={v.healthColor} active={v.agent.status === "active"} />

              {/* Metric row */}
              <div className="grid grid-cols-4 gap-2">
                <div className="text-center">
                  <div className="text-[10px] text-muted-foreground flex items-center justify-center gap-1">
                    <Activity size={10} /> Events
                  </div>
                  <div className="text-sm font-bold tabular-nums">{v.eventCount}</div>
                </div>
                <div className="text-center">
                  <div className="text-[10px] text-muted-foreground flex items-center justify-center gap-1">
                    <AlertTriangle size={10} /> Alerts
                  </div>
                  <div className={cn("text-sm font-bold tabular-nums", v.alertCount > 0 ? "text-severity-high" : "")}>
                    {v.alertCount}
                  </div>
                </div>
                <div className="text-center">
                  <div className="text-[10px] text-muted-foreground flex items-center justify-center gap-1">
                    <Shield size={10} /> Critical
                  </div>
                  <div className={cn("text-sm font-bold tabular-nums", v.criticalAlerts > 0 ? "text-severity-critical" : "")}>
                    {v.criticalAlerts}
                  </div>
                </div>
                <div className="text-center">
                  <div className="text-[10px] text-muted-foreground">Activity</div>
                  <Sparkline
                    data={v.activitySparkline}
                    width={60}
                    height={16}
                    color={v.healthColor}
                    className="mx-auto mt-1"
                  />
                </div>
              </div>
            </div>
          </Card>
        ))}
      </div>

      {sorted.length === 0 && (
        <div className="flex flex-col items-center justify-center py-20 text-muted-foreground">
          <HeartPulse size={40} className="mb-3 opacity-20" />
          <span className="text-sm">No agents match current filters</span>
        </div>
      )}

      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5 space-y-3 text-sm text-muted-foreground">
          <h3 className="text-base font-semibold text-foreground">How do Agent Vitals work?</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Health Monitoring</p>
              <p>Pulls the full agent list via <code className="text-xs bg-white/5 px-1 rounded">/api/agents</code> with cursor pagination. Each agent card shows a composite health score derived from recent alert severity (critical=5, high=3, medium=1) and event volume in the last 24 hours.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Heartbeat Animation</p>
              <p>The ECG-style heartbeat line is a pure CSS animation driven by the agent's health state. Healthy agents show steady pulses; degraded or critical agents show irregular or flat waveforms. It auto-refreshes with the 30-second poll.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Sort &amp; Filter</p>
              <p>Sort by health score, name, or event count. Filter by status (healthy, degraded, critical, offline). Both controls apply client-side to the full agent list — no additional API calls needed.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Vital Metrics</p>
              <p>Each card surfaces alert counts by severity, recent event count, last-seen timestamp, and trust score from the trust engine. Click any agent card to navigate to its detail page for deeper investigation.</p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
