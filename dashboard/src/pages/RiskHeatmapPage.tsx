// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Risk Heatmap Page.
 *
 * GitHub-contribution-style grid showing threat density per agent
 * over time. Color intensity = severity × count. Click cell → drill down.
 *
 * Data sources:
 *   - GET /api/v1/agents → row labels
 *   - GET /api/v1/alerts → severity/count per agent per time bucket
 *   - GET /api/v1/events → event density
 *
 * @module pages/RiskHeatmapPage
 */

import { useMemo, useState } from "react"
import {
  Flame,
  TrendingUp,
  AlertTriangle,
  Grid3x3,
  HelpCircle,
} from "lucide-react"
import { useThemeStore } from "@/stores/themeStore"
import { useAgents } from "@/api/agents"
import { useAlerts } from "@/api/alerts"
import { useEvents } from "@/api/events"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { cn } from "@/lib/utils"
import type { AgentSummary, AlertSummary, EventSummary } from "@/types"

/* ── Configuration ─────────────────────────────────────────── */

type TimeGranularity = "hour" | "day"
type DataMode = "alerts" | "events" | "combined"

const SEV_WEIGHT: Record<string, number> = {
  critical: 5,
  high: 3,
  medium: 2,
  low: 1,
  info: 0.2,
}

/* Heat colors — maps 0→1 intensity to color */
function heatColor(intensity: number, isDark: boolean): string {
  if (intensity === 0) return isDark ? "rgba(39,39,42,0.3)" : "rgba(0,0,0,0.06)"
  if (intensity < 0.15) return "rgba(34,197,94,0.2)"
  if (intensity < 0.3) return "rgba(34,197,94,0.4)"
  if (intensity < 0.5) return "rgba(234,179,8,0.4)"
  if (intensity < 0.7) return "rgba(249,115,22,0.5)"
  if (intensity < 0.85) return "rgba(239,68,68,0.5)"
  return "rgba(239,68,68,0.8)"
}

function heatBorder(intensity: number, isDark: boolean): string {
  if (intensity === 0) return isDark ? "rgba(63,63,70,0.15)" : "rgba(0,0,0,0.08)"
  if (intensity < 0.3) return "rgba(34,197,94,0.3)"
  if (intensity < 0.6) return "rgba(234,179,8,0.3)"
  return "rgba(239,68,68,0.3)"
}

/* ── Component ─────────────────────────────────────────────── */

export default function RiskHeatmapPage() {
  const isDark = useThemeStore((s) => s.resolved === "dark")
  const [granularity, setGranularity] = useState<TimeGranularity>("hour")
  const [mode, setMode] = useState<DataMode>("combined")
  const [hoveredCell, setHoveredCell] = useState<{ agent: string; bucket: number; score: number; count: number } | null>(null)
  const [mountTime] = useState(Date.now)
  const [showGuide, setShowGuide] = useState(false)

  const bucketCount = granularity === "hour" ? 24 : 14

  const since = useMemo(
    () => new Date(mountTime - (granularity === "hour" ? 86400_000 : 14 * 86400_000)).toISOString(),
    [granularity, mountTime],
  )

  const { data: agentsData } = useAgents({ limit: 100 })
  const { data: alertsData } = useAlerts({ since, limit: 100 }, 30_000)
  const { data: eventsData } = useEvents({ since, limit: 100 }, 30_000)

  const agents = useMemo(() => agentsData?.items ?? [], [agentsData?.items])
  const alerts = useMemo(() => alertsData?.items ?? [], [alertsData?.items])
  const events = useMemo(() => eventsData?.items ?? [], [eventsData?.items])

  /* ── Build heatmap data ──────────────────────────────── */
  const { grid, maxScore, topAgents } = useMemo(() => {
    const rangeMs = granularity === "hour" ? 86400_000 : 14 * 86400_000
    const bucketMs = rangeMs / bucketCount
    const start = mountTime - rangeMs

    // Score per (agent, bucket)
    const scores = new Map<string, number[]>()
    const counts = new Map<string, number[]>()

    const ensureAgent = (id: string) => {
      if (!scores.has(id)) {
        scores.set(id, new Array(bucketCount).fill(0))
        counts.set(id, new Array(bucketCount).fill(0))
      }
    }

    if (mode !== "events") {
      alerts.forEach((a: AlertSummary) => {
        if (!a.agent_id) return
        ensureAgent(a.agent_id)
        const ts = new Date(a.created_at).getTime()
        const bucket = Math.min(bucketCount - 1, Math.max(0, Math.floor((ts - start) / bucketMs)))
        scores.get(a.agent_id)![bucket] += SEV_WEIGHT[a.severity] ?? 1
        counts.get(a.agent_id)![bucket]++
      })
    }

    if (mode !== "alerts") {
      events.forEach((e: EventSummary) => {
        if (!e.agent_id) return
        ensureAgent(e.agent_id)
        const ts = new Date(e.timestamp).getTime()
        const bucket = Math.min(bucketCount - 1, Math.max(0, Math.floor((ts - start) / bucketMs)))
        scores.get(e.agent_id)![bucket] += SEV_WEIGHT[e.severity] ?? 0.5
        counts.get(e.agent_id)![bucket]++
      })
    }

    // Also include agents with 0 events
    agents.forEach((a: AgentSummary) => ensureAgent(a.id))

    let maxScore = 1
    scores.forEach((arr) => {
      const m = Math.max(...arr)
      if (m > maxScore) maxScore = m
    })

    // Sort agents by total score (highest risk first)
    const agentOrder = Array.from(scores.keys())
      .map((id) => ({ id, total: scores.get(id)!.reduce((a, b) => a + b, 0) }))
      .sort((a, b) => b.total - a.total)

    const grid = agentOrder.map(({ id }) => ({
      agentId: id,
      agent: agents.find((a: AgentSummary) => a.id === id),
      scores: scores.get(id)!,
      counts: counts.get(id)!,
      total: scores.get(id)!.reduce((a, b) => a + b, 0),
    }))

    return {
      grid,
      maxScore,
      topAgents: agentOrder.slice(0, 5),
    }
  }, [agents, alerts, events, granularity, mode, bucketCount, mountTime])

  /* ── Bucket labels ───────────────────────────────────── */
  const bucketLabels = useMemo(() => {
    const rangeMs = granularity === "hour" ? 86400_000 : 14 * 86400_000
    const bucketMs = rangeMs / bucketCount
    const start = mountTime - rangeMs
    return Array.from({ length: bucketCount }, (_, i) => {
      const ts = start + i * bucketMs
      const d = new Date(ts)
      return granularity === "hour"
        ? d.toLocaleTimeString("en-US", { hour: "2-digit" })
        : d.toLocaleDateString("en-US", { month: "short", day: "numeric" })
    })
  }, [granularity, bucketCount, mountTime])

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center h-9 w-9 rounded-lg bg-red-500/10 border border-red-500/20">
            <Flame size={18} className="text-red-400" />
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-tight">Risk Heatmap</h1>
            <p className="text-xs text-muted-foreground">Threat density per agent over time</p>
          </div>
          <button onClick={() => setShowGuide(!showGuide)} className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"><HelpCircle size={14} />{showGuide ? "Hide Guide" : "How does this work?"}</button>
        </div>
        <div className="flex items-center gap-2">
          {/* Mode */}
          <div className="flex items-center gap-1 bg-surface-1 border border-border/50 rounded-lg p-0.5">
            {(["combined", "alerts", "events"] as DataMode[]).map((m) => (
              <button
                key={m}
                onClick={() => setMode(m)}
                className={cn(
                  "px-2.5 py-1 rounded-md text-xs font-medium capitalize cursor-pointer transition-all",
                  mode === m ? "bg-primary/15 text-primary border border-primary/20" : "text-muted-foreground hover:text-foreground",
                )}
              >
                {m}
              </button>
            ))}
          </div>
          {/* Granularity */}
          <div className="flex items-center gap-1 bg-surface-1 border border-border/50 rounded-lg p-0.5">
            {(["hour", "day"] as TimeGranularity[]).map((g) => (
              <button
                key={g}
                onClick={() => setGranularity(g)}
                className={cn(
                  "px-2.5 py-1 rounded-md text-xs font-medium capitalize cursor-pointer transition-all",
                  granularity === g ? "bg-primary/15 text-primary border border-primary/20" : "text-muted-foreground hover:text-foreground",
                )}
              >
                {g === "hour" ? "24h (hourly)" : "14d (daily)"}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-12 gap-4">
        {/* Heatmap grid */}
        <div className="col-span-9">
          <Card className="p-0 overflow-hidden">
            <div className="overflow-x-auto">
              <div className="min-w-[700px]">
                {/* Column headers */}
                <div className="flex border-b border-border/30">
                  <div className="w-36 flex-shrink-0 px-3 py-2 text-[9px] font-semibold text-muted-foreground uppercase tracking-wider">
                    Agent
                  </div>
                  <div className="flex flex-1">
                    {bucketLabels.map((label, i) => (
                      <div
                        key={i}
                        className="flex-1 px-0.5 py-2 text-[8px] text-muted-foreground/50 text-center font-mono"
                      >
                        {i % (granularity === "hour" ? 3 : 2) === 0 ? label : ""}
                      </div>
                    ))}
                  </div>
                  <div className="w-16 flex-shrink-0 px-2 py-2 text-[9px] font-semibold text-muted-foreground uppercase text-right">
                    Score
                  </div>
                </div>

                {/* Rows */}
                {grid.slice(0, 30).map((row) => (
                  <div
                    key={row.agentId}
                    className="flex items-center border-b border-border/10 hover:bg-white/[0.01] transition-colors"
                  >
                    {/* Agent label */}
                    <div className="w-36 flex-shrink-0 px-3 py-1.5">
                      <a
                        href={`/agents/${row.agentId}`}
                        className="text-[11px] font-medium text-foreground hover:text-primary truncate block"
                      >
                        {row.agent?.name ?? `Agent-${row.agentId.slice(0, 8)}`}
                      </a>
                      <div className="text-[9px] text-muted-foreground">
                        {row.agent?.framework ?? "unknown"}
                      </div>
                    </div>

                    {/* Heat cells */}
                    <div className="flex flex-1 gap-px py-1">
                      {row.scores.map((score, i) => {
                        const intensity = maxScore > 0 ? score / maxScore : 0
                        return (
                          <div
                            key={i}
                            className="flex-1 relative group"
                            onMouseEnter={() => setHoveredCell({ agent: row.agent?.name ?? row.agentId.slice(0, 8), bucket: i, score, count: row.counts[i] })}
                            onMouseLeave={() => setHoveredCell(null)}
                          >
                            <div
                              className="h-6 rounded-sm transition-all duration-200 hover:scale-110 hover:z-10 cursor-pointer"
                              style={{
                                backgroundColor: heatColor(intensity, isDark),
                                border: `1px solid ${heatBorder(intensity, isDark)}`,
                                boxShadow: intensity > 0.7 ? `0 0 6px ${heatBorder(intensity, isDark)}` : undefined,
                              }}
                            />
                          </div>
                        )
                      })}
                    </div>

                    {/* Total score */}
                    <div className="w-16 flex-shrink-0 px-2 py-1.5 text-right">
                      <span className={cn(
                        "text-[11px] font-bold tabular-nums",
                        row.total > maxScore * 0.7 ? "text-severity-critical" :
                        row.total > maxScore * 0.4 ? "text-severity-medium" :
                        row.total > 0 ? "text-primary" : "text-muted-foreground/30",
                      )}>
                        {row.total.toFixed(0)}
                      </span>
                    </div>
                  </div>
                ))}

                {grid.length === 0 && (
                  <div className="flex items-center justify-center py-16 text-muted-foreground">
                    <Grid3x3 size={24} className="mr-2 opacity-30" />
                    <span className="text-sm">No agent data available</span>
                  </div>
                )}
              </div>
            </div>
          </Card>

          {/* Tooltip */}
          {hoveredCell && (
            <div className="fixed z-[9999] pointer-events-none" style={{ top: "50%", left: "50%", transform: "translate(-50%, -50%)" }}>
              {/* tooltip is shown inline via title for simplicity */}
            </div>
          )}

          {/* Color legend */}
          <div className="flex items-center gap-3 mt-3 px-1">
            <span className="text-[10px] text-muted-foreground">Less</span>
            <div className="flex gap-0.5">
              {[0, 0.15, 0.3, 0.5, 0.7, 0.85, 1].map((v) => (
                <div
                  key={v}
                  className="w-4 h-4 rounded-sm"
                  style={{ backgroundColor: heatColor(v, isDark), border: `1px solid ${heatBorder(v, isDark)}` }}
                />
              ))}
            </div>
            <span className="text-[10px] text-muted-foreground">More</span>
          </div>
        </div>

        {/* Side panel */}
        <div className="col-span-3 space-y-3">
          {/* Top risky agents */}
          <Card>
            <CardHeader>
              <CardTitle className="text-xs flex items-center gap-2">
                <TrendingUp size={14} />
                Top Risk Agents
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {topAgents.map(({ id, total }, idx) => {
                const agent = agents.find((a: AgentSummary) => a.id === id)
                return (
                  <div key={id} className="flex items-center gap-2">
                    <span className={cn(
                      "w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold",
                      idx === 0 ? "bg-severity-critical/20 text-severity-critical" :
                      idx === 1 ? "bg-severity-high/20 text-severity-high" :
                      "bg-surface-2 text-muted-foreground",
                    )}>
                      {idx + 1}
                    </span>
                    <div className="flex-1 min-w-0">
                      <div className="text-[11px] font-medium truncate">
                        {agent?.name ?? id.slice(0, 12)}
                      </div>
                    </div>
                    <span className="text-[10px] font-bold tabular-nums text-severity-high">
                      {total.toFixed(0)}
                    </span>
                  </div>
                )
              })}
              {topAgents.length === 0 && (
                <div className="text-xs text-muted-foreground text-center py-4">No data</div>
              )}
            </CardContent>
          </Card>

          {/* Summary stats */}
          <Card>
            <CardHeader>
              <CardTitle className="text-xs flex items-center gap-2">
                <AlertTriangle size={14} />
                Summary
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-xs">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Agents tracked</span>
                <span className="font-bold">{grid.length}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Total alerts</span>
                <span className="font-bold text-severity-high">{alerts.length}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Total events</span>
                <span className="font-bold">{events.length}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Max cell score</span>
                <span className="font-bold tabular-nums">{maxScore.toFixed(1)}</span>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5 space-y-3 text-sm text-muted-foreground">
          <h3 className="text-base font-semibold text-foreground">How does the Risk Heatmap work?</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Data Sources</p>
              <p>Combines agents from <code className="text-xs bg-white/5 px-1 rounded">useAgents</code>, alerts from <code className="text-xs bg-white/5 px-1 rounded">useAlerts</code>, and events from <code className="text-xs bg-white/5 px-1 rounded">useEvents</code>. Each cell score is weighted: critical alerts=5, high=3, medium=1, plus normalized event counts.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Time Bucketing</p>
              <p>Hourly view: 24 buckets across one day. Daily view: 14 buckets across two weeks. Each bucket shows aggregated risk for that agent during that time window. Hover for exact scores and event counts.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Color Scale</p>
              <p>Heat intensity from transparent (safe) to deep red (high risk). The colorscale is normalized to the maximum cell score in the current view. Hot cells indicate concentrated threat activity.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Mode Filter</p>
              <p><strong>Combined</strong> weighs both alerts and events. <strong>Alerts</strong> only counts detections. <strong>Events</strong> only counts raw telemetry volume. Use mode switching to isolate signal from noise.</p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
