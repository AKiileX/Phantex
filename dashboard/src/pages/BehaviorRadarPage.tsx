// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Behavior Radar Chart.
 *
 * Spider/radar chart per agent showing behavioral dimensions.
 * Deviation from baseline = visible shape distortion.
 *
 * Dimensions:
 *   - Network Activity
 *   - File Operations
 *   - Process Execution
 *   - Auth Events
 *   - Tool Usage
 *   - Anomaly Score
 *
 * Data sources:
 *   - GET /api/v1/agents → agent list
 *   - GET /api/v1/events → events for dimension scoring
 *   - GET /api/v1/alerts → anomaly signal
 *
 * @module pages/BehaviorRadarPage
 */

import { useMemo, useState } from "react"
import {
  Radar,
  Target,
  ChevronLeft,
  ChevronRight,
  Search,
  BarChart3,
  HelpCircle,
} from "lucide-react"
import { useAgents } from "@/api/agents"
import { useEvents } from "@/api/events"
import { useAlerts } from "@/api/alerts"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"
import { useThemeStore } from "@/stores/themeStore"
import type { AgentSummary, EventSummary, AlertSummary } from "@/types"

/* ── Radar dimensions ──────────────────────────────────────── */

const DIMENSIONS = [
  { key: "network", label: "Network", angle: 0 },
  { key: "file", label: "File Ops", angle: 60 },
  { key: "process", label: "Process", angle: 120 },
  { key: "auth", label: "Auth", angle: 180 },
  { key: "tool", label: "Tool Use", angle: 240 },
  { key: "anomaly", label: "Anomaly", angle: 300 },
] as const

type DimensionKey = (typeof DIMENSIONS)[number]["key"]

interface AgentProfile {
  id: string
  name: string
  status: string
  scores: Record<DimensionKey, number> // 0-1
  baseline: Record<DimensionKey, number> // 0-1 baseline reference
  deviation: number // 0-1 overall deviation
}

/* ── Classify event to dimension ───────────────────────────── */
function eventDimension(type: string): DimensionKey {
  const t = type.toLowerCase()
  if (t.includes("network") || t.includes("dns") || t.includes("conn") || t.includes("accept")) return "network"
  if (t.includes("file") || t.includes("write") || t.includes("read") || t.includes("mmap")) return "file"
  if (t.includes("process") || t.includes("exec") || t.includes("spawn")) return "process"
  if (t.includes("auth") || t.includes("login") || t.includes("token")) return "auth"
  if (t.includes("tool") || t.includes("mcp") || t.includes("invoke") || t.includes("a2a")) return "tool"
  return "anomaly"
}

/* ── SVG Radar polygon helper ──────────────────────────────── */
function radarPoint(dim: typeof DIMENSIONS[number], value: number, cx: number, cy: number, r: number) {
  const angle = ((dim.angle - 90) * Math.PI) / 180
  return { x: cx + r * value * Math.cos(angle), y: cy + r * value * Math.sin(angle) }
}

function radarPolygon(scores: Record<DimensionKey, number>, cx: number, cy: number, r: number): string {
  return DIMENSIONS.map((d) => {
    const p = radarPoint(d, scores[d.key], cx, cy, r)
    return `${p.x},${p.y}`
  }).join(" ")
}

/* ── Deviation color ─────────────────────────────────── */
function deviationColor(d: number): string {
  if (d > 0.35) return "#ef4444"
  if (d > 0.2) return "#eab308"
  return "#22c55e"
}

/* ── Radar SVG (v2 — premium) ──────────────────────────── */
const CX = 80, CY = 80, R = 65

function RadarChart({ profile, size = 160, showScan = false, isDark = false }: { profile: AgentProfile; size?: number; showScan?: boolean; isDark?: boolean }) {
  const scale = size / 160
  const cx = CX * scale, cy = CY * scale, r = R * scale
  const devColor = deviationColor(profile.deviation)

  return (
    <svg width={size} height={size} className="overflow-visible">
      <defs>
        {/* Gradient fill for the actual polygon */}
        <radialGradient id={`radar-fill-${profile.id}-${size}`} cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor={devColor} stopOpacity="0.15" />
          <stop offset="100%" stopColor={devColor} stopOpacity="0.03" />
        </radialGradient>
        {/* Glow filter */}
        <filter id={`radar-glow-${profile.id}-${size}`} x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur in="SourceGraphic" stdDeviation={2 * scale} result="blur" />
          <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
      </defs>

      {/* Grid rings with gradient opacity */}
      {[0.25, 0.5, 0.75, 1].map((lev) => (
        <polygon
          key={lev}
          points={DIMENSIONS.map((d) => {
            const p = radarPoint(d, lev, cx, cy, r)
            return `${p.x},${p.y}`
          }).join(" ")}
          fill="none"
          stroke={isDark ? `rgba(63,63,70,${0.1 + lev * 0.08})` : `rgba(0,0,0,${0.04 + lev * 0.03})`}
          strokeWidth={lev === 1 ? 0.8 : 0.5}
        />
      ))}

      {/* Axis lines */}
      {DIMENSIONS.map((d) => {
        const p = radarPoint(d, 1, cx, cy, r)
        return <line key={d.key} x1={cx} y1={cy} x2={p.x} y2={p.y} stroke={isDark ? "rgba(63,63,70,0.12)" : "rgba(0,0,0,0.04)"} strokeWidth={0.5} />
      })}

      {/* Baseline polygon (soft dashed) */}
      <polygon
        points={radarPolygon(profile.baseline, cx, cy, r)}
        fill="rgba(100,100,255,0.03)"
        stroke="rgba(100,100,255,0.25)"
        strokeWidth={0.8 * scale}
        strokeDasharray="3 3"
      />

      {/* Actual polygon with gradient fill and glow */}
      <polygon
        points={radarPolygon(profile.scores, cx, cy, r)}
        fill={`url(#radar-fill-${profile.id}-${size})`}
        stroke={devColor}
        strokeWidth={1.5 * scale}
        strokeLinejoin="round"
        filter={profile.deviation > 0.3 ? `url(#radar-glow-${profile.id}-${size})` : undefined}
      />

      {/* Dimension dots with glow on high deviation */}
      {DIMENSIONS.map((d) => {
        const p = radarPoint(d, profile.scores[d.key], cx, cy, r)
        const dimDev = Math.abs(profile.scores[d.key] - profile.baseline[d.key])
        return (
          <g key={d.key}>
            {dimDev > 0.2 && (
              <circle cx={p.x} cy={p.y} r={6 * scale} fill={devColor} opacity={0.15} />
            )}
            <circle
              cx={p.x} cy={p.y} r={3 * scale}
              fill={dimDev > 0.15 ? devColor : "var(--color-muted-foreground)"}
              stroke="var(--color-surface-1)"
              strokeWidth={1.2 * scale}
            />
          </g>
        )
      })}

      {/* Labels with subtle backgrounds */}
      {DIMENSIONS.map((d) => {
        const p = radarPoint(d, 1.25, cx, cy, r)
        const dimDev = Math.abs(profile.scores[d.key] - profile.baseline[d.key])
        return (
          <text
            key={d.key}
            x={p.x} y={p.y}
            textAnchor="middle"
            dominantBaseline="central"
            fill={dimDev > 0.15 ? devColor : "currentColor"}
            fontSize={7.5 * scale}
            fontWeight={dimDev > 0.15 ? "700" : "500"}
            className={dimDev > 0.15 ? "" : "text-muted-foreground"}
          >
            {d.label}
          </text>
        )
      })}

      {/* Animated scanning line (only on large detail view) */}
      {showScan && (
        <line
          x1={cx} y1={cy}
          x2={cx + r} y2={cy}
          stroke={devColor}
          strokeWidth={0.8}
          opacity={0.3}
          style={{
            transformOrigin: `${cx}px ${cy}px`,
            animation: "radar-scan 4s linear infinite",
          }}
        />
      )}
    </svg>
  )
}

/* ── Component ─────────────────────────────────────────────── */

export default function BehaviorRadarPage() {
  const [searchQuery, setSearchQuery] = useState("")
  const [selectedAgent, setSelectedAgent] = useState<AgentProfile | null>(null)
  const [page, setPage] = useState(0)
  const [showGuide, setShowGuide] = useState(false)
  const PAGE_SIZE = 12
  const isDark = useThemeStore((s) => s.resolved === "dark")

  const { data: agentsData } = useAgents({ limit: 100 })
  const { data: eventsData } = useEvents({ limit: 100 })
  const { data: alertsData } = useAlerts({ limit: 100 })

  const agents = useMemo(() => agentsData?.items ?? [], [agentsData?.items])
  const events = useMemo(() => eventsData?.items ?? [], [eventsData?.items])
  const alerts = useMemo(() => alertsData?.items ?? [], [alertsData?.items])

  /* ── Build profiles ──────────────────────────────────── */
  const profiles = useMemo(() => {
    // Index events by agent
    const evtByAgent = new Map<string, EventSummary[]>()
    events.forEach((e: EventSummary) => {
      if (!e.agent_id) return
      const list = evtByAgent.get(e.agent_id) ?? []
      list.push(e)
      evtByAgent.set(e.agent_id, list)
    })

    // Index alerts by agent
    const alertByAgent = new Map<string, AlertSummary[]>()
    alerts.forEach((a: AlertSummary) => {
      if (!a.agent_id) return
      const list = alertByAgent.get(a.agent_id) ?? []
      list.push(a)
      alertByAgent.set(a.agent_id, list)
    })

    return agents.map((agent: AgentSummary): AgentProfile => {
      const agentEvents = evtByAgent.get(agent.id) ?? []
      const agentAlerts = alertByAgent.get(agent.id) ?? []

      // Count per dimension
      const counts: Record<DimensionKey, number> = { network: 0, file: 0, process: 0, auth: 0, tool: 0, anomaly: 0 }
      agentEvents.forEach((e) => { counts[eventDimension(e.event_type)]++ })

      // Add anomaly from alerts
      counts.anomaly += agentAlerts.length * 3

      // Normalize to 0-1 range (max 20 events per dimension is "full")
      const MAX = 20
      const scores = {} as Record<DimensionKey, number>
      for (const d of DIMENSIONS) {
        scores[d.key] = Math.min(1, counts[d.key] / MAX)
      }

      // Static "baseline" — uniform low profile
      const baseline: Record<DimensionKey, number> = {
        network: 0.3, file: 0.25, process: 0.2, auth: 0.15, tool: 0.35, anomaly: 0.1,
      }

      // Deviation = mean absolute difference from baseline
      let devSum = 0
      for (const d of DIMENSIONS) {
        devSum += Math.abs(scores[d.key] - baseline[d.key])
      }
      const deviation = devSum / DIMENSIONS.length

      return {
        id: agent.id,
        name: agent.name ?? `Agent-${(agent.id ?? "unknown").slice(0, 8)}`,
        status: agent.status,
        scores,
        baseline,
        deviation,
      }
    }).sort((a: AgentProfile, b: AgentProfile) => b.deviation - a.deviation)
  }, [agents, events, alerts])

  /* ── Search + paginate ───────────────────────────────── */
  const filtered = searchQuery
    ? profiles.filter((p) => p.name.toLowerCase().includes(searchQuery.toLowerCase()))
    : profiles
  const totalPages = Math.ceil(filtered.length / PAGE_SIZE)
  const visibleProfiles = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center h-9 w-9 rounded-lg bg-violet-500/10 border border-violet-500/20">
            <Radar size={18} className="text-violet-400" />
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-tight">Behavior Radar</h1>
            <p className="text-xs text-muted-foreground">Multi-axis behavioral profiling — baseline deviation detection</p>
          </div>
          <button onClick={() => setShowGuide(!showGuide)} className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"><HelpCircle size={14} />{showGuide ? "Hide Guide" : "How does this work?"}</button>
        </div>
        {/* Search */}
        <div className="relative">
          <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => { setSearchQuery(e.target.value); setPage(0) }}
            placeholder="Search agents..."
            className="pl-8 pr-3 py-1.5 text-xs border border-border/50 rounded-lg bg-surface-1 focus:outline-none focus:ring-1 focus:ring-primary/30"
          />
        </div>
      </div>

      {/* Summary bar */}
      <div className="flex gap-3">
        {[
          { label: "Agents", value: profiles.length },
          { label: "High Deviation", value: profiles.filter((p) => p.deviation > 0.35).length, color: "text-severity-critical" },
          { label: "Medium Deviation", value: profiles.filter((p) => p.deviation > 0.2 && p.deviation <= 0.35).length, color: "text-severity-medium" },
          { label: "Normal", value: profiles.filter((p) => p.deviation <= 0.2).length, color: "text-status-active" },
        ].map((s) => (
          <div key={s.label} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-1/50 border border-border/30 text-xs">
            <span className="text-muted-foreground">{s.label}</span>
            <span className={cn("font-bold tabular-nums", s.color)}>{s.value}</span>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-12 gap-4">
        {/* Radar grid */}
        <div className="col-span-8 space-y-3">
          <div className="grid grid-cols-3 gap-3">
            {visibleProfiles.map((profile) => (
              <button
                key={profile.id}
                onClick={() => setSelectedAgent(selectedAgent?.id === profile.id ? null : profile)}
                className={cn(
                  "text-left transition-all cursor-pointer group",
                  selectedAgent?.id === profile.id ? "ring-1 ring-primary/30 scale-[1.02]" : "hover:scale-[1.01]",
                )}
              >
                <Card className="h-full overflow-hidden relative">
                  {/* Top accent gradient */}
                  <div
                    className="absolute top-0 left-0 right-0 h-[2px]"
                    style={{
                      background: `linear-gradient(90deg, transparent 10%, ${deviationColor(profile.deviation)}60, transparent 90%)`,
                    }}
                  />
                  <div className="p-3 space-y-2">
                    {/* Name + deviation badge */}
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold truncate">{profile.name}</span>
                      <Badge
                        variant={profile.deviation > 0.35 ? "critical" : profile.deviation > 0.2 ? "medium" : "active"}
                        className="text-[8px]"
                      >
                        {(profile.deviation * 100).toFixed(0)}% dev
                      </Badge>
                    </div>

                    {/* Radar */}
                    <div className="flex justify-center">
                      <RadarChart profile={profile} size={140} isDark={isDark} />
                    </div>

                    {/* Quick dimension bar */}
                    <div className="flex gap-0.5 h-1">
                      {DIMENSIONS.map((d) => {
                        const val = profile.scores[d.key]
                        const dev = Math.abs(val - profile.baseline[d.key])
                        return (
                          <div
                            key={d.key}
                            className="flex-1 rounded-full"
                            style={{
                              backgroundColor: dev > 0.15 ? deviationColor(profile.deviation) : isDark ? "rgba(63,63,70,0.2)" : "rgba(0,0,0,0.06)",
                              opacity: 0.3 + val * 0.7,
                            }}
                          />
                        )
                      })}
                    </div>
                  </div>
                </Card>
              </button>
            ))}
          </div>

          {visibleProfiles.length === 0 && (
            <div className="py-16 text-center text-muted-foreground">
              <Radar size={32} className="mx-auto mb-2 opacity-20" />
              <div className="text-sm">No agents found</div>
            </div>
          )}

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-center gap-2">
              <Button variant="outline" size="sm" disabled={page === 0} onClick={() => setPage(page - 1)}>
                <ChevronLeft size={14} />
              </Button>
              <span className="text-xs text-muted-foreground">
                {page + 1} / {totalPages}
              </span>
              <Button variant="outline" size="sm" disabled={page >= totalPages - 1} onClick={() => setPage(page + 1)}>
                <ChevronRight size={14} />
              </Button>
            </div>
          )}
        </div>

        {/* Detail panel */}
        <div className="col-span-4 space-y-3">
          {selectedAgent ? (
            <>
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Target size={14} />
                    {selectedAgent.name}
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  {/* Large radar with scanning line */}
                  <div className="flex justify-center relative">
                    <style>{`@keyframes radar-scan { to { transform: rotate(360deg); } }`}</style>
                    <RadarChart profile={selectedAgent} size={220} showScan isDark={isDark} />
                  </div>

                  {/* Deviation meter */}
                  <div>
                    <div className="flex items-center justify-between text-xs mb-1">
                      <span className="text-muted-foreground">Overall Deviation</span>
                      <span className="font-bold" style={{ color: deviationColor(selectedAgent.deviation) }}>
                        {(selectedAgent.deviation * 100).toFixed(1)}%
                      </span>
                    </div>
                    <div className="h-2 rounded-full bg-surface-2 overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all duration-500"
                        style={{
                          width: `${Math.min(100, selectedAgent.deviation * 200)}%`,
                          backgroundColor: deviationColor(selectedAgent.deviation),
                        }}
                      />
                    </div>
                  </div>

                  {/* Per-dimension scores */}
                  <div className="space-y-2">
                    <div className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">Dimensions</div>
                    {DIMENSIONS.map((d) => {
                      const score = selectedAgent.scores[d.key]
                      const base = selectedAgent.baseline[d.key]
                      const diff = score - base
                      return (
                        <div key={d.key}>
                          <div className="flex items-center justify-between text-[11px] mb-0.5">
                            <span className="text-muted-foreground">{d.label}</span>
                            <div className="flex items-center gap-2">
                              <span className="font-mono tabular-nums">{(score * 100).toFixed(0)}</span>
                              {Math.abs(diff) > 0.05 && (
                                <span className={cn("text-[9px] font-bold", diff > 0 ? "text-severity-high" : "text-status-active")}>
                                  {diff > 0 ? "+" : ""}{(diff * 100).toFixed(0)}
                                </span>
                              )}
                            </div>
                          </div>
                          <div className="h-1.5 rounded-full bg-surface-2 overflow-hidden">
                            <div
                              className="h-full rounded-full transition-all duration-300"
                              style={{
                                width: `${score * 100}%`,
                                backgroundColor: Math.abs(diff) > 0.15 ? "#ef4444" : Math.abs(diff) > 0.05 ? "#eab308" : "#22c55e",
                              }}
                            />
                          </div>
                        </div>
                      )
                    })}
                  </div>

                  {/* Legend */}
                  <div className="flex items-center gap-4 text-[9px] text-muted-foreground pt-2 border-t border-border/20">
                    <div className="flex items-center gap-1">
                      <div className="w-3 h-0.5 rounded bg-blue-400/50" style={{ borderTop: "1px dashed rgba(100,100,255,0.5)" }} />
                      Baseline
                    </div>
                    <div className="flex items-center gap-1">
                      <div className="w-3 h-0.5 rounded" style={{ backgroundColor: deviationColor(selectedAgent.deviation) }} />
                      Current
                    </div>
                  </div>
                </CardContent>
              </Card>
            </>
          ) : (
            <Card>
              <CardContent className="py-12 text-center text-muted-foreground">
                <BarChart3 size={32} className="mx-auto mb-2 opacity-20" />
                <div className="text-sm">Select an agent to inspect</div>
                <div className="text-xs">Radar shows deviation from baseline</div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>

      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5 space-y-3 text-sm text-muted-foreground">
          <h3 className="text-base font-semibold text-foreground">How does the Behavior Radar work?</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Behavioral Profiling</p>
              <p>Builds multi-axis profiles for each agent from <code className="text-xs bg-white/5 px-1 rounded">useAgents</code>, <code className="text-xs bg-white/5 px-1 rounded">useEvents</code>, and <code className="text-xs bg-white/5 px-1 rounded">useAlerts</code>. Axes include: tool call frequency, LLM request rate, error rate, data volume, and alert generation — all normalized against the agent's own baseline.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Radar Chart</p>
              <p>Spider/radar chart shows current behavior (blue area) vs. historical baseline (gray area). Axes extending beyond baseline indicate anomalous behavior — spikes in tool calls, unexpected data access patterns, or elevated error rates.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Agent Selection</p>
              <p>Browse agents in the left panel with search, pagination, and anomaly scores. Agents with high deviation from baseline are flagged. Click to load their full behavioral profile in the radar visualization.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Deviation Detection</p>
              <p>Case-insensitive comparison across all behavioral dimensions. Significant deviations trigger visual warnings. This helps catch compromised agents exhibiting unusual patterns before they trigger explicit rule-based alerts.</p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
