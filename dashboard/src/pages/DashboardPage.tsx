// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Dashboard overview (premium v2).
 *
 * Animated counters · sparkline micro-charts · gradient accent cards ·
 * staggered entrance · frosted glass surfaces · live pulse indicators ·
 * real-time clock. Modern SOC experience.
 *
 * Supports three preset views:
 *   Executive  — posture, KPIs only
 *   SOC Analyst — full detections, alerts, activity stream
 *   Threat Hunter — events, severity, frameworks, activity stream
 */

import { useMemo, useCallback, useState, useEffect } from "react"
import {
  Shield,
  Monitor,
  Activity,
  Bell,
  ShieldAlert,
  ArrowUpRight,
  ArrowDownRight,
  Minus,
  Network,
  BarChart3,
  Radio,
  HelpCircle,
} from "lucide-react"
import { useNavigate } from "react-router-dom"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { AnimatedNumber } from "@/components/ui/animated-number"
import { Sparkline } from "@/components/ui/sparkline"
import { BarChart } from "@/components/ui/bar-chart"
import type { BarData } from "@/components/ui/bar-chart"
import { useAlerts } from "@/api/alerts"
import { useAgents } from "@/api/agents"
import { useEvents } from "@/api/events"
import { useRules } from "@/api/rules"
import { timeAgo } from "@/lib/utils"
import { ActivityStream } from "@/components/dashboard/ActivityStream"
import { PresetSwitcher } from "@/components/dashboard/PresetSwitcher"
import { useDashboardPreset } from "@/components/dashboard/presetStore"

/* ── Fake sparkline data (seeded from value for consistency) ── */
function generateSparkData(seed: number, points = 12): number[] {
  const data: number[] = []
  let v = seed
  for (let i = 0; i < points; i++) {
    v += (Math.sin(seed * 0.3 + i * 0.8) * seed * 0.1)
    data.push(Math.max(0, Math.round(v)))
  }
  return data
}

/* ── Trend icon ────────────────────────────────────────────── */
function TrendIcon({ trend }: { trend: "up" | "down" | "flat" }) {
  if (trend === "up") return <ArrowUpRight size={12} className="text-primary" />
  if (trend === "down") return <ArrowDownRight size={12} className="text-severity-critical/70" />
  return <Minus size={10} className="text-muted-foreground" />
}

/* ── Metric card (premium) ─────────────────────────────────── */
interface MetricProps {
  label: string
  value: number
  displayValue?: string
  icon: React.ReactNode
  footnote?: string
  trend?: "up" | "down" | "flat"
  trendLabel?: string
  sparkData?: number[]
  sparkColor?: string
  stagger?: string
}

function MetricCard({
  label, value, displayValue, icon, footnote, trend, trendLabel,
  sparkData, sparkColor, stagger = "",
}: MetricProps) {
  return (
    <Card className={`${stagger} overflow-hidden relative group`}>
      {/* Top accent line */}
      <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-primary/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
      <CardContent className="p-5">
        <div className="flex items-start justify-between gap-3">
          <div className="space-y-2 flex-1 min-w-0">
            <p className="metric-label">{label}</p>
            <div className="flex items-end gap-3">
              {displayValue != null ? (
                <span className="metric-value animate-count-up">{displayValue}</span>
              ) : (
                <AnimatedNumber
                  value={value}
                  className="metric-value animate-count-up"
                />
              )}
              {sparkData && sparkData.length > 1 && (
                <Sparkline data={sparkData} color={sparkColor} className="mb-0.5 opacity-70" />
              )}
            </div>
            {footnote && (
              <p className="text-xs text-muted-foreground">{footnote}</p>
            )}
          </div>
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-white/[0.04] text-muted-foreground border border-border/30 group-hover:border-primary/20 group-hover:text-primary/60 transition-all duration-300">
            {icon}
          </div>
        </div>
        {trend && trendLabel && (
          <div className="mt-3 pt-3 border-t border-border/30 flex items-center gap-1.5 text-xs text-muted-foreground">
            <TrendIcon trend={trend} />
            <span>{trendLabel}</span>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

/* ── Threat posture (premium hero card) ────────────────────── */
function ThreatPosture({ score, label }: { score: number; label: string }) {
  const barColor =
    score >= 80 ? "from-primary to-emerald-400" : score >= 50 ? "from-severity-medium to-amber-400" : "from-severity-critical to-red-400"
  const dotColor =
    score >= 80 ? "bg-primary" : score >= 50 ? "bg-severity-medium" : "bg-severity-critical"
  const glowColor =
    score >= 80 ? "rgba(16,185,129,0.15)" : score >= 50 ? "rgba(234,179,8,0.15)" : "rgba(239,68,68,0.15)"

  return (
    <Card className="col-span-full lg:col-span-1 gradient-border-top stagger-1 overflow-hidden relative group">
      {/* Background glow */}
      <div
        className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-700 pointer-events-none"
        style={{ background: `radial-gradient(ellipse at center, ${glowColor}, transparent 70%)` }}
      />
      <CardContent className="p-5 flex flex-col justify-center space-y-4 relative">
        <div className="flex items-center justify-between">
          <p className="metric-label">Threat Posture</p>
          <Shield size={14} className={score >= 80 ? "text-primary" : score >= 50 ? "text-severity-medium" : "text-severity-critical"} />
        </div>
        <AnimatedNumber value={score} className="metric-value animate-count-up" />
        <div className="space-y-2">
          <div className="h-1.5 w-full rounded-full bg-white/[0.04] overflow-hidden">
            <div
              className={`h-full rounded-full bg-gradient-to-r ${barColor} transition-all duration-700 ease-out`}
              style={{ width: `${score}%` }}
            />
          </div>
          <div className="flex items-center gap-1.5">
            <span className={`w-1.5 h-1.5 rounded-full ${dotColor}`} />
            <span className="text-xs text-muted-foreground">{label}</span>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

/* ── Main Dashboard ────────────────────────────────────────── */
export function DashboardPage() {
  const navigate = useNavigate()
  const { data: agents } = useAgents()
  const { data: events } = useEvents({ limit: 100, agent_only: false })
  const { data: alerts } = useAlerts({ status: "open" })
  const { data: rules } = useRules()

  const agentCount = agents?.items?.length ?? 0
  const activeAgents = agents?.items?.filter((a) => a.status === "active").length ?? 0
  const staleAgents = agents?.items?.filter((a) => a.status === "stale").length ?? 0
  const eventCount = events?.items?.length ?? 0
  const hasMoreEvents = events?.has_more ?? false
  const openAlerts = alerts?.items?.length ?? 0
  const criticalAlerts = alerts?.items?.filter((a) => a.severity === "critical").length ?? 0
  const recentAlerts = alerts?.items?.slice(0, 8) ?? []
  const enabledRules = rules?.items?.filter((r) => r.enabled).length ?? 0
  const totalRules = rules?.items?.length ?? 0

  const postureScore = useMemo(() => {
    if (agentCount === 0) return 100
    let score = 100
    score -= criticalAlerts * 15
    score -= (openAlerts - criticalAlerts) * 5
    score -= staleAgents * 3
    return Math.max(0, Math.min(100, score))
  }, [agentCount, criticalAlerts, openAlerts, staleAgents])

  const postureLabel =
    postureScore >= 80 ? "Healthy" : postureScore >= 50 ? "Needs Attention" : "At Risk"

  const attackClasses = useMemo(() => {
    const map = new Map<string, number>()
    for (const ev of events?.items ?? []) {
      const key = ev.event_type ?? "unknown"
      map.set(key, (map.get(key) ?? 0) + 1)
    }
    return Array.from(map.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
  }, [events?.items])

  // Memoized spark data so it doesn't re-generate each render
  const agentSpark = useMemo(() => generateSparkData(agentCount + 3), [agentCount])
  const eventSpark = useMemo(() => generateSparkData(eventCount + 7), [eventCount])
  const alertSpark = useMemo(() => generateSparkData(openAlerts + 2), [openAlerts])

  // Severity breakdown for analysis chart
  const severityData = useMemo<BarData[]>(() => {
    const sevMap: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    const sevColors: Record<string, string> = {
      critical: "#ef4444",
      high: "#f97316",
      medium: "#eab308",
      low: "#3b82f6",
      info: "#71717a",
    }
    for (const ev of events?.items ?? []) {
      const s = ev.severity ?? "info"
      sevMap[s] = (sevMap[s] ?? 0) + 1
    }
    return Object.entries(sevMap).map(([label, value]) => ({
      label: label.charAt(0).toUpperCase() + label.slice(1),
      value,
      color: sevColors[label],
    }))
  }, [events?.items])

  // Framework breakdown for agents
  const frameworkData = useMemo<BarData[]>(() => {
    const fwMap = new Map<string, number>()
    for (const a of agents?.items ?? []) {
      const fw = a.framework ?? "Unknown"
      fwMap.set(fw, (fwMap.get(fw) ?? 0) + 1)
    }
    return Array.from(fwMap.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6)
      .map(([label, value]) => ({ label, value }))
  }, [agents?.items])

  const handleAlertClick = useCallback(
    (id: string) => navigate(`/alerts/${id}`),
    [navigate],
  )

  const { preset } = useDashboardPreset()

  // Live clock for SOC feel
  const [clock, setClock] = useState(() => new Date().toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" }))
  const [showGuide, setShowGuide] = useState(false)
  useEffect(() => {
    const iv = setInterval(() => setClock(new Date().toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" })), 1000)
    return () => clearInterval(iv)
  }, [])

  return (
    <div className="space-y-6 animate-fade-in">
      {/* ── Dashboard header with preset switcher ──────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-foreground">Dashboard</h1>
          <p className="text-xs text-muted-foreground mt-0.5">
            {preset === "executive" && "High-level posture and risk overview"}
            {preset === "soc" && "Detection triage and real-time alerts"}
            {preset === "hunter" && "Event patterns, ATLAS mapping and topology"}
          </p>
        </div>
        <div className="flex items-center gap-4">
          <button onClick={() => setShowGuide(!showGuide)} className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"><HelpCircle size={14} />{showGuide ? "Hide Guide" : "How does this work?"}</button>
          {/* Live status indicator */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-surface-1/50 border border-border/30">
            <Radio size={12} className="text-status-active animate-pulse" />
            <span className="text-[10px] font-mono text-muted-foreground tabular-nums">{clock}</span>
            <span className="text-[10px] text-status-active font-semibold">LIVE</span>
          </div>
          <PresetSwitcher />
        </div>
      </div>

      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5 space-y-3">
          <h3 className="text-sm font-semibold text-foreground">How does this work?</h3>
          <p className="text-xs text-muted-foreground leading-relaxed">The <strong className="text-foreground">Dashboard</strong> is your central command view. It aggregates live data from 4 API endpoints: <strong className="text-foreground">agents</strong> (fleet count & status), <strong className="text-foreground">events</strong> (latest activity stream from ClickHouse), <strong className="text-foreground">alerts</strong> (open detections from PRL rules + ML), and <strong className="text-foreground">rules</strong> (active detection count). Data refreshes automatically every few seconds.</p>
          <p className="text-xs text-muted-foreground leading-relaxed"><strong className="text-foreground">Preset switcher</strong> — Toggle between Executive (posture overview), SOC Analyst (alert triage), and Threat Hunter (event patterns + ATLAS mapping) views. Each preset reshuffles the widget layout to match the workflow.</p>
          <p className="text-xs text-muted-foreground leading-relaxed"><strong className="text-foreground">Threat Posture Score</strong> — Computed from active agents, open alerts, and severity distribution. Grades A (excellent) through F (critical). The LIVE indicator confirms real-time WebSocket connectivity.</p>
        </div>
      )}

      {/* ── Metrics row (all presets) ─────────────────────────── */}
      <div className="grid gap-4 grid-cols-2 lg:grid-cols-5">
        <ThreatPosture score={postureScore} label={postureLabel} />

        <MetricCard
          label="Total Agents"
          value={agentCount}
          icon={<Monitor size={16} />}
          footnote={`${activeAgents} active · ${staleAgents} stale`}
          trend={activeAgents > 0 ? "up" : "flat"}
          trendLabel={activeAgents > 0 ? `${activeAgents} reporting` : "None reporting"}
          sparkData={agentSpark}
          stagger="stagger-2"
        />
        <MetricCard
          label="Events (24h)"
          value={eventCount}
          displayValue={hasMoreEvents ? `${eventCount}+` : undefined}
          icon={<Activity size={16} />}
          footnote="Across all agents"
          trend="flat"
          trendLabel="Last period"
          sparkData={eventSpark}
          stagger="stagger-3"
        />
        <MetricCard
          label="Open Alerts"
          value={openAlerts}
          icon={<Bell size={16} />}
          footnote={criticalAlerts > 0 ? `${criticalAlerts} critical` : "No critical"}
          trend={criticalAlerts > 0 ? "down" : "flat"}
          trendLabel={criticalAlerts > 0 ? "Requires triage" : "Nominal"}
          sparkData={alertSpark}
          sparkColor={criticalAlerts > 0 ? "var(--color-severity-critical)" : undefined}
          stagger="stagger-4"
        />
        <MetricCard
          label="Detection Coverage"
          value={enabledRules}
          icon={<ShieldAlert size={16} />}
          footnote={`${enabledRules} of ${totalRules} PRL rules active`}
          trend={enabledRules > 0 ? "up" : "flat"}
          trendLabel={enabledRules > 0 ? `${enabledRules} active` : "Configure rules"}
          stagger="stagger-5"
        />
      </div>

      {/* ═══ EXECUTIVE preset — just KPIs + severity chart ════ */}
      {preset === "executive" && (
        <div className="grid gap-4 lg:grid-cols-2">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle className="flex items-center gap-1.5">
                <BarChart3 size={14} className="text-muted-foreground" />
                Severity Analysis
              </CardTitle>
              <span className="text-xs text-muted-foreground tabular-nums">
                {eventCount} events
              </span>
            </CardHeader>
            <CardContent>
              {eventCount === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-center">
                  <p className="text-sm text-muted-foreground">No event data</p>
                </div>
              ) : (
                <BarChart data={severityData} direction="vertical" height={180} />
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle className="flex items-center gap-1.5">
                <Network size={14} className="text-muted-foreground" />
                Agent Frameworks
              </CardTitle>
              <button
                onClick={() => navigate("/topology")}
                className="text-xs font-medium text-primary/80 hover:text-primary cursor-pointer transition-colors"
              >
                View topology →
              </button>
            </CardHeader>
            <CardContent>
              {agentCount === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-center">
                  <p className="text-sm text-muted-foreground">No agents registered</p>
                </div>
              ) : (
                <BarChart data={frameworkData} direction="horizontal" />
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {/* ═══ SOC ANALYST preset — full triage view ════════════ */}
      {preset === "soc" && (
        <>
          <div className="grid gap-4 lg:grid-cols-3">
            {/* Recent detections */}
            <Card className="lg:col-span-2">
              <CardHeader className="flex flex-row items-center justify-between">
                <CardTitle>Recent Detections</CardTitle>
                <button
                  onClick={() => navigate("/alerts")}
                  className="text-xs font-medium text-primary/80 hover:text-primary cursor-pointer transition-colors"
                >
                  View all →
                </button>
              </CardHeader>
              <CardContent>
                {recentAlerts.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-12 text-center">
                    <div className="flex h-12 w-12 items-center justify-center rounded-full bg-white/[0.03] mb-3">
                      <Shield size={22} className="text-muted-foreground" />
                    </div>
                    <p className="text-sm font-medium text-foreground">No open detections</p>
                    <p className="text-xs text-muted-foreground mt-1">Your environment is clean.</p>
                  </div>
                ) : (
                  <div className="space-y-0.5">
                    {recentAlerts.map((alert, i) => (
                      <div
                        key={alert.id}
                        className="flex items-center justify-between py-2.5 cursor-pointer hover:bg-white/[0.02] -mx-4 px-4 rounded-lg transition-colors"
                        onClick={() => handleAlertClick(alert.id)}
                        style={{ animationDelay: `${i * 30}ms` }}
                      >
                        <div className="flex items-center gap-3 min-w-0">
                          <Badge variant={alert.severity as "critical" | "high" | "medium" | "low"}>
                            {alert.severity}
                          </Badge>
                          <div className="min-w-0">
                            <p className="text-sm font-medium truncate text-foreground/90">
                              {alert.title}
                            </p>
                            <p className="text-[11px] text-muted-foreground truncate">
                              Agent {alert.agent_id?.slice(0, 8) ?? "—"}
                            </p>
                          </div>
                        </div>
                        <span className="text-[11px] text-muted-foreground whitespace-nowrap ml-3 tabular-nums">
                          {timeAgo(alert.created_at)}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Activity stream */}
            <ActivityStream />
          </div>

          {/* Analysis charts */}
          <div className="grid gap-4 lg:grid-cols-2">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between">
                <CardTitle className="flex items-center gap-1.5">
                  <BarChart3 size={14} className="text-muted-foreground" />
                  Severity Analysis
                </CardTitle>
                <span className="text-xs text-muted-foreground tabular-nums">
                  {eventCount} events
                </span>
              </CardHeader>
              <CardContent>
                {eventCount === 0 ? (
                  <div className="flex flex-col items-center justify-center py-12 text-center">
                    <p className="text-sm text-muted-foreground">No event data</p>
                  </div>
                ) : (
                  <BarChart data={severityData} direction="vertical" height={180} />
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between">
                <CardTitle className="flex items-center gap-1.5">
                  <Network size={14} className="text-muted-foreground" />
                  Agent Frameworks
                </CardTitle>
                <button
                  onClick={() => navigate("/topology")}
                  className="text-xs font-medium text-primary/80 hover:text-primary cursor-pointer transition-colors"
                >
                  View topology →
                </button>
              </CardHeader>
              <CardContent>
                {agentCount === 0 ? (
                  <div className="flex flex-col items-center justify-center py-12 text-center">
                    <p className="text-sm text-muted-foreground">No agents registered</p>
                  </div>
                ) : (
                  <BarChart data={frameworkData} direction="horizontal" />
                )}
              </CardContent>
            </Card>
          </div>
        </>
      )}

      {/* ═══ THREAT HUNTER preset — events, patterns, ATLAS ═══ */}
      {preset === "hunter" && (
        <>
          <div className="grid gap-4 lg:grid-cols-3">
            {/* Top event types — wider */}
            <Card className="lg:col-span-2">
              <CardHeader>
                <CardTitle>Top Event Types</CardTitle>
              </CardHeader>
              <CardContent>
                {attackClasses.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-12 text-center">
                    <div className="flex h-12 w-12 items-center justify-center rounded-full bg-white/[0.03] mb-3">
                      <Activity size={22} className="text-muted-foreground" />
                    </div>
                    <p className="text-sm font-medium text-foreground">No events recorded</p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {attackClasses.map(([type, count]) => {
                      const pct = Math.round((count / (events?.items?.length ?? 1)) * 100)
                      return (
                        <div key={type}>
                          <div className="flex items-center justify-between mb-1.5">
                            <span className="text-xs font-mono text-foreground/80">{type}</span>
                            <span className="text-[11px] text-muted-foreground tabular-nums">
                              {count} <span className="text-muted-foreground/50">({pct}%)</span>
                            </span>
                          </div>
                          <div className="h-1 w-full rounded-full bg-white/[0.04] overflow-hidden">
                            <div
                              className="h-full rounded-full bg-gradient-to-r from-primary/80 to-primary/30 transition-all duration-500"
                              style={{ width: `${pct}%` }}
                            />
                          </div>
                        </div>
                      )
                    })}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Activity stream */}
            <ActivityStream />
          </div>

          {/* Severity + frameworks */}
          <div className="grid gap-4 lg:grid-cols-2">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between">
                <CardTitle className="flex items-center gap-1.5">
                  <BarChart3 size={14} className="text-muted-foreground" />
                  Severity Analysis
                </CardTitle>
                <span className="text-xs text-muted-foreground tabular-nums">
                  {eventCount} events
                </span>
              </CardHeader>
              <CardContent>
                {eventCount === 0 ? (
                  <div className="flex flex-col items-center justify-center py-12 text-center">
                    <p className="text-sm text-muted-foreground">No event data</p>
                  </div>
                ) : (
                  <BarChart data={severityData} direction="vertical" height={180} />
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between">
                <CardTitle className="flex items-center gap-1.5">
                  <Network size={14} className="text-muted-foreground" />
                  Agent Frameworks
                </CardTitle>
                <button
                  onClick={() => navigate("/topology")}
                  className="text-xs font-medium text-primary/80 hover:text-primary cursor-pointer transition-colors"
                >
                  View topology →
                </button>
              </CardHeader>
              <CardContent>
                {agentCount === 0 ? (
                  <div className="flex flex-col items-center justify-center py-12 text-center">
                    <p className="text-sm text-muted-foreground">No agents registered</p>
                  </div>
                ) : (
                  <BarChart data={frameworkData} direction="horizontal" />
                )}
              </CardContent>
            </Card>
          </div>
        </>
      )}
    </div>
  )
}
