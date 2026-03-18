// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Executive Analytics Overview (Block AC · AC3).
 *
 * KPI cards  ·  severity trend area chart  ·  framework breakdown bar chart
 * data-volume sparkline  ·  time-range selector  ·  PDF/CSV export buttons.
 */

import { useState, useMemo } from "react"
import {
  ShieldAlert,
  Bell,
  Monitor,
  Swords,
  TrendingUp,
  Download,
  FileText,
  HelpCircle,
} from "lucide-react"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Sparkline } from "@/components/ui/sparkline"
import { BarChart } from "@/components/ui/bar-chart"
import type { BarData } from "@/components/ui/bar-chart"
import { AnimatedNumber } from "@/components/ui/animated-number"
import {
  useKpiSummary,
  useSeverityTrend,
  useFrameworkBreakdown,
  useDataVolumeTrend,
  downloadCsv,
  downloadPdf,
} from "@/api/analyticsV2"
import type { ValidRange } from "@/api/analyticsV2"

const RANGES: { label: string; value: ValidRange }[] = [
  { label: "1 h", value: "1h" },
  { label: "6 h", value: "6h" },
  { label: "24 h", value: "24h" },
  { label: "7 d", value: "7d" },
  { label: "30 d", value: "30d" },
  { label: "90 d", value: "90d" },
]

const SEV_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#10b981",
}

/* ── Severity area chart (stacked via SVG) ───────────────── */
function SeverityAreaChart({ data }: { data: { day: string; severity: string; count: number }[] }) {
  const grouped = useMemo(() => {
    const days = [...new Set(data.map(d => d.day))].sort()
    const series: Record<string, number[]> = { critical: [], high: [], medium: [], low: [] }
    for (const day of days) {
      for (const sev of ["critical", "high", "medium", "low"]) {
        const match = data.find(d => d.day === day && d.severity === sev)
        series[sev].push(match?.count ?? 0)
      }
    }
    return { days, series }
  }, [data])

  if (grouped.days.length < 1) return <p className="text-muted-foreground text-xs">Not enough data</p>

  const W = 600, H = 180, PX = 40, PY = 12
  const n = grouped.days.length
  const sevs = ["low", "medium", "high", "critical"]
  // stacked totals per day
  const stacked: number[][] = []
  for (let i = 0; i < n; i++) {
    let acc = 0
    const col: number[] = []
    for (const s of sevs) { acc += grouped.series[s][i]; col.push(acc) }
    stacked.push(col)
  }
  const maxVal = Math.max(...stacked.map(c => c[c.length - 1]), 1)

  const x = (i: number) => PX + (n > 1 ? (i / (n - 1)) : 0.5) * (W - PX * 2)
  const y = (v: number) => PY + (1 - v / maxVal) * (H - PY * 2)

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ height: H }}>
      {/* Grid lines */}
      {[0, 0.25, 0.5, 0.75, 1].map(p => (
        <line key={p} x1={PX} y1={y(p * maxVal)} x2={W - PX} y2={y(p * maxVal)} stroke="rgba(255,255,255,0.04)" />
      ))}
      {/* Y-axis labels */}
      {[0, 0.5, 1].map(p => (
        <text key={p} x={PX - 6} y={y(p * maxVal) + 3} textAnchor="end" fontSize="9" fill="#555">{Math.round(p * maxVal)}</text>
      ))}
      {/* Stacked areas (bottom to top) */}
      {sevs.map((sev, si) => {
        const topPts = Array.from({ length: n }, (_, i) => `${x(i).toFixed(1)},${y(stacked[i][si]).toFixed(1)}`).join(" ")
        const bottomPts = Array.from({ length: n }, (_, i) => {
          const base = si === 0 ? 0 : stacked[i][si - 1]
          return `${x(n - 1 - i).toFixed(1)},${y(base).toFixed(1)}`
        }).join(" ")
        return (
          <polygon key={sev} points={`${topPts} ${bottomPts}`} fill={SEV_COLORS[sev]} opacity={0.55} />
        )
      })}
      {/* X-axis labels (first, mid, last) */}
      {[0, Math.floor(n / 2), n - 1].map(i => (
        <text key={i} x={x(i)} y={H - 1} textAnchor="middle" fontSize="9" fill="#555">{grouped.days[i]?.slice(5)}</text>
      ))}
    </svg>
  )
}

/* ── Page component ──────────────────────────────────────── */
export function AnalyticsOverviewPage() {
  const [range, setRange] = useState<ValidRange>("24h")
  const [showGuide, setShowGuide] = useState(false)
  const kpi = useKpiSummary(range)
  const sevTrend = useSeverityTrend(range === "1h" || range === "6h" || range === "12h" ? "7d" : range)
  const fw = useFrameworkBreakdown(range === "1h" || range === "6h" || range === "12h" ? "30d" : range)
  const vol = useDataVolumeTrend(range)

  const fwBars: BarData[] = useMemo(
    () => (fw.data ?? []).slice(0, 8).map((d) => ({ label: d.framework, value: d.count })),
    [fw.data],
  )

  const volSpark = useMemo(() => (vol.data ?? []).map(d => d.events), [vol.data])

  const kpiCards = useMemo(() => {
    const d = kpi.data
    if (!d) return []
    return [
      { label: "Total Events", value: d.total_events, icon: <TrendingUp size={18} />, color: "text-blue-400" },
      { label: "Alerts", value: d.total_alerts, icon: <Bell size={18} />, color: "text-amber-400" },
      { label: "Active Agents", value: d.active_agents, icon: <Monitor size={18} />, color: "text-emerald-400" },
      { label: "Attack Classes", value: d.attack_classes, icon: <Swords size={18} />, color: "text-purple-400" },
      { label: "Critical", value: d.critical, icon: <ShieldAlert size={18} />, color: "text-severity-critical" },
      { label: "High", value: d.high, icon: <ShieldAlert size={18} />, color: "text-orange-400" },
    ]
  }, [kpi.data])

  return (
    <div className="space-y-6">
      {/* ── Header ──────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Analytics Overview</h1>
          <p className="text-muted-foreground text-sm mt-0.5">Executive KPIs &amp; trend summary</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => setShowGuide(!showGuide)} className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"><HelpCircle size={14} />{showGuide ? "Hide Guide" : "How does this work?"}</button>
          {/* Range selector */}
          <div className="flex gap-1 rounded-lg border border-border/50 bg-card p-0.5">
            {RANGES.map(r => (
              <button
                key={r.value}
                onClick={() => setRange(r.value)}
                className={`px-2.5 py-1 text-xs rounded-md transition-colors ${range === r.value ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:text-foreground"}`}
              >
                {r.label}
              </button>
            ))}
          </div>

          {/* Export buttons */}
          <button
            onClick={() => downloadCsv("kpi", range)}
            className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs rounded-md border border-border/50 bg-card text-muted-foreground hover:text-foreground transition-colors"
          >
            <Download size={12} /> CSV
          </button>
          <button
            onClick={() => downloadPdf(range)}
            className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs rounded-md border border-border/50 bg-card text-muted-foreground hover:text-foreground transition-colors"
          >
            <FileText size={12} /> PDF
          </button>
        </div>
      </div>

      {/* ── KPI cards ──────────────────────────── */}
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
        {kpi.isLoading ? (
          Array.from({ length: 6 }).map((_, i) => (
            <Card key={i} className="animate-pulse h-24" />
          ))
        ) : (
          kpiCards.map(c => (
            <Card key={c.label} className="relative overflow-hidden">
              <CardContent className="p-4">
                <div className="flex items-center gap-2 text-xs text-muted-foreground mb-1">
                  <span className={c.color}>{c.icon}</span> {c.label}
                </div>
                <span className="text-2xl font-bold tabular-nums">
                  <AnimatedNumber value={c.value} />
                </span>
              </CardContent>
            </Card>
          ))
        )}
      </div>

      {/* ── Severity breakdown badges ──────────── */}
      {kpi.data && (
        <div className="flex gap-2 flex-wrap">
          {(["critical", "high", "medium", "low"] as const).map(s => (
            <Badge key={s} variant="outline" className="gap-1.5 px-2.5 py-1">
              <span className="w-2 h-2 rounded-full" style={{ background: SEV_COLORS[s] }} />
              <span className="capitalize">{s}</span>
              <span className="font-mono text-xs">{kpi.data?.[s] ?? 0}</span>
            </Badge>
          ))}
        </div>
      )}

      {/* ── Charts row ──────────────────────────── */}
      <div className="grid lg:grid-cols-3 gap-4">
        {/* Severity trend */}
        <Card className="lg:col-span-2">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Severity Trend</CardTitle>
          </CardHeader>
          <CardContent>
            {sevTrend.isLoading ? (
              <div className="h-[180px] animate-pulse rounded bg-muted/10" />
            ) : (
              <SeverityAreaChart data={sevTrend.data ?? []} />
            )}
          </CardContent>
        </Card>

        {/* Data Volume sparkline */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Data Volume</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col items-center justify-center gap-3 pt-4">
            {vol.isLoading ? (
              <div className="h-16 w-full animate-pulse rounded bg-muted/10" />
            ) : (
              <>
                <Sparkline data={volSpark} width={220} height={60} color="#3b82f6" />
                <span className="text-xs text-muted-foreground">
                  {volSpark.reduce((a, b) => a + b, 0).toLocaleString()} events in period
                </span>
              </>
            )}
          </CardContent>
        </Card>
      </div>

      {/* ── Framework breakdown ─────────────────── */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">MITRE Framework Breakdown</CardTitle>
        </CardHeader>
        <CardContent>
          {fw.isLoading ? (
            <div className="h-[200px] animate-pulse rounded bg-muted/10" />
          ) : fwBars.length === 0 ? (
            <p className="text-muted-foreground text-xs py-8 text-center">No framework data available</p>
          ) : (
            <BarChart data={fwBars} height={220} />
          )}
        </CardContent>
      </Card>

      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5 space-y-3 text-sm text-muted-foreground">
          <h3 className="text-base font-semibold text-foreground">How does Analytics Overview work?</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Executive KPIs</p>
              <p>Pulls alert counts, event volumes, active agent counts, and MITRE technique coverage from <code className="text-xs bg-white/5 px-1 rounded">/api/analytics/kpi</code> for the selected time range. Summary cards show deltas from the previous period.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Trend Charts</p>
              <p>Time-series data from <code className="text-xs bg-white/5 px-1 rounded">/api/analytics/trends</code> powers the alert trend, event volume, and agent activity sparklines. Uses ClickHouse for fast aggregation across millions of events.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Compliance Frameworks</p>
              <p>The framework bar chart shows compliance scores per framework from <code className="text-xs bg-white/5 px-1 rounded">/api/analytics/frameworks</code>. Scores are calculated based on control pass rates across EU AI Act, NIST AI RMF, and custom frameworks.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Export</p>
              <p>Download KPI data as CSV or generate a PDF executive report for the selected time range. Reports include all visible metrics, trend summaries, and compliance scores — ready for stakeholder sharing.</p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default AnalyticsOverviewPage
