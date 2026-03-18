// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Threat Landscape page (Block AC · AC3).
 *
 * Attack-class trend  ·  top risky agents table  ·  tool-usage heatmap  ·
 * time-range selector  ·  CSV export.
 */

import { useState, useMemo } from "react"
import { Swords, Monitor, Download, FileText, Flame, HelpCircle } from "lucide-react"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { BarChart } from "@/components/ui/bar-chart"
import type { BarData } from "@/components/ui/bar-chart"
import {
  useAttackTrend,
  useTopAgentsRisk,
  useToolHeatmap,
  downloadCsv,
  downloadPdf,
} from "@/api/analyticsV2"
import type { ValidRange } from "@/api/analyticsV2"

const RANGES: { label: string; value: ValidRange }[] = [
  { label: "24 h", value: "24h" },
  { label: "7 d", value: "7d" },
  { label: "30 d", value: "30d" },
  { label: "90 d", value: "90d" },
]

const CLASS_COLORS: Record<string, string> = {
  "Lateral Movement": "#ef4444",
  "Privilege Escalation": "#f97316",
  "Data Exfiltration": "#eab308",
  "Credential Access": "#8b5cf6",
  "Defense Evasion": "#3b82f6",
  "Initial Access": "#10b981",
  "Command and Control": "#06b6d4",
  "Execution": "#ec4899",
}

/* ── Stacked bar chart for attack classes ──────────────── */
function AttackStackedBars({
  data,
}: {
  data: { day: string; attack_class: string; count: number; agents: number }[]
}) {
  const { days, classes, grouped, maxVal } = useMemo(() => {
    const days = [...new Set(data.map(d => d.day))].sort()
    const classes = [...new Set(data.map(d => d.attack_class))]
    const grouped: Record<string, Record<string, number>> = {}
    for (const d of data) {
      if (!grouped[d.day]) grouped[d.day] = {}
      grouped[d.day][d.attack_class] = d.count
    }
    let maxVal = 0
    for (const day of days) {
      const total = classes.reduce((s, c) => s + (grouped[day]?.[c] ?? 0), 0)
      if (total > maxVal) maxVal = total
    }
    return { days, classes, grouped, maxVal: maxVal || 1 }
  }, [data])

  if (days.length === 0) return <p className="text-muted-foreground text-xs py-8 text-center">No attack data</p>

  const W = 700, H = 200, PX = 36, PY = 16
  const barW = Math.min(24, (W - PX * 2) / days.length - 2)

  return (
    <div className="space-y-2">
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ height: H }}>
        {/* grid */}
        {[0, 0.5, 1].map(p => (
          <line key={p} x1={PX} y1={PY + (1 - p) * (H - PY * 2)} x2={W - PX} y2={PY + (1 - p) * (H - PY * 2)} stroke="rgba(255,255,255,0.04)" />
        ))}
        {[0, 0.5, 1].map(p => (
          <text key={p} x={PX - 4} y={PY + (1 - p) * (H - PY * 2) + 3} textAnchor="end" fontSize="9" fill="#555">{Math.round(p * maxVal)}</text>
        ))}

        {days.map((day, di) => {
          const cx = PX + ((di + 0.5) / days.length) * (W - PX * 2)
          let yAcc = 0
          return (
            <g key={day}>
              {classes.map(cls => {
                const val = grouped[day]?.[cls] ?? 0
                const h = (val / maxVal) * (H - PY * 2)
                const rect = (
                  <rect
                    key={cls}
                    x={cx - barW / 2}
                    y={H - PY - yAcc - h}
                    width={barW}
                    height={Math.max(h, 0)}
                    rx={2}
                    fill={CLASS_COLORS[cls] ?? "#666"}
                    opacity={0.7}
                  />
                )
                yAcc += h
                return rect
              })}
              {/* x-label every ~4 bars */}
              {(di % Math.max(1, Math.floor(days.length / 8)) === 0) && (
                <text x={cx} y={H - 2} textAnchor="middle" fontSize="8" fill="#555">{day.slice(5)}</text>
              )}
            </g>
          )
        })}
      </svg>

      {/* Legend */}
      <div className="flex flex-wrap gap-x-4 gap-y-1 px-2">
        {classes.map(c => (
          <span key={c} className="inline-flex items-center gap-1 text-xs text-muted-foreground">
            <span className="w-2 h-2 rounded-sm" style={{ background: CLASS_COLORS[c] ?? "#666" }} />
            {c}
          </span>
        ))}
      </div>
    </div>
  )
}

/* ── Heatmap grid for tool usage ─────────────────────────── */
function ToolHeatmapGrid({
  data,
}: {
  data: { tool: string; hour: string; calls: number; duration_ms: number }[]
}) {
  const { tools, hours, lookup, maxCalls } = useMemo(() => {
    const tools = [...new Set(data.map(d => d.tool))]
    const hours = [...new Set(data.map(d => d.hour))].sort()
    const lookup = new Map(data.map(d => [`${d.tool}|${d.hour}`, d.calls]))
    const maxCalls = Math.max(...data.map(d => d.calls), 1)
    return { tools, hours, lookup, maxCalls }
  }, [data])

  if (tools.length === 0) return <p className="text-muted-foreground text-xs py-8 text-center">No tool usage data</p>

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr>
            <th className="text-left font-medium text-muted-foreground pr-4 pb-1 w-32">Tool</th>
            {hours.map(h => (
              <th key={h} className="font-normal text-muted-foreground/50 px-0.5 pb-1 text-center w-6" title={h}>
                {h.slice(11, 13)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {tools.map(tool => (
            <tr key={tool}>
              <td className="text-muted-foreground pr-4 py-0.5 truncate max-w-[120px]" title={tool}>{tool}</td>
              {hours.map(h => {
                const v = lookup.get(`${tool}|${h}`) ?? 0
                const intensity = v / maxCalls
                return (
                  <td key={h} className="px-0.5 py-0.5">
                    <div
                      className="w-5 h-5 rounded-sm mx-auto"
                      style={{
                        background: v === 0
                          ? "rgba(255,255,255,0.02)"
                          : `rgba(59, 130, 246, ${0.15 + intensity * 0.75})`,
                      }}
                      title={`${tool} @ ${h}: ${v} calls`}
                    />
                  </td>
                )
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/* ── Page component ──────────────────────────────────────── */
export function ThreatLandscapePage() {
  const [range, setRange] = useState<ValidRange>("7d")
  const [showGuide, setShowGuide] = useState(false)
  const attack = useAttackTrend(range)
  const agents = useTopAgentsRisk(range)
  const heatmap = useToolHeatmap(range)

  const riskBars: BarData[] = useMemo(
    () => (agents.data ?? []).slice(0, 10).map(a => ({
      label: (a.agent_id || '(unknown)').slice(0, 12),
      value: a.critical * 4 + a.high * 3 + a.medium * 2 + a.low,
      color: a.critical > 0 ? "#ef4444" : a.high > 0 ? "#f97316" : "#10b981",
    })),
    [agents.data],
  )

  return (
    <div className="space-y-6">
      {/* ── Header ──────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Threat Landscape</h1>
          <p className="text-muted-foreground text-sm mt-0.5">Attack patterns, risky agents &amp; tool activity</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => setShowGuide(!showGuide)} className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"><HelpCircle size={14} />{showGuide ? "Hide Guide" : "How does this work?"}</button>
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
          <button
            onClick={() => downloadCsv("attack_trend", range)}
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

      {/* ── Attack class trend ──────────────────── */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Swords size={14} /> Attack Class Trend
          </CardTitle>
        </CardHeader>
        <CardContent>
          {attack.isLoading ? (
            <div className="h-[200px] animate-pulse rounded bg-muted/10" />
          ) : (
            <AttackStackedBars data={attack.data ?? []} />
          )}
        </CardContent>
      </Card>

      {/* ── Second row: agents + heatmap ──────── */}
      <div className="grid lg:grid-cols-2 gap-4">
        {/* Top risky agents */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Monitor size={14} /> Top Agents by Risk
            </CardTitle>
          </CardHeader>
          <CardContent>
            {agents.isLoading ? (
              <div className="h-[260px] animate-pulse rounded bg-muted/10" />
            ) : (agents.data ?? []).length === 0 ? (
              <p className="text-muted-foreground text-xs py-8 text-center">No agent risk data</p>
            ) : (
              <div className="space-y-4">
                <BarChart data={riskBars} height={220} />
                {/* Detail table */}
                <div className="max-h-48 overflow-y-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="text-muted-foreground border-b border-border/30">
                        <th className="text-left font-medium py-1">Agent</th>
                        <th className="text-right font-medium py-1">Events</th>
                        <th className="text-right font-medium py-1">Crit</th>
                        <th className="text-right font-medium py-1">High</th>
                        <th className="text-right font-medium py-1">Med</th>
                        <th className="text-right font-medium py-1">Low</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(agents.data ?? []).slice(0, 10).map(a => (
                        <tr key={a.agent_id} className="border-b border-border/10 hover:bg-muted/5">
                          <td className="py-1 font-mono">{(a.agent_id || '(unknown)').slice(0, 16)}</td>
                          <td className="py-1 text-right tabular-nums">{a.total_events}</td>
                          <td className="py-1 text-right tabular-nums text-severity-critical">{a.critical}</td>
                          <td className="py-1 text-right tabular-nums text-orange-400">{a.high}</td>
                          <td className="py-1 text-right tabular-nums text-yellow-400">{a.medium}</td>
                          <td className="py-1 text-right tabular-nums text-emerald-400">{a.low}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Tool heatmap */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Flame size={14} /> Tool Usage Heatmap
            </CardTitle>
          </CardHeader>
          <CardContent>
            {heatmap.isLoading ? (
              <div className="h-[260px] animate-pulse rounded bg-muted/10" />
            ) : (
              <ToolHeatmapGrid data={heatmap.data ?? []} />
            )}
          </CardContent>
        </Card>
      </div>

      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5 space-y-3 text-sm text-muted-foreground">
          <h3 className="text-base font-semibold text-foreground">How does the Threat Landscape work?</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Attack Patterns</p>
              <p>Analyzes MITRE ATLAS technique usage from <code className="text-xs bg-white/5 px-1 rounded">/api/analytics/landscape</code>. Shows top attack techniques, frequency trends, and technique categories. Time range filters from 24h to 90d.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Risky Agents</p>
              <p>Ranks agents by cumulative risk score — combining alert severity, event anomalies, and trust graph deviations. High-risk agents surface first with drill-down links to investigation pages.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Tool Heatmap</p>
              <p>The tool activity heatmap cross-references tool invocations against agents and time. Hot cells indicate concentrated tool usage — potential indicators of automated attacks or tool abuse patterns.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Export</p>
              <p>Download landscape data as CSV for offline analysis or generate PDF threat reports for stakeholders. Reports include all visible charts, risk rankings, and trend summaries for the selected range.</p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default ThreatLandscapePage
