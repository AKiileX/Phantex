// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Operational Metrics page (Block AC · AC3).
 *
 * Drill-down query builder  ·  data-volume trend  ·  CSV/PDF export buttons.
 */

import { useState, useMemo } from "react"
import {
  Download,
  FileText,
  BarChart3,
  TrendingUp,
  Filter,
  HelpCircle,
} from "lucide-react"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { Sparkline } from "@/components/ui/sparkline"
import { BarChart } from "@/components/ui/bar-chart"
import type { BarData } from "@/components/ui/bar-chart"
import {
  useDataVolumeTrend,
  useDrillDown,
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

const DIMENSIONS = [
  "severity",
  "attack_class",
  "event_type",
  "agent_id",
  "tool_name",
  "framework",
  "dest_ip",
  "dest_port",
] as const

const METRICS = ["count", "bytes_sent", "bytes_recv", "avg_duration"] as const

const SEVERITIES = ["", "critical", "high", "medium", "low"] as const

/* ── Query Builder ───────────────────────────────────────── */
function DrillDownBuilder({
  range,
  onExport,
}: {
  range: ValidRange
  onExport: (qt: string) => void
}) {
  const [dim1, setDim1] = useState<string>("severity")
  const [dim2, setDim2] = useState<string>("")
  const [metric, setMetric] = useState<string>("count")
  const [severity, setSeverity] = useState<string>("")
  const [attackClass, setAttackClass] = useState<string>("")
  const [limit, setLimit] = useState(20)

  const params = useMemo(
    () => ({
      dimension1: dim1,
      dimension2: dim2 || undefined,
      metric: metric || undefined,
      range,
      limit,
      severity: severity || undefined,
      attack_class: attackClass || undefined,
    }),
    [dim1, dim2, metric, range, limit, severity, attackClass],
  )

  const dd = useDrillDown(params, !!dim1)

  const bars: BarData[] = useMemo(() => {
    const rows = (dd.data as Record<string, unknown>[]) ?? []
    return rows.slice(0, limit).map((r) => ({
      label: String(r[dim1] ?? "unknown").slice(0, 20),
      value: Number(r[metric] ?? r.count ?? 0),
    }))
  }, [dd.data, dim1, metric, limit])

  const selectClass =
    "px-2 py-1.5 text-xs rounded-md border border-border/50 bg-card text-foreground appearance-none cursor-pointer"

  return (
    <div className="space-y-4">
      {/* Controls */}
      <div className="flex flex-wrap items-end gap-3">
        <label className="space-y-1">
          <span className="text-xs text-muted-foreground">Dimension 1</span>
          <select value={dim1} onChange={e => setDim1(e.target.value)} className={selectClass}>
            {DIMENSIONS.map(d => <option key={d} value={d}>{d}</option>)}
          </select>
        </label>

        <label className="space-y-1">
          <span className="text-xs text-muted-foreground">Dimension 2</span>
          <select value={dim2} onChange={e => setDim2(e.target.value)} className={selectClass}>
            <option value="">— none —</option>
            {DIMENSIONS.filter(d => d !== dim1).map(d => <option key={d} value={d}>{d}</option>)}
          </select>
        </label>

        <label className="space-y-1">
          <span className="text-xs text-muted-foreground">Metric</span>
          <select value={metric} onChange={e => setMetric(e.target.value)} className={selectClass}>
            {METRICS.map(m => <option key={m} value={m}>{m}</option>)}
          </select>
        </label>

        <label className="space-y-1">
          <span className="text-xs text-muted-foreground">Severity</span>
          <select value={severity} onChange={e => setSeverity(e.target.value)} className={selectClass}>
            {SEVERITIES.map(s => <option key={s} value={s}>{s || "all"}</option>)}
          </select>
        </label>

        <label className="space-y-1">
          <span className="text-xs text-muted-foreground">Attack Class</span>
          <input
            value={attackClass}
            onChange={e => setAttackClass(e.target.value)}
            placeholder="any"
            className="px-2 py-1.5 text-xs rounded-md border border-border/50 bg-card text-foreground w-32"
          />
        </label>

        <label className="space-y-1">
          <span className="text-xs text-muted-foreground">Limit</span>
          <select value={limit} onChange={e => setLimit(Number(e.target.value))} className={selectClass}>
            {[10, 20, 50, 100].map(n => <option key={n} value={n}>{n}</option>)}
          </select>
        </label>

        <button
          onClick={() => onExport("drill_down")}
          className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs rounded-md border border-border/50 bg-card text-muted-foreground hover:text-foreground transition-colors self-end"
        >
          <Download size={12} /> CSV
        </button>
      </div>

      {/* Results */}
      {dd.isLoading ? (
        <div className="h-[200px] animate-pulse rounded bg-muted/10" />
      ) : bars.length === 0 ? (
        <p className="text-muted-foreground text-xs py-8 text-center">No results — try different dimensions or filters</p>
      ) : (
        <BarChart data={bars} height={260} />
      )}

      {/* Raw data table */}
      {!dd.isLoading && ((dd.data as Record<string, unknown>[]) ?? []).length > 0 && (
        <div className="max-h-64 overflow-auto rounded border border-border/30">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-card">
              <tr className="text-muted-foreground border-b border-border/30">
                <th className="text-left font-medium py-1.5 px-2">{dim1}</th>
                {dim2 && <th className="text-left font-medium py-1.5 px-2">{dim2}</th>}
                <th className="text-right font-medium py-1.5 px-2">{metric}</th>
              </tr>
            </thead>
            <tbody>
              {((dd.data as Record<string, unknown>[]) ?? []).slice(0, limit).map((row: Record<string, unknown>, i: number) => (
                <tr key={i} className="border-b border-border/10 hover:bg-muted/5">
                  <td className="py-1 px-2 font-mono">{String(row[dim1] ?? "").slice(0, 30)}</td>
                  {dim2 && <td className="py-1 px-2 font-mono">{String(row[dim2] ?? "").slice(0, 30)}</td>}
                  <td className="py-1 px-2 text-right tabular-nums">{Number(row[metric] ?? row.count ?? 0).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

/* ── Page component ──────────────────────────────────────── */
export function OperationalMetricsPage() {
  const [range, setRange] = useState<ValidRange>("7d")
  const [showGuide, setShowGuide] = useState(false)
  const vol = useDataVolumeTrend(range)

  const volEvents = useMemo(() => (vol.data ?? []).map(d => d.events), [vol.data])
  const volBytes = useMemo(() => (vol.data ?? []).map(d => d.bytes_sent + d.bytes_recv), [vol.data])

  function formatBytes(b: number): string {
    if (b < 1024) return `${b} B`
    if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`
    if (b < 1024 * 1024 * 1024) return `${(b / 1024 / 1024).toFixed(1)} MB`
    return `${(b / 1024 / 1024 / 1024).toFixed(2)} GB`
  }

  return (
    <div className="space-y-6">
      {/* ── Header ──────────────────────────────── */}
      <div className="flex flex-col gap-3">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Operational Metrics</h1>
            <p className="text-muted-foreground text-sm mt-0.5">Drill-down analytics &amp; data-volume monitoring</p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowGuide(!showGuide)}
              className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"
            >
              <HelpCircle size={14} />
              {showGuide ? "Hide Guide" : "How does this work?"}
            </button>
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
              onClick={() => downloadCsv("data_volume", range)}
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

        {showGuide && (
          <div className="space-y-4">
            <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
              <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
                <BarChart3 size={16} className="text-primary" />
                What are Operational Metrics?
              </h3>
              <p className="mt-1.5 text-xs text-muted-foreground leading-relaxed">
                <strong className="text-foreground">Operational Metrics</strong> gives you a drill-down query builder to slice security data by any dimension (severity, attack class, agent, tool, destination). Combined with data-volume trends, you can monitor throughput, spot anomalies, and export reports.
              </p>
            </div>
            <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
              <h3 className="text-sm font-semibold text-foreground">How to Use</h3>
              <div className="mt-2 space-y-1 text-xs text-muted-foreground">
                <p><strong className="text-foreground">Drill-Down Builder</strong> — Pick a dimension, metric, optional severity filter, and time range to query detailed breakdowns.</p>
                <p><strong className="text-foreground">Data Volume Charts</strong> — Event count and byte volume sparklines show trends over the selected range.</p>
                <p><strong className="text-foreground">CSV / PDF</strong> — Export the current view for compliance reporting or sharing.</p>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* ── Data Volume ────────────────────────── */}
      <div className="grid lg:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <TrendingUp size={14} /> Event Volume
            </CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col items-center gap-2 pt-3">
            {vol.isLoading ? (
              <div className="h-16 w-full animate-pulse rounded bg-muted/10" />
            ) : (
              <>
                <Sparkline data={volEvents} width={280} height={60} color="#3b82f6" />
                <span className="text-xs text-muted-foreground">
                  {volEvents.reduce((a, b) => a + b, 0).toLocaleString()} events
                </span>
              </>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <BarChart3 size={14} /> Bandwidth Volume
            </CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col items-center gap-2 pt-3">
            {vol.isLoading ? (
              <div className="h-16 w-full animate-pulse rounded bg-muted/10" />
            ) : (
              <>
                <Sparkline data={volBytes} width={280} height={60} color="#10b981" />
                <span className="text-xs text-muted-foreground">
                  {formatBytes(volBytes.reduce((a, b) => a + b, 0))} total
                </span>
              </>
            )}
          </CardContent>
        </Card>
      </div>

      {/* ── Drill-down query builder ───────────── */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Filter size={14} /> Drill-Down Explorer
          </CardTitle>
        </CardHeader>
        <CardContent>
          <DrillDownBuilder range={range} onExport={(qt) => downloadCsv(qt, range)} />
        </CardContent>
      </Card>
    </div>
  )
}

export default OperationalMetricsPage
