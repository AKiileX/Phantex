// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — FinOps & Cost Monitoring Dashboard.
 *
 * Shows cost summary, per-agent breakdown, model costs, spend trend,
 * budget status gauges, projected spend, and cost anomalies.
 */

import { useState } from "react"
import {
  DollarSign,
  TrendingUp,
  Zap,
  Users,
  AlertTriangle,
  Loader2,
  RefreshCw,
  ShieldAlert,
  Cpu,
  Target,
  Download,
  FileText,
  HelpCircle,
} from "lucide-react"
import {
  useCostSummary,
  useCostByAgent,
  useCostByModel,
  useCostTrend,
  useCostProjection,
  useCostAnomalies,
  useRunAnomalyScan,
  useBudgetStatus,
  downloadFinopsCsv,
  downloadFinopsPdf,
  type AgentCost,
  type ModelCost,
  type CostTrendPoint,
  type CostAnomaly,
  type BudgetStatus,
} from "@/api/finops"

/* ── Range selector ─────────────────────────────────────── */

const RANGES = ["1h", "6h", "24h", "7d", "30d", "90d"] as const

function RangeSelector({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <div className="flex gap-1">
      {RANGES.map((r) => (
        <button
          key={r}
          onClick={() => onChange(r)}
          className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${
            value === r
              ? "bg-primary text-primary-foreground"
              : "bg-zinc-800 text-zinc-400 hover:bg-zinc-700"
          }`}
        >
          {r}
        </button>
      ))}
    </div>
  )
}

/* ── Stat card ──────────────────────────────────────────── */

function StatCard({
  label,
  value,
  icon,
  detail,
}: {
  label: string
  value: string
  icon: React.ReactNode
  detail?: string
}) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
      <div className="flex items-center gap-2 text-xs text-zinc-400">
        {icon}
        {label}
      </div>
      <p className="mt-2 text-2xl font-bold text-zinc-100">{value}</p>
      {detail && <p className="mt-1 text-xs text-zinc-500">{detail}</p>}
    </div>
  )
}

/* ── Severity badge ─────────────────────────────────────── */

const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-red-500/20 text-red-300 border-red-500/30",
  high: "bg-orange-500/20 text-orange-300 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-300 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-300 border-blue-500/30",
}

function SeverityBadge({ level }: { level: string }) {
  return (
    <span
      className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium uppercase ${
        SEVERITY_STYLES[level] ?? "bg-zinc-700 text-zinc-300 border-zinc-600"
      }`}
    >
      {level}
    </span>
  )
}

/* ── Budget gauge ───────────────────────────────────────── */

function BudgetGauge({ budget }: { budget: BudgetStatus }) {
  const pct = Math.min(budget.pct_used, 100)
  const color =
    pct >= 100 ? "bg-red-500" : pct >= 90 ? "bg-orange-500" : pct >= 80 ? "bg-yellow-500" : "bg-emerald-500"

  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-3">
      <div className="flex items-center justify-between text-xs">
        <span className="text-zinc-400 capitalize">{budget.scope}: {budget.scope_id.slice(0, 8)}</span>
        <span className="font-mono text-zinc-300">${budget.spent_usd.toFixed(2)} / ${budget.budget_usd.toFixed(2)}</span>
      </div>
      <div className="mt-2 h-2 rounded-full bg-zinc-800">
        <div className={`h-full rounded-full transition-all ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <div className="mt-1 flex items-center justify-between text-[10px] text-zinc-500">
        <span>{budget.pct_used.toFixed(1)}% used</span>
        {budget.capped && <span className="font-medium text-red-400">HARD CAP</span>}
      </div>
    </div>
  )
}

/* ── Sparkline (simple SVG) ─────────────────────────────── */

function Sparkline({ data }: { data: CostTrendPoint[] }) {
  if (!data.length) return <div className="h-32 text-center text-xs text-zinc-500 pt-12">No trend data</div>

  const costs = data.map((d) => d.cost_usd)
  const max = Math.max(...costs, 0.001)
  const w = 500
  const h = 120
  const step = w / Math.max(costs.length - 1, 1)

  const points = costs.map((c, i) => `${i * step},${h - (c / max) * (h - 10)}`).join(" ")

  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="w-full h-32" preserveAspectRatio="none">
      <polyline fill="none" stroke="rgb(59 130 246)" strokeWidth="2" points={points} />
      <polyline
        fill="url(#sparkFill)"
        stroke="none"
        points={`0,${h} ${points} ${(costs.length - 1) * step},${h}`}
      />
      <defs>
        <linearGradient id="sparkFill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="rgb(59 130 246)" stopOpacity="0.3" />
          <stop offset="100%" stopColor="rgb(59 130 246)" stopOpacity="0" />
        </linearGradient>
      </defs>
    </svg>
  )
}

/* ── Main ────────────────────────────────────────────────── */

export function FinOpsPage() {
  const [range, setRange] = useState("24h")
  const [showGuide, setShowGuide] = useState(false)

  const summary = useCostSummary(range)
  const byAgent = useCostByAgent(range)
  const byModel = useCostByModel(range)
  const trend = useCostTrend(range)
  const projection = useCostProjection()
  const anomalies = useCostAnomalies()
  const budgetStatus = useBudgetStatus()
  const scanMutation = useRunAnomalyScan()

  const loading = summary.isLoading || byAgent.isLoading

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex flex-col gap-3">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-zinc-100 flex items-center gap-2">
              <DollarSign size={24} />
              FinOps & Cost Monitoring
            </h1>
            <p className="mt-1 text-sm text-zinc-400">
              Track LLM token costs per agent, model, and provider
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowGuide(!showGuide)}
              className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"
            >
              <HelpCircle size={14} />
              {showGuide ? "Hide Guide" : "How does this work?"}
            </button>
            <button
              onClick={() => downloadFinopsCsv("summary", range)}
              className="inline-flex items-center gap-1 rounded-md border border-zinc-700 bg-zinc-800 px-2.5 py-1.5 text-xs font-medium text-zinc-300 hover:bg-zinc-700"
            >
              <Download size={12} /> CSV
            </button>
            <button
              onClick={() => downloadFinopsPdf(range)}
              className="inline-flex items-center gap-1 rounded-md border border-zinc-700 bg-zinc-800 px-2.5 py-1.5 text-xs font-medium text-zinc-300 hover:bg-zinc-700"
            >
              <FileText size={12} /> PDF
            </button>
            <RangeSelector value={range} onChange={setRange} />
          </div>
        </div>

        {showGuide && (
          <div className="space-y-4">
            <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
              <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
                <DollarSign size={16} className="text-emerald-400" />
                What is FinOps?
              </h3>
              <p className="mt-1.5 text-xs text-muted-foreground leading-relaxed">
                <strong className="text-foreground">FinOps</strong> tracks the cost of every LLM inference call across your AI agents. See total spend, per-agent breakdown, model-level costs, budget status, and anomaly detection — all in one dashboard.
              </p>
            </div>
            <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
              <h3 className="text-sm font-semibold text-foreground">Understanding the Dashboard</h3>
              <div className="mt-2 space-y-1 text-xs text-muted-foreground">
                <p><strong className="text-foreground">Cost Summary</strong> — Total tokens, spend, and average cost per call for the selected time range.</p>
                <p><strong className="text-foreground">By Agent / By Model</strong> — See which agents or models consume the most budget.</p>
                <p><strong className="text-foreground">Budget & Projection</strong> — Visual gauges showing spend vs budget, plus projected end-of-month spend.</p>
                <p><strong className="text-foreground">Anomaly Scan</strong> — Automatically detects unusual cost spikes and alerts you.</p>
              </div>
            </div>
          </div>
        )}
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-24">
          <Loader2 className="h-6 w-6 animate-spin text-zinc-500" />
        </div>
      ) : (
        <>
          {/* KPI Cards */}
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <StatCard
              label="Total Spend"
              value={`$${(summary.data?.total_cost_usd ?? 0).toFixed(4)}`}
              icon={<DollarSign size={14} />}
              detail={`${range} window`}
            />
            <StatCard
              label="Total Tokens"
              value={(summary.data?.total_tokens ?? 0).toLocaleString()}
              icon={<Zap size={14} />}
            />
            <StatCard
              label="Requests"
              value={(summary.data?.total_requests ?? 0).toLocaleString()}
              icon={<TrendingUp size={14} />}
            />
            <StatCard
              label="Active Agents"
              value={String(summary.data?.unique_agents ?? 0)}
              icon={<Users size={14} />}
            />
          </div>

          {/* Trend + Projection */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <div className="lg:col-span-2 rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
              <h2 className="text-sm font-medium text-zinc-300 mb-2">Cost Trend</h2>
              <Sparkline data={trend.data ?? []} />
            </div>
            <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
              <h2 className="text-sm font-medium text-zinc-300 mb-4">Projected Spend</h2>
              <div className="space-y-3">
                <div>
                  <p className="text-xs text-zinc-500">Last 7 Days</p>
                  <p className="text-xl font-bold text-zinc-100">${(projection.data?.last_7d_usd ?? 0).toFixed(2)}</p>
                </div>
                <div>
                  <p className="text-xs text-zinc-500">Projected Monthly</p>
                  <p className="text-xl font-bold text-emerald-400">${(projection.data?.projected_monthly_usd ?? 0).toFixed(2)}</p>
                </div>
              </div>
            </div>
          </div>

          {/* Per-Agent + Per-Model */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            {/* Top Agents */}
            <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
              <h2 className="text-sm font-medium text-zinc-300 mb-3 flex items-center gap-2">
                <Cpu size={14} /> Cost by Agent
              </h2>
              <div className="space-y-1 max-h-64 overflow-y-auto">
                {(byAgent.data ?? []).length === 0 && (
                  <p className="text-xs text-zinc-500 text-center py-4">No agent cost data</p>
                )}
                {(byAgent.data ?? []).map((a: AgentCost) => (
                  <div key={a.agent_id} className="flex items-center justify-between rounded-md px-2 py-1.5 hover:bg-zinc-800/50 text-xs">
                    <span className="font-mono text-zinc-300 truncate max-w-[180px]" title={a.agent_id}>{a.agent_id.slice(0, 12)}…</span>
                    <div className="flex items-center gap-4 text-zinc-400">
                      <span>{a.total_tokens.toLocaleString()} tok</span>
                      <span className="font-medium text-zinc-200">${a.cost_usd.toFixed(4)}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Models */}
            <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
              <h2 className="text-sm font-medium text-zinc-300 mb-3 flex items-center gap-2">
                <Target size={14} /> Cost by Model
              </h2>
              <div className="space-y-1 max-h-64 overflow-y-auto">
                {(byModel.data ?? []).length === 0 && (
                  <p className="text-xs text-zinc-500 text-center py-4">No model cost data</p>
                )}
                {(byModel.data ?? []).map((m: ModelCost, i: number) => (
                  <div key={`${m.provider}-${m.model}-${i}`} className="flex items-center justify-between rounded-md px-2 py-1.5 hover:bg-zinc-800/50 text-xs">
                    <div>
                      <span className="text-zinc-300">{m.model}</span>
                      <span className="ml-2 text-zinc-500">({m.provider})</span>
                    </div>
                    <div className="flex items-center gap-4 text-zinc-400">
                      <span>{m.requests.toLocaleString()} req</span>
                      <span className="font-medium text-zinc-200">${m.cost_usd.toFixed(4)}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Budget Gauges */}
          {(budgetStatus.data ?? []).length > 0 && (
            <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
              <h2 className="text-sm font-medium text-zinc-300 mb-3">Budget Status</h2>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
                {(budgetStatus.data ?? []).map((b: BudgetStatus) => (
                  <BudgetGauge key={b.id} budget={b} />
                ))}
              </div>
            </div>
          )}

          {/* Anomalies */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-medium text-zinc-300 flex items-center gap-2">
                <AlertTriangle size={14} /> Cost Anomalies (24h)
              </h2>
              <button
                onClick={() => scanMutation.mutate()}
                disabled={scanMutation.isPending}
                className="flex items-center gap-1.5 rounded-md bg-zinc-800 px-3 py-1.5 text-xs font-medium text-zinc-300 hover:bg-zinc-700 disabled:opacity-50"
              >
                {scanMutation.isPending ? <Loader2 size={12} className="animate-spin" /> : <RefreshCw size={12} />}
                Run Scan
              </button>
            </div>
            <div className="space-y-1 max-h-64 overflow-y-auto">
              {(anomalies.data ?? []).length === 0 && (
                <p className="text-xs text-zinc-500 text-center py-4">No anomalies detected</p>
              )}
              {(anomalies.data ?? []).map((a: CostAnomaly, i: number) => (
                <div key={`${a.agent_id}-${a.timestamp}-${i}`} className="flex items-center justify-between rounded-md px-2 py-2 hover:bg-zinc-800/50 text-xs">
                  <div className="flex items-center gap-2">
                    <SeverityBadge level={a.severity} />
                    <span className="text-zinc-300 capitalize">{a.anomaly_type.replace("_", " ")}</span>
                    {a.correlated_alert_id && (
                      <span className="text-red-400 flex items-center gap-1">
                        <ShieldAlert size={11} /> security correlated
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-3 text-zinc-400">
                    <span>${a.cost_usd.toFixed(4)}</span>
                    <span>{a.deviation_factor.toFixed(1)}× baseline</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  )
}

export default FinOpsPage
