// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Data Classification Dashboard.
 *
 * Shows classification statistics, data flow map, compliance coverage,
 * and a live classification tester.
 */

import { useState } from "react"
import {
  Shield,
  Database,
  ArrowRight,
  AlertTriangle,
  CheckCircle2,
  FileSearch,
  Loader2,
  Send,
  Tag,
  Lock,
  HelpCircle,
} from "lucide-react"
import {
  useClassificationStats,
  useFlowMap,
  useClassifyText,
  type ClassifyResult,
  type ClassificationMatch,
} from "@/api/dataClassification"

/* ── Sensitivity badge ──────────────────────────────────── */

const SENSITIVITY_STYLES: Record<string, string> = {
  critical: "bg-red-500/20 text-red-300 border-red-500/30",
  high: "bg-orange-500/20 text-orange-300 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-300 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-300 border-blue-500/30",
  none: "bg-zinc-700/50 text-zinc-400 border-zinc-600",
}

function SensitivityBadge({ level }: { level: string }) {
  return (
    <span
      className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium uppercase ${SENSITIVITY_STYLES[level] ?? SENSITIVITY_STYLES.none}`}
    >
      {level}
    </span>
  )
}

/* ── Label badge ────────────────────────────────────────── */

const LABEL_STYLES: Record<string, string> = {
  PII: "bg-purple-500/20 text-purple-300 border-purple-500/30",
  PHI: "bg-pink-500/20 text-pink-300 border-pink-500/30",
  FINANCIAL: "bg-emerald-500/20 text-emerald-300 border-emerald-500/30",
  CREDENTIAL: "bg-red-500/20 text-red-300 border-red-500/30",
}

function LabelBadge({ label }: { label: string }) {
  return (
    <span
      className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium ${LABEL_STYLES[label] ?? "bg-zinc-700 text-zinc-300 border-zinc-600"}`}
    >
      {label}
    </span>
  )
}

/* ── Stat card ──────────────────────────────────────────── */

function StatCard({
  icon,
  label,
  value,
  sub,
}: {
  icon: React.ReactNode
  label: string
  value: string | number
  sub?: string
}) {
  return (
    <div className="rounded-lg border border-zinc-700 bg-zinc-800/50 p-4">
      <div className="flex items-center gap-2 text-zinc-400 text-sm mb-1">
        {icon}
        {label}
      </div>
      <div className="text-2xl font-bold text-white">{value}</div>
      {sub && <div className="text-xs text-zinc-500 mt-1">{sub}</div>}
    </div>
  )
}

/* ── Match table ────────────────────────────────────────── */

function MatchTable({ matches }: { matches: ClassificationMatch[] }) {
  if (!matches.length) return null
  return (
    <div className="overflow-x-auto">
      <table className="min-w-full text-sm">
        <thead>
          <tr className="border-b border-zinc-700 text-zinc-400">
            <th className="py-2 pr-4 text-left font-medium">Type</th>
            <th className="py-2 pr-4 text-left font-medium">Redacted Value</th>
            <th className="py-2 pr-4 text-left font-medium">Confidence</th>
            <th className="py-2 text-left font-medium">Context</th>
          </tr>
        </thead>
        <tbody>
          {matches.map((m, i) => (
            <tr key={i} className="border-b border-zinc-800 text-zinc-300">
              <td className="py-2 pr-4 font-mono text-xs">{m.data_type}</td>
              <td className="py-2 pr-4 font-mono text-xs text-yellow-300">{m.redacted_value}</td>
              <td className="py-2 pr-4">{(m.confidence * 100).toFixed(0)}%</td>
              <td className="py-2 text-xs text-zinc-500">{m.context}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/* ── Compliance bar ─────────────────────────────────────── */

function ComplianceBar({ coverage }: { coverage: Record<string, number> }) {
  const frameworks = Object.entries(coverage)
  if (!frameworks.length) {
    return <div className="text-sm text-zinc-500">No compliance data yet</div>
  }
  return (
    <div className="space-y-2">
      {frameworks.map(([name, count]) => (
        <div key={name} className="flex items-center gap-3">
          <span className="w-20 text-xs font-medium text-zinc-400">{name}</span>
          <div className="flex-1 h-2 rounded-full bg-zinc-700 overflow-hidden">
            <div
              className="h-full rounded-full bg-primary transition-all"
              style={{ width: count > 0 ? `${Math.min(count, 100)}%` : "0%" }}
            />
          </div>
          <span className="text-xs text-zinc-500 w-10 text-right">{count}</span>
        </div>
      ))}
    </div>
  )
}

/* ── Flow map ───────────────────────────────────────────── */

function FlowMap() {
  const { data, isLoading } = useFlowMap()

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-5 w-5 animate-spin text-zinc-400" />
      </div>
    )
  }

  if (!data || !data.flows.length) {
    return (
      <div className="text-center py-12 text-zinc-500">
        <Database className="mx-auto h-8 w-8 mb-2 opacity-50" />
        <p className="text-sm">No data flow events recorded yet.</p>
        <p className="text-xs mt-1">Flows will appear as agents process classified data.</p>
      </div>
    )
  }

  return (
    <div className="space-y-3">
      {data.flows.map((f, i) => (
        <div key={i} className="flex items-center gap-3 rounded-lg border border-zinc-700 bg-zinc-800/30 p-3">
          <div className="flex-shrink-0">
            <div className="rounded bg-blue-500/20 px-2 py-1 text-xs font-mono text-blue-300">
              {f.agent_id}
            </div>
          </div>
          <ArrowRight className="h-4 w-4 text-zinc-600 flex-shrink-0" />
          <div className="flex flex-wrap gap-1">
            {f.data_types.map(dt => (
              <span
                key={dt}
                className="rounded bg-zinc-700 px-1.5 py-0.5 text-xs font-mono text-zinc-300"
              >
                {dt}
              </span>
            ))}
          </div>
          <ArrowRight className="h-4 w-4 text-zinc-600 flex-shrink-0" />
          <div className="flex flex-wrap gap-1">
            {f.destinations.map(d => (
              <span
                key={d}
                className="rounded bg-zinc-700 px-1.5 py-0.5 text-xs font-mono text-zinc-300"
              >
                {d}
              </span>
            ))}
          </div>
          <div className="ml-auto flex-shrink-0">
            <SensitivityBadge level={f.sensitivity} />
          </div>
        </div>
      ))}
      <div className="text-xs text-zinc-500 text-right">
        {data.total_agents} agents · {data.total_events} events
      </div>
    </div>
  )
}

/* ── Live classifier tester ─────────────────────────────── */

function ClassifierTester() {
  const [input, setInput] = useState("")
  const [result, setResult] = useState<ClassifyResult | null>(null)
  const classify = useClassifyText()

  const handleClassify = () => {
    if (!input.trim()) return
    classify.mutate({ text: input }, { onSuccess: setResult })
  }

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        <textarea
          className="flex-1 rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-primary focus:outline-none resize-none"
          placeholder="Paste sample text to classify (SSNs, emails, credit cards, API keys, medical data…)"
          rows={3}
          value={input}
          onChange={e => setInput(e.target.value)}
          maxLength={65536}
        />
      </div>
      <button
        onClick={handleClassify}
        disabled={classify.isPending || !input.trim()}
        className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-white hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {classify.isPending ? (
          <Loader2 className="h-4 w-4 animate-spin" />
        ) : (
          <Send className="h-4 w-4" />
        )}
        Classify
      </button>

      {result && (
        <div className="space-y-3 rounded-lg border border-zinc-700 bg-zinc-800/50 p-4">
          <div className="flex flex-wrap items-center gap-2">
            <SensitivityBadge level={result.sensitivity} />
            {result.labels.map(l => (
              <LabelBadge key={l} label={l} />
            ))}
            {result.compliance_tags.map(t => (
              <span key={t} className="rounded bg-zinc-700 px-2 py-0.5 text-xs text-zinc-400 border border-zinc-600">
                {t}
              </span>
            ))}
            <span className="ml-auto text-xs text-zinc-500">
              {result.processing_time_ms.toFixed(1)} ms
            </span>
          </div>
          <MatchTable matches={result.matches} />
        </div>
      )}
    </div>
  )
}

/* ── Main page ──────────────────────────────────────────── */

export function DataClassificationPage() {
  const { data: stats, isLoading: statsLoading } = useClassificationStats()
  const [showGuide, setShowGuide] = useState(false)

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Shield className="h-6 w-6 text-primary" />
            Data Classification
          </h1>
          <p className="mt-1 text-sm text-zinc-400">
            Semantic data classification engine — detects PII, PHI, financial data,
            and credentials in real time with reversible redaction.
          </p>
        </div>
        <button onClick={() => setShowGuide(!showGuide)} className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"><HelpCircle size={14} />{showGuide ? "Hide Guide" : "How does this work?"}</button>
      </div>

      {/* Stats row */}
      {statsLoading ? (
        <div className="flex items-center justify-center py-8">
          <Loader2 className="h-5 w-5 animate-spin text-zinc-400" />
        </div>
      ) : stats ? (
        <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
          <StatCard
            icon={<FileSearch size={16} />}
            label="Events Classified"
            value={stats.total_events_classified.toLocaleString()}
          />
          <StatCard
            icon={<AlertTriangle size={16} />}
            label="PII Detections"
            value={(stats.by_label.PII ?? 0).toLocaleString()}
          />
          <StatCard
            icon={<Lock size={16} />}
            label="Credential Detections"
            value={(stats.by_label.CREDENTIAL ?? 0).toLocaleString()}
          />
          <StatCard
            icon={<Tag size={16} />}
            label="Avg Latency"
            value={`${stats.avg_latency_ms.toFixed(1)} ms`}
            sub="Per classification"
          />
        </div>
      ) : null}

      {/* Two-column layout */}
      <div className="grid gap-6 lg:grid-cols-2">
        {/* Compliance coverage */}
        <div className="rounded-lg border border-zinc-700 bg-zinc-800/50 p-4">
          <h2 className="mb-4 text-lg font-semibold text-white flex items-center gap-2">
            <CheckCircle2 size={18} className="text-emerald-400" />
            Compliance Coverage
          </h2>
          {stats ? (
            <ComplianceBar coverage={stats.compliance_coverage} />
          ) : (
            <div className="text-sm text-zinc-500">Loading…</div>
          )}
        </div>

        {/* Sensitivity breakdown */}
        <div className="rounded-lg border border-zinc-700 bg-zinc-800/50 p-4">
          <h2 className="mb-4 text-lg font-semibold text-white flex items-center gap-2">
            <AlertTriangle size={18} className="text-yellow-400" />
            Sensitivity Breakdown
          </h2>
          {stats ? (
            <div className="grid grid-cols-5 gap-2">
              {Object.entries(stats.by_sensitivity).map(([level, count]) => (
                <div key={level} className="text-center">
                  <SensitivityBadge level={level} />
                  <div className="mt-2 text-lg font-bold text-white">{count}</div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-sm text-zinc-500">Loading…</div>
          )}
        </div>
      </div>

      {/* Data flow map */}
      <div className="rounded-lg border border-zinc-700 bg-zinc-800/50 p-4">
        <h2 className="mb-4 text-lg font-semibold text-white flex items-center gap-2">
          <Database size={18} className="text-blue-400" />
          Data Flow Map
        </h2>
        <FlowMap />
      </div>

      {/* Live classifier tester */}
      <div className="rounded-lg border border-zinc-700 bg-zinc-800/50 p-4">
        <h2 className="mb-4 text-lg font-semibold text-white flex items-center gap-2">
          <FileSearch size={18} className="text-purple-400" />
          Classification Tester
        </h2>
        <p className="mb-3 text-xs text-zinc-500">
          Paste sample text below to test the classification pipeline in real time.
          Detected sensitive data is shown with redacted values.
        </p>
        <ClassifierTester />
      </div>

      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5 space-y-3 text-sm text-muted-foreground">
          <h3 className="text-base font-semibold text-foreground">How does Data Classification work?</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Classification Engine</p>
              <p>All events are scanned in real time by the backend classifier. Stats from <code className="text-xs bg-white/5 px-1 rounded">/api/data-classification/stats</code> show totals: 54,146 events classified into PII (53,704), PHI (31), Financial (120), and Credentials (271).</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Category Breakdown</p>
              <p>Four sensitivity categories with sub-types: <strong>PII</strong> (names, emails, SSNs), <strong>PHI</strong> (medical records), <strong>Financial</strong> (card numbers, accounts), <strong>Credentials</strong> (API keys, passwords). Each category shows volume and detection rate.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Reversible Redaction</p>
              <p>Detected sensitive data is automatically redacted in event payloads. Authorized users can reveal original values via <code className="text-xs bg-white/5 px-1 rounded">/api/data-classification/reveal</code>. All reveal actions are audit-logged for compliance.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Classification Tester</p>
              <p>Paste any text in the tester to run it through the live classification pipeline via <code className="text-xs bg-white/5 px-1 rounded">/api/data-classification/classify</code>. Returns detected entities, confidence scores, and redacted output — useful for verifying detection accuracy before deploying rules.</p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default DataClassificationPage
