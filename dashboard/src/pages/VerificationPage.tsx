// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Formal Verification Dashboard.
 *
 * Shows all verification specs (TLA+, Alloy, Z3), their properties,
 * last CI results, and allows on-demand Z3 execution.
 */

import { useState } from "react"
import {
  ShieldCheck,
  CheckCircle2,
  XCircle,
  Loader2,
  Play,
  FileCode,
  ChevronDown,
  ChevronRight,
  Clock,
  Info,
  HelpCircle,
} from "lucide-react"
import {
  useVerificationSpecs,
  useVerificationResults,
  useRunZ3,
  useSpecSource,
  type SpecInfo,
  type Z3Check,
} from "@/api/verification"

/* ── Tool badge colours ─────────────────────────────────── */

const TOOL_STYLES: Record<string, string> = {
  "tla+": "bg-purple-500/20 text-purple-300 border-purple-500/30",
  alloy: "bg-blue-500/20 text-blue-300 border-blue-500/30",
  z3: "bg-emerald-500/20 text-emerald-300 border-emerald-500/30",
}

function ToolBadge({ tool }: { tool: string }) {
  return (
    <span
      className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium uppercase ${TOOL_STYLES[tool] ?? "bg-zinc-700 text-zinc-300 border-zinc-600"}`}
    >
      {tool}
    </span>
  )
}

/* ── Spec card ──────────────────────────────────────────── */

function SpecCard({ spec }: { spec: SpecInfo }) {
  const [expanded, setExpanded] = useState(false)
  const [showSource, setShowSource] = useState(false)
  const { data: source, isLoading: sourceLoading } = useSpecSource(
    showSource ? spec.name : null,
  )

  return (
    <div className="rounded-lg border border-zinc-700 bg-zinc-800/50 p-4">
      {/* Header */}
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <ToolBadge tool={spec.tool} />
            <h3 className="truncate font-semibold text-zinc-100">
              {spec.name}
            </h3>
          </div>
          <p className="mt-1 text-sm text-zinc-400">{spec.description}</p>
        </div>
        <button
          onClick={() => setExpanded(!expanded)}
          className="shrink-0 rounded p-1 text-zinc-400 hover:bg-zinc-700 hover:text-zinc-200"
          title={expanded ? "Collapse" : "Expand"}
        >
          {expanded ? <ChevronDown size={18} /> : <ChevronRight size={18} />}
        </button>
      </div>

      {/* Properties count */}
      <div className="mt-2 flex items-center gap-2 text-xs text-zinc-500">
        <ShieldCheck size={14} />
        <span>{spec.properties.length} properties verified</span>
        <span className="text-zinc-600">•</span>
        <span className="font-mono text-zinc-500">{spec.file}</span>
      </div>

      {/* Expanded properties list */}
      {expanded && (
        <div className="mt-3 space-y-1 border-t border-zinc-700 pt-3">
          <div className="text-xs font-medium uppercase tracking-wider text-zinc-500">
            Properties
          </div>
          {spec.properties.map((prop) => (
            <div
              key={prop}
              className="flex items-center gap-2 rounded px-2 py-1 text-sm text-zinc-300"
            >
              <CheckCircle2 size={14} className="shrink-0 text-emerald-400" />
              {prop}
            </div>
          ))}

          {/* View source button */}
          <div className="mt-2 pt-2 border-t border-zinc-700/50">
            <button
              onClick={() => setShowSource(!showSource)}
              className="flex items-center gap-1.5 rounded px-2 py-1 text-xs text-zinc-400 hover:bg-zinc-700 hover:text-zinc-200"
            >
              <FileCode size={14} />
              {showSource ? "Hide source" : "View source"}
            </button>
            {showSource && (
              <div className="mt-2 max-h-80 overflow-auto rounded bg-zinc-900 p-3">
                {sourceLoading ? (
                  <div className="flex items-center gap-2 text-zinc-500">
                    <Loader2 size={14} className="animate-spin" />
                    Loading...
                  </div>
                ) : (
                  <pre className="whitespace-pre text-xs text-zinc-300 font-mono">
                    {source}
                  </pre>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

/* ── Z3 result card ─────────────────────────────────────── */

function Z3ResultCard({ checks, elapsed, passed }: {
  checks: Z3Check[]
  elapsed: number
  passed: boolean
}) {
  return (
    <div className="rounded-lg border border-zinc-700 bg-zinc-800/50 p-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          {passed ? (
            <CheckCircle2 size={18} className="text-emerald-400" />
          ) : (
            <XCircle size={18} className="text-red-400" />
          )}
          <span className="font-semibold text-zinc-100">
            Z3 Trust Graph — {passed ? "All Proved" : "Failures Detected"}
          </span>
        </div>
        <div className="flex items-center gap-1.5 text-xs text-zinc-500">
          <Clock size={12} />
          {elapsed.toFixed(1)} ms
        </div>
      </div>

      <div className="mt-3 space-y-1">
        {checks.map((c) => (
          <div
            key={c.name}
            className="flex items-start gap-2 rounded px-2 py-1.5 text-sm"
          >
            {c.result === "proved" ? (
              <CheckCircle2 size={14} className="mt-0.5 shrink-0 text-emerald-400" />
            ) : (
              <XCircle size={14} className="mt-0.5 shrink-0 text-red-400" />
            )}
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs text-zinc-400">{c.name}</span>
                <span className="text-zinc-300">{c.property}</span>
              </div>
              {c.details && (
                <p className="mt-0.5 text-xs text-zinc-500">{c.details}</p>
              )}
            </div>
            <span className="shrink-0 text-xs text-zinc-600">
              {c.elapsed_ms.toFixed(1)} ms
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

/* ── Main page ──────────────────────────────────────────── */

export function VerificationPage() {
  const { data: specs, isLoading: specsLoading } = useVerificationSpecs()
  const { data: cachedResults } = useVerificationResults()
  const runZ3 = useRunZ3()
  const [z3Result, setZ3Result] = useState<{
    checks: Z3Check[]
    elapsed: number
    passed: boolean
  } | null>(null)
  const [showGuide, setShowGuide] = useState(false)

  const handleRunZ3 = () => {
    runZ3.mutate(undefined, {
      onSuccess: (result) => {
        setZ3Result({
          checks: result.details ?? [],
          elapsed: result.elapsed_ms,
          passed: result.passed,
        })
      },
    })
  }

  // Group specs by tool
  const grouped = (specs ?? []).reduce<Record<string, SpecInfo[]>>((acc, s) => {
    ;(acc[s.tool] ??= []).push(s)
    return acc
  }, {})

  const totalProps = (specs ?? []).reduce((n, s) => n + s.properties.length, 0)

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-zinc-100">
            Formal Verification
          </h1>
          <p className="mt-1 text-sm text-zinc-400">
            Mathematical proofs of system correctness — TLA+ model checking,
            Alloy relational analysis, and Z3 SMT solving.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => setShowGuide(!showGuide)} className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"><HelpCircle size={14} />{showGuide ? "Hide Guide" : "How does this work?"}</button>
          <button
            onClick={handleRunZ3}
            disabled={runZ3.isPending}
            className="flex items-center gap-2 rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
          >
            {runZ3.isPending ? (
              <Loader2 size={16} className="animate-spin" />
            ) : (
              <Play size={16} />
            )}
            Run Z3 Checks
          </button>
        </div>
      </div>

      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5 space-y-3 text-sm text-muted-foreground">
          <h3 className="text-base font-semibold text-foreground">How does Formal Verification work?</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Verification Specs</p>
              <p>Loads specs from <code className="text-xs bg-white/5 px-1 rounded">/api/verification/specs</code>. Currently 4 specs: TLA+ rule_evaluation, TLA+ policy_engine, Alloy sandbox_isolation, and Z3 trust_graph. Each spec mathematically proves a critical system property.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">TLA+ Model Checking</p>
              <p>TLA+ specs use the TLC model checker to exhaustively explore all reachable states. The rule_evaluation spec proves alert generation correctness. The policy_engine spec verifies RBAC enforcement at every state transition.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Alloy Analysis</p>
              <p>The sandbox_isolation spec uses Alloy's relational logic with SAT solvers to prove that agent sandboxes never leak data across tenant boundaries. Checks all possible configuration combinations.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Z3 SMT Solving</p>
              <p>Run Z3 checks on demand via <code className="text-xs bg-white/5 px-1 rounded">/api/verification/z3/run</code>. Proves trust graph invariants — score bounds, transitivity, and consistency. Results show per-check pass/fail with elapsed time.</p>
            </div>
          </div>
        </div>
      )}

      {/* Summary bar */}
      <div className="grid grid-cols-4 gap-4">
        {[
          {
            label: "Total Specs",
            value: specs?.length ?? 0,
            sub: "TLA+ / Alloy / Z3",
          },
          {
            label: "Properties",
            value: totalProps,
            sub: "Safety + liveness invariants",
          },
          {
            label: "Tools",
            value: Object.keys(grouped).length,
            sub: "Verification engines",
          },
          {
            label: "CI Status",
            value: cachedResults && Object.keys(cachedResults).length > 0 ? "Results cached" : "No cached runs",
            sub: "Latest pipeline results",
          },
        ].map((card) => (
          <div
            key={card.label}
            className="rounded-lg border border-zinc-700 bg-zinc-800/50 p-4"
          >
            <div className="text-xs font-medium uppercase tracking-wider text-zinc-500">
              {card.label}
            </div>
            <div className="mt-1 text-2xl font-bold text-zinc-100">
              {card.value}
            </div>
            <div className="mt-0.5 text-xs text-zinc-500">{card.sub}</div>
          </div>
        ))}
      </div>

      {/* Z3 on-demand result */}
      {z3Result && (
        <Z3ResultCard
          checks={z3Result.checks}
          elapsed={z3Result.elapsed}
          passed={z3Result.passed}
        />
      )}

      {runZ3.isError && (
        <div className="flex items-center gap-2 rounded-lg border border-red-700/50 bg-red-900/20 px-4 py-3 text-sm text-red-300">
          <XCircle size={16} />
          Z3 execution failed: {(runZ3.error as Error)?.message ?? "Unknown error"}
        </div>
      )}

      {/* Specs by tool */}
      {specsLoading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 size={24} className="animate-spin text-zinc-500" />
        </div>
      ) : !specs?.length ? (
        <div className="flex items-center gap-2 rounded-lg border border-amber-700/50 bg-amber-900/20 px-4 py-3 text-sm text-amber-300">
          <Info size={16} />
          No verification specs available. Check backend connectivity.
        </div>
      ) : (
        Object.entries(grouped).map(([tool, toolSpecs]) => (
          <div key={tool}>
            <div className="mb-3 flex items-center gap-2">
              <ToolBadge tool={tool} />
              <span className="text-sm font-medium text-zinc-400">
                {toolSpecs.length} spec{toolSpecs.length > 1 ? "s" : ""}
              </span>
            </div>
            <div className="space-y-3">
              {toolSpecs.map((spec) => (
                <SpecCard key={spec.name} spec={spec} />
              ))}
            </div>
          </div>
        ))
      )}

      {/* Info footer */}
      <div className="flex items-start gap-2 rounded-lg border border-zinc-700/50 bg-zinc-800/30 px-4 py-3 text-xs text-zinc-500">
        <Info size={14} className="mt-0.5 shrink-0" />
        <div>
          <strong className="text-zinc-400">How it works:</strong>{" "}
          TLA+ specs use the TLC model checker (Java) to explore all reachable
          states. Alloy uses relational logic with SAT solvers to check
          isolation properties. Z3 uses SMT solving to prove trust graph
          invariants. All three run in CI on every PR touching relevant code.
        </div>
      </div>
    </div>
  )
}

export default VerificationPage
