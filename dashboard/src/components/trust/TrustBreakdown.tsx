// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — TrustBreakdown: detail side-panel for a selected entity (O4).
 *
 * Shows:
 *   - Entity name / id / type badge
 *   - Trust score gauge bar
 *   - Factor breakdown (radar-style list)
 *   - Metadata key-values
 *   - Last-updated timestamp
 *
 * Raw float scores are shown to all users via the gauge bar.
 * The factor list shows both weight and computed value.
 *
 * @module components/trust/TrustBreakdown
 */

import { useTrustScore } from "@/api/trust"
import type { TrustGraphNode, TrustFactor } from "@/types"

/* ── Color helpers ─────────────────────────────────────────────────────────── */

function scoreBadge(score: number): { label: string; bg: string; text: string } {
  if (score >= 0.7) return { label: "High", bg: "bg-emerald-500/20", text: "text-emerald-400" }
  if (score >= 0.3) return { label: "Medium", bg: "bg-yellow-500/20", text: "text-yellow-400" }
  return { label: "Low", bg: "bg-red-500/20", text: "text-red-400" }
}

function entityBadge(type: string): { bg: string; text: string } {
  switch (type) {
    case "agent":   return { bg: "bg-violet-500/20", text: "text-violet-400" }
    case "tool":    return { bg: "bg-blue-500/20",   text: "text-blue-400" }
    case "file":    return { bg: "bg-amber-500/20",  text: "text-amber-400" }
    case "network": return { bg: "bg-cyan-500/20",   text: "text-cyan-400" }
    default:        return { bg: "bg-zinc-500/20",   text: "text-zinc-400" }
  }
}

function barColor(value: number): string {
  if (value >= 0.7) return "bg-emerald-500"
  if (value >= 0.3) return "bg-yellow-500"
  return "bg-red-500"
}

function relativeTime(ts: number | null | undefined): string {
  if (ts == null) return "—"
  const now = Date.now()
  // ts is epoch seconds from backend
  const then = ts * 1000
  const diff = Math.max(0, Math.floor((now - then) / 1000))
  if (diff < 60) return `${diff}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

/* ── Props ─────────────────────────────────────────────────────────────────── */

interface TrustBreakdownProps {
  /** Selected node from the graph. */
  node: TrustGraphNode
  /** Called to close / deselect. */
  onClose?: () => void
}

/* ── Component ─────────────────────────────────────────────────────────────── */

export function TrustBreakdown({ node, onClose }: TrustBreakdownProps) {
  const { data: score, isLoading } = useTrustScore(
    { entityId: node.id, entityType: node.entity_type },
    true,
  )

  const badge = scoreBadge(node.trust_score)
  const eBadge = entityBadge(node.entity_type)
  const displayName = node.metadata.name ?? node.id.slice(0, 12) + "…"

  return (
    <aside
      className="flex flex-col gap-4 rounded-lg border border-border/50 bg-card p-4
                 shadow-lg overflow-y-auto max-h-full"
      style={{ minWidth: 280, maxWidth: 340 }}
    >
      {/* Header */}
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-foreground truncate" title={node.id}>
            {displayName}
          </h3>
          <div className="flex gap-1.5 mt-1 flex-wrap">
            <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px]
                              font-medium uppercase tracking-wide ${eBadge.bg} ${eBadge.text}`}>
              {node.entity_type}
            </span>
            <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px]
                              font-medium uppercase tracking-wide ${badge.bg} ${badge.text}`}>
              {badge.label}
            </span>
          </div>
        </div>
        {onClose && (
          <button
            onClick={onClose}
            className="shrink-0 rounded p-1 text-muted-foreground hover:text-foreground
                       hover:bg-surface-2/50 transition-colors cursor-pointer"
            aria-label="Close detail panel"
          >
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
              <path d="M3 3l8 8M11 3l-8 8" stroke="currentColor" strokeWidth="1.5"
                strokeLinecap="round" />
            </svg>
          </button>
        )}
      </div>

      {/* Trust Score Gauge */}
      <div>
        <div className="flex items-center justify-between text-xs mb-1">
          <span className="text-muted-foreground">Trust Score</span>
          <span className={`font-mono font-semibold ${badge.text}`}>
            {node.trust_score.toFixed(3)}
          </span>
        </div>
        <div className="h-2 rounded-full bg-surface-2/50 overflow-hidden">
          <div
            className={`h-full rounded-full ${barColor(node.trust_score)} transition-all duration-500`}
            style={{ width: `${Math.round(node.trust_score * 100)}%` }}
          />
        </div>
      </div>

      {/* Factor Breakdown */}
      <section>
        <h4 className="text-xs font-medium text-muted-foreground mb-2">Factor Breakdown</h4>
        {isLoading ? (
          <div className="space-y-2">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-6 rounded bg-surface-2/30 animate-pulse" />
            ))}
          </div>
        ) : score?.factors && score.factors.length > 0 ? (
          <ul className="space-y-2">
            {score.factors.map((f: TrustFactor) => (
              <FactorRow key={f.name} factor={f} />
            ))}
          </ul>
        ) : (
          <p className="text-xs text-muted-foreground italic">No factor data — trust engine may be offline</p>
        )}
      </section>

      {/* Metadata */}
      {Object.keys(node.metadata).length > 0 && (
        <section>
          <h4 className="text-xs font-medium text-muted-foreground mb-1.5">Metadata</h4>
          <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
            {Object.entries(node.metadata).map(([k, v]) => (
              <div key={k} className="contents">
                <dt className="text-muted-foreground truncate">{k}</dt>
                <dd className="text-foreground/80 truncate font-mono" title={v}>{v}</dd>
              </div>
            ))}
          </dl>
        </section>
      )}

      {/* Footer — entity id & last-updated */}
      <div className="flex flex-col gap-0.5 border-t border-border/30 pt-2 text-[10px]
                      font-mono text-muted-foreground/60">
        <span className="truncate" title={node.id}>{node.id}</span>
        {score?.last_updated && (
          <span>Updated {relativeTime(score.last_updated)}</span>
        )}
      </div>
    </aside>
  )
}

/* ── Factor Row ────────────────────────────────────────────────────────────── */

function FactorRow({ factor }: { factor: TrustFactor }) {
  const pct = Math.round(factor.value * 100)

  return (
    <li className="flex flex-col gap-0.5">
      <div className="flex items-center justify-between text-[11px]">
        <span className="text-foreground/80 capitalize">
          {factor.name.replaceAll("_", " ")}
        </span>
        <span className="font-mono text-muted-foreground">
          {factor.value.toFixed(2)}{" "}
          <span className="text-[9px] opacity-50">w{factor.weight.toFixed(1)}</span>
        </span>
      </div>
      <div className="h-1 rounded-full bg-surface-2/40 overflow-hidden">
        <div
          className={`h-full rounded-full ${barColor(factor.value)} transition-all duration-300`}
          style={{ width: `${pct}%` }}
        />
      </div>
    </li>
  )
}
