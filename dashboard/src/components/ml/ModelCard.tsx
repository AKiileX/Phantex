// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — ModelCard component (O11).
 *
 * Renders a compact card for a single ML model version with:
 *   - Version tag + creation date
 *   - Stage availability indicators (IF/XGB/AE)
 *   - Validation metrics (precision, recall, FPR)
 *   - Retrain trigger label (auto / manual)
 *   - Signature badge if present (INT-07)
 *
 * @module components/ml/ModelCard
 */

import { ShieldCheck, Cpu, Clock } from "lucide-react"
import { Card, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import type { MLModelVersion } from "@/types"

/* ── Stage labels ──────────────────────────────────────────────────────────── */

const STAGE_LABELS: Record<string, string> = {
  stage1: "IF",
  stage2: "XGB",
  stage3: "AE",
}

/* ── Component ─────────────────────────────────────────────────────────────── */

interface ModelCardProps {
  model: MLModelVersion
  isCurrent?: boolean
}

export function ModelCard({ model, isCurrent = false }: ModelCardProps) {
  const m = model.metrics?.stage1_validation
  const trigger = model.metrics?.retrain_trigger
  const samples = model.metrics?.training_samples

  return (
    <Card
      className={
        isCurrent
          ? "border-primary/30 bg-primary/[0.03]"
          : "border-border/30"
      }
    >
      <CardContent className="p-4 space-y-3">
        {/* Header row */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Cpu className="h-4 w-4 text-primary/60" />
            <span className="font-mono text-sm font-semibold">
              {model.version}
            </span>
            {isCurrent && (
              <Badge variant="active" className="text-[10px]">
                Active
              </Badge>
            )}
          </div>
          <div className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
            <Clock className="h-3 w-3" />
            {new Date(model.created_at * 1000).toLocaleDateString()}
          </div>
        </div>

        {/* Stage chips */}
        <div className="flex items-center gap-1.5">
          {(["stage1", "stage2", "stage3"] as const).map((s) => (
            <span
              key={s}
              className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide ${
                model.stages[s]
                  ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/25"
                  : "bg-muted/30 text-muted-foreground/50 border border-border/30"
              }`}
            >
              {STAGE_LABELS[s]}
            </span>
          ))}
          {model.signature && (
            <span className="inline-flex items-center gap-0.5 rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide bg-blue-500/15 text-blue-400 border border-blue-500/25">
              <ShieldCheck className="h-2.5 w-2.5" />
              Signed
            </span>
          )}
        </div>

        {/* Metrics */}
        {m && (
          <div className="grid grid-cols-3 gap-2 text-center">
            <MetricPill label="Precision" value={m.precision} good={m.precision >= 0.9} />
            <MetricPill label="Recall" value={m.recall} good={m.recall >= 0.8} />
            <MetricPill label="FPR" value={m.fpr} good={m.fpr <= 0.05} invert />
          </div>
        )}

        {/* Footer: trigger + samples */}
        <div className="flex items-center justify-between text-[10px] text-muted-foreground">
          {trigger && (
            <Badge variant={trigger === "auto" ? "secondary" : "info"} className="text-[10px]">
              {trigger}
            </Badge>
          )}
          {samples != null && (
            <span>{samples.toLocaleString()} samples</span>
          )}
        </div>
      </CardContent>
    </Card>
  )
}

/* ── Metric Pill ───────────────────────────────────────────────────────────── */

function MetricPill({
  label,
  value,
  good,
}: {
  label: string
  value: number
  good: boolean
  invert?: boolean
}) {
  const color = good
    ? "text-emerald-400"
    : "text-amber-400"

  return (
    <div className="rounded-md border border-border/30 px-2 py-1">
      <p className="text-[9px] uppercase tracking-widest text-muted-foreground">
        {label}
      </p>
      <p className={`text-sm font-bold tabular-nums ${color}`}>
        {(value * 100).toFixed(1)}%
      </p>
    </div>
  )
}
