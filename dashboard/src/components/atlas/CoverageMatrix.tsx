// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — ATLAS Coverage Matrix (O8).
 *
 * Grid-based heatmap showing detection coverage across all MITRE ATLAS techniques.
 * Color-coded by confidence level:
 *   - high = green
 *   - medium = yellow/amber
 *   - low = orange/red
 *   - none = gray
 *
 * Click a technique to open the detail panel.
 *
 * @module components/atlas/CoverageMatrix
 */

import { useCallback, useMemo } from "react"
import { cn } from "@/lib/utils"
import { Badge } from "@/components/ui/badge"
import type { AtlasTechnique, AtlasConfidence } from "@/types"

/* ── Confidence color map ──────────────────────────────────────────────────── */

const confidenceColors: Record<AtlasConfidence, string> = {
  high: "bg-emerald-500/20 border-emerald-500/40 text-emerald-400 hover:bg-emerald-500/30",
  medium:
    "bg-amber-500/20 border-amber-500/40 text-amber-400 hover:bg-amber-500/30",
  low: "bg-orange-500/20 border-orange-500/40 text-orange-400 hover:bg-orange-500/30",
  none: "bg-white/[0.03] border-border/40 text-muted-foreground hover:bg-white/[0.06]",
}

const confidenceLabel: Record<AtlasConfidence, string> = {
  high: "High",
  medium: "Medium",
  low: "Low",
  none: "None",
}

/* ── Group by tactic ───────────────────────────────────────────────────────── */

interface TacticGroup {
  tactic: string
  techniques: AtlasTechnique[]
}

function groupByTactic(techniques: AtlasTechnique[]): TacticGroup[] {
  const map = new Map<string, AtlasTechnique[]>()
  for (const t of techniques) {
    const tactic = t.tactic || "Uncategorized"
    const group = map.get(tactic)
    if (group) group.push(t)
    else map.set(tactic, [t])
  }
  return Array.from(map.entries()).map(([tactic, techniques]) => ({
    tactic,
    techniques,
  }))
}

/* ── Component ─────────────────────────────────────────────────────────────── */

interface CoverageMatrixProps {
  techniques: AtlasTechnique[]
  selectedId: string | null
  onSelect: (id: string) => void
}

export function CoverageMatrix({
  techniques,
  selectedId,
  onSelect,
}: CoverageMatrixProps) {
  const groups = useMemo(() => groupByTactic(techniques), [techniques])

  const handleClick = useCallback(
    (id: string) => {
      onSelect(id)
    },
    [onSelect],
  )

  return (
    <div className="space-y-4">
      {groups.map((group) => (
        <div key={group.tactic}>
          <h3 className="text-xs font-semibold uppercase tracking-widest text-muted-foreground mb-2 px-1">
            {group.tactic}
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-2">
            {group.techniques.map((t) => (
              <button
                key={t.id}
                type="button"
                onClick={() => handleClick(t.id)}
                className={cn(
                  "flex flex-col gap-1 rounded-lg border p-3 text-left transition-all duration-200 cursor-pointer",
                  confidenceColors[t.best_confidence],
                  selectedId === t.id &&
                    "ring-2 ring-primary/50 shadow-[0_0_12px_-4px_rgba(99,102,241,0.3)]",
                )}
                aria-label={`Technique ${t.id}: ${t.name} — confidence ${t.best_confidence}`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[10px] font-mono font-bold opacity-70">
                    {t.id}
                  </span>
                  <Badge
                    variant={
                      t.best_confidence === "high"
                        ? "active"
                        : t.best_confidence === "medium"
                          ? "medium"
                          : t.best_confidence === "low"
                            ? "low"
                            : "secondary"
                    }
                    className="text-[9px] px-1.5 py-0"
                  >
                    {confidenceLabel[t.best_confidence]}
                  </Badge>
                </div>
                <span className="text-xs font-medium leading-tight line-clamp-2">
                  {t.name}
                </span>
                {t.detected && (
                  <span className="text-[10px] opacity-60">
                    {t.detected_by.length} detector
                    {t.detected_by.length !== 1 ? "s" : ""}
                  </span>
                )}
              </button>
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}
