// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — ATLAS Technique Detail Panel (O8).
 *
 * Slide-in panel showing full technique info when a technique is selected
 * from the coverage matrix. Lists detectors, confidence, and ATLAS reference link.
 *
 * @module components/atlas/TechniqueDetail
 */

import { X, ExternalLink, ShieldCheck, Brain, FileSearch } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { useAtlasTechnique } from "@/api/atlas"
import type { AtlasConfidence, DetectionSource } from "@/types"

/* ── Source icons + labels ─────────────────────────────────────────────────── */

const sourceIcon: Record<DetectionSource, typeof ShieldCheck> = {
  prl_rule: ShieldCheck,
  ml_model: Brain,
  content_classifier: FileSearch,
}

const sourceLabel: Record<DetectionSource, string> = {
  prl_rule: "PRL Rule",
  ml_model: "ML Model",
  content_classifier: "Content Classifier",
}

const confidenceBadge: Record<
  AtlasConfidence,
  "active" | "medium" | "low" | "secondary"
> = {
  high: "active",
  medium: "medium",
  low: "low",
  none: "secondary",
}

/* ── Component ─────────────────────────────────────────────────────────────── */

interface TechniqueDetailProps {
  techniqueId: string
  onClose: () => void
}

export function TechniqueDetail({
  techniqueId,
  onClose,
}: TechniqueDetailProps) {
  const { data, isLoading, error } = useAtlasTechnique(techniqueId)

  return (
    <Card className="flex flex-col h-full border-l bg-card/80 backdrop-blur-sm">
      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="flex items-start justify-between gap-3 border-b border-border/40 p-4">
        <div className="flex-1 min-w-0">
          <p className="text-[10px] font-mono font-bold text-muted-foreground">
            {techniqueId}
          </p>
          {data && (
            <h2 className="text-sm font-semibold mt-1 leading-tight">
              {data.name}
            </h2>
          )}
        </div>
        <Button
          variant="ghost"
          size="icon"
          className="shrink-0 -mt-1 -mr-1"
          onClick={onClose}
          aria-label="Close technique detail"
        >
          <X className="h-4 w-4" />
        </Button>
      </div>

      {/* ── Body ───────────────────────────────────────────────────────────── */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {isLoading && (
          <div className="flex items-center justify-center py-12">
            <div className="h-5 w-5 animate-spin rounded-full border-2 border-primary/20 border-t-primary" />
          </div>
        )}

        {error && (
          <p className="text-sm text-destructive" role="alert">
            Failed to load technique details.
          </p>
        )}

        {data && (
          <>
            {/* Tactic */}
            <div>
              <span className="text-[10px] uppercase tracking-widest text-muted-foreground">
                Tactic
              </span>
              <p className="text-sm mt-0.5">{data.tactic}</p>
            </div>

            {/* Description */}
            {data.description && (
              <div>
                <span className="text-[10px] uppercase tracking-widest text-muted-foreground">
                  Description
                </span>
                <p className="text-xs leading-relaxed mt-1 text-foreground/80">
                  {data.description}
                </p>
              </div>
            )}

            {/* Detectors */}
            <div>
              <span className="text-[10px] uppercase tracking-widest text-muted-foreground">
                Detectors ({(data.detected_by ?? []).length})
              </span>

              {(data.detected_by ?? []).length === 0 ? (
                <p className="text-xs text-muted-foreground mt-2 italic">
                  No active detectors for this technique.
                </p>
              ) : (
                <ul className="mt-2 space-y-2">
                  {(data.detected_by ?? []).map((d) => {
                    const Icon = sourceIcon[d.source]
                    return (
                      <li
                        key={`${d.source}-${d.name}`}
                        className="flex items-center justify-between gap-2 rounded-md border border-border/30 bg-white/[0.02] px-3 py-2"
                      >
                        <div className="flex items-center gap-2 min-w-0">
                          <Icon className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                          <div className="min-w-0">
                            <p className="text-xs font-medium truncate">
                              {d.name}
                            </p>
                            <p className="text-[10px] text-muted-foreground">
                              {sourceLabel[d.source]}
                            </p>
                          </div>
                        </div>
                        <Badge variant={confidenceBadge[d.confidence]}>
                          {d.confidence}
                        </Badge>
                      </li>
                    )
                  })}
                </ul>
              )}
            </div>

            {/* ATLAS Reference */}
            {data.url && (
              <a
                href={data.url}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 text-xs text-primary/80 hover:text-primary transition-colors"
              >
                <ExternalLink className="h-3 w-3" />
                View on MITRE ATLAS
              </a>
            )}
          </>
        )}
      </div>
    </Card>
  )
}
