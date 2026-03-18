// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — RetrainHistory component (O11).
 *
 * Visual timeline of retrain runs with:
 *   - Success / failure status
 *   - Version produced
 *   - Duration + reason
 *   - Quality gate pass/fail
 *
 * @module components/ml/RetrainHistory
 */

import { CheckCircle2, XCircle, Clock, Zap } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import type { MLRetrainResult } from "@/types"

interface RetrainHistoryProps {
  results: MLRetrainResult[]
}

export function RetrainHistory({ results }: RetrainHistoryProps) {
  if (results.length === 0) {
    return (
      <p className="text-sm text-muted-foreground py-6 text-center">
        No retrain history available.
      </p>
    )
  }

  return (
    <div className="relative space-y-0">
      {/* Timeline line */}
      <div className="absolute left-[11px] top-2 bottom-2 w-px bg-border/40" />

      {results.map((r, idx) => (
        <div key={`${r.version ?? "fail"}-${idx}`} className="relative flex gap-3 py-2">
          {/* Dot */}
          <div
            className={`z-10 mt-1 h-[22px] w-[22px] shrink-0 rounded-full flex items-center justify-center ${
              r.success
                ? "bg-emerald-500/20 text-emerald-400"
                : "bg-destructive/20 text-destructive"
            }`}
          >
            {r.success ? (
              <CheckCircle2 className="h-3.5 w-3.5" />
            ) : (
              <XCircle className="h-3.5 w-3.5" />
            )}
          </div>

          {/* Content */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              {r.version ? (
                <span className="font-mono text-xs font-semibold">
                  {r.version}
                </span>
              ) : (
                <span className="text-xs text-muted-foreground italic">
                  No version produced
                </span>
              )}
              <Badge
                variant={r.success ? "active" : "critical"}
                className="text-[10px]"
              >
                {r.success ? "Success" : "Failed"}
              </Badge>
            </div>

            <div className="flex items-center gap-3 mt-1 text-[11px] text-muted-foreground flex-wrap">
              <span className="flex items-center gap-1">
                <Clock className="h-3 w-3" />
                {r.training_time_seconds.toFixed(1)}s
              </span>
              <span className="flex items-center gap-1">
                <Zap className="h-3 w-3" />
                {r.reason}
              </span>
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}
