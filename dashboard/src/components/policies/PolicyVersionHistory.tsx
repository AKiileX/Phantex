// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — PolicyVersionHistory: version list with diff view (O5).
 *
 * Shows all versions with timestamps, change summaries, and
 * a side-by-side YAML diff between any two selected versions.
 *
 * @module components/policies/PolicyVersionHistory
 */

import { useState, useMemo } from "react"
import { usePolicyVersions } from "@/api/policies"
import { History, ChevronRight, GitCompareArrows } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import type { PolicyVersion } from "@/types"

/* ── Helpers ───────────────────────────────────────────────────────────────── */

function yamlFromDef(def: Record<string, unknown>): string {
  return toYamlString(def, 0)
}

function toYamlString(obj: unknown, indent: number): string {
  const pad = "  ".repeat(indent)

  if (obj === null || obj === undefined) return "null"
  if (typeof obj === "string") return JSON.stringify(obj)
  if (typeof obj === "number" || typeof obj === "boolean") return String(obj)

  if (Array.isArray(obj)) {
    if (obj.length === 0) return "[]"
    return obj.map((item) => `${pad}- ${toYamlString(item, indent + 1).trimStart()}`).join("\n")
  }

  if (typeof obj === "object") {
    const entries = Object.entries(obj as Record<string, unknown>)
    if (entries.length === 0) return "{}"
    return entries
      .map(([k, v]) => {
        const val = toYamlString(v, indent + 1)
        const isComplex = typeof v === "object" && v !== null
        return isComplex
          ? `${pad}${k}:\n${val}`
          : `${pad}${k}: ${val}`
      })
      .join("\n")
  }

  return String(obj)
}

/* Compute simple line-level diff */
interface DiffLine {
  type: "same" | "add" | "remove"
  text: string
}

function computeDiff(a: string, b: string): DiffLine[] {
  const linesA = a.split("\n")
  const linesB = b.split("\n")

  /* Simple LCS-based diff for reasonable-length policies */
  const n = linesA.length
  const m = linesB.length

  /* For very large diffs, fall back to a simpler approach */
  if (n * m > 500_000) {
    return [...linesA.map((l) => ({ type: "remove" as const, text: l })),
            ...linesB.map((l) => ({ type: "add" as const, text: l }))]
  }

  const dp: number[][] = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0))
  for (let i = 1; i <= n; i++) {
    for (let j = 1; j <= m; j++) {
      dp[i][j] = linesA[i - 1] === linesB[j - 1]
        ? dp[i - 1][j - 1] + 1
        : Math.max(dp[i - 1][j], dp[i][j - 1])
    }
  }

  const result: DiffLine[] = []
  let i = n, j = m
  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && linesA[i - 1] === linesB[j - 1]) {
      result.push({ type: "same", text: linesA[i - 1] })
      i--; j--
    } else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
      result.push({ type: "add", text: linesB[j - 1] })
      j--
    } else {
      result.push({ type: "remove", text: linesA[i - 1] })
      i--
    }
  }
  return result.reverse()
}

/* ── Props ─────────────────────────────────────────────────────────────────── */

interface PolicyVersionHistoryProps {
  policyId: string
}

/* ── Component ─────────────────────────────────────────────────────────────── */

export function PolicyVersionHistory({ policyId }: PolicyVersionHistoryProps) {
  const { data: versions, isLoading } = usePolicyVersions(policyId)
  const [selectedA, setSelectedA] = useState<number | null>(null)
  const [selectedB, setSelectedB] = useState<number | null>(null)
  const [showDiff, setShowDiff] = useState(false)

  const versionList: PolicyVersion[] = useMemo(
    () => (versions as PolicyVersion[] | undefined) ?? [],
    [versions],
  )

  const diff = useMemo(() => {
    if (!showDiff || selectedA === null || selectedB === null) return null
    const a = versionList.find((v) => v.version === selectedA)
    const b = versionList.find((v) => v.version === selectedB)
    if (!a || !b) return null
    return computeDiff(yamlFromDef(a.definition as unknown as Record<string, unknown>), yamlFromDef(b.definition as unknown as Record<string, unknown>))
  }, [showDiff, selectedA, selectedB, versionList])

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-8 text-muted-foreground text-xs">
        Loading version history…
      </div>
    )
  }

  if (versionList.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-8 text-muted-foreground gap-2">
        <History className="size-5" />
        <span className="text-xs">No version history</span>
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-4">
      {/* Version list */}
      <div className="space-y-1.5">
        {versionList.map((v) => {
          const isA = selectedA === v.version
          const isB = selectedB === v.version
          return (
            <div
              key={v.version}
              className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-xs
                ${isA ? "border-blue-500/50 bg-blue-500/10" :
                  isB ? "border-emerald-500/50 bg-emerald-500/10" :
                  "border-border/30 bg-card/40"}
                cursor-pointer hover:bg-surface-2/50 transition-colors`}
              onClick={() => {
                if (!selectedA || selectedA === v.version) {
                  setSelectedA(v.version === selectedA ? null : v.version)
                } else if (!selectedB || selectedB === v.version) {
                  setSelectedB(v.version === selectedB ? null : v.version)
                } else {
                  setSelectedA(selectedB)
                  setSelectedB(v.version)
                }
              }}
            >
              <Badge variant="outline" className="text-[9px] px-1.5">
                v{v.version}
              </Badge>
              <ChevronRight className="size-3 text-muted-foreground" />
              <span className="text-muted-foreground truncate flex-1">
                {v.change_summary || "Initial version"}
              </span>
              <span className="text-muted-foreground/60 shrink-0">
                {v.created_by ?? "system"}
              </span>
              <span className="text-muted-foreground/40 shrink-0">
                {new Date(v.created_at).toLocaleDateString()}
              </span>
            </div>
          )
        })}
      </div>

      {/* Diff controls */}
      {selectedA !== null && selectedB !== null && (
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            className="text-xs gap-1.5"
            onClick={() => setShowDiff(!showDiff)}
          >
            <GitCompareArrows className="size-3" />
            {showDiff ? "Hide diff" : `Diff v${Math.min(selectedA, selectedB)} ↔ v${Math.max(selectedA, selectedB)}`}
          </Button>
        </div>
      )}

      {/* Diff view */}
      {diff && (
        <div
          className="rounded-lg border border-border/40 bg-black/30 p-3 font-mono text-[11px] leading-5 overflow-auto max-h-72"
          role="region"
          aria-label="Policy diff"
        >
          {diff.map((line, i) => (
            <div
              key={i}
              className={`whitespace-pre ${
                line.type === "add"
                  ? "text-emerald-400 bg-emerald-500/10"
                  : line.type === "remove"
                  ? "text-red-400 bg-red-500/10"
                  : "text-muted-foreground/70"
              }`}
            >
              {line.type === "add" ? "+ " : line.type === "remove" ? "- " : "  "}
              {line.text}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
