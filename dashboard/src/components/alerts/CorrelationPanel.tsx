// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — CorrelationPanel: side panel showing correlated alert graph + list.
 *
 * Renders a force-directed mini-graph of correlated alerts and a list of
 * correlation groups below. Click a node → navigate to alert detail.
 * Hidden automatically when no correlations exist.
 *
 * @module components/alerts/CorrelationPanel
 */

import { useState, useCallback } from "react"
import {
  X,
  GitBranch,
  ChevronDown,
  ChevronRight,
  ExternalLink,
} from "lucide-react"
import { CorrelationGraph } from "./CorrelationGraph"
import { Badge } from "@/components/ui/badge"
import { timeAgo } from "@/lib/utils"
import type { CorrelationResult, CorrelationGroup } from "@/hooks/useAlertCorrelation"
import type { AlertSummary, Severity } from "@/types"

/* ── Props ─────────────────────────────────────────────────────────────────── */

interface CorrelationPanelProps {
  /** Correlation result from useAlertCorrelation. */
  correlation: CorrelationResult
  /** Called when user clicks an alert node or list item. */
  onAlertClick: (alert: AlertSummary) => void
  /** Called when user closes the panel. */
  onClose: () => void
  /** Currently selected alert ID for highlighting. */
  selectedAlertId?: string | null
}

/* ── Component ─────────────────────────────────────────────────────────────── */

export function CorrelationPanel({
  correlation,
  onAlertClick,
  onClose,
  selectedAlertId,
}: CorrelationPanelProps) {
  const [highlightId, setHighlightId] = useState<string | null>(
    selectedAlertId ?? null,
  )

  const handleNodeClick = useCallback(
    (alert: AlertSummary) => {
      setHighlightId(alert.id)
      onAlertClick(alert)
    },
    [onAlertClick],
  )

  return (
    <div className="flex flex-col h-full bg-card border-l border-border/50">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-border/40">
        <div className="flex items-center gap-2">
          <GitBranch size={14} className="text-primary" />
          <span className="text-sm font-semibold text-foreground">
            Correlations
          </span>
          <span className="text-xs text-muted-foreground tabular-nums">
            {correlation.groups.length} cluster{correlation.groups.length !== 1 ? "s" : ""}
            {" · "}
            {correlation.totalEdges} edge{correlation.totalEdges !== 1 ? "s" : ""}
          </span>
        </div>
        <button
          onClick={onClose}
          className="p-1 rounded-md hover:bg-surface-2 text-muted-foreground hover:text-foreground transition-colors cursor-pointer"
          aria-label="Close correlation panel"
        >
          <X size={14} />
        </button>
      </div>

      {/* Graph */}
      <div className="px-3 pt-3 pb-2">
        <CorrelationGraph
          nodes={correlation.nodes}
          edges={correlation.edges}
          width={320}
          height={220}
          onNodeClick={handleNodeClick}
          highlightId={highlightId}
        />
      </div>

      {/* Truncation warning */}
      {correlation.truncated && (
        <div className="mx-3 mb-2 px-2 py-1.5 bg-severity-medium/5 border border-severity-medium/20 rounded-md text-[10px] text-severity-medium">
          Graph capped at 500 nodes for performance.
        </div>
      )}

      {/* Correlation groups list */}
      <div className="flex-1 overflow-y-auto px-3 pb-3 space-y-1.5">
        <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium pt-1 pb-1">
          Clusters
        </p>
        {correlation.groups.map((group) => (
          <CorrelationGroupCard
            key={group.id}
            group={group}
            onAlertClick={handleNodeClick}
            highlightId={highlightId}
          />
        ))}
      </div>
    </div>
  )
}

/* ── CorrelationGroupCard ──────────────────────────────────────────────────── */

interface CorrelationGroupCardProps {
  group: CorrelationGroup
  onAlertClick: (alert: AlertSummary) => void
  highlightId: string | null
}

function CorrelationGroupCard({
  group,
  onAlertClick,
  highlightId,
}: CorrelationGroupCardProps) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div className="rounded-lg border border-border/40 bg-surface-2/20 overflow-hidden">
      {/* Group header */}
      <button
        onClick={() => setExpanded((v) => !v)}
        className="w-full flex items-center gap-2 px-3 py-2 text-left hover:bg-white/[0.02] transition-colors cursor-pointer"
      >
        {expanded ? (
          <ChevronDown size={12} className="text-muted-foreground flex-shrink-0" />
        ) : (
          <ChevronRight size={12} className="text-muted-foreground flex-shrink-0" />
        )}
        <Badge
          variant={group.severity as Severity}
          className="text-[9px] px-1.5 py-0"
        >
          {group.severity}
        </Badge>
        <span className="text-xs text-foreground font-medium truncate flex-1">
          {group.label}
        </span>
        <span className="text-[10px] text-muted-foreground tabular-nums flex-shrink-0">
          {group.edgeCount} link{group.edgeCount !== 1 ? "s" : ""}
        </span>
      </button>

      {/* Expanded alert list */}
      {expanded && (
        <div className="border-t border-border/30">
          {group.alerts.map((alert) => (
            <button
              key={alert.id}
              onClick={() => onAlertClick(alert)}
              className={`w-full flex items-center gap-2 px-3 py-1.5 pl-7 text-left hover:bg-white/[0.03] transition-colors cursor-pointer ${
                highlightId === alert.id ? "bg-primary/5" : ""
              }`}
            >
              <Badge
                variant={alert.severity as Severity}
                className="text-[8px] px-1 py-0"
              >
                {alert.severity.charAt(0).toUpperCase()}
              </Badge>
              <span className="text-[11px] text-foreground truncate flex-1">
                {alert.title}
              </span>
              <span className="text-[10px] text-muted-foreground whitespace-nowrap">
                {timeAgo(alert.created_at)}
              </span>
              <ExternalLink size={10} className="text-muted-foreground opacity-0 group-hover:opacity-100 flex-shrink-0" />
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
