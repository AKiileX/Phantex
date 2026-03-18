// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — AlertGroupRow: expandable grouped alert card.
 *
 * Used in the alerts panel when grouping is enabled.
 * Shows a card-style summary row with severity indicator bar;
 * click to expand and reveal individual alerts within the group.
 *
 * @module components/alerts/AlertGroupRow
 */

import { useState, useCallback } from "react"
import {
  CheckSquare,
  ChevronDown,
  ChevronRight,
  Layers,
  Clock,
  Server,
  Square,
} from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { timeAgo } from "@/lib/utils"
import type { AlertGroup } from "@/hooks/useAlertGrouping"
import type { AlertSummary } from "@/types"

/* ── Severity → accent colour map for left-border indicator ───────────────── */

const SEVERITY_BORDER: Record<string, string> = {
  critical: "border-l-red-500",
  high: "border-l-orange-500",
  medium: "border-l-yellow-500",
  low: "border-l-blue-400",
  info: "border-l-slate-400",
}

const SEVERITY_DOT: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-blue-400",
  info: "bg-slate-400",
}

interface AlertGroupRowProps {
  group: AlertGroup
  onAlertClick: (alert: AlertSummary) => void
  selectedAlerts?: Set<string>
  onToggleAlert?: (id: string, e: React.MouseEvent) => void
  onToggleGroup?: (ids: string[], e: React.MouseEvent) => void
}

export function AlertGroupRow({ group, onAlertClick, selectedAlerts, onToggleAlert, onToggleGroup }: AlertGroupRowProps) {
  const [expanded, setExpanded] = useState(false)

  const toggleExpand = useCallback((e: React.MouseEvent) => {
    e.stopPropagation()
    setExpanded((v) => !v)
  }, [])

  const borderColor = SEVERITY_BORDER[group.severity] ?? "border-l-slate-400"

  /* ── Single-alert row (no expand) ─────────────────────── */
  const hasSelection = !!selectedAlerts && !!onToggleAlert
  const groupIds = group.alerts.map((a) => a.id)
  const allSelected = hasSelection && groupIds.length > 0 && groupIds.every((id) => selectedAlerts!.has(id))
  const someSelected = hasSelection && !allSelected && groupIds.some((id) => selectedAlerts!.has(id))

  if (group.count === 1) {
    const alert = group.alerts[0]
    const bc = SEVERITY_BORDER[alert.severity] ?? "border-l-slate-400"
    return (
      <div
        className={`group rounded-lg border border-border/50 border-l-[3px] ${bc} bg-card/60 backdrop-blur-sm cursor-pointer transition-all duration-150 hover:bg-white/[0.04] hover:shadow-md hover:shadow-black/10`}
        onClick={() => onAlertClick(alert)}
      >
        <div className="flex items-center gap-4 px-4 py-3.5">
          {hasSelection && (
            <button
              onClick={(e) => { e.stopPropagation(); onToggleAlert!(alert.id, e) }}
              className="flex items-center justify-center w-5 h-5 cursor-pointer shrink-0"
            >
              {selectedAlerts!.has(alert.id)
                ? <CheckSquare size={14} className="text-primary" />
                : <Square size={14} className="text-muted-foreground/40 hover:text-muted-foreground" />}
            </button>
          )}
          {/* Severity badge */}
          <Badge variant={alert.severity as "critical" | "high" | "medium" | "low"}>
            {alert.severity}
          </Badge>

          {/* Title */}
          <span className="text-sm text-foreground font-medium truncate flex-1 min-w-0">
            {alert.title}
          </span>

          {/* Meta pills */}
          <div className="flex items-center gap-3 flex-shrink-0">
            <Badge variant="outline" className="capitalize">
              {alert.status.replaceAll("_", " ")}
            </Badge>

            {alert.agent_id && (
              <span className="inline-flex items-center gap-1 font-mono text-[11px] text-muted-foreground">
                <Server size={10} className="opacity-50" />
                {alert.agent_id.slice(0, 8)}
              </span>
            )}

            <span className="inline-flex items-center gap-1 text-xs text-muted-foreground whitespace-nowrap">
              <Clock size={10} className="opacity-50" />
              {timeAgo(alert.created_at)}
            </span>

            <ChevronRight
              size={14}
              className="text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity"
            />
          </div>
        </div>
      </div>
    )
  }

  /* ── Multi-alert group card ───────────────────────────── */
  return (
    <div
      className={`rounded-lg border border-border/50 border-l-[3px] ${borderColor} bg-card/60 backdrop-blur-sm overflow-hidden transition-all duration-200 ${
        expanded ? "shadow-lg shadow-black/10" : "hover:shadow-md hover:shadow-black/10"
      }`}
    >
      {/* Group summary row */}
      <div
        className="flex items-center gap-4 px-4 py-3.5 cursor-pointer transition-colors hover:bg-white/[0.03]"
        onClick={toggleExpand}
      >
        {/* Group checkbox */}
        {hasSelection && onToggleGroup && (
          <button
            onClick={(e) => { e.stopPropagation(); onToggleGroup(groupIds, e) }}
            className="flex items-center justify-center w-5 h-5 cursor-pointer shrink-0"
          >
            {allSelected
              ? <CheckSquare size={14} className="text-primary" />
              : someSelected
                ? <CheckSquare size={14} className="text-primary/50" />
                : <Square size={14} className="text-muted-foreground/40 hover:text-muted-foreground" />}
          </button>
        )}

        {/* Expand icon */}
        <button
          className="flex-shrink-0 p-0.5 rounded text-muted-foreground hover:text-foreground transition-colors"
          onClick={toggleExpand}
          aria-label={expanded ? "Collapse group" : "Expand group"}
        >
          {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        </button>

        {/* Severity badge */}
        <Badge variant={group.severity as "critical" | "high" | "medium" | "low"}>
          {group.severity}
        </Badge>

        {/* Title + group count */}
        <div className="flex items-center gap-2.5 flex-1 min-w-0">
          <Layers size={13} className="text-muted-foreground/60 flex-shrink-0" />
          <span className="text-sm text-foreground font-medium truncate">
            {group.title}
          </span>
          <span className="inline-flex items-center justify-center min-w-[22px] h-[22px] rounded-full bg-primary/15 px-1.5 text-[10px] font-bold text-primary tabular-nums flex-shrink-0">
            {group.count}
          </span>
        </div>

        {/* Status */}
        <Badge variant="outline" className="capitalize flex-shrink-0">
          {group.status.replaceAll("_", " ")}
        </Badge>

        {/* Agent */}
        {group.agent_id && (
          <span className="inline-flex items-center gap-1 font-mono text-[11px] text-muted-foreground flex-shrink-0">
            <Server size={10} className="opacity-50" />
            {group.agent_id.slice(0, 8)}
          </span>
        )}

        {/* Time range */}
        <span className="inline-flex items-center gap-1 text-xs text-muted-foreground whitespace-nowrap flex-shrink-0">
          <Clock size={10} className="opacity-50" />
          {timeAgo(group.first_at)} – {timeAgo(group.last_at)}
        </span>
      </div>

      {/* Expanded individual alerts */}
      {expanded && (
        <div className="border-t border-border/30 bg-black/[0.08]">
          <div className="divide-y divide-border/20">
            {group.alerts.map((alert) => {
              const dot = SEVERITY_DOT[alert.severity] ?? "bg-slate-400"
              return (
                <div
                  key={alert.id}
                  className="group/item flex items-center gap-4 px-4 py-3 pl-12 cursor-pointer transition-colors hover:bg-white/[0.03]"
                  onClick={() => onAlertClick(alert)}
                >
                  {/* Severity dot */}
                  {hasSelection && (
                    <button
                      onClick={(e) => { e.stopPropagation(); onToggleAlert!(alert.id, e) }}
                      className="flex items-center justify-center w-5 h-5 cursor-pointer shrink-0"
                    >
                      {selectedAlerts!.has(alert.id)
                        ? <CheckSquare size={13} className="text-primary" />
                        : <Square size={13} className="text-muted-foreground/40 hover:text-muted-foreground" />}
                    </button>
                  )}
                  <span className={`h-2 w-2 rounded-full flex-shrink-0 ${dot}`} />

                  {/* Title */}
                  <span className="text-[13px] text-foreground/90 truncate flex-1 min-w-0">
                    {alert.title}
                  </span>

                  {/* Meta */}
                  <Badge variant="outline" className="capitalize text-[10px]">
                    {alert.status.replaceAll("_", " ")}
                  </Badge>

                  {alert.agent_id && (
                    <span className="font-mono text-[11px] text-muted-foreground/70 flex-shrink-0">
                      {alert.agent_id.slice(0, 8)}
                    </span>
                  )}

                  <span className="text-xs text-muted-foreground/70 whitespace-nowrap flex-shrink-0">
                    {timeAgo(alert.created_at)}
                  </span>

                  <ChevronRight
                    size={12}
                    className="text-muted-foreground opacity-0 group-hover/item:opacity-100 transition-opacity flex-shrink-0"
                  />
                </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}

/* ── Helper: single alert cells for flat VirtualTable view ─────────────────── */

export function SingleAlertCells({ alert }: { alert: AlertSummary }) {
  return (
    <>
      <div className="px-3 py-3 flex items-center">
        <Badge variant={alert.severity as "critical" | "high" | "medium" | "low"}>
          {alert.severity}
        </Badge>
      </div>
      <div className="px-3 py-3 flex items-center text-sm text-foreground font-medium truncate">
        {alert.title}
      </div>
      <div className="px-3 py-3 flex items-center">
        <Badge variant="outline" className="capitalize">
          {alert.status.replace("_", " ")}
        </Badge>
      </div>
      <div className="px-3 py-3 flex items-center font-mono text-xs text-muted-foreground">
        {alert.agent_id?.slice(0, 8) ?? "—"}
      </div>
      <div className="px-3 py-3 flex items-center text-xs text-muted-foreground whitespace-nowrap">
        {timeAgo(alert.created_at)}
      </div>
      <div className="px-3 py-3 flex items-center w-8">
        <ChevronRight size={14} className="text-muted-foreground" />
      </div>
    </>
  )
}
