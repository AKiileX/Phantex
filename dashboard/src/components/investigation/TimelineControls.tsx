// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — TimelineControls: zoom, filter, and time range controls.
 *
 * Provides event type filter chips, severity filter, zoom range slider,
 * and total count display for the investigation timeline.
 *
 * @module components/investigation/TimelineControls
 */

import { useMemo } from "react"
import { Filter, ZoomIn, ZoomOut, RotateCcw } from "lucide-react"
import type { TimelineEvent, Severity, DataSourceStatus } from "@/types"
import type { TimelineRange } from "@/api/timeline"

/* ── Props ─────────────────────────────────────────────────────────────────── */

interface TimelineControlsProps {
  events: TimelineEvent[]
  /** Currently selected event type filters (empty = show all). */
  eventTypeFilter: Set<string>
  onEventTypeFilterChange: (types: Set<string>) => void
  /** Currently selected severity filter (null = show all). */
  severityFilter: Severity | null
  onSeverityFilterChange: (severity: Severity | null) => void
  /** Current time range (agent timeline only). */
  range?: TimelineRange
  onRangeChange?: (range: TimelineRange) => void
  /** Data source status badges. */
  dataSources: DataSourceStatus[]
  /** Total event count (pre-filter). */
  totalEvents: number
}

/* ── Constants ─────────────────────────────────────────────────────────────── */

const SEVERITY_OPTIONS: (Severity | "all")[] = [
  "all",
  "critical",
  "high",
  "medium",
  "low",
  "info",
]

const RANGE_OPTIONS: TimelineRange[] = ["1h", "6h", "12h", "24h", "48h", "72h"]

/* ── Component ─────────────────────────────────────────────────────────────── */

export function TimelineControls({
  events,
  eventTypeFilter,
  onEventTypeFilterChange,
  severityFilter,
  onSeverityFilterChange,
  range,
  onRangeChange,
  dataSources,
  totalEvents,
}: TimelineControlsProps) {
  // Collect unique event types from the data
  const eventTypes = useMemo(() => {
    const types = new Map<string, number>()
    for (const e of events) {
      types.set(e.event_type, (types.get(e.event_type) ?? 0) + 1)
    }
    return Array.from(types.entries()).sort((a, b) => b[1] - a[1])
  }, [events])

  const toggleEventType = (type: string) => {
    const next = new Set(eventTypeFilter)
    if (next.has(type)) {
      next.delete(type)
    } else {
      next.add(type)
    }
    onEventTypeFilterChange(next)
  }

  const clearFilters = () => {
    onEventTypeFilterChange(new Set())
    onSeverityFilterChange(null)
  }

  const hasActiveFilters = eventTypeFilter.size > 0 || severityFilter !== null

  return (
    <div className="space-y-3">
      {/* ── Top row: counts + data sources + range ────── */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="text-xs text-muted-foreground tabular-nums">
            {totalEvents.toLocaleString()} event{totalEvents !== 1 ? "s" : ""}
          </span>

          {/* Data source indicators */}
          <div className="flex items-center gap-1.5">
            {dataSources.map((ds) => (
              <span
                key={ds.source}
                className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-medium ${
                  ds.available
                    ? "bg-status-active/10 text-status-active"
                    : "bg-surface-2 text-muted-foreground/50 line-through"
                }`}
                title={
                  ds.available
                    ? `${ds.source}: ${ds.event_count} events (${ds.latency_ms?.toFixed(0) ?? "?"}ms)`
                    : `${ds.source}: unavailable${ds.error ? ` — ${ds.error}` : ""}`
                }
              >
                {ds.source.replace("_", " ")}
              </span>
            ))}
          </div>
        </div>

        {/* Range selector (agent timeline only) */}
        {range && onRangeChange && (
          <div className="flex items-center gap-1">
            <ZoomOut size={12} className="text-muted-foreground" />
            <div className="flex items-center bg-surface-2/50 rounded-md p-0.5">
              {RANGE_OPTIONS.map((r) => (
                <button
                  key={r}
                  onClick={() => onRangeChange(r)}
                  className={`px-2 py-0.5 text-[10px] font-medium rounded-sm transition-colors cursor-pointer ${
                    range === r
                      ? "bg-primary/15 text-primary"
                      : "text-muted-foreground hover:text-foreground"
                  }`}
                >
                  {r}
                </button>
              ))}
            </div>
            <ZoomIn size={12} className="text-muted-foreground" />
          </div>
        )}
      </div>

      {/* ── Filter row: severity + event types ────────── */}
      <div className="flex items-center gap-2 flex-wrap">
        <Filter size={12} className="text-muted-foreground flex-shrink-0" />

        {/* Severity dropdown */}
        <select
          value={severityFilter ?? "all"}
          onChange={(e) =>
            onSeverityFilterChange(
              e.target.value === "all" ? null : (e.target.value as Severity),
            )
          }
          className="h-6 rounded-md border border-border bg-surface-2 px-1.5 text-[10px] text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
        >
          {SEVERITY_OPTIONS.map((s) => (
            <option key={s} value={s}>
              {s === "all" ? "All severities" : s.charAt(0).toUpperCase() + s.slice(1)}
            </option>
          ))}
        </select>

        {/* Event type chips */}
        <div className="flex items-center gap-1 flex-wrap">
          {eventTypes.map(([type, count]) => {
            const active = eventTypeFilter.size === 0 || eventTypeFilter.has(type)
            return (
              <button
                key={type}
                onClick={() => toggleEventType(type)}
                className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium transition-colors cursor-pointer ${
                  active
                    ? "bg-primary/10 text-primary border border-primary/20"
                    : "bg-surface-2 text-muted-foreground/50 border border-transparent"
                }`}
              >
                {type}
                <span className="tabular-nums text-[9px] opacity-60">{count}</span>
              </button>
            )
          })}
        </div>

        {/* Clear filters */}
        {hasActiveFilters && (
          <button
            onClick={clearFilters}
            className="flex items-center gap-1 text-[10px] text-muted-foreground hover:text-foreground transition-colors cursor-pointer ml-1"
          >
            <RotateCcw size={10} />
            Clear
          </button>
        )}
      </div>
    </div>
  )
}
