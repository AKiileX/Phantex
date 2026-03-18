// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — TimelineEvent: individual event card on the investigation timeline.
 *
 * Renders as a node on the vertical timeline axis, color-coded by severity,
 * with event type icon, description, timestamp, and optional ATLAS badge.
 *
 * @module components/investigation/TimelineEvent
 */

import { memo } from "react"
import {
  Cog,
  FileText,
  Globe,
  Wrench,
  Bell,
  Shield,
  HelpCircle,
} from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { formatDate } from "@/lib/utils"
import type { TimelineEvent as TEvent, Severity } from "@/types"

/* ── Event type → icon mapping ─────────────────────────────────────────────── */

/** Stable wrapper — avoids creating dynamic component ref during render */
function EventIcon({ eventType, size, className }: { eventType: string; size: number; className?: string }) {
  const category = eventType.split("_")[0]
  switch (category) {
    case "process": return <Cog size={size} className={className} />
    case "file": return <FileText size={size} className={className} />
    case "network": return <Globe size={size} className={className} />
    case "tool": return <Wrench size={size} className={className} />
    case "alert": return <Bell size={size} className={className} />
    case "trust": return <Shield size={size} className={className} />
    default: return <HelpCircle size={size} className={className} />
  }
}

/* ── Severity colors for the timeline dot ──────────────────────────────────── */

const DOT_COLOR: Record<Severity, string> = {
  critical: "bg-severity-critical shadow-[0_0_8px_rgba(239,68,68,0.4)]",
  high: "bg-severity-high shadow-[0_0_6px_rgba(249,115,22,0.3)]",
  medium: "bg-severity-medium",
  low: "bg-severity-low",
  info: "bg-muted-foreground/40",
}

const LINE_COLOR: Record<Severity, string> = {
  critical: "border-severity-critical/30",
  high: "border-severity-high/25",
  medium: "border-severity-medium/20",
  low: "border-severity-low/15",
  info: "border-border/40",
}

/* ── Props ─────────────────────────────────────────────────────────────────── */

interface TimelineEventProps {
  event: TEvent
  isSelected: boolean
  isFirst: boolean
  isLast: boolean
  onClick: (event: TEvent) => void
}

/* ── Component ─────────────────────────────────────────────────────────────── */

export const TimelineEventCard = memo(function TimelineEventCard({
  event,
  isSelected,
  isFirst,
  isLast,
  onClick,
}: TimelineEventProps) {
  const severity = event.severity as Severity

  return (
    <div
      className={`relative flex gap-4 cursor-pointer group transition-colors ${
        isSelected ? "bg-primary/5" : "hover:bg-white/[0.02]"
      }`}
      onClick={() => onClick(event)}
    >
      {/* ── Timeline axis ─────────────────────────────── */}
      <div className="flex flex-col items-center w-8 flex-shrink-0 relative">
        {/* Top connector line */}
        {!isFirst && (
          <div className={`w-px flex-1 border-l-2 ${LINE_COLOR[severity]}`} />
        )}
        {isFirst && <div className="flex-1" />}

        {/* Timeline dot */}
        <div
          className={`w-3 h-3 rounded-full flex-shrink-0 ring-2 ring-card ${DOT_COLOR[severity]} transition-transform ${
            isSelected ? "scale-125" : "group-hover:scale-110"
          }`}
        />

        {/* Bottom connector line */}
        {!isLast && (
          <div className={`w-px flex-1 border-l-2 ${LINE_COLOR[severity]}`} />
        )}
        {isLast && <div className="flex-1" />}
      </div>

      {/* ── Event card ────────────────────────────────── */}
      <div
        className={`flex-1 py-2.5 pr-4 border-b border-border/20 ${
          isSelected ? "border-primary/20" : ""
        }`}
      >
        <div className="flex items-start gap-2">
          {/* Event icon */}
          <div className="flex items-center justify-center w-7 h-7 rounded-lg bg-surface-2/50 mt-0.5 flex-shrink-0">
            <EventIcon eventType={event.event_type} size={14} className="text-muted-foreground" />
          </div>

          <div className="flex-1 min-w-0">
            {/* Header row */}
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono text-muted-foreground/70">
                {event.event_type}
              </span>
              <Badge
                variant={severity}
                className="text-[8px] px-1.5 py-0"
              >
                {severity}
              </Badge>
              {event.trust_score != null && (
                <span
                  className={`text-[10px] font-mono tabular-nums ${
                    event.trust_score < 0.3
                      ? "text-severity-critical"
                      : event.trust_score < 0.6
                        ? "text-severity-medium"
                        : "text-severity-low"
                  }`}
                >
                  T:{event.trust_score.toFixed(2)}
                </span>
              )}
            </div>

            {/* Description */}
            <p className="text-sm text-foreground mt-0.5 leading-snug">
              {event.description || event.event_type}
            </p>

            {/* ATLAS techniques */}
            {event.atlas_techniques.length > 0 && (
              <div className="flex flex-wrap gap-1 mt-1">
                {event.atlas_techniques.map((tech, i) => (
                  <span
                    key={i}
                    className="inline-flex items-center px-1.5 py-0.5 rounded text-[9px] font-mono bg-primary/10 text-primary/80"
                  >
                    {String(tech.technique_id ?? tech.id ?? `T${i}`)}
                  </span>
                ))}
              </div>
            )}

            {/* Timestamp + source */}
            <div className="flex items-center gap-2 mt-1">
              <span className="text-[10px] text-muted-foreground">
                {formatDate(event.timestamp)}
              </span>
              <span className="text-[10px] text-muted-foreground/50">
                via {event.source}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
})
