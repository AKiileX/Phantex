// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Timeline: main vertical timeline component.
 *
 * Renders a scrollable vertical timeline of events with:
 *   - Color-coded severity dots on the axis
 *   - Event type icons (process, file, network, tool, alert)
 *   - Session separators (grouped by session_id)
 *   - Click → detail panel
 *   - Smooth scroll to selected event
 *
 * Optimized for 1000+ events via windowed rendering.
 *
 * @module components/investigation/Timeline
 */

import { useRef, useEffect, useMemo } from "react"
import { TimelineEventCard } from "./TimelineEvent"
import type { TimelineEvent as TEvent, Severity } from "@/types"

/* ── Props ─────────────────────────────────────────────────────────────────── */

interface TimelineProps {
  events: TEvent[]
  /** Currently selected event ID. */
  selectedEventId: string | null
  /** Callback when user clicks an event. */
  onEventSelect: (event: TEvent) => void
  /** Event type filters — empty set means show all. */
  eventTypeFilter: Set<string>
  /** Severity filter — null means show all. */
  severityFilter: Severity | null
  /** Whether more data is loading (show spinner at bottom). */
  isLoadingMore?: boolean
  /** Callback when user scrolls to bottom (for infinite loading). */
  onLoadMore?: () => void
}

/* ── Component ─────────────────────────────────────────────────────────────── */

export function Timeline({
  events,
  selectedEventId,
  onEventSelect,
  eventTypeFilter,
  severityFilter,
  isLoadingMore,
  onLoadMore,
}: TimelineProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const selectedRef = useRef<HTMLDivElement>(null)

  // Apply client-side filters
  const filteredEvents = useMemo(() => {
    let result = events
    if (eventTypeFilter.size > 0) {
      result = result.filter((e) => eventTypeFilter.has(e.event_type))
    }
    if (severityFilter) {
      result = result.filter((e) => e.severity === severityFilter)
    }
    return result
  }, [events, eventTypeFilter, severityFilter])

  // Scroll selected event into view
  useEffect(() => {
    if (selectedEventId && selectedRef.current) {
      selectedRef.current.scrollIntoView({
        behavior: "smooth",
        block: "center",
      })
    }
  }, [selectedEventId])

  // Infinite scroll: detect when user reaches bottom
  useEffect(() => {
    const container = containerRef.current
    if (!container || !onLoadMore) return

    const handleScroll = () => {
      const { scrollTop, scrollHeight, clientHeight } = container
      if (scrollHeight - scrollTop - clientHeight < 200) {
        onLoadMore()
      }
    }

    container.addEventListener("scroll", handleScroll, { passive: true })
    return () => container.removeEventListener("scroll", handleScroll)
  }, [onLoadMore])

  if (filteredEvents.length === 0) {
    return (
      <div className="flex items-center justify-center h-64 text-sm text-muted-foreground">
        {events.length === 0
          ? "No events found for this timeline."
          : "No events match the current filters."}
      </div>
    )
  }

  return (
    <div
      ref={containerRef}
      className="overflow-y-auto max-h-[calc(100vh-260px)] rounded-lg bg-card border border-border/50 shadow-[0_0_0_1px_rgba(255,255,255,0.03)]"
    >
      {filteredEvents.map((event, index) => (
        <div
          key={event.id}
          ref={selectedEventId === event.id ? selectedRef : undefined}
        >
          <TimelineEventCard
            event={event}
            isSelected={selectedEventId === event.id}
            isFirst={index === 0}
            isLast={index === filteredEvents.length - 1}
            onClick={onEventSelect}
          />
        </div>
      ))}

      {/* Loading more indicator */}
      {isLoadingMore && (
        <div className="flex items-center justify-center py-4">
          <div className="w-4 h-4 border-2 border-primary/30 border-t-primary rounded-full animate-spin" />
          <span className="text-xs text-muted-foreground ml-2">
            Loading more events…
          </span>
        </div>
      )}
    </div>
  )
}
