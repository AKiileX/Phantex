// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — InvestigationPage: forensic investigation timeline (O3).
 *
 * Routes:
 *   /investigate/alert/:id  → events ±5 min around alert
 *   /investigate/agent/:id  → agent activity timeline with zoom
 *
 * Features:
 *   - Vertical timeline with severity-coded dots and event type icons
 *   - Event type + severity filters
 *   - Time range zoom (agent mode: 1h → 72h)
 *   - Click event → detail panel (full JSON, ATLAS, trust score)
 *   - Data source availability badges
 *   - Infinite scroll for large timelines
 *
 * Security:
 *   - Requires analyst or admin role (enforced by ProtectedRoute in routes.tsx)
 *   - All text rendered via React (auto-escaped, prevents XSS)
 *   - JSON payloads displayed in <pre> with no dangerouslySetInnerHTML
 *
 * @module pages/InvestigationPage
 */

import { useState, useMemo, useCallback } from "react"
import { useParams, useNavigate, Link } from "react-router-dom"
import {
  ArrowLeft,
  Search,
  AlertTriangle,
  HelpCircle,
} from "lucide-react"
import { useAgentTimeline, useAlertTimeline } from "@/api/timeline"
import type { TimelineRange } from "@/api/timeline"
import { Timeline } from "@/components/investigation/Timeline"
import { TimelineControls } from "@/components/investigation/TimelineControls"
import { EventDetailPanel } from "@/components/investigation/EventDetailPanel"
import type { TimelineEvent as TEvent, Severity } from "@/types"

/* ── Validation ────────────────────────────────────────────────────────────── */

/** Strict UUID v4 — blocks path-traversal, injection, and garbage IDs. */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/* ── Component ─────────────────────────────────────────────────────────────── */

export function InvestigationPage() {
  const { type, id } = useParams<{ type: string; id: string }>()
  const navigate = useNavigate()

  const isAgent = type === "agent"
  const isAlert = type === "alert"

  // Validate route params — id must be a valid UUID (defence-in-depth)
  if (!id || (!isAgent && !isAlert) || !UUID_RE.test(id)) {
    return (
      <div className="flex flex-col items-center justify-center h-64 gap-3">
        <AlertTriangle size={32} className="text-severity-medium" />
        <p className="text-sm text-muted-foreground">
          Invalid investigation URL. Expected /investigate/agent/:id or /investigate/alert/:id
        </p>
        <Link
          to="/alerts"
          className="text-xs text-primary hover:underline"
        >
          ← Back to Alerts
        </Link>
      </div>
    )
  }

  return (
    <InvestigationContent
      type={isAgent ? "agent" : "alert"}
      id={id}
      navigate={navigate}
    />
  )
}

/* ── Inner component (after param validation) ──────────────────────────────── */

interface InvestigationContentProps {
  type: "agent" | "alert"
  id: string
  navigate: ReturnType<typeof useNavigate>
}

function InvestigationContent({ type, id, navigate }: InvestigationContentProps) {
  /* ── State ──────────────────────────────────────────── */
  const [range, setRange] = useState<TimelineRange>("24h")
  const [selectedEvent, setSelectedEvent] = useState<TEvent | null>(null)
  const [eventTypeFilter, setEventTypeFilter] = useState<Set<string>>(new Set())
  const [severityFilter, setSeverityFilter] = useState<Severity | null>(null)
  const [showGuide, setShowGuide] = useState(false)

  /* ── Data fetching ──────────────────────────────────── */
  const agentQuery = useAgentTimeline(
    { agentId: id, range, limit: 100 },
    type === "agent",
  )
  const alertQuery = useAlertTimeline(
    { alertId: id, limit: 100 },
    type === "alert",
  )

  const query = type === "agent" ? agentQuery : alertQuery
  const isLoading = query.isLoading
  const isError = query.isError

  // Flatten infinite query pages or use single query data
  const timelineData = useMemo(() => {
    if (type === "agent" && agentQuery.data) {
      // Infinite query — flatten pages
      const pages = "pages" in agentQuery.data ? agentQuery.data.pages : []
      const events = pages.flatMap((p) => p.events)
      const lastPage = pages[pages.length - 1]
      return {
        events,
        sessions: lastPage?.sessions ?? [],
        dataSources: lastPage?.data_sources ?? [],
        totalEvents: lastPage?.total_events ?? events.length,
        hasMore: lastPage?.has_more ?? false,
      }
    }
    if (type === "alert" && alertQuery.data) {
      return {
        events: alertQuery.data.events,
        sessions: alertQuery.data.sessions,
        dataSources: alertQuery.data.data_sources,
        totalEvents: alertQuery.data.total_events,
        hasMore: false,
      }
    }
    return { events: [], sessions: [], dataSources: [], totalEvents: 0, hasMore: false }
  }, [type, agentQuery.data, alertQuery.data])

  /* ── Callbacks ──────────────────────────────────────── */
  const handleEventSelect = useCallback((event: TEvent) => {
    setSelectedEvent((prev) => (prev?.id === event.id ? null : event))
  }, [])

  const handleCloseDetail = useCallback(() => {
    setSelectedEvent(null)
  }, [])

  const handleLoadMore = useCallback(() => {
    if (
      type === "agent" &&
      "hasNextPage" in agentQuery &&
      agentQuery.hasNextPage &&
      !agentQuery.isFetchingNextPage
    ) {
      void agentQuery.fetchNextPage()
    }
  }, [type, agentQuery])

  /* ── Render ──────────────────────────────────────────── */
  return (
    <div className="space-y-4 animate-fade-in">
      {/* ── Header ────────────────────────────────────── */}
      <div className="flex items-center gap-3">
        <button
          onClick={() => navigate(-1)}
          className="p-1.5 rounded-md hover:bg-surface-2 text-muted-foreground hover:text-foreground transition-colors cursor-pointer"
          aria-label="Go back"
        >
          <ArrowLeft size={16} />
        </button>
        <div>
          <h1 className="text-lg font-semibold text-foreground tracking-tight">
            <Search size={16} className="inline mr-1.5 opacity-60" />
            {type === "agent" ? "Agent Investigation" : "Alert Investigation"}
          </h1>
          <p className="text-xs text-muted-foreground font-mono">
            {type === "agent" ? "Agent" : "Alert"}: {id}
          </p>
        </div>
        <button onClick={() => setShowGuide(!showGuide)} className="ml-auto flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"><HelpCircle size={14} />{showGuide ? "Hide Guide" : "How does this work?"}</button>
      </div>

      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5 space-y-3 text-sm text-muted-foreground">
          <h3 className="text-base font-semibold text-foreground">How does Investigation work?</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Timeline Engine</p>
              <p>Builds a chronological timeline by querying <code className="text-xs bg-white/5 px-1 rounded">useAgentTimeline</code> or <code className="text-xs bg-white/5 px-1 rounded">useAlertTimeline</code> depending on investigation type. Events are fetched with infinite scroll and displayed on a visual timeline strip.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Time Range Control</p>
              <p>Selectable ranges: 1h, 6h, 24h, 7d, 30d. For agent investigations, events are scoped to that agent's PAID. For alert investigations, the timeline shows the alert's triggering event and surrounding context.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Filter Controls</p>
              <p>Filter by event type (multi-select) and severity level. The timeline dynamically updates — grayed-out events still show position for context but filtered events are highlighted. Data source indicators show which backends contributed.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Event Detail Panel</p>
              <p>Click any timeline event to open a side panel with full event metadata, raw JSON payload, and linked alerts. The split-pane view lets you scrub the timeline while examining individual events.</p>
            </div>
          </div>
        </div>
      )}

      {/* ── Controls ──────────────────────────────────── */}
      {!isLoading && !isError && (
        <TimelineControls
          events={timelineData.events}
          eventTypeFilter={eventTypeFilter}
          onEventTypeFilterChange={setEventTypeFilter}
          severityFilter={severityFilter}
          onSeverityFilterChange={setSeverityFilter}
          range={type === "agent" ? range : undefined}
          onRangeChange={type === "agent" ? setRange : undefined}
          dataSources={timelineData.dataSources}
          totalEvents={timelineData.totalEvents}
        />
      )}

      {/* ── Main content: timeline + detail panel ─────── */}
      <div className="flex gap-0">
        {/* Timeline */}
        <div className={`transition-all duration-200 ${selectedEvent ? "flex-1 min-w-0" : "w-full"}`}>
          {isLoading ? (
            <div className="flex items-center justify-center h-64">
              <div className="w-5 h-5 border-2 border-primary/30 border-t-primary rounded-full animate-spin" />
              <span className="text-sm text-muted-foreground ml-3">
                Assembling forensic timeline…
              </span>
            </div>
          ) : isError ? (
            <div className="flex flex-col items-center justify-center h-64 gap-2">
              <AlertTriangle size={24} className="text-severity-medium" />
              <p className="text-sm text-muted-foreground">
                Failed to load timeline data. The {type} may not exist or you lack permissions.
              </p>
              <button
                onClick={() => query.refetch()}
                className="text-xs text-primary hover:underline cursor-pointer"
              >
                Retry
              </button>
            </div>
          ) : (
            <Timeline
              events={timelineData.events}
              selectedEventId={selectedEvent?.id ?? null}
              onEventSelect={handleEventSelect}
              eventTypeFilter={eventTypeFilter}
              severityFilter={severityFilter}
              isLoadingMore={
                type === "agent" && "isFetchingNextPage" in agentQuery
                  ? agentQuery.isFetchingNextPage
                  : false
              }
              onLoadMore={timelineData.hasMore ? handleLoadMore : undefined}
            />
          )}
        </div>

        {/* Detail panel */}
        {selectedEvent && (
          <div className="w-[400px] flex-shrink-0 h-[calc(100vh-200px)] sticky top-4">
            <EventDetailPanel
              event={selectedEvent}
              onClose={handleCloseDetail}
            />
          </div>
        )}
      </div>
    </div>
  )
}
