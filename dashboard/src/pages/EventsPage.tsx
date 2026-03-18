// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Event feed page (enterprise data grid).
 *
 * Virtualized, filterable event list with severity color coding.
 * Infinite scroll via VirtualTable (100K memory cap), live mode toggle,
 * click-to-detail. Columns: Timestamp, Severity, Event Type, Agent.
 */

import { useState, useMemo, useCallback } from "react"
import { useNavigate } from "react-router-dom"
import { Activity, Search, ChevronRight, X, Radio, Shield, HelpCircle } from "lucide-react"
import { useInfiniteEvents, type EventFilters } from "@/api/events"
import { VirtualTable, type VirtualTableColumn } from "@/components/ui/virtual-table"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { formatDate } from "@/lib/utils"
import { useSort } from "@/hooks/useSort"
import type { EventSummary } from "@/types"

const MAX_ITEMS = 100_000

const SEVERITY_OPTIONS = ["critical", "high", "medium", "low", "info"] as const
const EVENT_TYPE_OPTIONS = [
  "PROCESS_EXEC",
  "PROCESS_EXIT",
  "FILE_OPEN",
  "FILE_READ",
  "FILE_WRITE",
  "NETWORK_CONNECT",
  "NETWORK_DNS",
  "MEMORY_MAP",
  "TOOL_CALL",
  "TOOL_RESPONSE",
  "AGENT_DISCOVERED",
  "AGENT_TERMINATED",
] as const

function buildColumns(): VirtualTableColumn<EventSummary>[] {
  return [
    {
      key: "timestamp",
      header: "Timestamp",
      width: "180px",
      render: (event) => (
        <span className="text-xs text-muted-foreground whitespace-nowrap font-mono">
          {formatDate(event.timestamp)}
        </span>
      ),
    },
    {
      key: "severity",
      header: "Severity",
      width: "100px",
      render: (event) => (
        <Badge variant={event.severity as "critical" | "high" | "medium" | "low" | "info"}>
          {event.severity}
        </Badge>
      ),
    },
    {
      key: "event_type",
      header: "Event Type",
      width: "1fr",
      render: (event) => (
        <span className="font-mono text-xs text-foreground">{event.event_type}</span>
      ),
    },
    {
      key: "agent_id",
      header: "Agent",
      width: "1fr",
      render: (event) => (
        <span className="font-mono text-xs text-muted-foreground">
          {event.agent_id ? `${event.agent_id.slice(0, 8)}…` : "—"}
        </span>
      ),
    },
    {
      key: "chevron",
      header: "",
      width: "32px",
      render: () => (
        <ChevronRight size={14} className="text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
      ),
    },
  ]
}

export function EventsPage() {
  const navigate = useNavigate()

  // ── Filter state ───────────────────────────────────────────
  const [search, setSearch] = useState("")
  const [severityFilter, setSeverityFilter] = useState<string | undefined>()
  const [eventTypeFilter, setEventTypeFilter] = useState<string | undefined>()
  const [showGuide, setShowGuide] = useState(false)
  const [sinceFilter, setSinceFilter] = useState<string | undefined>()
  const [liveMode, setLiveMode] = useState(false)
  const [agentOnly, setAgentOnly] = useState(true)

  const filters: Omit<EventFilters, "cursor"> = useMemo(
    () => ({
      ...(search ? { agent_id: search } : {}),
      ...(severityFilter ? { severity: severityFilter } : {}),
      ...(eventTypeFilter ? { event_type: eventTypeFilter } : {}),
      ...(sinceFilter ? { since: sinceFilter } : {}),
      agent_only: agentOnly,
      limit: 50,
    }),
    [search, severityFilter, eventTypeFilter, sinceFilter, agentOnly],
  )

  // ── Infinite query for virtual scroll ──────────────────────
  const refetchMs = liveMode ? 2_000 : 10_000
  const {
    data: infiniteData,
    isLoading,
    isFetching,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
  } = useInfiniteEvents(filters, refetchMs)

  // Flatten all pages into one array, enforcing memory cap
  const events = useMemo(() => {
    if (!infiniteData?.pages) return []
    const all = infiniteData.pages.flatMap((page) => page.items)
    return all.length > MAX_ITEMS ? all.slice(0, MAX_ITEMS) : all
  }, [infiniteData])

  const hasFilters = !!severityFilter || !!eventTypeFilter || !!sinceFilter || !!search || !agentOnly

  // ── Client-side sort ───────────────────────────────────────
  const { sorted: sortedEvents } = useSort(events, {
    key: "timestamp",
    dir: "desc",
  })

  // ── Infinite scroll trigger ────────────────────────────────
  const handleEndReached = useCallback(() => {
    if (hasNextPage && !isFetchingNextPage) {
      void fetchNextPage()
    }
  }, [hasNextPage, isFetchingNextPage, fetchNextPage])

  // ── Column definitions ─────────────────────────────────────
  const columns = useMemo(() => buildColumns(), [])

  function clearFilters() {
    setSearch("")
    setSeverityFilter(undefined)
    setEventTypeFilter(undefined)
    setSinceFilter(undefined)
    setAgentOnly(true)
  }

  function updateFilter(setter: (v: string | undefined) => void, value: string | undefined) {
    setter(value)
  }

  // ── Time presets ───────────────────────────────────────────
  function setTimePreset(hours: number) {
    const d = new Date()
    d.setHours(d.getHours() - hours)
    updateFilter(setSinceFilter, d.toISOString())
  }

  // ── Empty state ────────────────────────────────────────────
  const emptyState = (
    <div className="flex flex-col items-center gap-3 py-12">
      <div className="flex h-12 w-12 items-center justify-center rounded-full bg-white/[0.03]">
        <Activity size={22} className="text-muted-foreground" />
      </div>
      <p className="text-sm text-muted-foreground">
        {hasFilters ? "No events match filters" : "No events recorded"}
      </p>
      <p className="text-xs text-muted-foreground">
        {agentOnly && !hasFilters
          ? "No AI agent activity detected yet. Toggle \"All Events\" to see raw sensor data."
          : hasFilters ? "Try broadening your search." : "Events appear once sensors report."}
      </p>
    </div>
  )

  return (
    <div className="space-y-4 animate-fade-in">
      {/* ── Toolbar ──────────────────────────────────── */}
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div className="flex items-center gap-3">
          <div>
            <h1 className="text-lg font-semibold text-foreground tracking-tight">Event Feed</h1>
            <p className="text-sm text-muted-foreground">
              {events.length.toLocaleString()} events
              {isFetching && !isLoading ? " · refreshing…" : ""}
            </p>
          </div>
          <button onClick={() => setShowGuide(!showGuide)} className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"><HelpCircle size={14} />{showGuide ? "Hide Guide" : "How does this work?"}</button>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {/* Live mode toggle */}
          <Button
            variant={liveMode ? "default" : "outline"}
            size="sm"
            onClick={() => setLiveMode(!liveMode)}
            className="gap-1.5 text-xs"
          >
            <Radio size={12} />
            {liveMode ? "Live" : "Live"}
          </Button>

          {/* Agent-only toggle */}
          <Button
            variant={agentOnly ? "default" : "outline"}
            size="sm"
            onClick={() => setAgentOnly(!agentOnly)}
            className="gap-1.5 text-xs"
          >
            <Shield size={12} />
            {agentOnly ? "Agent Only" : "All Events"}
          </Button>

          {/* Agent ID search */}
          <div className="relative">
            <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
            <input
              type="text"
              placeholder="Filter by agent ID…"
              value={search}
              onChange={(e) => updateFilter(setSearch as (v: string | undefined) => void, e.target.value || undefined)}
              className="h-8 w-48 rounded-md border border-border bg-surface-2 pl-8 pr-3 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring"
            />
          </div>

          {/* Severity filter */}
          <select
            value={severityFilter ?? ""}
            onChange={(e) => updateFilter(setSeverityFilter, e.target.value || undefined)}
            className="h-8 rounded-md border border-border bg-surface-2 px-2.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-ring cursor-pointer"
          >
            <option value="">All severities</option>
            {SEVERITY_OPTIONS.map((s) => (
              <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
            ))}
          </select>

          {/* Event type filter */}
          <select
            value={eventTypeFilter ?? ""}
            onChange={(e) => updateFilter(setEventTypeFilter, e.target.value || undefined)}
            className="h-8 rounded-md border border-border bg-surface-2 px-2.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-ring cursor-pointer"
          >
            <option value="">All types</option>
            {EVENT_TYPE_OPTIONS.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>

          {/* Time range presets */}
          <select
            value={sinceFilter ?? ""}
            onChange={(e) => {
              const v = e.target.value
              if (v === "") updateFilter(setSinceFilter, undefined)
              else setTimePreset(parseInt(v, 10))
            }}
            className="h-8 rounded-md border border-border bg-surface-2 px-2.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-ring cursor-pointer"
          >
            <option value="">All time</option>
            <option value="1">Last 1 hour</option>
            <option value="6">Last 6 hours</option>
            <option value="24">Last 24 hours</option>
            <option value="168">Last 7 days</option>
          </select>

          {/* Clear filters */}
          {hasFilters && (
            <Button variant="ghost" size="sm" onClick={clearFilters} className="gap-1 text-xs">
              <X size={12} /> Clear
            </Button>
          )}
        </div>
      </div>

      {/* ── Virtualized table ─────────────────────────── */}
      <VirtualTable<EventSummary>
        items={sortedEvents}
        columns={columns}
        getItemKey={(event) => event.id}
        rowHeight={44}
        overscan={20}
        maxItems={MAX_ITEMS}
        autoScroll={liveMode}
        isLoading={isLoading}
        emptyState={emptyState}
        onRowClick={(event) => navigate(`/events/${event.id}`)}
        onEndReached={handleEndReached}
        endReachedThreshold={500}
      />

      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5 space-y-3 text-sm text-muted-foreground">
          <h3 className="text-base font-semibold text-foreground">How does the Event Feed work?</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Data Pipeline</p>
              <p>Events flow through: <strong>Sensor → Gateway (Go/gRPC) → Kafka → Consumer → ClickHouse</strong>. The dashboard calls <code className="text-xs bg-white/5 px-1 rounded">GET /api/v1/events</code> with infinite scroll pagination. Events are stored in ClickHouse for high-throughput analytics (54K+ events observed).</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Event Types</p>
              <p>Includes AGENT_DISCOVERED, TOOL_CALL, LLM_REQUEST, PROMPT_INJECTION, SANDBOX_VIOLATION, and more. Each event carries severity (info–critical), agent ID, timestamp, and structured metadata from the originating sensor.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Live Mode</p>
              <p>The <strong>LIVE</strong> toggle enables 5-second polling for real‑time event streaming. <strong>Agent Only</strong> filters to AI-agent-originated events, hiding raw sensor telemetry. Both are server-side filters applied before data reaches the frontend.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Virtual Scrolling</p>
              <p>Uses a virtualized table with a 100K-row memory cap. Only visible rows are rendered in the DOM, enabling smooth scrolling through tens of thousands of events. Click any row to see full event detail with raw JSON payload.</p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
