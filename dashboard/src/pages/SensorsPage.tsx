// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Sensor fleet page (enterprise data grid).
 *
 * Dense, filterable sensor list with health status indicators.
 * Cursor pagination, live mode refresh, click-to-detail.
 * Columns: Sensor ID, Host, Status, Probes, Events Sent, Drops, CPU, Last Heartbeat.
 */

import { useState, useMemo } from "react"
import { useNavigate } from "react-router-dom"
import { Radio, Search, ChevronRight, ChevronLeft, X, Wifi, WifiOff, HardDrive, HelpCircle } from "lucide-react"
import { useSensors, type SensorFilters } from "@/api/sensors"
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table"
import { SortableHead } from "@/components/ui/sortable-head"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { timeAgo } from "@/lib/utils"
import { useSort } from "@/hooks/useSort"

const STATUS_OPTIONS = ["online", "degraded", "offline"] as const

/** Inline OS icons */
function LinuxIcon({ size = 14, className = "" }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" className={className}>
      <path d="M12.5 2C10 2 8.2 4.1 8.2 7c0 1.3.4 2.5 1 3.5-.6.4-1 .8-1.5 1.3C6.5 13 6 14.2 6 15.5c0 .3 0 .6.1.9C4.8 17 4 17.8 4 19c0 1.7 2.2 3 5 3 1.5 0 2.8-.3 3.8-.9 1 .6 2.3.9 3.8.9 2.8 0 5-1.3 5-3 0-1.2-.8-2-2.1-2.6.1-.3.1-.6.1-.9 0-1.3-.5-2.5-1.7-3.7-.5-.5-.9-.9-1.5-1.3.6-1 1-2.2 1-3.5C17.4 4.1 15.6 2 13.1 2h-.6z" />
    </svg>
  )
}

function WindowsIcon({ size = 14, className = "" }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" className={className}>
      <path d="M3 5.5l7.5-1V11H3V5.5zm0 7H10.5v6.5L3 17.5V12.5zm8.5-8.2L21 3v8H11.5V4.3zm0 8.2H21v8l-9.5-1.3V12.5z" />
    </svg>
  )
}

function AppleIcon({ size = 14, className = "" }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" className={className}>
      <path d="M18.7 19.5c-.9 1.2-1.8 2.4-3.3 2.4-1.4 0-1.9-.9-3.5-.9-1.6 0-2.2.9-3.5.9-1.4 0-2.5-1.3-3.4-2.5C3.2 16.8 2 13.3 3.9 11c.9-1.2 2.4-2 3.9-2 1.4 0 2.3.9 3.5.9 1.1 0 1.8-.9 3.5-.9 1.3 0 2.6.7 3.5 1.8-3.1 1.7-2.6 6 .5 7.1-.5 1-1 1.7-1.5 2.2l1.4.4zM15 4c.1-1.6-.4-3.1-1.2-4.2-.9 1-2 1.8-2 3.3 0 1.5 1.2 2.4 1.7 2.4.6 0 1.4-.8 1.5-1.5z" />
    </svg>
  )
}

function OsIcon({ osType, size = 14 }: { osType: string | null; size?: number }) {
  const os = (osType ?? "").toLowerCase()
  if (os.includes("linux") || os.includes("ubuntu") || os.includes("debian"))
    return <LinuxIcon size={size} className="text-[#FCC624]" />
  if (os.includes("windows") || os.includes("win"))
    return <WindowsIcon size={size} className="text-[#00A4EF]" />
  if (os.includes("darwin") || os.includes("macos") || os.includes("mac"))
    return <AppleIcon size={size} className="text-muted-foreground" />
  return <HardDrive size={size} className="text-muted-foreground" />
}

function statusVariant(s: string): "default" | "medium" | "critical" {
  if (s === "online") return "default"
  if (s === "degraded") return "medium"
  return "critical"
}

export function SensorsPage() {
  const navigate = useNavigate()

  // ── Filter state ───────────────────────────────────────────
  const [search, setSearch] = useState("")
  const [statusFilter, setStatusFilter] = useState<string | undefined>()
  const [cursorStack, setCursorStack] = useState<string[]>([])
  const [currentCursor, setCurrentCursor] = useState<string | undefined>()
  const [liveMode, setLiveMode] = useState(true)
  const [showGuide, setShowGuide] = useState(false)

  const filters: SensorFilters = useMemo(
    () => ({
      ...(search ? { search } : {}),
      ...(statusFilter ? { status: statusFilter } : {}),
      ...(currentCursor ? { cursor: currentCursor } : {}),
      limit: 50,
    }),
    [search, statusFilter, currentCursor],
  )

  const refetchMs = liveMode ? 5_000 : 30_000
  const { data, isLoading, isFetching } = useSensors(filters, refetchMs)
  const sensors = data?.items ?? []
  const hasMore = data?.has_more ?? false
  const hasFilters = !!statusFilter || !!search

  // ── Client-side sort ───────────────────────────────────────
  const { sorted: sortedSensors, sortState, toggleSort } = useSort(sensors, {
    key: "last_heartbeat",
    dir: "desc",
  })

  // ── Pagination handlers ────────────────────────────────────
  function handleNextPage() {
    if (data?.next_cursor) {
      setCursorStack((prev) => [...prev, currentCursor ?? ""])
      setCurrentCursor(data.next_cursor)
    }
  }

  function handlePrevPage() {
    setCursorStack((prev) => {
      const next = [...prev]
      const prevCursor = next.pop()
      setCurrentCursor(prevCursor || undefined)
      return next
    })
  }

  function clearFilters() {
    setSearch("")
    setStatusFilter(undefined)
    setCursorStack([])
    setCurrentCursor(undefined)
  }

  function updateFilter(setter: (v: string | undefined) => void, value: string | undefined) {
    setter(value)
    setCursorStack([])
    setCurrentCursor(undefined)
  }

  const pageNumber = cursorStack.length + 1

  // ── Stats summary ──────────────────────────────────────────
  const onlineCount = sensors.filter(s => s.status === "online").length
  const degradedCount = sensors.filter(s => s.status === "degraded").length
  const offlineCount = sensors.filter(s => s.status === "offline").length
  const totalDrops = sensors.reduce((sum, s) => sum + (s.events_dropped ?? 0), 0)

  return (
    <div className="space-y-4 animate-fade-in">
      {/* ── Toolbar ──────────────────────────────────── */}
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div className="flex items-center gap-3">
          <div>
            <h1 className="text-lg font-semibold text-foreground tracking-tight">Sensor Fleet</h1>
            <p className="text-sm text-muted-foreground">
              {sensors.length} sensors · {onlineCount} online
              {degradedCount > 0 ? ` · ${degradedCount} degraded` : ""}
              {offlineCount > 0 ? ` · ${offlineCount} offline` : ""}
              {totalDrops > 0 ? ` · ${totalDrops.toLocaleString()} drops` : ""}
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

          {/* Search */}
          <div className="relative">
            <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
            <input
              type="text"
              placeholder="Search sensor or host…"
              value={search}
              onChange={(e) => updateFilter(setSearch as (v: string | undefined) => void, e.target.value || undefined)}
              className="h-8 w-48 rounded-md border border-border bg-surface-2 pl-8 pr-3 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring"
            />
          </div>

          {/* Status filter */}
          <select
            value={statusFilter ?? ""}
            onChange={(e) => updateFilter(setStatusFilter, e.target.value || undefined)}
            className="h-8 rounded-md border border-border bg-surface-2 px-2.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-ring cursor-pointer"
          >
            <option value="">All statuses</option>
            {STATUS_OPTIONS.map((s) => (
              <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
            ))}
          </select>

          {/* Clear filters */}
          {hasFilters && (
            <Button variant="ghost" size="sm" onClick={clearFilters} className="gap-1 text-xs">
              <X size={12} /> Clear
            </Button>
          )}
        </div>
      </div>

      {/* ── Table ─────────────────────────────────── */}
      <div className="bg-card backdrop-blur-xl border border-border/50 rounded-xl overflow-hidden shadow-[0_0_0_1px_rgba(255,255,255,0.03)]">
        <Table>
          <TableHeader>
            <TableRow>
              <SortableHead sortKey="sensor_id" activeKey={sortState.key} activeDir={sortState.dir} onSort={toggleSort}>Sensor ID</SortableHead>
              <TableHead className="w-10">OS</TableHead>
              <SortableHead sortKey="hostname" activeKey={sortState.key} activeDir={sortState.dir} onSort={toggleSort}>Host</SortableHead>
              <SortableHead sortKey="status" activeKey={sortState.key} activeDir={sortState.dir} onSort={toggleSort} className="w-24">Status</SortableHead>
              <SortableHead sortKey="probes_loaded" activeKey={sortState.key} activeDir={sortState.dir} onSort={toggleSort} className="w-20">Probes</SortableHead>
              <SortableHead sortKey="events_sent" activeKey={sortState.key} activeDir={sortState.dir} onSort={toggleSort} className="w-28">Events Sent</SortableHead>
              <SortableHead sortKey="events_dropped" activeKey={sortState.key} activeDir={sortState.dir} onSort={toggleSort} className="w-20">Drops</SortableHead>
              <SortableHead sortKey="cpu_percent" activeKey={sortState.key} activeDir={sortState.dir} onSort={toggleSort} className="w-16">CPU</SortableHead>
              <SortableHead sortKey="last_heartbeat" activeKey={sortState.key} activeDir={sortState.dir} onSort={toggleSort} className="w-32">Last Heartbeat</SortableHead>
              <TableHead className="w-8" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={10} className="text-center py-12 text-muted-foreground text-sm">
                  Loading sensors…
                </TableCell>
              </TableRow>
            ) : sensors.length === 0 ? (
              <TableRow>
                <TableCell colSpan={10} className="text-center py-12">
                  <div className="flex flex-col items-center gap-3">
                    <div className="flex h-12 w-12 items-center justify-center rounded-full bg-white/[0.03]">
                      <WifiOff size={22} className="text-muted-foreground" />
                    </div>
                    <p className="text-sm text-muted-foreground">
                      {hasFilters ? "No sensors match filters" : "No sensors registered"}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {hasFilters ? "Try broadening your search." : "Deploy a sensor to start monitoring AI agents."}
                    </p>
                  </div>
                </TableCell>
              </TableRow>
            ) : (
              sortedSensors.map((sensor) => (
                <TableRow
                  key={sensor.id}
                  className="cursor-pointer group"
                  onClick={() => navigate(`/sensors/${sensor.id}`)}
                >
                  <TableCell className="font-mono text-xs text-foreground">
                    {sensor.sensor_id}
                  </TableCell>
                  <TableCell>
                    <OsIcon osType={sensor.os_type} size={18} />
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {sensor.hostname ?? "—"}
                  </TableCell>
                  <TableCell>
                    <Badge variant={statusVariant(sensor.status)}>
                      <span className="flex items-center gap-1">
                        {sensor.status === "online" ? <Wifi size={10} /> : <WifiOff size={10} />}
                        {sensor.status}
                      </span>
                    </Badge>
                  </TableCell>
                  <TableCell className="font-mono text-xs text-foreground">
                    {sensor.probes_loaded}/{sensor.probes_total > 0 ? sensor.probes_total : sensor.probes_loaded}
                  </TableCell>
                  <TableCell className="font-mono text-xs text-foreground">
                    {sensor.events_sent?.toLocaleString() ?? "0"}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    <span className={sensor.events_dropped > 0 ? "text-severity-high" : "text-muted-foreground"}>
                      {sensor.events_dropped?.toLocaleString() ?? "0"}
                    </span>
                  </TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">
                    {sensor.cpu_percent != null ? `${sensor.cpu_percent.toFixed(1)}%` : "—"}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                    {timeAgo(sensor.last_heartbeat)}
                  </TableCell>
                  <TableCell>
                    <ChevronRight size={14} className="text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      {/* ── Pagination ────────────────────────────── */}
      {(hasMore || cursorStack.length > 0) && (
        <div className="flex items-center justify-between">
          <p className="text-xs text-muted-foreground">
            Page {pageNumber}
          </p>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={cursorStack.length === 0}
              onClick={handlePrevPage}
              className="gap-1"
            >
              <ChevronLeft size={14} /> Previous
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={!hasMore}
              onClick={handleNextPage}
              className="gap-1"
            >
              Next <ChevronRight size={14} />
            </Button>
          </div>
        </div>
      )}

      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5 space-y-3 text-sm text-muted-foreground">
          <h3 className="text-base font-semibold text-foreground">How does the Sensor Fleet work?</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Sensor Architecture</p>
              <p>Sensors are lightweight agents deployed on hosts running AI workloads. They hook into AI framework processes (LangChain, AutoGen, CrewAI, etc.) and stream events via gRPC to the Go gateway. Each sensor reports heartbeats, discovered agents, and telemetry.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Data Source</p>
              <p>Calls <code className="text-xs bg-white/5 px-1 rounded">GET /api/v1/sensors</code> with cursor pagination. Backend <code className="text-xs bg-white/5 px-1 rounded">sensors.py</code> queries PostgreSQL with RLS isolation. Each sensor shows status, version, drop count, and the agents it has discovered.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Health States</p>
              <p><strong>Online</strong> — heartbeat received within the threshold. <strong>Degraded</strong> — elevated drop rate or intermittent connectivity. <strong>Offline</strong> — no heartbeat received. The fleet status bar shows real-time counts and total event drops across all sensors.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Live Refresh</p>
              <p>Live mode auto-refreshes the sensor list every 10 seconds so you see status changes in near real-time. Click any sensor row to drill into its detail page with per-sensor metrics, discovered agents, and configuration.</p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
