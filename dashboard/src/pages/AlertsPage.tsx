// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Alert Panel (O1+O2 — SOC Hunting upgrade).
 *
 * Full-featured SOC alert triage interface:
 *   - Time range filters (15m / 1h / 6h / 24h / 7d / All)
 *   - Full-text keyword search (server-side)
 *   - Severity quick-filter pills
 *   - Status filter tabs with live count badges
 *   - Group by Agent toggle
 *   - Virtual scrolling via @tanstack/react-virtual (50K+ rows at 60fps)
 *   - Alert grouping by rule + agent within 5-min window
 *   - Correlation graph: force-directed mini-graph of linked alerts (O2)
 *   - Live mode toggle (2s polling vs 10s default)
 *   - Memory cap: 100K items max
 */

import { useState, useMemo, useCallback, useEffect, useRef } from "react"
import { useNavigate } from "react-router-dom"
import {
  Bell,
  ChevronRight,
  ChevronDown,
  ChevronUp,
  RefreshCw,
  Radio,
  Layers,
  List,
  GitBranch,
  Search,
  Clock,
  Filter,
  Server,
  AlertTriangle,
  CheckSquare,
  Square,
  XCircle,
  CheckCircle2,
  ShieldAlert,
  Eye,
  HelpCircle,
} from "lucide-react"
import { useInfiniteAlerts, useAlerts, useBulkUpdateStatus } from "@/api/alerts"
import type { AlertFilters } from "@/api/alerts"
import { VirtualTable, type VirtualTableColumn } from "@/components/ui/virtual-table"
import { AlertGroupRow } from "@/components/alerts/AlertGroupRow"
import { CorrelationPanel } from "@/components/alerts/CorrelationPanel"
import { useAlertGrouping } from "@/hooks/useAlertGrouping"
import { useAlertCorrelation } from "@/hooks/useAlertCorrelation"
import { Badge } from "@/components/ui/badge"
import { cn, timeAgo } from "@/lib/utils"
import { useSort } from "@/hooks/useSort"
import type { AlertStatus, AlertSummary } from "@/types"

/* ── Constants ────────────────────────────────────────────────────────────── */

type AlertTimeRange = "15m" | "1h" | "6h" | "24h" | "7d" | "all"
type GroupMode = "none" | "agent"

const TIME_RANGES: { key: AlertTimeRange; label: string; iso: string | null }[] = [
  { key: "15m", label: "15 min", iso: null },
  { key: "1h", label: "1 hour", iso: null },
  { key: "6h", label: "6 hours", iso: null },
  { key: "24h", label: "24 hours", iso: null },
  { key: "7d", label: "7 days", iso: null },
  { key: "all", label: "All time", iso: null },
]

const TIME_MS: Record<AlertTimeRange, number> = {
  "15m": 15 * 60_000,
  "1h": 60 * 60_000,
  "6h": 6 * 60 * 60_000,
  "24h": 24 * 60 * 60_000,
  "7d": 7 * 24 * 60 * 60_000,
  all: 0,
}

function sinceFromTimeRange(range: AlertTimeRange): string | undefined {
  if (range === "all") return undefined
  return new Date(Date.now() - TIME_MS[range]).toISOString()
}

const STATUS_FILTERS: (AlertStatus | "all")[] = [
  "all",
  "open",
  "acknowledged",
  "resolved",
  "false_positive",
]

const STATUS_LABEL: Record<string, string> = {
  all: "All",
  open: "Open",
  acknowledged: "Acknowledged",
  resolved: "Resolved",
  false_positive: "False Positive",
}

const SEVERITY_OPTIONS = ["all", "critical", "high", "medium", "low", "info"] as const
const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

const MAX_ITEMS = 100_000

/* ── Column definitions for VirtualTable ──────────────────────────────────── */

function buildColumns(navigate: ReturnType<typeof useNavigate>): VirtualTableColumn<AlertSummary>[] {
  // We don't use navigate here since onRowClick handles it,
  // but columns need to be stable
  void navigate
  return [
    {
      key: "severity",
      header: "Severity",
      width: "100px",
      render: (alert) => (
        <Badge variant={alert.severity as "critical" | "high" | "medium" | "low"}>
          {alert.severity}
        </Badge>
      ),
    },
    {
      key: "title",
      header: "Title",
      width: "1fr",
      render: (alert) => (
        <span className="text-sm text-foreground font-medium truncate">
          {alert.title}
        </span>
      ),
      className: "min-w-0",
    },
    {
      key: "status",
      header: "Status",
      width: "130px",
      render: (alert) => (
        <Badge variant="outline" className="capitalize">
          {alert.status.replaceAll("_", " ")}
        </Badge>
      ),
    },
    {
      key: "agent_id",
      header: "Agent",
      width: "90px",
      render: (alert) => (
        <span className="font-mono text-xs text-muted-foreground">
          {alert.agent_id?.slice(0, 8) ?? "—"}
        </span>
      ),
    },
    {
      key: "created_at",
      header: "Created",
      width: "100px",
      render: (alert) => (
        <span className="text-xs text-muted-foreground whitespace-nowrap">
          {timeAgo(alert.created_at)}
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

/* ── Component ────────────────────────────────────────────────────────────── */

export function AlertsPage() {
  const navigate = useNavigate()

  /* ── Filter state ──────────────────────────────────────── */
  const [statusFilter, setStatusFilter] = useState<AlertStatus | "all">("all")
  const [severityFilter, setSeverityFilter] = useState<string>("all")
  const [timeRange, setTimeRange] = useState<AlertTimeRange>("all")
  const [search, setSearch] = useState("")
  const [showGuide, setShowGuide] = useState(false)
  const [debouncedSearch, setDebouncedSearch] = useState("")
  const [live, setLive] = useState(false)
  const [grouped, setGrouped] = useState(true)
  const [groupMode, setGroupMode] = useState<GroupMode>("none")
  const [showCorrelation, setShowCorrelation] = useState(false)
  const [expandedAgents, setExpandedAgents] = useState<Set<string>>(new Set())
  const [selectedAlerts, setSelectedAlerts] = useState<Set<string>>(new Set())
  const searchTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  /* ── Debounced search ──────────────────────────────────── */
  useEffect(() => {
    if (searchTimer.current) clearTimeout(searchTimer.current)
    searchTimer.current = setTimeout(() => {
      setDebouncedSearch(search.trim())
    }, 350)
    return () => { if (searchTimer.current) clearTimeout(searchTimer.current) }
  }, [search])

  /* ── Build query filters ────────────────────────────────── */
  const filters: Omit<AlertFilters, "cursor"> = useMemo(() => {
    const f: Omit<AlertFilters, "cursor"> = { limit: 100 }
    if (statusFilter !== "all") f.status = statusFilter
    if (severityFilter !== "all") f.severity = severityFilter
    const since = sinceFromTimeRange(timeRange)
    if (since) f.since = since
    if (debouncedSearch) f.search = debouncedSearch
    return f
  }, [statusFilter, severityFilter, timeRange, debouncedSearch])

  const refetchMs = live ? 2_000 : 10_000

  /* ── Infinite query for virtual scroll ──────────────────── */
  const {
    data: infiniteData,
    isLoading,
    dataUpdatedAt,
    refetch,
    isFetching,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
  } = useInfiniteAlerts(filters, refetchMs)

  // Flatten all pages into one array
  const alerts = useMemo(() => {
    if (!infiniteData?.pages) return []
    const all = infiniteData.pages.flatMap((page) => page.items)
    return all.length > MAX_ITEMS ? all.slice(0, MAX_ITEMS) : all
  }, [infiniteData])

  // Client-side sort
  const { sorted: sortedAlerts } = useSort(alerts, {
    key: "created_at",
    dir: "desc",
  })

  /* ── Alert grouping by rule+agent ──────────────────────── */
  const { groups, isGrouped: hasGroups } = useAlertGrouping(sortedAlerts, {
    enabled: grouped && groupMode === "none",
  })

  /* ── Group by agent ─────────────────────────────────────── */
  const agentGroups = useMemo(() => {
    if (groupMode !== "agent") return null
    const map = new Map<string, { agentId: string; alerts: AlertSummary[]; worstSeverity: string }>()
    sortedAlerts.forEach((a) => {
      const key = a.agent_id ?? "unknown"
      if (!map.has(key)) {
        map.set(key, { agentId: key, alerts: [], worstSeverity: a.severity })
      }
      const g = map.get(key)!
      g.alerts.push(a)
      if ((SEVERITY_ORDER[a.severity] ?? 5) < (SEVERITY_ORDER[g.worstSeverity] ?? 5)) {
        g.worstSeverity = a.severity
      }
    })
    return Array.from(map.values()).sort(
      (a, b) => (SEVERITY_ORDER[a.worstSeverity] ?? 5) - (SEVERITY_ORDER[b.worstSeverity] ?? 5),
    )
  }, [sortedAlerts, groupMode])

  /* ── Alert correlation (O2) ─────────────────────────────── */
  const { correlation, hasCorrelations } = useAlertCorrelation(sortedAlerts)

  /* ── Badge counts (separate lightweight query) ──────────── */
  const { data: allData } = useAlerts({ limit: 100 })
  const statusCounts = useMemo(() => {
    const items = allData?.items ?? []
    const map: Record<string, number> = { all: items.length }
    for (const a of items) {
      map[a.status] = (map[a.status] ?? 0) + 1
    }
    return map
  }, [allData])

  /* ── Stats strip ────────────────────────────────────────── */
  const stats = useMemo(() => {
    const s = { total: sortedAlerts.length, open: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, agents: new Set<string>() }
    for (const a of sortedAlerts) {
      if (a.status === "open") s.open++
      if (a.severity === "critical") s.critical++
      else if (a.severity === "high") s.high++
      else if (a.severity === "medium") s.medium++
      else if (a.severity === "low") s.low++
      else if (a.severity === "info") s.info++
      if (a.agent_id) s.agents.add(a.agent_id)
    }
    return { ...s, agentCount: s.agents.size }
  }, [sortedAlerts])

  const hasCriticalOpen = useMemo(
    () => (allData?.items ?? []).some((a) => a.severity === "critical" && a.status === "open"),
    [allData],
  )

  /* ── Callbacks ──────────────────────────────────────────── */
  const handleStatusChange = useCallback((s: AlertStatus | "all") => {
    setStatusFilter(s)
  }, [])

  const handleRowClick = useCallback(
    (alert: AlertSummary) => {
      navigate(`/alerts/${alert.id}`)
    },
    [navigate],
  )

  const handleEndReached = useCallback(() => {
    if (hasNextPage && !isFetchingNextPage) {
      void fetchNextPage()
    }
  }, [hasNextPage, isFetchingNextPage, fetchNextPage])

  /* ── Column defs (stable) ──────────────────────────────── */
  const columns = useMemo(() => buildColumns(navigate), [navigate])

  /* ── Batch selection helpers ────────────────────────────── */
  const bulkUpdate = useBulkUpdateStatus()

  const toggleAlert = useCallback((id: string, e?: React.MouseEvent) => {
    e?.stopPropagation()
    setSelectedAlerts((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id); else next.add(id)
      return next
    })
  }, [])

  const toggleAll = useCallback(() => {
    if (selectedAlerts.size === sortedAlerts.length) {
      setSelectedAlerts(new Set())
    } else {
      setSelectedAlerts(new Set(sortedAlerts.map((a) => a.id)))
    }
  }, [selectedAlerts.size, sortedAlerts])

  const clearSelection = useCallback(() => setSelectedAlerts(new Set()), [])

  const handleBulkAction = useCallback((status: "acknowledged" | "resolved" | "false_positive") => {
    const ids = Array.from(selectedAlerts)
    if (ids.length === 0) return
    bulkUpdate.mutate({ alertIds: ids, status: status as AlertStatus }, {
      onSuccess: () => {
        setSelectedAlerts(new Set())
      },
    })
  }, [selectedAlerts, bulkUpdate])

  const isAllSelected = sortedAlerts.length > 0 && selectedAlerts.size === sortedAlerts.length

  /* ── Checkbox column prepended to VirtualTable ─────────── */
  const columnsWithCheckbox = useMemo(() => [
    {
      key: "select" as const,
      header: (
        <button
          onClick={(e: React.MouseEvent) => { e.stopPropagation(); toggleAll() }}
          className="flex items-center justify-center w-5 h-5 cursor-pointer"
        >
          {isAllSelected
            ? <CheckSquare size={14} className="text-primary" />
            : <Square size={14} className="text-muted-foreground" />}
        </button>
      ) as unknown as string,
      width: "36px",
      render: (alert: AlertSummary) => (
        <button
          onClick={(e: React.MouseEvent) => toggleAlert(alert.id, e)}
          className="flex items-center justify-center w-5 h-5 cursor-pointer"
        >
          {selectedAlerts.has(alert.id)
            ? <CheckSquare size={14} className="text-primary" />
            : <Square size={14} className="text-muted-foreground/40 hover:text-muted-foreground" />}
        </button>
      ),
    },
    ...columns,
  ], [columns, selectedAlerts, isAllSelected, toggleAlert, toggleAll])

  return (
    <div className="flex gap-4 animate-fade-in">
      {/* ── Main content ──────────────────────────────────── */}
      <div className={`space-y-4 transition-all duration-200 ${showCorrelation && correlation ? "flex-1 min-w-0" : "w-full"}`}>

      {/* ── Header ────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div>
            <h1 className="text-xl font-semibold text-foreground tracking-tight">Alerts</h1>
            <p className="text-sm text-muted-foreground mt-0.5">
              Security detections from PRL rules
              {sortedAlerts.length > 0 && (
                <span className="ml-2 text-xs tabular-nums">
                  ({sortedAlerts.length.toLocaleString()} total
                  {hasGroups && groups ? `, ${groups.length} groups` : ""}
                  {groupMode === "agent" && agentGroups ? `, ${agentGroups.length} agents` : ""})
                </span>
              )}
            </p>
          </div>
          <button onClick={() => setShowGuide(!showGuide)} className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"><HelpCircle size={14} />{showGuide ? "Hide Guide" : "How does this work?"}</button>
        </div>
        <div className="flex items-center gap-2">
          {/* Live mode toggle */}
          <button
            onClick={() => setLive((v) => !v)}
            className={cn(
              "flex items-center gap-1.5 text-xs font-medium transition-all cursor-pointer px-3 py-1.5 rounded-full border",
              live
                ? "bg-status-active/10 text-status-active border-status-active/30"
                : "text-muted-foreground border-border/50 hover:text-foreground hover:border-border",
            )}
          >
            <Radio size={12} />
            {live ? "Live" : "Auto"}
          </button>

          {/* Refresh */}
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors cursor-pointer disabled:opacity-50 px-3 py-1.5"
          >
            <RefreshCw size={12} className={isFetching ? "animate-spin" : ""} />
            {dataUpdatedAt
              ? `Updated ${timeAgo(new Date(dataUpdatedAt).toISOString())}`
              : "Refresh"}
          </button>
        </div>
      </div>

      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5 space-y-3 text-sm text-muted-foreground">
          <h3 className="text-base font-semibold text-foreground">How does the Alerts Panel work?</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Alert Generation</p>
              <p>Alerts are created when events match PRL (Phantex Rule Language) detection rules. The backend <code className="text-xs bg-white/5 px-1 rounded">alerts.py</code> router serves <code className="text-xs bg-white/5 px-1 rounded">GET /api/v1/alerts</code> with cursor pagination (limit 100). Currently tracking 36 alerts across critical/high/medium severities.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">SOC Triage Workflow</p>
              <p>Status lifecycle: <strong>open → acknowledged → resolved/false_positive</strong>. Bulk actions let you select multiple alerts and change status at once. Status filter tabs show live counts for each state. Keyboard-friendly for rapid triage.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Grouping &amp; Correlation</p>
              <p><strong>Group by Rule</strong> clusters alerts sharing the same detection rule within a 5-minute window. <strong>Group by Agent</strong> shows which AI agents are generating the most alerts. The correlation panel (sidebar) renders a force-directed graph of linked alerts.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Live Mode &amp; Virtual Scroll</p>
              <p><strong>Live</strong> polls every 2 seconds for real-time SOC monitoring. <strong>Auto</strong> refreshes every 10 seconds. The table uses virtual scrolling (100K row cap) — only DOM-visible rows render, supporting 50K+ alerts at 60fps.</p>
            </div>
          </div>
        </div>
      )}

      {/* ── Stats strip ───────────────────────────────────── */}
      <div className="flex items-center gap-3 flex-wrap">
        {[
          { label: "Alerts", value: stats.total, icon: <Bell size={13} /> },
          { label: "Open", value: stats.open, icon: <AlertTriangle size={13} />, color: "text-severity-high" },
          { label: "Critical", value: stats.critical, color: "text-severity-critical" },
          { label: "High", value: stats.high, color: "text-severity-high" },
          ...(stats.medium > 0 ? [{ label: "Medium", value: stats.medium, color: "text-severity-medium" }] : []),
          ...(stats.low > 0 ? [{ label: "Low", value: stats.low, color: "text-severity-low" }] : []),
          ...(stats.info > 0 ? [{ label: "Info", value: stats.info, color: "text-muted-foreground" }] : []),
          { label: "Agents", value: stats.agentCount, icon: <Server size={13} /> },
        ].map((s) => (
          <div key={s.label} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-1/50 border border-border/30 text-xs">
            {s.icon}
            <span className="text-muted-foreground">{s.label}</span>
            <span className={cn("font-bold tabular-nums", s.color)}>{s.value}</span>
          </div>
        ))}
      </div>

      {/* ── Bulk Action Bar ──────────────────────────────────── */}
      {selectedAlerts.size > 0 && (
        <div className="flex items-center gap-3 px-4 py-2.5 rounded-xl border border-primary/30 bg-primary/5 animate-fade-in">
          <span className="text-xs font-medium text-primary">
            {selectedAlerts.size} alert{selectedAlerts.size > 1 ? "s" : ""} selected
          </span>
          <div className="flex items-center gap-1.5 ml-auto">
            <button
              onClick={() => handleBulkAction("acknowledged")}
              disabled={bulkUpdate.isPending}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-blue-500/10 text-blue-400 hover:bg-blue-500/20 border border-blue-500/20 transition-colors disabled:opacity-50"
            >
              <Eye size={12} /> Acknowledge
            </button>
            <button
              onClick={() => handleBulkAction("resolved")}
              disabled={bulkUpdate.isPending}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-green-500/10 text-green-400 hover:bg-green-500/20 border border-green-500/20 transition-colors disabled:opacity-50"
            >
              <CheckCircle2 size={12} /> Resolve
            </button>
            <button
              onClick={() => handleBulkAction("false_positive")}
              disabled={bulkUpdate.isPending}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-amber-500/10 text-amber-400 hover:bg-amber-500/20 border border-amber-500/20 transition-colors disabled:opacity-50"
            >
              <ShieldAlert size={12} /> False Positive
            </button>
            <button
              onClick={clearSelection}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-muted/30 text-muted-foreground hover:bg-muted/50 border border-border/30 transition-colors ml-1"
            >
              <XCircle size={12} /> Clear
            </button>
          </div>
        </div>
      )}

      {/* ── SOC Hunting Filter Toolbar ─────────────────────── */}
      <div className="rounded-xl border border-border/40 bg-surface-1/30 p-0">
        <div className="flex items-center gap-2 px-3 py-2 flex-wrap">
          {/* Search */}
          <div className="relative">
            <Search size={12} className="absolute left-2 top-1/2 -translate-y-1/2 text-muted-foreground/50" />
            <input
              type="text"
              placeholder="Search alerts..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-7 pr-2 py-1.5 text-xs bg-surface-1 border border-border/30 rounded-md w-52 focus:outline-none focus:ring-1 focus:ring-primary/30 text-foreground placeholder:text-muted-foreground/50"
            />
          </div>

          {/* Time range pills */}
          <div className="flex items-center gap-0.5 bg-surface-1 border border-border/30 rounded-md p-0.5">
            <Clock size={11} className="ml-1 text-muted-foreground/50" />
            {TIME_RANGES.map((t) => (
              <button
                key={t.key}
                onClick={() => setTimeRange(t.key)}
                className={cn(
                  "px-1.5 py-1 rounded text-[10px] font-medium cursor-pointer transition-all",
                  timeRange === t.key ? "bg-primary/15 text-primary" : "text-muted-foreground/50 hover:text-muted-foreground",
                )}
              >
                {t.label}
              </button>
            ))}
          </div>

          {/* Severity pills */}
          <div className="flex items-center gap-0.5 bg-surface-1 border border-border/30 rounded-md p-0.5">
            <Filter size={11} className="ml-1 text-muted-foreground/50" />
            {SEVERITY_OPTIONS.map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={cn(
                  "px-1.5 py-1 rounded text-[10px] font-medium capitalize cursor-pointer transition-all",
                  severityFilter === sev ? "bg-primary/15 text-primary" : "text-muted-foreground/50 hover:text-muted-foreground",
                )}
              >
                {sev}
              </button>
            ))}
          </div>

          {/* Correlation toggle */}
          {hasCorrelations && (
            <button
              onClick={() => setShowCorrelation((v) => !v)}
              className={cn(
                "flex items-center gap-1 px-2 py-1.5 rounded-md text-[10px] font-medium border cursor-pointer transition-all",
                showCorrelation
                  ? "bg-primary/15 text-primary border-primary/20"
                  : "bg-surface-1 text-muted-foreground/70 border-border/30 hover:text-muted-foreground",
              )}
            >
              <GitBranch size={11} />
              Correlations
              <span className="inline-flex items-center justify-center min-w-[16px] h-4 rounded-full bg-primary/10 px-1 text-[9px] font-bold text-primary tabular-nums">
                {correlation?.groups.length ?? 0}
              </span>
            </button>
          )}

          {/* Group by agent toggle */}
          <button
            onClick={() => setGroupMode(groupMode === "none" ? "agent" : "none")}
            className={cn(
              "flex items-center gap-1 px-2 py-1.5 rounded-md text-[10px] font-medium border cursor-pointer transition-all",
              groupMode !== "none"
                ? "bg-primary/15 text-primary border-primary/20"
                : "bg-surface-1 text-muted-foreground/70 border-border/30 hover:text-muted-foreground",
            )}
          >
            <Server size={11} />
            Group by Agent
          </button>

          {/* Grouped/Flat toggle */}
          {groupMode === "none" && (
            <button
              onClick={() => setGrouped((v) => !v)}
              className={cn(
                "flex items-center gap-1 px-2 py-1.5 rounded-md text-[10px] font-medium border cursor-pointer transition-all",
                grouped
                  ? "bg-primary/15 text-primary border-primary/20"
                  : "bg-surface-1 text-muted-foreground/70 border-border/30 hover:text-muted-foreground",
              )}
            >
              {grouped ? <Layers size={11} /> : <List size={11} />}
              {grouped ? "Grouped" : "Flat"}
            </button>
          )}

          {/* Result count */}
          <span className="ml-auto text-[10px] text-muted-foreground/50 tabular-nums">
            {sortedAlerts.length} alert{sortedAlerts.length !== 1 ? "s" : ""}
          </span>
        </div>
      </div>

      {/* ── Status filter tabs with count badges ──────────── */}
      <div className="flex items-center gap-1 border-b border-border/50 pb-px">
        {STATUS_FILTERS.map((s) => {
          const count = statusCounts[s] ?? 0
          const isActive = statusFilter === s
          return (
            <button
              key={s}
              onClick={() => handleStatusChange(s)}
              className={`group relative flex items-center gap-1.5 px-3.5 py-2 text-sm font-medium transition-all border-b-2 -mb-px cursor-pointer ${
                isActive
                  ? "border-primary text-foreground"
                  : "border-transparent text-muted-foreground hover:text-foreground hover:border-border/50"
              }`}
            >
              {isActive && (
                <span className="absolute inset-0 rounded-t-lg bg-primary/[0.06] pointer-events-none" />
              )}
              <span className="relative">{STATUS_LABEL[s]}</span>
              {count > 0 && (
                <span
                  className={`relative inline-flex h-[18px] min-w-[18px] items-center justify-center rounded-full px-1 text-[10px] font-bold tabular-nums leading-none ${
                    isActive
                      ? s === "open" && hasCriticalOpen
                        ? "bg-red-500/20 text-red-400"
                        : s === "open"
                          ? "bg-red-500/20 text-red-400"
                          : "bg-primary/15 text-primary"
                      : "bg-surface-3 text-muted-foreground group-hover:bg-surface-3/80"
                  }`}
                >
                  {count}
                </span>
              )}
            </button>
          )
        })}
      </div>

      {/* ── Agent-grouped view ─────────────────────────────── */}
      {groupMode === "agent" && agentGroups ? (
        <div className="space-y-1 max-h-[calc(100vh-380px)] overflow-y-auto pr-1 rounded-xl border border-border/40 bg-surface-1/20 divide-y divide-border/10">
          {agentGroups.length === 0 ? (
            <EmptyState statusFilter={statusFilter} />
          ) : agentGroups.map((group) => {
            const isOpen = expandedAgents.has(group.agentId)
            return (
              <div key={group.agentId}>
                <button
                  onClick={() => {
                    setExpandedAgents((prev) => {
                      const next = new Set(prev)
                      if (next.has(group.agentId)) next.delete(group.agentId); else next.add(group.agentId)
                      return next
                    })
                  }}
                  className="w-full flex items-center gap-2 px-4 py-2.5 hover:bg-surface-1/40 cursor-pointer transition-all text-left"
                >
                  {isOpen ? <ChevronDown size={12} /> : <ChevronUp size={12} className="rotate-180" />}
                  <Server size={12} className="text-muted-foreground" />
                  <span className="text-xs font-medium font-mono truncate max-w-[280px]" title={group.agentId}>
                    {group.agentId === "unknown" ? "Unknown Agent" : group.agentId}
                  </span>
                  <Badge
                    variant={
                      group.worstSeverity === "critical" ? "critical" :
                      group.worstSeverity === "high" ? "high" :
                      group.worstSeverity === "medium" ? "medium" : "low"
                    }
                    className="text-[8px] py-0 px-1.5"
                  >
                    {group.worstSeverity}
                  </Badge>
                  <span className="text-[10px] text-muted-foreground/60 tabular-nums">
                    ×{group.alerts.length}
                  </span>
                  <span className="ml-auto text-[10px] text-muted-foreground/40">
                    {group.alerts.filter((a) => a.status === "open").length} open
                  </span>
                </button>
                {isOpen && (
                  <div className="border-t border-border/10">
                    {group.alerts.map((alert) => (
                      <div
                        key={alert.id}
                        className="w-full flex items-center gap-3 px-6 py-2 hover:bg-white/[0.02] transition-colors border-b border-border/5 last:border-b-0"
                      >
                        <button
                          onClick={(e) => toggleAlert(alert.id, e)}
                          className="flex items-center justify-center w-5 h-5 cursor-pointer shrink-0"
                        >
                          {selectedAlerts.has(alert.id)
                            ? <CheckSquare size={13} className="text-primary" />
                            : <Square size={13} className="text-muted-foreground/40 hover:text-muted-foreground" />}
                        </button>
                        <button
                          onClick={() => handleRowClick(alert)}
                          className="flex items-center gap-3 flex-1 cursor-pointer text-left min-w-0"
                        >
                          <Badge variant={alert.severity as "critical" | "high" | "medium" | "low"} className="text-[9px] py-0 px-1.5 shrink-0">
                            {alert.severity}
                          </Badge>
                          <span className="text-xs text-foreground font-medium truncate flex-1">{alert.title}</span>
                          <Badge variant="outline" className="capitalize text-[9px] shrink-0">
                            {alert.status.replaceAll("_", " ")}
                          </Badge>
                          <span className="text-[10px] text-muted-foreground whitespace-nowrap shrink-0">
                            {timeAgo(alert.created_at)}
                          </span>
                          <ChevronRight size={12} className="text-muted-foreground opacity-0 group-hover:opacity-100 shrink-0" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      ) : grouped && groups && groupMode === "none" ? (
        /* ── Rule+agent grouped view (card-based) ─────────── */
        <div className="space-y-2 max-h-[calc(100vh-380px)] overflow-y-auto pr-1">
          {isLoading ? (
            <div className="text-center py-16 text-muted-foreground text-sm">
              Loading alerts…
            </div>
          ) : groups.length === 0 ? (
            <EmptyState statusFilter={statusFilter} />
          ) : (
            groups.map((group) => (
              <AlertGroupRow
                key={group.id}
                group={group}
                onAlertClick={handleRowClick}
                selectedAlerts={selectedAlerts}
                onToggleAlert={toggleAlert}
                onToggleGroup={(ids) => {
                  setSelectedAlerts((prev) => {
                    const next = new Set(prev)
                    const allIn = ids.every((id) => next.has(id))
                    if (allIn) { ids.forEach((id) => next.delete(id)) }
                    else { ids.forEach((id) => next.add(id)) }
                    return next
                  })
                }}
              />
            ))
          )}
        </div>
      ) : (
        /* ── Flat virtual table view ──────────────────────── */
        <VirtualTable<AlertSummary>
          items={sortedAlerts}
          columns={columnsWithCheckbox}
          getItemKey={(alert) => alert.id}
          rowHeight={44}
          overscan={20}
          maxItems={MAX_ITEMS}
          autoScroll={live}
          isLoading={isLoading}
          onRowClick={handleRowClick}
          onEndReached={handleEndReached}
          endReachedThreshold={500}
          emptyState={<EmptyState statusFilter={statusFilter} />}
          loadingState={
            <div className="text-center py-12 text-muted-foreground text-sm">
              Loading alerts…
            </div>
          }
        />
      )}

      {/* ── Loading more indicator ────────────────────────── */}
      {isFetchingNextPage && (
        <div className="flex items-center justify-center py-2">
          <RefreshCw size={14} className="animate-spin text-muted-foreground mr-2" />
          <span className="text-xs text-muted-foreground">Loading more…</span>
        </div>
      )}
      </div>

      {/* ── Correlation panel sidebar (O2) ────────────────── */}
      {showCorrelation && correlation && (
        <div className="w-[360px] flex-shrink-0 h-[calc(100vh-120px)] sticky top-4">
          <CorrelationPanel
            correlation={correlation}
            onAlertClick={handleRowClick}
            onClose={() => setShowCorrelation(false)}
            selectedAlertId={null}
          />
        </div>
      )}
    </div>
  )
}

/* ── Empty state sub-component ────────────────────────────────────────────── */

function EmptyState({ statusFilter }: { statusFilter: string }) {
  return (
    <div className="text-center py-16">
      <div className="flex flex-col items-center gap-2">
        <div className="flex h-12 w-12 items-center justify-center rounded-full bg-surface-2">
          <Bell size={22} className="text-muted-foreground" />
        </div>
        <p className="text-sm font-medium text-foreground">
          No alerts match this filter
        </p>
        <p className="text-xs text-muted-foreground">
          {statusFilter === "all"
            ? "No alerts have been generated yet. Try adjusting time range or search criteria."
            : "Try switching to a different status filter or adjusting the time range."}
        </p>
      </div>
    </div>
  )
}
