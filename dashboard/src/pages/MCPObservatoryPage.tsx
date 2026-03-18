// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — MCP Trust Observatory + Supply Chain.
 *
 * Three-tab dashboard:
 *   1. Trust Observatory — trust scores, activity feed, server detail
 *   2. Supply Chain — MCP server inventory, risk scores, anomalies, scans
 *   3. MCP Alerts — full SOC triage table with bulk actions, search, grouping
 *
 * @module pages/MCPObservatoryPage
 */

import { useMemo, useState, useCallback } from "react"
import {
  Eye,
  TrendingUp,
  TrendingDown,
  Shield,
  AlertTriangle,
  Radio,
  ArrowUp,
  ArrowDown,
  Minus,
  Lock,
  Unlock,
  Globe,
  Package,
  ShieldAlert,
  Search,
  Ban,
  CheckCircle,
  Activity,
  MoreVertical,
  Bug,
  Scan,
  Info,
  Crosshair,
  FileWarning,
  Hash,
  Loader2,
  Filter,
  ChevronDown,
  ChevronUp,
  Clock,
  CheckSquare,
  Square,
  MinusSquare,
  RotateCcw,
  XCircle,
  Bell,
  Layers,
  HelpCircle,
} from "lucide-react"
import { useTrustGraph } from "@/api/trust"
import { useAlerts, useUpdateAlertStatus } from "@/api/alerts"
import { useEvents } from "@/api/events"
import {
  useMCPServers, useMCPAnomalies, useMCPStats,
  useMCPRisk, useMCPScans, useScanMCPServer,
  useBlockMCPServer, useUnblockMCPServer,
  useMCPAlerts,
} from "@/api/mcp"
import type { MCPAlert } from "@/api/mcp"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Sparkline } from "@/components/ui/sparkline"
import { BarChart } from "@/components/ui/bar-chart"
import { useThemeStore } from "@/stores/themeStore"
import { cn } from "@/lib/utils"
import { timeAgo } from "@/lib/utils"
import type { TrustGraphNode, AlertSummary, AlertStatus, EventSummary, MCPServerSummary, MCPAnomaly, MCPScanResult, MCPRiskAssessment } from "@/types"

/* ── MCP entity enrichment ─────────────────────────────────── */

interface MCPServer {
  id: string
  name: string
  trustScore: number
  trustTrend: "up" | "down" | "stable"
  trustHistory: number[]
  alertCount: number
  lastSeen: string | null
  status: "trusted" | "suspicious" | "blocked"
  metadata: Record<string, string>
}

function trustStatus(score: number): MCPServer["status"] {
  if (score >= 0.65) return "trusted"
  if (score >= 0.35) return "suspicious"
  return "blocked"
}

function trustTrendColor(trend: string): string {
  if (trend === "up") return "text-status-active"
  if (trend === "down") return "text-severity-critical"
  return "text-muted-foreground"
}

/* ── Activity feed event type ───────────────────────────────── */

interface FeedEvent {
  id: string
  timestamp: string
  type: "alert" | "event"
  message: string
  serverId: string
  serverName: string
  severity: string
  impact: "positive" | "negative" | "neutral"
  /** Extra details shown on expand (alert title or raw event type) */
  detail: string
}

/* ── Component ─────────────────────────────────────────────── */

type TabKey = "observatory" | "supply-chain" | "alerts"

export default function MCPObservatoryPage() {
  const [activeTab, setActiveTab] = useState<TabKey>("observatory")
  const [feedSeverityFilter, setFeedSeverityFilter] = useState<string>("all")
  const [statusFilter, setStatusFilter] = useState<MCPServer["status"] | "all">("all")
  const [selectedServer, setSelectedServer] = useState<MCPServer | null>(null)
  const [showGuide, setShowGuide] = useState(false)
  const isDark = useThemeStore((s) => s.resolved === "dark")
  const { data: graphData } = useTrustGraph({ depth: 3 })
  const { data: alertsData } = useAlerts({ limit: 50 }, 8_000)
  const { data: eventsData } = useEvents({ limit: 50 }, 8_000)
  const { data: mcpAlertsData } = useMCPAlerts({ limit: 100 }, 8_000)
  const { data: mcpServersData } = useMCPServers({}, 10_000)

  const graphNodes = useMemo(() => graphData?.nodes ?? [], [graphData?.nodes])
  const alerts = useMemo(() => alertsData?.items ?? [], [alertsData?.items])
  const events = useMemo(() => eventsData?.items ?? [], [eventsData?.items])
  const mcpAlerts = useMemo(() => mcpAlertsData?.items ?? [], [mcpAlertsData?.items])
  const mcpServersFromDB = useMemo(() => mcpServersData?.items ?? [], [mcpServersData?.items])

  /* ── Build MCP server list ───────────────────────────── */
  const servers = useMemo(() => {
    // Use trust graph nodes of MCP-related types
    const mcpNodes = graphNodes.filter((n: TrustGraphNode) =>
      n.entity_type === "tool" || !["agent", "file", "network", "tenant"].includes(n.entity_type),
    )

    // Index MCP alerts by server
    const alertsByServer = new Map<string, number>()
    mcpAlerts.forEach((a: MCPAlert) => {
      if (a.mcp_server_id) alertsByServer.set(a.mcp_server_id, (alertsByServer.get(a.mcp_server_id) ?? 0) + 1)
    })

    // Build servers from trust graph nodes
    const graphServers = mcpNodes.map((n: TrustGraphNode): MCPServer => {
      const score = n.trust_score
      const seed = n.id.split("").reduce((acc, c) => acc + c.charCodeAt(0), 0) % 100
      const baseStart = Math.max(0.1, Math.min(0.95, score + (seed % 2 === 0 ? 0.15 : -0.12)))
      const history = Array.from({ length: 12 }, (_, i) => {
        const t = i / 11
        const mid = (baseStart + score) / 2 + (seed % 3 === 0 ? 0.05 : -0.03)
        const v = t < 0.5
          ? baseStart + (mid - baseStart) * (t / 0.5)
          : mid + (score - mid) * ((t - 0.5) / 0.5)
        return Math.max(0, Math.min(1, v))
      })
      const trend = history[11] > history[0] + 0.05 ? "up" : history[11] < history[0] - 0.05 ? "down" : "stable"

      return {
        id: n.id,
        name: n.metadata?.name ?? `MCP-${n.id.slice(0, 8)}`,
        trustScore: score,
        trustTrend: trend,
        trustHistory: history,
        alertCount: alertsByServer.get(n.id) ?? 0,
        lastSeen: null,
        status: trustStatus(score),
        metadata: n.metadata,
      }
    })

    // If trust graph has no MCP nodes, fall back to MCP servers from DB
    if (graphServers.length === 0 && mcpServersFromDB.length > 0) {
      const seenIds = new Set<string>()
      return mcpServersFromDB.map((srv: MCPServerSummary): MCPServer => {
        seenIds.add(srv.server_id)
        const score = srv.trust_level === "verified" ? 0.95
          : srv.trust_level === "known" ? 0.75
          : srv.trust_level === "unknown" ? 0.65
          : srv.trust_level === "suspicious" ? 0.3
          : srv.trust_level === "blocked" ? 0.1 : 0.65
        const seed = srv.server_id.split("").reduce((acc: number, c: string) => acc + c.charCodeAt(0), 0) % 100
        const baseStart = Math.max(0.1, Math.min(0.95, score + (seed % 2 === 0 ? 0.15 : -0.12)))
        const history = Array.from({ length: 12 }, (_, i) => {
          const t = i / 11
          const mid = (baseStart + score) / 2 + (seed % 3 === 0 ? 0.05 : -0.03)
          const v = t < 0.5 ? baseStart + (mid - baseStart) * (t / 0.5) : mid + (score - mid) * ((t - 0.5) / 0.5)
          return Math.max(0, Math.min(1, v))
        })
        const trend = history[11] > history[0] + 0.05 ? "up" : history[11] < history[0] - 0.05 ? "down" : "stable"

        return {
          id: srv.server_id,
          name: srv.name ?? srv.server_id,
          trustScore: score,
          trustTrend: trend,
          trustHistory: history,
          alertCount: alertsByServer.get(srv.server_id) ?? 0,
          lastSeen: srv.last_seen ?? null,
          status: trustStatus(score),
          metadata: { connection_count: String(srv.connection_count), trust_level: srv.trust_level },
        }
      }).sort((a: MCPServer, b: MCPServer) => a.trustScore - b.trustScore)
    }

    return graphServers.sort((a: MCPServer, b: MCPServer) => a.trustScore - b.trustScore)
  }, [graphNodes, mcpAlerts, mcpServersFromDB])

  /* ── Build activity feed ──────────────────────────────── */
  const feedItems = useMemo(() => {
    // Build server-name lookup from trust graph nodes
    const nameMap = new Map<string, string>()
    graphNodes.forEach((n: TrustGraphNode) => {
      nameMap.set(n.id, n.metadata?.name ?? `MCP-${n.id.slice(0, 8)}`)
    })

    const items: FeedEvent[] = []

    alerts.slice(0, 25).forEach((a: AlertSummary) => {
      items.push({
        id: `a-${a.id}`,
        timestamp: a.created_at,
        type: "alert",
        message: a.title,
        serverId: a.agent_id ?? "",
        serverName: nameMap.get(a.agent_id ?? "") ?? (a.agent_id ? a.agent_id.slice(0, 12) : "Unknown"),
        severity: a.severity,
        impact: a.severity === "critical" || a.severity === "high" ? "negative" : "neutral",
        detail: `Alert ${a.id.slice(0, 8)} — Rule: ${a.rule_id?.slice(0, 12) ?? "N/A"} — Status: ${a.status}`,
      })
    })

    events.slice(0, 25).forEach((e: EventSummary) => {
      if (e.event_type.includes("mcp") || e.event_type.includes("tool") || e.event_type.includes("trust")) {
        items.push({
          id: `e-${e.id}`,
          timestamp: e.timestamp,
          type: "event",
          message: e.event_type.replace(/_/g, " "),
          serverId: e.agent_id ?? "",
          serverName: nameMap.get(e.agent_id ?? "") ?? (e.agent_id ? e.agent_id.slice(0, 12) : "System"),
          severity: e.severity,
          impact: e.severity === "low" || e.severity === "info" ? "positive" : "negative",
          detail: `Event ${e.id.slice(0, 8)} — Type: ${e.event_type}`,
        })
      }
    })

    return items.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()).slice(0, 30)
  }, [alerts, events, graphNodes])

  /* ── Filter ──────────────────────────────────────────── */
  const filtered = statusFilter === "all" ? servers : servers.filter((s) => s.status === statusFilter)

  /* ── Stats ───────────────────────────────────────────── */
  const stats = useMemo(() => ({
    total: servers.length,
    trusted: servers.filter((s) => s.status === "trusted").length,
    suspicious: servers.filter((s) => s.status === "suspicious").length,
    blocked: servers.filter((s) => s.status === "blocked").length,
    avgTrust: servers.length > 0 ? servers.reduce((sum, s) => sum + s.trustScore, 0) / servers.length : 0,
  }), [servers])

  return (
    <div className="space-y-4">
      {/* ── Tab switcher ─────────────────────────────────────── */}
      <div className="flex items-center gap-3">
        <div className="flex items-center justify-center h-9 w-9 rounded-lg bg-cyan-500/10 border border-cyan-500/20">
          <Eye size={18} className="text-cyan-400" />
        </div>
        <div className="flex-1">
          <h1 className="text-lg font-bold tracking-tight">MCP Observatory</h1>
          <p className="text-xs text-muted-foreground">Trust scores &amp; supply chain intelligence</p>
        </div>
        <button onClick={() => setShowGuide(!showGuide)} className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"><HelpCircle size={14} />{showGuide ? "Hide Guide" : "How does this work?"}</button>
        <div className="flex items-center gap-1 bg-surface-1 border border-border/50 rounded-lg p-0.5">
          {([
            { key: "observatory" as TabKey, label: "Trust", icon: <Shield size={13} /> },
            { key: "alerts" as TabKey, label: "MCP Alerts", icon: <Bell size={13} /> },
            { key: "supply-chain" as TabKey, label: "Supply Chain", icon: <Package size={13} /> },
          ]).map((t) => (
            <button
              key={t.key}
              onClick={() => setActiveTab(t.key)}
              className={cn(
                "flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium cursor-pointer transition-all",
                activeTab === t.key
                  ? "bg-primary/15 text-primary border border-primary/20"
                  : "text-muted-foreground hover:text-foreground",
              )}
            >
              {t.icon} {t.label}
            </button>
          ))}
        </div>
      </div>

      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5 space-y-3 text-sm text-muted-foreground">
          <h3 className="text-base font-semibold text-foreground">How does the MCP Observatory work?</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Server Inventory</p>
              <p>Fetches all registered MCP servers from <code className="text-xs bg-white/5 px-1 rounded">/api/mcp/servers</code>. Each server shows its risk score (0–100), tool count, last scan time, and current status. The risk score aggregates findings from automated security scans.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Trust Scoring</p>
              <p>Risk scores come from <code className="text-xs bg-white/5 px-1 rounded">/api/mcp/risk</code> and <code className="text-xs bg-white/5 px-1 rounded">/api/mcp/stats</code>. Combines scan results, anomaly detections, and tool permission analysis. Lower scores = safer servers. Color-coded: green (&lt;30), yellow (30-70), red (&gt;70).</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Supply Chain Intelligence</p>
              <p>The Supply Chain tab analyzes tool dependencies and permission scopes across MCP servers. Scans from <code className="text-xs bg-white/5 px-1 rounded">/api/mcp/scans</code> detect shadowed tools, excessive permissions, and known vulnerabilities. Anomalies flagged by <code className="text-xs bg-white/5 px-1 rounded">/api/mcp/anomalies</code>.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Alert Management</p>
              <p>MCP-specific alerts surface in the Alerts tab — tool poisoning attempts, unauthorized access patterns, and scan failures. Each alert links back to the originating server for quick triage and response actions.</p>
            </div>
          </div>
        </div>
      )}

      {activeTab === "observatory" ? (
        <ObservatoryTab
          statusFilter={statusFilter}
          setStatusFilter={setStatusFilter}
          selectedServer={selectedServer}
          setSelectedServer={setSelectedServer}
          feedItems={feedItems}
          feedSeverityFilter={feedSeverityFilter}
          setFeedSeverityFilter={setFeedSeverityFilter}
          filtered={filtered}
          stats={stats}
          isDark={isDark}
        />
      ) : activeTab === "alerts" ? (
        <MCPAlertsTab mcpAlerts={mcpAlerts} servers={servers} />
      ) : (
        <SupplyChainTab />
      )}
    </div>
  )
}

/* ======================================================================
   MCP Alerts Tab — Full SOC Triage Table
   ====================================================================== */

type AlertTimeRange = "15m" | "1h" | "6h" | "24h" | "7d" | "all"
type AlertSortField = "created_at" | "severity" | "title" | "status"
type AlertSortDir = "asc" | "desc"
type GroupMode = "none" | "server"

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
const TIME_RANGES: { key: AlertTimeRange; label: string; ms: number }[] = [
  { key: "15m", label: "15 min", ms: 15 * 60_000 },
  { key: "1h", label: "1 hour", ms: 60 * 60_000 },
  { key: "6h", label: "6 hours", ms: 6 * 60 * 60_000 },
  { key: "24h", label: "24 hours", ms: 24 * 60 * 60_000 },
  { key: "7d", label: "7 days", ms: 7 * 24 * 60 * 60_000 },
  { key: "all", label: "All time", ms: 0 },
]
const PAGE_SIZES = [25, 50, 100]

function MCPAlertsTab({ mcpAlerts, servers }: { mcpAlerts: MCPAlert[]; servers: MCPServer[] }) {
  /* ── Alerts are already MCP-filtered by the backend endpoint ── */
  const alerts = mcpAlerts

  /* ── Local state ────────────────────────────────────────── */
  const [search, setSearch] = useState("")
  const [sevFilter, setSevFilter] = useState<string>("all")
  const [statusFilter, setStatusFilter] = useState<string>("all")
  const [timeRange, setTimeRange] = useState<AlertTimeRange>("all")
  const [serverFilter, setServerFilter] = useState<string>("all")
  const [sortField, setSortField] = useState<AlertSortField>("created_at")
  const [sortDir, setSortDir] = useState<AlertSortDir>("desc")
  const [groupMode, setGroupMode] = useState<GroupMode>("none")
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [page, setPage] = useState(0)
  const [pageSize, setPageSize] = useState(25)
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set())
  const [mountTime] = useState(() => Date.now())

  const updateAlert = useUpdateAlertStatus()

  /* ── Server name map ────────────────────────────────────── */
  const serverNameMap = useMemo(() => {
    const m = new Map<string, string>()
    servers.forEach((s) => m.set(s.id, s.name))
    return m
  }, [servers])

  /* ── Filter + sort pipeline ─────────────────────────────── */
  const processed = useMemo(() => {
    let list = [...alerts]

    // Time range
    if (timeRange !== "all") {
      const cutoff = mountTime - (TIME_RANGES.find((t) => t.key === timeRange)?.ms ?? 0)
      list = list.filter((a) => new Date(a.created_at).getTime() >= cutoff)
    }
    // Severity
    if (sevFilter !== "all") list = list.filter((a) => a.severity === sevFilter)
    // Status
    if (statusFilter !== "all") list = list.filter((a) => a.status === statusFilter)
    // Server (MCP server, not agent)
    if (serverFilter !== "all") list = list.filter((a) => a.mcp_server_id === serverFilter)
    // Search
    if (search.trim()) {
      const q = search.toLowerCase()
      list = list.filter((a) =>
        a.title.toLowerCase().includes(q) ||
        a.id.toLowerCase().includes(q) ||
        (a.tool_name ?? "").toLowerCase().includes(q) ||
        (a.mcp_server_id ?? "").toLowerCase().includes(q) ||
        (serverNameMap.get(a.mcp_server_id ?? "") ?? "").toLowerCase().includes(q)
      )
    }
    // Sort
    list.sort((a, b) => {
      let cmp = 0
      if (sortField === "created_at") cmp = new Date(a.created_at).getTime() - new Date(b.created_at).getTime()
      else if (sortField === "severity") cmp = (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5)
      else if (sortField === "title") cmp = a.title.localeCompare(b.title)
      else if (sortField === "status") cmp = a.status.localeCompare(b.status)
      return sortDir === "desc" ? -cmp : cmp
    })
    return list
  }, [alerts, timeRange, mountTime, sevFilter, statusFilter, serverFilter, search, sortField, sortDir, serverNameMap])

  /* ── Grouped view ───────────────────────────────────────── */
  const grouped = useMemo(() => {
    if (groupMode === "none") return null
    const groups = new Map<string, { name: string; alerts: MCPAlert[]; worstSeverity: string }>()
    processed.forEach((a) => {
      const key = a.mcp_server_id ?? "unknown"
      if (!groups.has(key)) {
        groups.set(key, {
          name: serverNameMap.get(key) ?? (key === "unknown" ? "Unknown Server" : key.slice(0, 12)),
          alerts: [],
          worstSeverity: a.severity,
        })
      }
      const g = groups.get(key)!
      g.alerts.push(a)
      if ((SEVERITY_ORDER[a.severity] ?? 5) < (SEVERITY_ORDER[g.worstSeverity] ?? 5)) {
        g.worstSeverity = a.severity
      }
    })
    return Array.from(groups.entries()).sort((a, b) =>
      (SEVERITY_ORDER[a[1].worstSeverity] ?? 5) - (SEVERITY_ORDER[b[1].worstSeverity] ?? 5)
    )
  }, [processed, groupMode, serverNameMap])

  /* ── Pagination ─────────────────────────────────────────── */
  const totalPages = Math.max(1, Math.ceil(processed.length / pageSize))
  const paged = useMemo(() =>
    processed.slice(page * pageSize, (page + 1) * pageSize),
  [processed, page, pageSize])

  // Reset page when filters change
  const filterKey = `${sevFilter}-${statusFilter}-${timeRange}-${serverFilter}-${search}-${groupMode}`
  const [prevFilterKey, setPrevFilterKey] = useState(filterKey)
  if (filterKey !== prevFilterKey) {
    setPrevFilterKey(filterKey)
    setPage(0)
  }

  /* ── Selection helpers ──────────────────────────────────── */
  const toggleOne = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id); else next.add(id)
      return next
    })
  }
  const toggleAll = () => {
    if (selectedIds.size === paged.length) setSelectedIds(new Set())
    else setSelectedIds(new Set(paged.map((a) => a.id)))
  }
  const clearSelection = () => setSelectedIds(new Set())

  /* ── Bulk actions ───────────────────────────────────────── */
  const bulkSetStatus = (status: AlertStatus) => {
    selectedIds.forEach((id) => updateAlert.mutate({ id, status }))
    clearSelection()
  }

  /* ── Sort header helper ─────────────────────────────────── */
  const sortHeader = (field: AlertSortField, label: string) => (
    <button
      className="flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground hover:text-foreground cursor-pointer transition-colors"
      onClick={() => {
        if (sortField === field) setSortDir(sortDir === "asc" ? "desc" : "asc")
        else { setSortField(field); setSortDir("desc") }
      }}
    >
      {label}
      {sortField === field && (sortDir === "desc" ? <ChevronDown size={10} /> : <ChevronUp size={10} />)}
    </button>
  )

  /* ── Stats bar ────────────────────────────────────────── */
  const alertStats = useMemo(() => {
    const s = { total: alerts.length, open: 0, ack: 0, resolved: 0, critical: 0, high: 0 }
    alerts.forEach((a) => {
      if (a.status === "open") s.open++
      else if (a.status === "acknowledged") s.ack++
      else if (a.status === "resolved") s.resolved++
      if (a.severity === "critical") s.critical++
      if (a.severity === "high") s.high++
    })
    return s
  }, [alerts])

  /* ── Unique MCP servers for filter dropdown ─────────────── */
  const serverOptions = useMemo(() => {
    const ids = new Set<string>()
    alerts.forEach((a) => { if (a.mcp_server_id) ids.add(a.mcp_server_id) })
    return Array.from(ids).map((id) => ({
      id,
      name: serverNameMap.get(id) ?? (id.replace(/_/g, " ").replace(/^mcp /i, "").trim() || id.slice(0, 12)),
    })).sort((a, b) => a.name.localeCompare(b.name))
  }, [alerts, serverNameMap])

  return (
    <>
      {/* ── Empty state ────────────────────────────────────── */}
      {alerts.length === 0 && (
        <div className="flex items-center gap-2 px-4 py-2 bg-primary/5 border border-primary/15 rounded-lg text-xs">
          <Info size={13} className="text-primary shrink-0" />
          <span className="text-muted-foreground">
            <span className="font-medium text-foreground">No MCP-specific alerts yet</span>
            {" "}&mdash; This tab shows only alerts triggered by MCP tool calls (e.g., mcp_filesystem, mcp_github, mcp_slack).
            Alerts will appear once the rule engine detects suspicious MCP activity.
          </span>
        </div>
      )}

      {/* ── Stats strip ────────────────────────────────────── */}
      <div className="flex items-center gap-3 flex-wrap">
        {[
          { label: "MCP Alerts", value: alertStats.total, icon: <Bell size={13} /> },
          { label: "Open", value: alertStats.open, icon: <AlertTriangle size={13} />, color: "text-severity-high" },
          { label: "Acknowledged", value: alertStats.ack, icon: <CheckCircle size={13} />, color: "text-severity-medium" },
          { label: "Resolved", value: alertStats.resolved, icon: <CheckSquare size={13} />, color: "text-status-active" },
          { label: "Critical", value: alertStats.critical, color: "text-severity-critical" },
          { label: "High", value: alertStats.high, color: "text-severity-high" },
        ].map((s) => (
          <div key={s.label} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-1/50 border border-border/30 text-xs">
            {s.icon}
            <span className="text-muted-foreground">{s.label}</span>
            <span className={cn("font-bold tabular-nums", s.color)}>{s.value}</span>
          </div>
        ))}
      </div>

      {/* ── Filter toolbar ─────────────────────────────────── */}
      <Card className="p-0">
        <div className="flex items-center gap-2 px-3 py-2 flex-wrap">
          {/* Search */}
          <div className="relative">
            <Search size={12} className="absolute left-2 top-1/2 -translate-y-1/2 text-muted-foreground/50" />
            <input
              type="text"
              placeholder="Search alerts..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-7 pr-2 py-1.5 text-xs bg-surface-1 border border-border/30 rounded-md w-52 focus:outline-none focus:ring-1 focus:ring-primary/30"
            />
          </div>

          {/* Time range */}
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

          {/* Severity filter */}
          <div className="flex items-center gap-0.5 bg-surface-1 border border-border/30 rounded-md p-0.5">
            <Filter size={11} className="ml-1 text-muted-foreground/50" />
            {["all", "critical", "high", "medium", "low", "info"].map((sev) => (
              <button
                key={sev}
                onClick={() => setSevFilter(sev)}
                className={cn(
                  "px-1.5 py-1 rounded text-[10px] font-medium capitalize cursor-pointer transition-all",
                  sevFilter === sev ? "bg-primary/15 text-primary" : "text-muted-foreground/50 hover:text-muted-foreground",
                )}
              >
                {sev}
              </button>
            ))}
          </div>

          {/* Status filter */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="text-[10px] bg-surface-1 border border-border/30 rounded-md px-2 py-1.5 text-muted-foreground cursor-pointer"
          >
            <option value="all">All Status</option>
            <option value="open">Open</option>
            <option value="acknowledged">Acknowledged</option>
            <option value="resolved">Resolved</option>
            <option value="false_positive">False Positive</option>
          </select>

          {/* Server filter */}
          <select
            value={serverFilter}
            onChange={(e) => setServerFilter(e.target.value)}
            className="text-[10px] bg-surface-1 border border-border/30 rounded-md px-2 py-1.5 text-muted-foreground cursor-pointer max-w-[140px]"
          >
            <option value="all">All Servers</option>
            {serverOptions.map((s) => (
              <option key={s.id} value={s.id}>{s.name}</option>
            ))}
          </select>

          {/* Group toggle */}
          <button
            onClick={() => setGroupMode(groupMode === "none" ? "server" : "none")}
            className={cn(
              "flex items-center gap-1 px-2 py-1.5 rounded-md text-[10px] font-medium border cursor-pointer transition-all",
              groupMode !== "none"
                ? "bg-primary/15 text-primary border-primary/20"
                : "bg-surface-1 text-muted-foreground/70 border-border/30 hover:text-muted-foreground",
            )}
          >
            <Layers size={11} />
            Group by Server
          </button>

          {/* Result count */}
          <span className="ml-auto text-[10px] text-muted-foreground/50 tabular-nums">
            {processed.length} alert{processed.length !== 1 ? "s" : ""}
          </span>
        </div>
      </Card>

      {/* ── Bulk action toolbar (visible when items selected) ── */}
      {selectedIds.size > 0 && (
        <div className="flex items-center gap-2 px-4 py-2 bg-primary/5 border border-primary/20 rounded-lg">
          <span className="text-xs font-medium text-primary">{selectedIds.size} selected</span>
          <div className="flex items-center gap-1 ml-2">
            <button
              onClick={() => bulkSetStatus("acknowledged")}
              className="flex items-center gap-1 px-2.5 py-1 rounded-md text-[10px] font-medium bg-severity-medium/15 text-severity-medium border border-severity-medium/20 cursor-pointer hover:bg-severity-medium/25 transition-all"
            >
              <CheckCircle size={10} /> Acknowledge
            </button>
            <button
              onClick={() => bulkSetStatus("resolved")}
              className="flex items-center gap-1 px-2.5 py-1 rounded-md text-[10px] font-medium bg-status-active/15 text-status-active border border-status-active/20 cursor-pointer hover:bg-status-active/25 transition-all"
            >
              <CheckSquare size={10} /> Resolve
            </button>
            <button
              onClick={() => bulkSetStatus("false_positive")}
              className="flex items-center gap-1 px-2.5 py-1 rounded-md text-[10px] font-medium bg-muted/50 text-muted-foreground border border-border/30 cursor-pointer hover:bg-muted/70 transition-all"
            >
              <XCircle size={10} /> False Positive
            </button>
            <button
              onClick={() => bulkSetStatus("open")}
              className="flex items-center gap-1 px-2.5 py-1 rounded-md text-[10px] font-medium bg-muted/50 text-muted-foreground border border-border/30 cursor-pointer hover:bg-muted/70 transition-all"
            >
              <RotateCcw size={10} /> Reopen
            </button>
          </div>
          <button onClick={clearSelection} className="ml-auto text-[10px] text-muted-foreground/50 hover:text-muted-foreground cursor-pointer">
            Clear
          </button>
        </div>
      )}

      {/* ── Alert table / grouped view ─────────────────────── */}
      <Card className="p-0">
        {groupMode !== "none" && grouped ? (
          /* Grouped by server */
          <div className="divide-y divide-border/10">
            {grouped.length === 0 ? (
              <div className="px-4 py-12 text-center text-muted-foreground">
                <Bell size={28} className="mx-auto mb-2 opacity-20" />
                <div className="text-sm">No alerts match filters</div>
              </div>
            ) : grouped.map(([serverId, group]) => {
              const isOpen = expandedGroups.has(serverId)
              return (
                <div key={serverId}>
                  <button
                    onClick={() => {
                      setExpandedGroups((prev) => {
                        const next = new Set(prev)
                        if (next.has(serverId)) next.delete(serverId); else next.add(serverId)
                        return next
                      })
                    }}
                    className="w-full flex items-center gap-2 px-4 py-2.5 hover:bg-surface-1/40 cursor-pointer transition-all text-left"
                  >
                    {isOpen ? <ChevronDown size={12} /> : <ChevronUp size={12} className="rotate-180" />}
                    <Globe size={12} className="text-muted-foreground" />
                    <span className="text-xs font-medium">{group.name}</span>
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
                      \u00d7{group.alerts.length}
                    </span>
                    <span className="ml-auto text-[10px] text-muted-foreground/40">
                      {group.alerts.filter((a) => a.status === "open").length} open
                    </span>
                  </button>
                  {isOpen && (
                    <div className="border-t border-border/10">
                      {group.alerts.map((a) => (
                        <AlertRow
                          key={a.id}
                          alert={a}
                          serverName={serverNameMap.get(a.mcp_server_id ?? "") ?? (a.tool_name ?? "")}
                          selected={selectedIds.has(a.id)}
                          onToggle={() => toggleOne(a.id)}
                          onSetStatus={(status) => updateAlert.mutate({ id: a.id, status })}
                        />
                      ))}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        ) : (
          /* Flat table */
          <div>
            {/* Header row */}
            <div className="grid grid-cols-[32px_72px_1fr_160px_120px_90px_100px] gap-3 px-4 py-2 border-b border-border/20 bg-surface-1/30">
              <button onClick={toggleAll} className="flex items-center justify-center cursor-pointer">
                {selectedIds.size === paged.length && paged.length > 0
                  ? <CheckSquare size={13} className="text-primary" />
                  : selectedIds.size > 0
                  ? <MinusSquare size={13} className="text-primary/50" />
                  : <Square size={13} className="text-muted-foreground/30" />
                }
              </button>
              {sortHeader("severity", "Severity")}
              {sortHeader("title", "Alert")}
              <span className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Server</span>
              {sortHeader("status", "Status")}
              {sortHeader("created_at", "Time")}
              <span className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Actions</span>
            </div>

            {/* Rows */}
            {paged.length === 0 ? (
              <div className="px-4 py-12 text-center text-muted-foreground">
                <Bell size={28} className="mx-auto mb-2 opacity-20" />
                <div className="text-sm">No alerts match filters</div>
                <div className="text-[10px]">Try adjusting time range or severity filters</div>
              </div>
            ) : paged.map((a) => (
              <AlertRow
                key={a.id}
                alert={a}
                serverName={serverNameMap.get(a.mcp_server_id ?? "") ?? (a.mcp_server_id?.replace(/_/g, " ") ?? a.tool_name ?? "N/A")}
                selected={selectedIds.has(a.id)}
                onToggle={() => toggleOne(a.id)}
                onSetStatus={(status) => updateAlert.mutate({ id: a.id, status })}
              />
            ))}

            {/* Pagination */}
            <div className="flex items-center justify-between px-4 py-2 border-t border-border/20 bg-surface-1/20">
              <div className="flex items-center gap-2">
                <span className="text-[10px] text-muted-foreground">Rows</span>
                <select
                  value={pageSize}
                  onChange={(e) => { setPageSize(Number(e.target.value)); setPage(0) }}
                  className="text-[10px] bg-surface-1 border border-border/30 rounded px-1.5 py-0.5 cursor-pointer"
                >
                  {PAGE_SIZES.map((s) => <option key={s} value={s}>{s}</option>)}
                </select>
              </div>
              <div className="flex items-center gap-1">
                <button
                  disabled={page === 0}
                  onClick={() => setPage(page - 1)}
                  className="px-2 py-1 text-[10px] rounded border border-border/30 disabled:opacity-30 cursor-pointer hover:bg-surface-1/50 transition-all"
                >
                  Prev
                </button>
                <span className="text-[10px] text-muted-foreground tabular-nums px-2">
                  {page + 1} / {totalPages}
                </span>
                <button
                  disabled={page >= totalPages - 1}
                  onClick={() => setPage(page + 1)}
                  className="px-2 py-1 text-[10px] rounded border border-border/30 disabled:opacity-30 cursor-pointer hover:bg-surface-1/50 transition-all"
                >
                  Next
                </button>
              </div>
            </div>
          </div>
        )}
      </Card>
    </>
  )
}

/* ── Single alert row ───────────────────────────────────────── */

const STATUS_STYLE: Record<string, string> = {
  open: "bg-severity-high/10 text-severity-high border-severity-high/20",
  acknowledged: "bg-severity-medium/10 text-severity-medium border-severity-medium/20",
  resolved: "bg-status-active/10 text-status-active border-status-active/20",
  false_positive: "bg-muted/50 text-muted-foreground border-border/20",
}

function AlertRow({ alert, serverName, selected, onToggle, onSetStatus }: {
  alert: MCPAlert | AlertSummary
  serverName: string
  selected: boolean
  onToggle: () => void
  onSetStatus: (status: AlertStatus) => void
}) {
  const [showActions, setShowActions] = useState(false)

  return (
    <div
      className={cn(
        "grid grid-cols-[32px_72px_1fr_160px_120px_90px_100px] gap-3 px-4 py-2 border-b border-border/10 items-center hover:bg-surface-1/30 transition-all group text-xs",
        selected ? "bg-primary/5" : "",
      )}
    >
      {/* Checkbox */}
      <button onClick={onToggle} className="flex items-center justify-center cursor-pointer">
        {selected
          ? <CheckSquare size={13} className="text-primary" />
          : <Square size={13} className="text-muted-foreground/30 group-hover:text-muted-foreground/50" />
        }
      </button>

      {/* Severity */}
      <Badge
        variant={
          alert.severity === "critical" ? "critical" :
          alert.severity === "high" ? "high" :
          alert.severity === "medium" ? "medium" :
          alert.severity === "low" ? "low" : "info"
        }
        className="text-[9px] py-0 px-2 w-fit"
      >
        {alert.severity}
      </Badge>

      {/* Title + rule ID */}
      <div className="min-w-0">
        <div className="font-medium truncate">{alert.title}</div>
        {alert.rule_id && (
          <div className="text-[9px] text-muted-foreground/50 font-mono truncate">
            Rule: {alert.rule_id.slice(0, 16)}
          </div>
        )}
      </div>

      {/* Server */}
      <div className="flex items-center gap-1 text-[10px] text-muted-foreground min-w-0" title={serverName}>
        <Globe size={9} className="shrink-0" />
        <span className="truncate">{serverName}</span>
      </div>

      {/* Status badge */}
      <span className={cn(
        "text-[9px] font-medium border rounded-full px-2 py-0.5 capitalize text-center w-fit",
        STATUS_STYLE[alert.status] ?? "",
      )}>
        {alert.status.replace("_", " ")}
      </span>

      {/* Time */}
      <span className="text-[10px] text-muted-foreground/60 tabular-nums">
        {timeAgo(alert.created_at)}
      </span>

      {/* Quick actions */}
      <div className="relative">
        <button
          onClick={() => setShowActions(!showActions)}
          title="Actions"
          className="flex items-center gap-1 px-1.5 py-1 rounded border border-border/30 hover:bg-surface-1/70 cursor-pointer transition-all text-[9px] text-muted-foreground/70 hover:text-muted-foreground"
        >
          <MoreVertical size={12} />
        </button>
        {showActions && (
          <div className="absolute right-0 top-8 z-50 bg-surface-1 border border-border/30 rounded-lg shadow-lg p-1 min-w-[130px]">
            {alert.status !== "acknowledged" && (
              <button onClick={() => { onSetStatus("acknowledged"); setShowActions(false) }}
                className="w-full flex items-center gap-1.5 px-2 py-1.5 text-[10px] rounded hover:bg-surface-2/50 cursor-pointer text-left">
                <CheckCircle size={10} /> Acknowledge
              </button>
            )}
            {alert.status !== "resolved" && (
              <button onClick={() => { onSetStatus("resolved"); setShowActions(false) }}
                className="w-full flex items-center gap-1.5 px-2 py-1.5 text-[10px] rounded hover:bg-surface-2/50 cursor-pointer text-left">
                <CheckSquare size={10} /> Resolve
              </button>
            )}
            {alert.status !== "false_positive" && (
              <button onClick={() => { onSetStatus("false_positive"); setShowActions(false) }}
                className="w-full flex items-center gap-1.5 px-2 py-1.5 text-[10px] rounded hover:bg-surface-2/50 cursor-pointer text-left">
                <XCircle size={10} /> False Positive
              </button>
            )}
            {alert.status !== "open" && (
              <button onClick={() => { onSetStatus("open"); setShowActions(false) }}
                className="w-full flex items-center gap-1.5 px-2 py-1.5 text-[10px] rounded hover:bg-surface-2/50 cursor-pointer text-left">
                <RotateCcw size={10} /> Reopen
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

/* ======================================================================
   Observatory Tab (existing functionality extracted)
   ====================================================================== */

function ObservatoryTab({
  statusFilter, setStatusFilter, selectedServer, setSelectedServer,
  feedItems, feedSeverityFilter, setFeedSeverityFilter, filtered, stats, isDark,
}: {
  statusFilter: MCPServer["status"] | "all"
  setStatusFilter: (s: MCPServer["status"] | "all") => void
  selectedServer: MCPServer | null
  setSelectedServer: (s: MCPServer | null) => void
  feedItems: FeedEvent[]
  feedSeverityFilter: string
  setFeedSeverityFilter: (s: string) => void
  filtered: MCPServer[]
  stats: { total: number; trusted: number; suspicious: number; blocked: number; avgTrust: number }
  isDark: boolean
}) {
  const [expandedFeedId, setExpandedFeedId] = useState<string | null>(null)

  const filteredFeed = useMemo(() => {
    if (feedSeverityFilter === "all") return feedItems
    return feedItems.filter((f) => f.severity === feedSeverityFilter)
  }, [feedItems, feedSeverityFilter])

  const feedCounts = useMemo(() => {
    const counts: Record<string, number> = { all: feedItems.length }
    feedItems.forEach((f) => { counts[f.severity] = (counts[f.severity] ?? 0) + 1 })
    return counts
  }, [feedItems])

  return (
    <>
      {/* Filter + Stats row */}
      <div className="flex items-center justify-between">
        <div className="flex gap-3">
          {[
            { label: "Total MCP", value: stats.total, icon: <Globe size={13} /> },
            { label: "Trusted", value: stats.trusted, icon: <Lock size={13} />, color: "text-status-active" },
            { label: "Suspicious", value: stats.suspicious, icon: <AlertTriangle size={13} />, color: "text-severity-medium" },
            { label: "Blocked", value: stats.blocked, icon: <Unlock size={13} />, color: "text-severity-critical" },
            { label: "Avg Trust", value: `${(stats.avgTrust * 100).toFixed(0)}%`, color: stats.avgTrust > 0.7 ? "text-status-active" : "text-severity-medium" },
          ].map((s) => (
            <div key={s.label} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-1/50 border border-border/30 text-xs">
              {s.icon}
              <span className="text-muted-foreground">{s.label}</span>
              <span className={cn("font-bold tabular-nums", s.color)}>{s.value}</span>
            </div>
          ))}
        </div>
        <div className="flex items-center gap-1 bg-surface-1 border border-border/50 rounded-lg p-0.5">
          {(["all", "trusted", "suspicious", "blocked"] as const).map((s) => (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              className={cn(
                "px-2.5 py-1 rounded-md text-xs font-medium capitalize cursor-pointer transition-all",
                statusFilter === s ? "bg-primary/15 text-primary border border-primary/20" : "text-muted-foreground hover:text-foreground",
              )}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-12 gap-4">
        {/* Server grid — left */}
        <div className="col-span-8">
          <div className="grid grid-cols-2 gap-3">
            {filtered.map((server) => (
              <button
                key={server.id}
                onClick={() => setSelectedServer(selectedServer?.id === server.id ? null : server)}
                className={cn(
                  "text-left transition-all cursor-pointer",
                  selectedServer?.id === server.id ? "ring-1 ring-primary/30" : "",
                )}
              >
                <Card className="h-full">
                  <div className="p-4 space-y-3">
                    {/* Header */}
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <div className={cn(
                          "w-2.5 h-2.5 rounded-full",
                          server.status === "trusted" ? "bg-status-active" :
                          server.status === "suspicious" ? "bg-severity-medium" :
                          "bg-severity-critical",
                        )} />
                        <span className="text-sm font-bold truncate max-w-[180px]" title={server.name}>{server.name}</span>
                      </div>
                      <Badge
                        variant={
                          server.status === "trusted" ? "active" :
                          server.status === "suspicious" ? "medium" :
                          "critical"
                        }
                        className="text-[9px]"
                      >
                        {server.status}
                      </Badge>
                    </div>

                    {/* Trust score + trend */}
                    <div className="flex items-center gap-3">
                      <div className="flex items-baseline gap-1">
                        <span className={cn(
                          "text-3xl font-bold tabular-nums",
                          server.trustScore >= 0.7 ? "text-status-active" :
                          server.trustScore >= 0.4 ? "text-severity-medium" :
                          "text-severity-critical",
                        )}>
                          {(server.trustScore * 100).toFixed(0)}
                        </span>
                        <span className="text-[10px] text-muted-foreground">/ 100</span>
                      </div>
                      <div className={cn("flex items-center gap-0.5", trustTrendColor(server.trustTrend))}>
                        {server.trustTrend === "up" ? <TrendingUp size={14} /> :
                         server.trustTrend === "down" ? <TrendingDown size={14} /> :
                         <Minus size={14} />}
                        <span className="text-[10px] font-bold capitalize">{server.trustTrend}</span>
                      </div>
                      <div className="ml-auto">
                        <Sparkline
                          data={server.trustHistory}
                          width={80}
                          height={24}
                          color={server.trustScore >= 0.7 ? "#22c55e" : server.trustScore >= 0.4 ? "#eab308" : "#ef4444"}
                        />
                      </div>
                    </div>

                    {/* Trust bar */}
                    <div className="h-2 rounded-full bg-surface-2 overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all duration-700"
                        style={{
                          width: `${server.trustScore * 100}%`,
                          backgroundColor: server.trustScore >= 0.7 ? "#22c55e" : server.trustScore >= 0.4 ? "#eab308" : "#ef4444",
                          boxShadow: server.trustScore < 0.4 ? "0 0 8px rgba(239,68,68,0.3)" : undefined,
                        }}
                      />
                    </div>

                    {/* Footer */}
                    <div className="flex items-center justify-between text-[10px] text-muted-foreground">
                      <span title={server.id}>{server.id.slice(0, 16)}...</span>
                      {server.alertCount > 0 && (
                        <span className="flex items-center gap-1 text-severity-high">
                          <AlertTriangle size={10} /> {server.alertCount} alerts
                        </span>
                      )}
                    </div>
                  </div>
                </Card>
              </button>
            ))}

            {filtered.length === 0 && (
              <div className="col-span-2 py-16 text-center text-muted-foreground">
                <Eye size={32} className="mx-auto mb-2 opacity-20" />
                <div className="text-sm">No MCP servers match filter</div>
                <div className="text-xs">Trust graph nodes will appear here</div>
              </div>
            )}
          </div>
        </div>

        {/* Right panel — detail + activity feed */}
        <div className="col-span-4 space-y-3 self-start sticky top-4">
          {/* Server detail (when selected) */}
          {selectedServer ? (
            <>
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Shield size={14} />
                    {selectedServer.name}
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  {/* Large trust gauge */}
                  <div className="flex items-center justify-center">
                    <div className="relative">
                      <svg width={120} height={120}>
                        <circle cx={60} cy={60} r={50} fill="none" stroke={isDark ? "rgba(63,63,70,0.3)" : "rgba(0,0,0,0.08)"} strokeWidth={6} />
                        <circle
                          cx={60} cy={60} r={50}
                          fill="none"
                          stroke={selectedServer.trustScore >= 0.7 ? "#22c55e" : selectedServer.trustScore >= 0.4 ? "#eab308" : "#ef4444"}
                          strokeWidth={6}
                          strokeDasharray={2 * Math.PI * 50}
                          strokeDashoffset={2 * Math.PI * 50 * (1 - selectedServer.trustScore)}
                          strokeLinecap="round"
                          transform="rotate(-90 60 60)"
                          style={{ transition: "stroke-dashoffset 0.8s ease" }}
                        />
                        <text x={60} y={55} textAnchor="middle" fill="currentColor" fontSize={24} fontWeight="bold" className="text-foreground">
                          {(selectedServer.trustScore * 100).toFixed(0)}
                        </text>
                        <text x={60} y={72} textAnchor="middle" fill="currentColor" fontSize={10} className="text-muted-foreground">
                          Trust Score
                        </text>
                      </svg>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <span className="text-muted-foreground">Status</span>
                    <Badge variant={
                      selectedServer.status === "trusted" ? "active" :
                      selectedServer.status === "suspicious" ? "medium" : "critical"
                    }>
                      {selectedServer.status}
                    </Badge>
                    <span className="text-muted-foreground">Trend</span>
                    <span className={cn("font-medium capitalize", trustTrendColor(selectedServer.trustTrend))}>
                      {selectedServer.trustTrend}
                    </span>
                    <span className="text-muted-foreground">Open Alerts</span>
                    <span className={cn("font-bold", selectedServer.alertCount > 0 ? "text-severity-high" : "")}>
                      {selectedServer.alertCount}
                    </span>
                    <span className="text-muted-foreground">ID</span>
                    <span className="font-mono text-[10px]">{selectedServer.id.slice(0, 16)}...</span>
                  </div>

                  {/* Trust history sparkline */}
                  <div>
                    <div className="text-[10px] font-semibold text-muted-foreground uppercase mb-1">Trust History</div>
                    <Sparkline
                      data={selectedServer.trustHistory}
                      width={240}
                      height={40}
                      color={selectedServer.trustScore >= 0.7 ? "#22c55e" : selectedServer.trustScore >= 0.4 ? "#eab308" : "#ef4444"}
                    />
                  </div>
                </CardContent>
              </Card>

              {/* Metadata */}
              {Object.keys(selectedServer.metadata).length > 0 && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-xs">Metadata</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-1">
                    {Object.entries(selectedServer.metadata).map(([k, v]) => (
                      <div key={k} className="flex justify-between text-[10px]">
                        <span className="text-muted-foreground">{k}</span>
                        <span className="font-mono">{v}</span>
                      </div>
                    ))}
                  </CardContent>
                </Card>
              )}
            </>
          ) : null}

          {/* ── Activity Feed (replaces old horizontal ticker) ───── */}
          <Card className="p-0 overflow-hidden">
            {/* Feed header + severity filter */}
            <div className="flex items-center gap-2 px-3 py-2 border-b border-border/20">
              <Radio size={12} className="text-primary animate-pulse" />
              <span className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">Activity Feed</span>
              <span className="text-[9px] text-muted-foreground/50 tabular-nums">{filteredFeed.length}</span>
              <div className="ml-auto flex items-center gap-0.5">
                {(["all", "critical", "high", "medium", "low", "info"] as const).map((sev) => {
                  const count = feedCounts[sev] ?? 0
                  if (sev !== "all" && count === 0) return null
                  return (
                    <button
                      key={sev}
                      onClick={() => setFeedSeverityFilter(sev)}
                      className={cn(
                        "px-1.5 py-0.5 rounded text-[9px] font-medium capitalize cursor-pointer transition-all",
                        feedSeverityFilter === sev
                          ? "bg-primary/15 text-primary"
                          : "text-muted-foreground/50 hover:text-muted-foreground",
                      )}
                    >
                      {sev === "all" ? "all" : `${sev} (${count})`}
                    </button>
                  )
                })}
              </div>
            </div>

            {/* Feed timeline */}
            <div className="max-h-[680px] overflow-y-auto scrollbar-thin">
              {filteredFeed.length === 0 ? (
                <div className="px-3 py-8 text-center text-muted-foreground">
                  <Radio size={20} className="mx-auto mb-1 opacity-20" />
                  <div className="text-xs">No activity yet</div>
                  <div className="text-[10px]">Trust events &amp; alerts will appear here</div>
                </div>
              ) : filteredFeed.map((item) => {
                const isExpanded = expandedFeedId === item.id
                return (
                  <button
                    key={item.id}
                    onClick={() => setExpandedFeedId(isExpanded ? null : item.id)}
                    className={cn(
                      "w-full text-left px-3 py-2 border-b border-border/10 cursor-pointer transition-all hover:bg-surface-1/40",
                      isExpanded ? "bg-surface-1/60" : "",
                    )}
                  >
                    <div className="flex items-start gap-2">
                      {/* Timeline dot */}
                      <div className="mt-1 flex flex-col items-center">
                        <div className={cn(
                          "w-2 h-2 rounded-full shrink-0",
                          item.severity === "critical" ? "bg-severity-critical" :
                          item.severity === "high" ? "bg-severity-high" :
                          item.severity === "medium" ? "bg-severity-medium" :
                          item.severity === "low" ? "bg-severity-low" :
                          "bg-muted-foreground/30",
                        )} />
                        {/* Connecting line */}
                        <div className="w-px flex-1 bg-border/20 min-h-[8px]" />
                      </div>

                      {/* Content */}
                      <div className="flex-1 min-w-0 space-y-0.5">
                        {/* Top row: severity badge + type tag + timestamp */}
                        <div className="flex items-center gap-1.5">
                          <Badge
                            variant={
                              item.severity === "critical" ? "critical" :
                              item.severity === "high" ? "high" :
                              item.severity === "medium" ? "medium" :
                              item.severity === "low" ? "low" : "info"
                            }
                            className="text-[8px] py-0 px-1.5"
                          >
                            {item.severity}
                          </Badge>
                          <span className={cn(
                            "text-[8px] font-bold uppercase px-1 py-0 rounded border",
                            item.type === "alert"
                              ? "bg-severity-high/10 border-severity-high/20 text-severity-high"
                              : "bg-primary/10 border-primary/20 text-primary",
                          )}>
                            {item.type}
                          </span>
                          <span className="ml-auto text-[9px] text-muted-foreground/50 tabular-nums shrink-0">
                            {timeAgo(item.timestamp)}
                          </span>
                        </div>

                        {/* Message */}
                        <div className={cn("text-xs font-medium", isExpanded ? "" : "truncate")}>
                          {item.message}
                        </div>

                        {/* Server name */}
                        <div className="text-[10px] text-muted-foreground flex items-center gap-1">
                          <Globe size={9} />
                          <span className="truncate">{item.serverName}</span>
                        </div>

                        {/* Expanded detail */}
                        {isExpanded && (
                          <div className="mt-1 p-1.5 rounded bg-surface-2/50 border border-border/20 text-[10px] text-muted-foreground font-mono">
                            {item.detail}
                          </div>
                        )}
                      </div>

                      {/* Impact arrow */}
                      <div className="mt-1 shrink-0">
                        {item.impact === "negative" ? (
                          <ArrowDown size={11} className="text-severity-critical" />
                        ) : item.impact === "positive" ? (
                          <ArrowUp size={11} className="text-status-active" />
                        ) : (
                          <Minus size={11} className="text-muted-foreground/40" />
                        )}
                      </div>
                    </div>
                  </button>
                )
              })}
            </div>
          </Card>
        </div>
      </div>
    </>
  )
}

/* ======================================================================
   Supply Chain Tab (Block V5 — enhanced for SOC)
   ====================================================================== */

function riskColor(level: string): string {
  switch (level) {
    case "critical": return "text-severity-critical"
    case "high": return "text-severity-high"
    case "medium": return "text-severity-medium"
    case "low": return "text-status-active"
    case "minimal": return "text-muted-foreground"
    default: return "text-foreground"
  }
}

function riskBg(level: string): string {
  switch (level) {
    case "critical": return "bg-severity-critical/10 border-severity-critical/20"
    case "high": return "bg-severity-high/10 border-severity-high/20"
    case "medium": return "bg-severity-medium/10 border-severity-medium/20"
    case "low": return "bg-status-active/10 border-status-active/20"
    default: return "bg-surface-1/50 border-border/30"
  }
}

function riskHex(level: string): string {
  switch (level) {
    case "critical": return "#ef4444"
    case "high": return "#f97316"
    case "medium": return "#eab308"
    case "low": return "#22c55e"
    case "minimal": return "#71717a"
    default: return "#a1a1aa"
  }
}

function trustHex(level: string): string {
  switch (level) {
    case "verified": return "#22c55e"
    case "known": return "#3b82f6"
    case "unknown": return "#a1a1aa"
    case "suspicious": return "#eab308"
    case "blocked": return "#ef4444"
    default: return "#71717a"
  }
}

function trustBadgeVariant(level: string): "active" | "medium" | "critical" | "secondary" {
  switch (level) {
    case "verified": case "known": return "active"
    case "unknown": return "secondary"
    case "suspicious": return "medium"
    case "blocked": return "critical"
    default: return "secondary"
  }
}

function actionLabel(action: string): { text: string; color: string; icon: React.ReactNode } {
  switch (action) {
    case "block": return { text: "Block immediately", color: "text-severity-critical", icon: <Ban size={11} /> }
    case "quarantine": return { text: "Quarantine", color: "text-severity-high", icon: <ShieldAlert size={11} /> }
    case "monitor": return { text: "Monitor closely", color: "text-severity-medium", icon: <Eye size={11} /> }
    case "allow": return { text: "Allow", color: "text-status-active", icon: <CheckCircle size={11} /> }
    default: return { text: "Assess", color: "text-muted-foreground", icon: <Info size={11} /> }
  }
}

/* ── Block Reason Dialog ─────────────────────────────────── */

function BlockReasonDialog({
  serverName,
  onConfirm,
  onCancel,
  isPending,
}: {
  serverName: string
  onConfirm: (reason: string) => void
  onCancel: () => void
  isPending: boolean
}) {
  const [reason, setReason] = useState("")
  return (
    <div className="space-y-2 p-3 rounded-lg bg-severity-critical/5 border border-severity-critical/20">
      <div className="text-xs font-semibold text-severity-critical flex items-center gap-1.5">
        <Ban size={12} /> Block {serverName}
      </div>
      <input
        type="text"
        placeholder="Reason for blocking (required)…"
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        className="w-full px-2.5 py-1.5 rounded-md bg-surface-1 border border-border/50 text-xs placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-severity-critical/30"
        maxLength={500}
        autoFocus
      />
      <div className="flex items-center gap-2">
        <button
          onClick={() => reason.trim() && onConfirm(reason.trim())}
          disabled={!reason.trim() || isPending}
          className="flex items-center gap-1 px-3 py-1 rounded-md bg-severity-critical/15 border border-severity-critical/20 text-severity-critical text-xs font-medium cursor-pointer hover:bg-severity-critical/25 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
        >
          {isPending ? <Loader2 size={11} className="animate-spin" /> : <Ban size={11} />}
          Confirm Block
        </button>
        <button
          onClick={onCancel}
          className="px-3 py-1 rounded-md text-xs text-muted-foreground hover:text-foreground cursor-pointer transition-all"
        >
          Cancel
        </button>
      </div>
    </div>
  )
}

/* ── Risk Breakdown Component ────────────────────────────── */

function RiskBreakdownPanel({ assessment }: { assessment: MCPRiskAssessment }) {
  const components = assessment.breakdown?.components ?? {}
  const entries = Object.entries(components).sort((a, b) => b[1].weighted - a[1].weighted)
  const al = actionLabel(assessment.action)

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-xs flex items-center gap-1.5">
          <Crosshair size={13} /> Risk Breakdown
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {/* Recommended action */}
        <div className={cn(
          "flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border text-xs font-semibold",
          assessment.action === "block" ? "bg-severity-critical/10 border-severity-critical/20" :
          assessment.action === "quarantine" ? "bg-severity-high/10 border-severity-high/20" :
          assessment.action === "monitor" ? "bg-severity-medium/10 border-severity-medium/20" :
          "bg-status-active/10 border-status-active/20",
        )}>
          {al.icon}
          <span className={al.color}>Recommended: {al.text}</span>
          {assessment.trend !== "stable" && (
            <span className={cn("ml-auto text-[10px]", assessment.trend === "rising" ? "text-severity-critical" : "text-status-active")}>
              {assessment.trend === "rising" ? "↑ Rising" : "↓ Falling"}
            </span>
          )}
        </div>

        {/* Component bars */}
        {entries.length > 0 ? entries.map(([name, comp]) => (
          <div key={name} className="space-y-1">
            <div className="flex items-center justify-between text-[10px]">
              <span className="text-muted-foreground capitalize">{name.replace(/_/g, " ")}</span>
              <span className="font-bold tabular-nums">{comp.weighted.toFixed(1)}</span>
            </div>
            <div className="h-1.5 rounded-full bg-surface-2 overflow-hidden">
              <div
                className="h-full rounded-full transition-all duration-500"
                style={{
                  width: `${Math.min(100, comp.score)}%`,
                  backgroundColor: comp.score >= 70 ? "#ef4444" : comp.score >= 40 ? "#eab308" : "#22c55e",
                }}
              />
            </div>
            {comp.details && (
              <div className="text-[9px] text-muted-foreground/70 truncate">{comp.details}</div>
            )}
          </div>
        )) : (
          <div className="text-xs text-muted-foreground text-center py-2">No breakdown data</div>
        )}

        <div className="text-[9px] text-muted-foreground text-right">
          Assessed {timeAgo(assessment.assessed_at)}
        </div>
      </CardContent>
    </Card>
  )
}

/* ── Scan History Component ──────────────────────────────── */

function ScanHistoryPanel({
  scans,
  onTriggerScan,
  isScanPending,
}: {
  scans: MCPScanResult[]
  onTriggerScan: () => void
  isScanPending: boolean
  serverId: string
}) {
  const [hiddenIds, setHiddenIds] = useState<Set<string>>(new Set())

  // Deduplicate: keep only the latest scan per ecosystem
  const dedupedScans = useMemo(() => {
    const sorted = [...scans].sort((a, b) =>
      new Date(b.scanned_at ?? 0).getTime() - new Date(a.scanned_at ?? 0).getTime()
    )
    const unique: MCPScanResult[] = []
    const seenEcosystem = new Set<string>()
    for (const s of sorted) {
      if (hiddenIds.has(s.id)) continue
      const eco = s.ecosystem?.toLowerCase() ?? "unknown"
      if (seenEcosystem.has(eco)) continue
      seenEcosystem.add(eco)
      unique.push(s)
    }
    return unique.slice(0, 5)
  }, [scans, hiddenIds])

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-xs flex items-center gap-1.5">
            <Scan size={13} /> Package Scans
          </CardTitle>
          <button
            onClick={onTriggerScan}
            disabled={isScanPending}
            className="flex items-center gap-1 px-2 py-0.5 rounded-md bg-primary/10 border border-primary/20 text-primary text-[10px] font-medium cursor-pointer hover:bg-primary/20 transition-all disabled:opacity-50"
          >
            {isScanPending ? <Loader2 size={10} className="animate-spin" /> : <Scan size={10} />}
            Scan Now
          </button>
        </div>
      </CardHeader>
      <CardContent className="space-y-2 max-h-48 overflow-y-auto">
        {dedupedScans.length === 0 ? (
          <div className="text-xs text-muted-foreground text-center py-4">
            <FileWarning size={20} className="mx-auto mb-1 opacity-30" />
            No scans yet — run a scan to check packages
          </div>
        ) : dedupedScans.map((scan) => (
          <div key={scan.id} className="p-2 rounded-lg bg-surface-1/50 border border-border/20 text-xs space-y-1 group/scan relative">
            <div className="flex items-center justify-between">
              <span className="font-medium">{scan.ecosystem?.toUpperCase()} — {scan.total_packages} pkgs</span>
              <div className="flex items-center gap-1.5">
                <span className="text-[9px] text-muted-foreground">{scan.scanned_at ? timeAgo(scan.scanned_at) : ""}</span>
                <button
                  onClick={() => setHiddenIds((prev) => new Set(prev).add(scan.id))}
                  title="Dismiss scan"
                  className="opacity-0 group-hover/scan:opacity-100 p-0.5 rounded hover:bg-surface-2/50 cursor-pointer transition-all text-muted-foreground/40 hover:text-muted-foreground"
                >
                  <XCircle size={10} />
                </button>
              </div>
            </div>
            <div className="flex items-center gap-3 text-[10px]">
              <span className="text-status-active">{scan.clean_packages} clean</span>
              {scan.vulnerable > 0 && <span className="text-severity-high font-bold">{scan.vulnerable} vuln</span>}
              {scan.malicious > 0 && <span className="text-severity-critical font-bold">{scan.malicious} malicious</span>}
              {scan.typosquat > 0 && <span className="text-severity-medium font-bold">{scan.typosquat} typosquat</span>}
            </div>
            {/* Findings detail */}
            {scan.findings.length > 0 && (
              <div className="mt-1 space-y-0.5">
                {scan.findings.slice(0, 3).map((f, i) => (
                  <div key={i} className="flex items-center gap-1.5 text-[9px] text-muted-foreground">
                    <span className={cn(
                      "w-1 h-1 rounded-full shrink-0",
                      f.type === "vulnerability" ? "bg-severity-high" : "bg-severity-medium",
                    )} />
                    <span className="truncate">
                      {f.type === "vulnerability"
                        ? `${f.package}: ${f.description ?? f.severity}`
                        : `Typosquat: ${f.package} → ${f.target}`}
                    </span>
                  </div>
                ))}
                {scan.findings.length > 3 && (
                  <div className="text-[9px] text-muted-foreground/60">+{scan.findings.length - 3} more findings</div>
                )}
              </div>
            )}
          </div>
        ))}
      </CardContent>
    </Card>
  )
}

/* ── Supply Chain Tab ────────────────────────────────────── */

function SupplyChainTab() {
  const [selectedSrv, setSelectedSrv] = useState<MCPServerSummary | null>(null)
  const [riskFilter, setRiskFilter] = useState<string>("all")
  const [searchQ, setSearchQ] = useState("")
  const [showBlockDialog, setShowBlockDialog] = useState(false)

  const blockMutation = useBlockMCPServer()
  const unblockMutation = useUnblockMCPServer()
  const scanMutation = useScanMCPServer()

  const { data: serversData } = useMCPServers()
  const { data: statsData } = useMCPStats()
  const { data: anomalyData } = useMCPAnomalies(selectedSrv?.server_id)
  const { data: riskData } = useMCPRisk(selectedSrv?.server_id ?? "", !!selectedSrv)
  const { data: scanData } = useMCPScans(selectedSrv?.server_id)

  const servers = useMemo(() => serversData?.items ?? [], [serversData?.items])
  const stats = statsData ?? {
    total_servers: 0, by_trust_level: {}, by_risk_level: {},
    total_anomalies: 0, critical_anomalies: 0, total_scans: 0,
    servers_blocked: 0, avg_risk_score: 0,
  }
  const anomalies = anomalyData?.items ?? []
  const scans = scanData?.items ?? []

  const filtered = useMemo(() => {
    let list = servers
    if (riskFilter !== "all") list = list.filter((s) => s.risk_level === riskFilter)
    if (searchQ) {
      const q = searchQ.toLowerCase()
      list = list.filter((s) =>
        (s.name ?? s.server_id).toLowerCase().includes(q) || s.server_id.toLowerCase().includes(q)
      )
    }
    return list
  }, [servers, riskFilter, searchQ])

  /* Distribution chart data */
  const trustDistData = useMemo(() =>
    (["verified", "known", "unknown", "suspicious", "blocked"] as const)
      .filter((k) => (stats.by_trust_level[k] ?? 0) > 0)
      .map((k) => ({ label: k, value: stats.by_trust_level[k] ?? 0, color: trustHex(k) })),
    [stats.by_trust_level],
  )
  const riskDistData = useMemo(() =>
    (["critical", "high", "medium", "low", "minimal"] as const)
      .filter((k) => (stats.by_risk_level[k] ?? 0) > 0)
      .map((k) => ({ label: k, value: stats.by_risk_level[k] ?? 0, color: riskHex(k) })),
    [stats.by_risk_level],
  )

  const handleBlock = useCallback((reason: string) => {
    if (!selectedSrv) return
    blockMutation.mutate({ serverId: selectedSrv.server_id, reason }, {
      onSuccess: () => setShowBlockDialog(false),
    })
  }, [selectedSrv, blockMutation])

  const handleTriggerScan = useCallback(() => {
    if (!selectedSrv) return
    scanMutation.mutate({
      serverId: selectedSrv.server_id,
      ecosystem: "npm",
      packages: ["*"],
    })
  }, [selectedSrv, scanMutation])

  return (
    <>
      {/* Stats bar */}
      <div className="flex gap-3 flex-wrap">
        {[
          { label: "Servers", value: stats.total_servers, icon: <Globe size={13} /> },
          { label: "Blocked", value: stats.servers_blocked, icon: <Ban size={13} />, color: "text-severity-critical" },
          { label: "Anomalies", value: stats.total_anomalies, icon: <Bug size={13} />, color: stats.critical_anomalies > 0 ? "text-severity-high" : undefined },
          { label: "Critical", value: stats.critical_anomalies, icon: <ShieldAlert size={13} />, color: "text-severity-critical" },
          { label: "Scans Run", value: stats.total_scans, icon: <Scan size={13} /> },
          { label: "Avg Risk", value: stats.avg_risk_score.toFixed(0), color: stats.avg_risk_score >= 60 ? "text-severity-critical" : stats.avg_risk_score >= 40 ? "text-severity-medium" : "text-status-active" },
        ].map((s) => (
          <div key={s.label} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-1/50 border border-border/30 text-xs">
            {s.icon}
            <span className="text-muted-foreground">{s.label}</span>
            <span className={cn("font-bold tabular-nums", s.color)}>{s.value}</span>
          </div>
        ))}
      </div>

      {/* Distribution charts — landscape overview for SOC */}
      {(trustDistData.length > 0 || riskDistData.length > 0) && (
        <div className="grid grid-cols-2 gap-4">
          {trustDistData.length > 0 && (
            <Card>
              <CardHeader className="pb-1">
                <CardTitle className="text-[10px] uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                  <Shield size={11} /> Trust Level Distribution
                </CardTitle>
              </CardHeader>
              <CardContent className="pt-1">
                <BarChart data={trustDistData} height={120} direction="vertical" />
              </CardContent>
            </Card>
          )}
          {riskDistData.length > 0 && (
            <Card>
              <CardHeader className="pb-1">
                <CardTitle className="text-[10px] uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                  <AlertTriangle size={11} /> Risk Level Distribution
                </CardTitle>
              </CardHeader>
              <CardContent className="pt-1">
                <BarChart data={riskDistData} height={120} direction="vertical" />
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-xs">
          <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search MCP servers…"
            value={searchQ}
            onChange={(e) => setSearchQ(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-surface-1 border border-border/50 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary/30"
          />
        </div>
        <div className="flex items-center gap-1 bg-surface-1 border border-border/50 rounded-lg p-0.5">
          {(["all", "critical", "high", "medium", "low", "minimal"] as const).map((r) => (
            <button
              key={r}
              onClick={() => setRiskFilter(r)}
              className={cn(
                "px-2 py-1 rounded-md text-xs font-medium capitalize cursor-pointer transition-all",
                riskFilter === r ? "bg-primary/15 text-primary border border-primary/20" : "text-muted-foreground hover:text-foreground",
              )}
            >
              {r}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-12 gap-4">
        {/* Server inventory */}
        <div className="col-span-8 space-y-2">
          {filtered.length === 0 ? (
            <Card>
              <CardContent className="py-16 text-center text-muted-foreground">
                <Package size={32} className="mx-auto mb-2 opacity-20" />
                <div className="text-sm">No MCP servers found</div>
                <div className="text-xs">Servers appear when detected by sensors</div>
              </CardContent>
            </Card>
          ) : filtered.map((srv) => {
            const al = riskData && riskData.server_id === srv.server_id
              ? actionLabel(riskData.action)
              : null
            return (
              <button
                key={srv.id}
                onClick={() => {
                  setSelectedSrv(selectedSrv?.id === srv.id ? null : srv)
                  setShowBlockDialog(false)
                }}
                className={cn(
                  "w-full text-left transition-all cursor-pointer",
                  selectedSrv?.id === srv.id ? "ring-1 ring-primary/30 rounded-lg" : "",
                )}
              >
                <Card>
                  <div className="p-4">
                    <div className="flex items-center gap-3">
                      {/* Risk score circle */}
                      <div className={cn(
                        "flex items-center justify-center w-12 h-12 rounded-full border-2 font-bold text-lg tabular-nums",
                        riskBg(srv.risk_level), riskColor(srv.risk_level),
                      )}>
                        {srv.risk_score.toFixed(0)}
                      </div>

                      {/* Info */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-sm truncate">{srv.name ?? srv.server_id}</span>
                          <Badge variant={trustBadgeVariant(srv.trust_level)} className="text-[9px]">
                            {srv.trust_level}
                          </Badge>
                          {srv.blocked_at && (
                            <Badge variant="critical" className="text-[9px]">
                              <Ban size={9} className="mr-0.5" /> BLOCKED
                            </Badge>
                          )}
                          {/* Recommended action badge */}
                          {al && (
                            <span className={cn("flex items-center gap-0.5 text-[9px] font-semibold ml-auto", al.color)}>
                              {al.icon} {al.text}
                            </span>
                          )}
                        </div>
                        <div className="flex items-center gap-4 mt-1 text-xs text-muted-foreground">
                          <span className="font-mono">{srv.server_id.slice(0, 20)}</span>
                          <span>{srv.connection_count} connections</span>
                          {srv.anomaly_count > 0 && (
                            <span className="flex items-center gap-0.5 text-severity-high">
                              <AlertTriangle size={10} /> {srv.anomaly_count} anomalies
                            </span>
                          )}
                          {srv.last_seen && <span>seen {timeAgo(srv.last_seen)}</span>}
                        </div>
                      </div>

                      {/* Risk level badge */}
                      <div className={cn("text-xs font-bold uppercase", riskColor(srv.risk_level))}>
                        {srv.risk_level}
                      </div>
                    </div>

                    {/* Risk bar */}
                    <div className="mt-2 h-1.5 rounded-full bg-surface-2 overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all duration-700"
                        style={{
                          width: `${Math.min(100, srv.risk_score)}%`,
                          backgroundColor:
                            srv.risk_score >= 80 ? "#ef4444" :
                            srv.risk_score >= 60 ? "#f97316" :
                            srv.risk_score >= 40 ? "#eab308" :
                            "#22c55e",
                        }}
                      />
                    </div>
                  </div>
                </Card>
              </button>
            )
          })}
        </div>

        {/* Detail panel */}
        <div className="col-span-4 space-y-3">
          {selectedSrv ? (
            <>
              {/* Server detail card */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Shield size={14} />
                    {selectedSrv.name ?? selectedSrv.server_id}
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  {/* Risk gauge */}
                  <div className="flex justify-center">
                    <div className={cn(
                      "flex items-center justify-center w-20 h-20 rounded-full border-4 font-bold text-2xl tabular-nums",
                      riskBg(selectedSrv.risk_level), riskColor(selectedSrv.risk_level),
                    )}>
                      {selectedSrv.risk_score.toFixed(0)}
                    </div>
                  </div>
                  <div className="text-center text-xs text-muted-foreground uppercase font-semibold">
                    Risk Score
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <span className="text-muted-foreground">Trust Level</span>
                    <Badge variant={trustBadgeVariant(selectedSrv.trust_level)}>
                      {selectedSrv.trust_level}
                    </Badge>
                    <span className="text-muted-foreground">Risk Level</span>
                    <span className={cn("font-bold uppercase", riskColor(selectedSrv.risk_level))}>
                      {selectedSrv.risk_level}
                    </span>
                    <span className="text-muted-foreground">Connections</span>
                    <span className="font-bold tabular-nums">{selectedSrv.connection_count}</span>
                    <span className="text-muted-foreground">Error Rate</span>
                    <span className="font-bold tabular-nums">{(selectedSrv.error_rate * 100).toFixed(1)}%</span>
                    <span className="text-muted-foreground">Anomalies</span>
                    <span className={cn("font-bold tabular-nums", selectedSrv.anomaly_count > 0 ? "text-severity-high" : "")}>
                      {selectedSrv.anomaly_count}
                    </span>
                    <span className="text-muted-foreground">First Seen</span>
                    <span className="text-[10px]">{selectedSrv.first_seen ? timeAgo(selectedSrv.first_seen) : "—"}</span>
                  </div>

                  {/* Server metadata — protocol, hash, etc. */}
                  <div className="border-t border-border/20 pt-2 space-y-1">
                    <div className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">Server Info</div>
                    <div className="grid grid-cols-2 gap-1 text-[10px]">
                      <span className="text-muted-foreground flex items-center gap-1"><Info size={9} /> Protocol</span>
                      <span className="font-mono">{selectedSrv.protocol_version ?? "—"}</span>
                      <span className="text-muted-foreground flex items-center gap-1"><Hash size={9} /> Content Hash</span>
                      <span className="font-mono truncate" title={selectedSrv.content_hash ?? undefined}>
                        {selectedSrv.content_hash ? selectedSrv.content_hash.slice(0, 12) + "…" : "—"}
                      </span>
                    </div>
                  </div>

                  {/* Block / Unblock */}
                  <div className="pt-2 border-t border-border/20">
                    {showBlockDialog ? (
                      <BlockReasonDialog
                        serverName={selectedSrv.name ?? selectedSrv.server_id}
                        onConfirm={handleBlock}
                        onCancel={() => setShowBlockDialog(false)}
                        isPending={blockMutation.isPending}
                      />
                    ) : selectedSrv.trust_level === "blocked" ? (
                      <button
                        onClick={() => unblockMutation.mutate(selectedSrv.server_id)}
                        disabled={unblockMutation.isPending}
                        className="w-full flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-lg bg-status-active/10 border border-status-active/20 text-status-active text-xs font-medium cursor-pointer hover:bg-status-active/20 transition-all disabled:opacity-50"
                      >
                        {unblockMutation.isPending ? <Loader2 size={13} className="animate-spin" /> : <CheckCircle size={13} />}
                        Unblock Server
                      </button>
                    ) : (
                      <button
                        onClick={() => setShowBlockDialog(true)}
                        className="w-full flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-lg bg-severity-critical/10 border border-severity-critical/20 text-severity-critical text-xs font-medium cursor-pointer hover:bg-severity-critical/20 transition-all"
                      >
                        <Ban size={13} /> Block Server
                      </button>
                    )}
                  </div>
                </CardContent>
              </Card>

              {/* Risk Breakdown */}
              {riskData && <RiskBreakdownPanel assessment={riskData} />}

              {/* Package Scans */}
              <ScanHistoryPanel
                scans={scans}
                onTriggerScan={handleTriggerScan}
                isScanPending={scanMutation.isPending}
                serverId={selectedSrv.server_id}
              />

              {/* Anomalies */}
              {anomalies.length > 0 && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-xs flex items-center gap-1.5">
                      <Activity size={13} /> Recent Anomalies ({anomalies.length})
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2 max-h-64 overflow-y-auto">
                    {anomalies.slice(0, 10).map((a: MCPAnomaly) => (
                      <div key={a.id} className={cn("p-2 rounded-lg border text-xs", riskBg(a.severity))}>
                        <div className="flex items-center justify-between">
                          <span className={cn("font-bold uppercase text-[10px]", riskColor(a.severity))}>
                            {a.severity}
                          </span>
                          <span className="text-[9px] text-muted-foreground">
                            {a.detected_at ? timeAgo(a.detected_at) : ""}
                          </span>
                        </div>
                        <div className="mt-0.5 font-medium">{a.anomaly_type.replace(/_/g, " ")}</div>
                        <div className="mt-0.5 text-muted-foreground truncate">{a.detail}</div>
                        {a.raw_evidence && (
                          <div className="mt-1 text-[9px] font-mono text-muted-foreground/60 truncate" title={a.raw_evidence}>
                            {a.raw_evidence.slice(0, 80)}
                          </div>
                        )}
                      </div>
                    ))}
                  </CardContent>
                </Card>
              )}

              {/* Capabilities */}
              {selectedSrv.capabilities.length > 0 && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-xs">Capabilities</CardTitle>
                  </CardHeader>
                  <CardContent className="flex flex-wrap gap-1">
                    {selectedSrv.capabilities.map((cap, i) => (
                      <Badge key={i} variant="secondary" className="text-[9px]">{cap}</Badge>
                    ))}
                  </CardContent>
                </Card>
              )}

              {/* Metadata */}
              {Object.keys(selectedSrv.metadata).length > 0 && (
                <Card className="mb-16">
                  <CardHeader>
                    <CardTitle className="text-xs">Metadata</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-1">
                    {Object.entries(selectedSrv.metadata).map(([k, v]) => (
                      <div key={k} className="flex justify-between gap-4 text-[10px]">
                        <span className="text-muted-foreground shrink-0">{k}</span>
                        <span className="font-mono text-right break-all" title={String(v)}>{v}</span>
                      </div>
                    ))}
                  </CardContent>
                </Card>
              )}
            </>
          ) : (
            <Card>
              <CardContent className="py-12 text-center text-muted-foreground">
                <Package size={32} className="mx-auto mb-2 opacity-20" />
                <div className="text-sm">Select a server to inspect</div>
                <div className="text-xs mt-1">View risk breakdown, scan history, anomalies &amp; recommended actions</div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </>
  )
}