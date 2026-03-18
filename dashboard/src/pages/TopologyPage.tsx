// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Agent Topology page (enterprise fleet visualization).
 *
 * Data source: GET /api/v1/agents → CursorPage<AgentSummary>
 * Each agent: id, paid, name, framework, status, last_seen.
 *
 * Layout:
 *   1. Header + filter bar (status, framework)
 *   2. Stats summary cards
 *   3. Hub-and-spoke graph (gateway → agents) + optional agent table
 *
 * Phase 1: All agent data is real from the API.
 *   - Graph shows agents → gateway connections (every agent reports to gateway).
 *   - No inter-agent communication data yet
 * Phase 2 planned: real network connections, WebSocket live updates,
 *   drag-to-reposition, zoom/pan, edge labels with traffic volume.
 */

import { useNavigate } from "react-router-dom"
import { useCallback, useMemo, useState } from "react"
import {
  Network,
  Monitor,
  Wifi,
  WifiOff,
  CircleDot,
  Filter,
  List,
  LayoutGrid,
  ExternalLink,
  HelpCircle,
} from "lucide-react"
import { useAgents } from "@/api/agents"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { TopologyGraph } from "@/components/ui/topology-graph"
import { AnimatedNumber } from "@/components/ui/animated-number"
import { timeAgo } from "@/lib/utils"
import type { AgentSummary } from "@/types"

/* ── Filter state ──────────────────────────────────────────── */
type ViewMode = "graph" | "table"
type StatusFilter = "all" | "active" | "stale" | "terminated"

const STATUS_BADGE: Record<string, string> = {
  active: "bg-status-active/15 text-status-active border border-status-active/20",
  stale: "bg-severity-medium/15 text-severity-medium border border-severity-medium/20",
  terminated: "bg-white/5 text-muted-foreground border border-border/30",
}

export function TopologyPage() {
  const navigate = useNavigate()
  const { data: agents, isLoading } = useAgents()

  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all")
  const [fwFilter, setFwFilter] = useState<string>("all")
  const [view, setView] = useState<ViewMode>("graph")
  const [showGuide, setShowGuide] = useState(false)

  const items = useMemo(() => agents?.items ?? [], [agents?.items])

  // Unique frameworks for filter dropdown
  const frameworks = useMemo(() => {
    const set = new Set<string>()
    items.forEach((a) => {
      if (a.framework) set.add(a.framework)
    })
    return Array.from(set).sort()
  }, [items])

  // Filtered agents
  const filtered = useMemo(() => {
    let list = items
    if (statusFilter !== "all") list = list.filter((a) => a.status === statusFilter)
    if (fwFilter !== "all") list = list.filter((a) => a.framework === fwFilter)
    return list
  }, [items, statusFilter, fwFilter])

  const active = useMemo(
    () => items.filter((a) => a.status === "active").length,
    [items],
  )
  const stale = useMemo(
    () => items.filter((a) => a.status === "stale").length,
    [items],
  )
  const terminated = useMemo(
    () => items.filter((a) => a.status === "terminated").length,
    [items],
  )

  const handleNodeClick = useCallback(
    (agentId: string) => navigate(`/agents/${agentId}`),
    [navigate],
  )

  return (
    <div className="space-y-5 animate-fade-in">
      {/* ── Header ─────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 text-primary border border-primary/20">
            <Network size={20} />
          </div>
          <div>
            <h1 className="text-xl font-semibold tracking-tight text-foreground">
              Agent Topology
            </h1>
            <p className="text-sm text-muted-foreground">
              AI agent fleet · data from{" "}
              <span className="font-mono text-xs text-primary/60">
                GET /api/v1/agents
              </span>
            </p>
          </div>
          <button onClick={() => setShowGuide(!showGuide)} className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"><HelpCircle size={14} />{showGuide ? "Hide Guide" : "How does this work?"}</button>
        </div>

        {/* View toggle */}
        <div className="flex items-center gap-1 rounded-lg border border-border/30 p-0.5">
          <Button
            variant={view === "graph" ? "secondary" : "ghost"}
            size="sm"
            className="h-7 px-2.5 text-xs"
            onClick={() => setView("graph")}
          >
            <LayoutGrid size={13} className="mr-1" /> Graph
          </Button>
          <Button
            variant={view === "table" ? "secondary" : "ghost"}
            size="sm"
            className="h-7 px-2.5 text-xs"
            onClick={() => setView("table")}
          >
            <List size={13} className="mr-1" /> Table
          </Button>
        </div>
      </div>

      {/* ── Stats row ──────────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <StatCard
          icon={<Monitor size={15} />}
          label="Total"
          value={items.length}
          stagger="stagger-1"
        />
        <StatCard
          icon={<Wifi size={15} />}
          label="Active"
          value={active}
          color="text-status-active"
          iconBg="bg-status-active/10 text-status-active border-status-active/20"
          stagger="stagger-2"
        />
        <StatCard
          icon={<WifiOff size={15} />}
          label="Stale"
          value={stale}
          color="text-severity-medium"
          iconBg="bg-severity-medium/10 text-severity-medium border-severity-medium/20"
          stagger="stagger-3"
        />
        <StatCard
          icon={<CircleDot size={15} />}
          label="Offline"
          value={terminated}
          color="text-muted-foreground"
          stagger="stagger-4"
        />
      </div>

      {/* ── Filter bar ─────────────────────────────────────── */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <Filter size={12} />
          <span className="font-medium">Filter:</span>
        </div>
        {/* Status */}
        <div className="flex items-center gap-1">
          {(["all", "active", "stale", "terminated"] as const).map((s) => (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              className={`px-2.5 py-1 rounded-md text-xs font-medium transition-colors cursor-pointer ${
                statusFilter === s
                  ? "bg-primary/15 text-primary border border-primary/20"
                  : "text-muted-foreground hover:text-foreground hover:bg-white/[0.03]"
              }`}
            >
              {s === "all" ? "All Status" : s.charAt(0).toUpperCase() + s.slice(1)}
            </button>
          ))}
        </div>

        {/* Framework */}
        {frameworks.length > 0 && (
          <>
            <div className="h-4 w-px bg-border/50" />
            <div className="flex items-center gap-1">
              <button
                onClick={() => setFwFilter("all")}
                className={`px-2.5 py-1 rounded-md text-xs font-medium transition-colors cursor-pointer ${
                  fwFilter === "all"
                    ? "bg-primary/15 text-primary border border-primary/20"
                    : "text-muted-foreground hover:text-foreground hover:bg-white/[0.03]"
                }`}
              >
                All Frameworks
              </button>
              {frameworks.map((fw) => (
                <button
                  key={fw}
                  onClick={() => setFwFilter(fw)}
                  className={`px-2.5 py-1 rounded-md text-xs font-medium transition-colors cursor-pointer ${
                    fwFilter === fw
                      ? "bg-primary/15 text-primary border border-primary/20"
                      : "text-muted-foreground hover:text-foreground hover:bg-white/[0.03]"
                  }`}
                >
                  {fw}
                </button>
              ))}
            </div>
          </>
        )}

        <div className="ml-auto text-xs text-muted-foreground tabular-nums">
          {filtered.length} of {items.length} agents
        </div>
      </div>

      {/* ── Main visualization ─────────────────────────────── */}
      <Card className="stagger-5">
        <CardHeader className="flex flex-row items-center justify-between pb-2">
          <CardTitle className="text-sm">
            {view === "graph" ? "Agent Network Map" : "Agent Fleet"}
          </CardTitle>
          <span className="text-xs text-muted-foreground font-mono">
            {filtered.length} node{filtered.length !== 1 ? "s" : ""}
          </span>
        </CardHeader>
        <CardContent className="p-2 md:p-4">
          {isLoading ? (
            <div className="flex items-center justify-center py-24 text-sm text-muted-foreground">
              Loading topology…
            </div>
          ) : filtered.length === 0 ? (
            <EmptyState total={items.length} />
          ) : view === "graph" ? (
            <TopologyGraph
              agents={filtered}
              width={920}
              height={500}
              onNodeClick={handleNodeClick}
            />
          ) : (
            <AgentTable agents={filtered} onRowClick={handleNodeClick} />
          )}
        </CardContent>
      </Card>

      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5 space-y-3 text-sm text-muted-foreground">
          <h3 className="text-base font-semibold text-foreground">How does Agent Topology work?</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Data Source</p>
              <p>Fetches all agents from <code className="text-xs bg-white/5 px-1 rounded">GET /api/v1/agents</code>. Each node in the graph represents an agent with its status (active/stale/terminated), framework, and network location. Agents auto-appear when sensors discover them.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Graph vs Table View</p>
              <p>Toggle between a force-directed graph visualization (nodes + edges) and a sortable data table. Graph view shows relationships and clustering. Table view gives filterable, sortable access to all agent properties.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Filters</p>
              <p>Filter by status (active/stale/terminated) and framework (LangChain, AutoGen, etc.). Status summary shows counts at each state. Click any node to navigate to that agent's detail page.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Status Indicators</p>
              <p>Green pulsing = active (recent heartbeat). Yellow = stale (missed heartbeats). Gray = terminated. The topology auto-refreshes to reflect real-time fleet changes.</p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

/* ── Sub-components ────────────────────────────────────────── */

function StatCard({
  icon,
  label,
  value,
  color = "text-foreground",
  iconBg = "bg-white/[0.04] text-muted-foreground border-border/30",
  stagger = "",
}: {
  icon: React.ReactNode
  label: string
  value: number
  color?: string
  iconBg?: string
  stagger?: string
}) {
  return (
    <Card className={stagger}>
      <CardContent className="p-4 flex items-center gap-3">
        <div
          className={`flex h-8 w-8 items-center justify-center rounded-lg border ${iconBg}`}
        >
          {icon}
        </div>
        <div>
          <p className="metric-label">{label}</p>
          <AnimatedNumber
            value={value}
            className={`text-lg font-semibold tabular-nums ${color}`}
          />
        </div>
      </CardContent>
    </Card>
  )
}

function EmptyState({ total }: { total: number }) {
  return (
    <div className="flex flex-col items-center justify-center py-24 text-center gap-3">
      <div className="flex h-14 w-14 items-center justify-center rounded-full bg-white/[0.03]">
        <Network size={28} className="text-muted-foreground" />
      </div>
      <div>
        <p className="text-sm font-medium text-foreground">
          {total === 0
            ? "No agents registered"
            : "No agents match filters"}
        </p>
        <p className="text-xs text-muted-foreground mt-1">
          {total === 0
            ? "Deploy an agent with the Phantex SDK to see the topology"
            : "Try adjusting your filters above"}
        </p>
      </div>
    </div>
  )
}

function AgentTable({
  agents,
  onRowClick,
}: {
  agents: AgentSummary[]
  onRowClick: (id: string) => void
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border/40">
            <th className="text-left py-2.5 px-3 text-xs font-medium text-muted-foreground tracking-wider">
              STATUS
            </th>
            <th className="text-left py-2.5 px-3 text-xs font-medium text-muted-foreground tracking-wider">
              AGENT
            </th>
            <th className="text-left py-2.5 px-3 text-xs font-medium text-muted-foreground tracking-wider">
              PAID
            </th>
            <th className="text-left py-2.5 px-3 text-xs font-medium text-muted-foreground tracking-wider">
              FRAMEWORK
            </th>
            <th className="text-left py-2.5 px-3 text-xs font-medium text-muted-foreground tracking-wider">
              LAST SEEN
            </th>
            <th className="w-10" />
          </tr>
        </thead>
        <tbody>
          {agents.map((agent) => (
            <tr
              key={agent.id}
              onClick={() => onRowClick(agent.id)}
              className="border-b border-border/20 cursor-pointer hover:bg-white/[0.02] transition-colors"
            >
              <td className="py-2.5 px-3">
                <span
                  className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-medium ${STATUS_BADGE[agent.status] ?? ""}`}
                >
                  <span
                    className={`w-1.5 h-1.5 rounded-full ${
                      agent.status === "active"
                        ? "bg-status-active"
                        : agent.status === "stale"
                          ? "bg-severity-medium"
                          : "bg-muted-foreground"
                    }`}
                  />
                  {agent.status}
                </span>
              </td>
              <td className="py-2.5 px-3 font-medium text-foreground/90">
                {agent.name ?? "—"}
              </td>
              <td className="py-2.5 px-3 font-mono text-xs text-muted-foreground">
                {agent.paid.slice(0, 16)}
              </td>
              <td className="py-2.5 px-3">
                {agent.framework ? (
                  <Badge variant="outline" className="text-[10px]">
                    {agent.framework}
                  </Badge>
                ) : (
                  <span className="text-xs text-muted-foreground">—</span>
                )}
              </td>
              <td className="py-2.5 px-3 text-xs text-muted-foreground tabular-nums">
                {timeAgo(agent.last_seen)}
              </td>
              <td className="py-2.5 px-3">
                <ExternalLink
                  size={12}
                  className="text-muted-foreground/50"
                />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
