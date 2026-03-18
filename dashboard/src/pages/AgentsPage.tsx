// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Agent inventory page (enterprise data grid).
 *
 * Dense table with status dots, monospaced PAIDs, sortable columns.
 * Click row → agent detail. Filters: status, framework, search.
 * Cursor-based pagination. Auto-refresh every 30s.
 */

import { useState, useMemo } from "react"
import { useNavigate } from "react-router-dom"
import { Monitor, Search, ChevronRight, ChevronLeft, X, HelpCircle } from "lucide-react"
import { useAgents, type AgentFilters } from "@/api/agents"
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

const STATUS_OPTIONS = ["active", "stale", "terminated"] as const
const FRAMEWORK_OPTIONS = [
  "LangChain", "AutoGen", "CrewAI", "LlamaIndex", "OpenAI Agents", "Anthropic",
  "Ollama", "LM Studio", "llama-cpp", "LocalAI", "GPT4All", "Jan", "KoboldCpp",
  "Phantex SDK",
] as const

export function AgentsPage() {
  const navigate = useNavigate()

  // ── Filter state ───────────────────────────────────────────
  const [search, setSearch] = useState("")
  const [statusFilter, setStatusFilter] = useState<string | undefined>()
  const [frameworkFilter, setFrameworkFilter] = useState<string | undefined>()
  const [showGuide, setShowGuide] = useState(false)
  const [cursorStack, setCursorStack] = useState<string[]>([])
  const [currentCursor, setCurrentCursor] = useState<string | undefined>()

  const filters: AgentFilters = useMemo(
    () => ({
      ...(search ? { search } : {}),
      ...(statusFilter ? { status: statusFilter } : {}),
      ...(frameworkFilter ? { framework: frameworkFilter } : {}),
      ...(currentCursor ? { cursor: currentCursor } : {}),
      limit: 50,
    }),
    [search, statusFilter, frameworkFilter, currentCursor],
  )

  const { data, isLoading, isFetching } = useAgents(filters)
  const agents = data?.items ?? []
  const hasMore = data?.has_more ?? false
  const hasFilters = !!statusFilter || !!frameworkFilter || !!search

  // ── Client-side sort ───────────────────────────────────────
  const { sorted: sortedAgents, sortState, toggleSort } = useSort(agents, {
    key: "last_seen",
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
    setFrameworkFilter(undefined)
    setCursorStack([])
    setCurrentCursor(undefined)
  }

  // Reset pagination when filters change
  function updateFilter(setter: (v: string | undefined) => void, value: string | undefined) {
    setter(value)
    setCursorStack([])
    setCurrentCursor(undefined)
  }

  const pageNumber = cursorStack.length + 1

  return (
    <div className="space-y-4 animate-fade-in">
      {/* ── Toolbar ──────────────────────────────────── */}
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div className="flex items-center gap-3">
          <div>
            <h1 className="text-lg font-semibold text-foreground tracking-tight">Agent Inventory</h1>
            <p className="text-sm text-muted-foreground">
              {agents.length} agents{hasMore ? "+" : ""} · page {pageNumber}
              {isFetching && !isLoading ? " · refreshing…" : ""}
            </p>
          </div>
          <button onClick={() => setShowGuide(!showGuide)} className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"><HelpCircle size={14} />{showGuide ? "Hide Guide" : "How does this work?"}</button>
        </div>

        <div className="flex items-center gap-2">
          {/* Search */}
          <div className="relative">
            <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
            <input
              type="text"
              placeholder="Filter by PAID or name…"
              value={search}
              onChange={(e) => updateFilter(setSearch as (v: string | undefined) => void, e.target.value || undefined)}
              className="h-8 w-56 rounded-md border border-border bg-surface-2 pl-8 pr-3 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring"
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

          {/* Framework filter */}
          <select
            value={frameworkFilter ?? ""}
            onChange={(e) => updateFilter(setFrameworkFilter, e.target.value || undefined)}
            className="h-8 rounded-md border border-border bg-surface-2 px-2.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-ring cursor-pointer"
          >
            <option value="">All frameworks</option>
            {FRAMEWORK_OPTIONS.map((f) => (
              <option key={f} value={f}>{f}</option>
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
              <SortableHead sortKey="status" activeKey={sortState.key} activeDir={sortState.dir} onSort={toggleSort} className="w-24">Status</SortableHead>
              <SortableHead sortKey="paid" activeKey={sortState.key} activeDir={sortState.dir} onSort={toggleSort}>PAID</SortableHead>
              <SortableHead sortKey="name" activeKey={sortState.key} activeDir={sortState.dir} onSort={toggleSort}>Name</SortableHead>
              <SortableHead sortKey="framework" activeKey={sortState.key} activeDir={sortState.dir} onSort={toggleSort}>Framework</SortableHead>
              <SortableHead sortKey="os_type" activeKey={sortState.key} activeDir={sortState.dir} onSort={toggleSort}>OS</SortableHead>
              <SortableHead sortKey="ip_address" activeKey={sortState.key} activeDir={sortState.dir} onSort={toggleSort}>IP / Host</SortableHead>
              <SortableHead sortKey="last_seen" activeKey={sortState.key} activeDir={sortState.dir} onSort={toggleSort}>Last Seen</SortableHead>
              <TableHead className="w-8" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={8} className="text-center py-12 text-muted-foreground text-sm">
                  Loading agents…
                </TableCell>
              </TableRow>
            ) : agents.length === 0 ? (
              <TableRow>
                <TableCell colSpan={8} className="text-center py-12">
                  <div className="flex flex-col items-center gap-3">
                    <div className="flex h-12 w-12 items-center justify-center rounded-full bg-white/[0.03]">
                      <Monitor size={22} className="text-muted-foreground" />
                    </div>
                    <p className="text-sm text-muted-foreground">
                      {hasFilters ? "No agents match filters" : "No agents registered"}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {hasFilters ? "Try broadening your search." : "Deploy a sensor to get started."}
                    </p>
                  </div>
                </TableCell>
              </TableRow>
            ) : (
              sortedAgents.map((agent) => (
                <TableRow
                  key={agent.id}
                  className="cursor-pointer group"
                  onClick={() => navigate(`/agents/${agent.id}`)}
                >
                  <TableCell>
                    <Badge variant={agent.status as "active" | "stale" | "terminated"}>
                      {agent.status}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-mono text-xs text-foreground">
                    {agent.paid}
                  </TableCell>
                  <TableCell className="text-sm">
                    {agent.name ?? <span className="text-muted-foreground">—</span>}
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {agent.framework ?? "—"}
                  </TableCell>
                  <TableCell className="text-xs">
                    {agent.os_type ? (
                      <span className="capitalize font-medium">{agent.os_type}</span>
                    ) : <span className="text-muted-foreground">—</span>}
                  </TableCell>
                  <TableCell className="text-xs font-mono">
                    <div className="flex flex-col">
                      {agent.ip_address ? (
                        <span>{agent.ip_address}</span>
                      ) : <span className="text-muted-foreground">—</span>}
                      {agent.hostname && (
                        <span className="text-muted-foreground text-[11px] truncate max-w-[140px]">{agent.hostname}</span>
                      )}
                    </div>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {timeAgo(agent.last_seen)}
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
          <h3 className="text-base font-semibold text-foreground">How does the Agent Inventory work?</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Data Source</p>
              <p>Calls <code className="text-xs bg-white/5 px-1 rounded">GET /api/v1/agents</code> with cursor-based pagination (limit 50). The backend router <code className="text-xs bg-white/5 px-1 rounded">agents.py</code> queries PostgreSQL with RLS tenant isolation. Each agent has a unique UUID and a human-readable PAID (Phantex Agent ID).</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">How Agents Register</p>
              <p>Agents are automatically discovered when a sensor detects an AI framework process. The gateway writes an AGENT_DISCOVERED event, and the backend upserts the agent record with framework, OS, IP, and hostname metadata.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Status Lifecycle</p>
              <p><strong>Active</strong> — seen within heartbeat window. <strong>Stale</strong> — missed heartbeats but not yet timed out. <strong>Terminated</strong> — process exited or manually marked. Statuses update on each sensor heartbeat cycle (30s default).</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Filters &amp; Sorting</p>
              <p>Client-side sorting on all columns. Server-side filtering by status, framework, and PAID/name search. Cursor pagination keeps requests lightweight — each page fetches the next 50 agents from where you left off.</p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
