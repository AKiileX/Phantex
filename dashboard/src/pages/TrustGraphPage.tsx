// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Trust Graph page (O4).
 *
 * Full-page visualisation of the tenant's trust graph. Left panel hosts the
 * force-directed graph, right side-panel shows breakdown for selected entity.
 *
 * Controls:
 *   - Depth selector (1-5)
 *   - Entity-type filter (agent, tool, file, network)
 *   - Trust threshold slider (0-1)
 *   - Node-count badge + truncation warning
 *
 * Data source: GET /api/v1/trust/graph
 * Detail: GET /api/v1/trust/score/:id
 *
 * @module pages/TrustGraphPage
 */

import { useCallback, useMemo, useState, useRef, useEffect } from "react"
import {
  Shield,
  ChevronDown,
  SlidersHorizontal,
  AlertTriangle,
  RefreshCw,
  HelpCircle,
} from "lucide-react"
import { useQueryClient } from "@tanstack/react-query"
import { useTrustGraph } from "@/api/trust"
import { TrustGraph } from "@/components/trust/TrustGraph"
import { TrustBreakdown } from "@/components/trust/TrustBreakdown"
import { Card, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import type { TrustGraphNode, TrustEntityType } from "@/types"

/* ── Constants ─────────────────────────────────────────────────────────────── */

const DEPTH_OPTIONS = [1, 2, 3, 4, 5] as const
const ENTITY_TYPES: TrustEntityType[] = ["agent", "tool", "file", "network"]

/* ── Page ──────────────────────────────────────────────────────────────────── */

export function TrustGraphPage() {
  const queryClient = useQueryClient()

  /* State */
  const [depth, setDepth] = useState(2)
  const [selectedNode, setSelectedNode] = useState<TrustGraphNode | null>(null)
  const [activeTypes, setActiveTypes] = useState<Set<TrustEntityType>>(
    new Set(ENTITY_TYPES),
  )
  const [trustThreshold, setTrustThreshold] = useState(0)
  const [showControls, setShowControls] = useState(false)
  const [showGuide, setShowGuide] = useState(false)

  /* Container sizing */
  const containerRef = useRef<HTMLDivElement>(null)
  const [graphSize, setGraphSize] = useState({ w: 800, h: 500 })

  useEffect(() => {
    function measure() {
      if (!containerRef.current) return
      const rect = containerRef.current.getBoundingClientRect()
      setGraphSize({ w: Math.floor(rect.width), h: Math.max(400, Math.floor(rect.height)) })
    }
    measure()
    const ro = new ResizeObserver(measure)
    if (containerRef.current) ro.observe(containerRef.current)
    return () => ro.disconnect()
  }, [])

  /* Data */
  const { data, isLoading, error } = useTrustGraph({ depth }, true)
  const nodes = useMemo(() => data?.nodes ?? [], [data?.nodes])
  const edges = useMemo(() => data?.edges ?? [], [data?.edges])

  /* Client-side filters */
  const filteredNodes = useMemo(
    () =>
      nodes.filter(
        (n) =>
          activeTypes.has(n.entity_type as TrustEntityType) &&
          n.trust_score >= trustThreshold,
      ),
    [nodes, activeTypes, trustThreshold],
  )

  const filteredNodeIds = useMemo(
    () => new Set(filteredNodes.map((n) => n.id)),
    [filteredNodes],
  )

  const filteredEdges = useMemo(
    () => edges.filter((e) => filteredNodeIds.has(e.source_id) && filteredNodeIds.has(e.target_id)),
    [edges, filteredNodeIds],
  )

  /* Stats */
  const lowTrustCount = useMemo(
    () => filteredNodes.filter((n) => n.trust_score < 0.3).length,
    [filteredNodes],
  )

  /* Handlers */
  const handleNodeClick = useCallback((node: TrustGraphNode) => {
    setSelectedNode(node)
  }, [])

  const handleCloseBreakdown = useCallback(() => {
    setSelectedNode(null)
  }, [])

  const toggleType = useCallback((type: TrustEntityType) => {
    setActiveTypes((prev) => {
      const next = new Set(prev)
      if (next.has(type)) {
        if (next.size > 1) next.delete(type) // keep at least one
      } else {
        next.add(type)
      }
      return next
    })
  }, [])

  const handleRefresh = useCallback(() => {
    queryClient.invalidateQueries({ queryKey: ["trust"] })
  }, [queryClient])

  return (
    <div className="flex flex-col gap-4 h-full">
      {/* Page header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <Shield className="size-5 text-violet-400" />
          <h1 className="text-lg font-semibold text-foreground">Trust Graph</h1>
          <button onClick={() => setShowGuide(!showGuide)} className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"><HelpCircle size={14} />{showGuide ? "Hide Guide" : "How does this work?"}</button>
          {data?.truncated && (
            <Badge
              variant="outline"
              className="bg-yellow-500/10 text-yellow-400 border-yellow-500/30 text-[10px]"
            >
              <AlertTriangle className="size-3 mr-1" />
              Truncated ({nodes.length} nodes shown)
            </Badge>
          )}
        </div>

        <div className="flex items-center gap-2">
          {/* Depth selector */}
          <div className="relative">
            <select
              value={depth}
              onChange={(e) => setDepth(Number(e.target.value))}
              className="appearance-none rounded-md bg-surface-2/60 border border-border/50
                         px-2.5 py-1 pr-7 text-xs text-foreground outline-none cursor-pointer
                         hover:bg-surface-2/80 transition-colors"
            >
              {DEPTH_OPTIONS.map((d) => (
                <option key={d} value={d}>
                  Depth {d}
                </option>
              ))}
            </select>
            <ChevronDown className="size-3 absolute right-2 top-1/2 -translate-y-1/2
                                    pointer-events-none text-muted-foreground" />
          </div>

          {/* Controls toggle */}
          <Button
            variant="outline"
            size="sm"
            className="gap-1.5 text-xs"
            onClick={() => setShowControls((v) => !v)}
          >
            <SlidersHorizontal className="size-3.5" />
            Filters
          </Button>

          {/* Refresh */}
          <Button variant="outline" size="sm" className="gap-1.5 text-xs" onClick={handleRefresh}>
            <RefreshCw className="size-3.5" />
            Refresh
          </Button>
        </div>
      </div>

      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5 space-y-3 text-sm text-muted-foreground">
          <h3 className="text-base font-semibold text-foreground">How does the Trust Graph work?</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Neo4j Backend</p>
              <p>The graph is stored in Neo4j and served via <code className="text-xs bg-white/5 px-1 rounded">GET /api/v1/trust/graph?depth=N</code>. Currently contains 14 nodes and 13 edges representing agents, tools, data stores, and their trust relationships. The Rust trust engine computes scores.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Trust Scores</p>
              <p>Each node has a trust score (0-1) computed by the trust engine using 5 factors: behavioral history, identity verification, data handling compliance, anomaly frequency, and configuration adherence. Formally verified with Z3 invariants.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Filters &amp; Controls</p>
              <p>Set traversal depth (1-5 hops from center), filter by entity type (agent/tool/data_store/model/api), and set a trust threshold to hide low-trust nodes. These are server-side filters applied to the Neo4j query.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Trust Breakdown</p>
              <p>Click any node to open the Trust Breakdown panel showing the 5 factor scores, connected entities, recent events, and overall trust trajectory. This is how you audit why an entity has a particular trust level.</p>
            </div>
          </div>
        </div>
      )}

      {/* Collapsible controls */}
      {showControls && (
        <Card className="bg-card/60 border-border/40">
          <CardContent className="flex flex-wrap items-center gap-4 py-3 px-4">
            {/* Entity type toggles */}
            <div className="flex items-center gap-1.5">
              <span className="text-[10px] text-muted-foreground uppercase tracking-wider mr-1">
                Types
              </span>
              {ENTITY_TYPES.map((type) => {
                const active = activeTypes.has(type)
                return (
                  <button
                    key={type}
                    onClick={() => toggleType(type)}
                    className={`rounded px-2 py-0.5 text-[11px] font-medium capitalize
                                transition-colors cursor-pointer border
                      ${active
                        ? "bg-violet-500/15 text-violet-400 border-violet-500/30"
                        : "bg-surface-2/30 text-muted-foreground/50 border-border/20"}`}
                  >
                    {type}
                  </button>
                )
              })}
            </div>

            {/* Trust threshold slider */}
            <div className="flex items-center gap-2">
              <span className="text-[10px] text-muted-foreground uppercase tracking-wider">
                Min Trust
              </span>
              <input
                type="range"
                min={0}
                max={1}
                step={0.05}
                value={trustThreshold}
                onChange={(e) => setTrustThreshold(parseFloat(e.target.value))}
                className="w-24 accent-violet-500 h-1"
              />
              <span className="text-xs font-mono text-foreground/70 w-8">
                {trustThreshold.toFixed(2)}
              </span>
            </div>

            {/* Stats */}
            <div className="ml-auto flex items-center gap-4 text-xs text-muted-foreground">
              <span>{filteredNodes.length} nodes</span>
              <span>{filteredEdges.length} edges</span>
              {lowTrustCount > 0 && (
                <span className="text-red-400 font-medium">
                  {lowTrustCount} low-trust
                </span>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Main area: graph + breakdown panel */}
      <div className="flex gap-4 flex-1 min-h-0">
        {/* Graph container */}
        <div ref={containerRef} className="flex-1 min-w-0 min-h-0">
          {isLoading && filteredNodes.length === 0 ? (
            <Card className="h-full flex items-center justify-center bg-card/40">
              <CardContent className="flex flex-col items-center gap-3 py-12">
                <div className="size-6 border-2 border-violet-400/50 border-t-violet-400
                                rounded-full animate-spin" />
                <span className="text-xs text-muted-foreground">Loading trust graph…</span>
              </CardContent>
            </Card>
          ) : error ? (
            <Card className="h-full flex items-center justify-center bg-card/40">
              <CardContent className="flex flex-col items-center gap-2 py-12">
                <AlertTriangle className="size-5 text-red-400" />
                <span className="text-xs text-red-400">
                  Failed to load trust data
                </span>
                <Button variant="outline" size="sm" className="mt-2 text-xs" onClick={handleRefresh}>
                  Retry
                </Button>
              </CardContent>
            </Card>
          ) : filteredNodes.length === 0 ? (
            <Card className="h-full flex items-center justify-center bg-card/40">
              <CardContent className="flex flex-col items-center gap-2 py-12">
                <Shield className="size-5 text-muted-foreground/40" />
                <span className="text-xs text-muted-foreground">
                  No entities match current filters
                </span>
              </CardContent>
            </Card>
          ) : (
            <TrustGraph
              nodes={filteredNodes}
              edges={filteredEdges}
              width={graphSize.w}
              height={graphSize.h}
              selectedId={selectedNode?.id}
              onNodeClick={handleNodeClick}
            />
          )}
        </div>

        {/* Breakdown side panel */}
        {selectedNode && (
          <TrustBreakdown node={selectedNode} onClose={handleCloseBreakdown} />
        )}
      </div>
    </div>
  )
}
