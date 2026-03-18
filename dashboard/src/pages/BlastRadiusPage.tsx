// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Blast Radius Simulator.
 *
 * "What if this agent is compromised?" — visualise reachable assets,
 * downstream agents, tools, and data stores that could be impacted.
 *
 * Data sources:
 *   - GET /api/v1/trust/graph → relationship graph
 *   - GET /api/v1/agents → agent list
 *   - GET /api/v1/alerts → active alerts (severity indicators)
 *
 * @module pages/BlastRadiusPage
 */

import { useMemo, useState, useCallback, useEffect, useRef } from "react"
import {
  Crosshair,
  Zap,
  Shield,
  AlertTriangle,
  Search,
  Play,
  RotateCcw,
  Layers,
  CircleDot,
  HelpCircle,
} from "lucide-react"
import { useTrustGraph } from "@/api/trust"
import { useAgents } from "@/api/agents"
import { useAlerts } from "@/api/alerts"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"
import { useThemeStore } from "@/stores/themeStore"
import type { TrustGraphNode, TrustGraphEdge, AgentSummary, AlertSummary } from "@/types"

/* ── Impact node type ──────────────────────────────────────── */

interface ImpactNode {
  id: string
  name: string
  type: string
  depth: number // hops from origin
  trustScore: number
  impacted: boolean
  hasAlerts: boolean
  x: number
  y: number
}

/* ── Component ─────────────────────────────────────────────── */

export default function BlastRadiusPage() {
  const [searchQuery, setSearchQuery] = useState("")
  const [selectedOrigin, setSelectedOrigin] = useState<string | null>(null)
  const [maxHops, setMaxHops] = useState(3)
  const [animating, setAnimating] = useState(false)
  const [animatedDepth, setAnimatedDepth] = useState(0)
  const [showGuide, setShowGuide] = useState(false)
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const isDark = useThemeStore((s) => s.resolved === "dark")

  const { data: graphData } = useTrustGraph({ depth: 4 })
  const { data: agentsData } = useAgents({ limit: 100 })
  const { data: alertsData } = useAlerts({ status: "open" })

  const graphNodes = useMemo(() => graphData?.nodes ?? [], [graphData?.nodes])
  const graphEdges = useMemo(() => graphData?.edges ?? [], [graphData?.edges])
  const agents = useMemo(() => agentsData?.items ?? [], [agentsData?.items])
  const alerts = useMemo(() => alertsData?.items ?? [], [alertsData?.items])

  // Alert index
  const alertAgents = useMemo(() => {
    const set = new Set<string>()
    alerts.forEach((a: AlertSummary) => { if (a.agent_id) set.add(a.agent_id) })
    return set
  }, [alerts])

  /* ── Build adjacency map ─────────────────────────────── */
  const adjacency = useMemo(() => {
    const map = new Map<string, Set<string>>()
    graphEdges.forEach((e: TrustGraphEdge) => {
      if (!map.has(e.source_id)) map.set(e.source_id, new Set())
      if (!map.has(e.target_id)) map.set(e.target_id, new Set())
      map.get(e.source_id)!.add(e.target_id)
      map.get(e.target_id)!.add(e.source_id)
    })
    return map
  }, [graphEdges])

  /* ── Agent picker list ───────────────────────────────── */
  const agentList = useMemo(() => {
    const all = agents.map((a: AgentSummary) => ({
      id: a.id,
      name: a.name ?? `Agent-${(a.id ?? "unknown").slice(0, 8)}`,
      status: a.status,
    }))
    if (!searchQuery) return all
    return all.filter((a) => a.name.toLowerCase().includes(searchQuery.toLowerCase()))
  }, [agents, searchQuery])

  /* ── BFS blast radius calculation ────────────────────── */
  const { impactNodes, impactEdges, stats } = useMemo(() => {
    if (!selectedOrigin) return { impactNodes: [] as ImpactNode[], impactEdges: [] as [string, string][], stats: { total: 0, byDepth: [] as number[], avgTrust: 0 } }

    const visited = new Map<string, number>() // id -> depth
    const queue: [string, number][] = [[selectedOrigin, 0]]
    visited.set(selectedOrigin, 0)

    while (queue.length > 0) {
      const [current, depth] = queue.shift()!
      if (depth >= maxHops) continue
      const neighbors = adjacency.get(current) ?? new Set()
      for (const n of neighbors) {
        if (!visited.has(n)) {
          visited.set(n, depth + 1)
          queue.push([n, depth + 1])
        }
      }
    }

    // Node index
    const nodeIndex = new Map<string, TrustGraphNode>()
    graphNodes.forEach((n: TrustGraphNode) => nodeIndex.set(n.id, n))

    // Layout: concentric rings
    const byDepth = new Map<number, string[]>()
    visited.forEach((depth, id) => {
      const arr = byDepth.get(depth) ?? []
      arr.push(id)
      byDepth.set(depth, arr)
    })

    const CX = 400, CY = 300
    const RING_SPACING = 90

    const nodes: ImpactNode[] = []
    visited.forEach((depth, id) => {
      const gn = nodeIndex.get(id)
      const ring = byDepth.get(depth) ?? [id]
      const idx = ring.indexOf(id)
      const angleStep = (2 * Math.PI) / ring.length
      const angle = angleStep * idx - Math.PI / 2
      const radius = depth * RING_SPACING

      nodes.push({
        id,
        name: gn?.metadata?.name ?? id.slice(0, 10),
        type: gn?.entity_type ?? "unknown",
        depth,
        trustScore: gn?.trust_score ?? 0.5,
        impacted: depth <= (animating ? animatedDepth : maxHops),
        hasAlerts: alertAgents.has(id),
        x: CX + radius * Math.cos(angle),
        y: CY + radius * Math.sin(angle),
      })
    })

    // Edges between impacted nodes
    const impactSet = new Set(visited.keys())
    const edges: [string, string][] = []
    graphEdges.forEach((e: TrustGraphEdge) => {
      if (impactSet.has(e.source_id) && impactSet.has(e.target_id)) {
        edges.push([e.source_id, e.target_id])
      }
    })

    // Stats
    const depthCounts: number[] = []
    byDepth.forEach((ids, d) => { depthCounts[d] = ids.length })
    const avgTrust = nodes.length > 0 ? nodes.reduce((s, n) => s + n.trustScore, 0) / nodes.length : 0

    return { impactNodes: nodes, impactEdges: edges, stats: { total: nodes.length, byDepth: depthCounts, avgTrust } }
  }, [selectedOrigin, maxHops, graphNodes, graphEdges, adjacency, alertAgents, animating, animatedDepth])

  /* ── Canvas render (v2 — premium) ─────────────────────── */
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext("2d")
    if (!ctx) return

    const dpr = window.devicePixelRatio || 1
    const rect = canvas.getBoundingClientRect()
    canvas.width = rect.width * dpr
    canvas.height = rect.height * dpr
    ctx.scale(dpr, dpr)
    ctx.clearRect(0, 0, rect.width, rect.height)

    const CX = rect.width / 2, CY = rect.height / 2
    const RING = 90

    // Draw concentric blast rings with gradient fills
    const currentDepth = animating ? animatedDepth : maxHops
    for (let d = maxHops; d >= 1; d--) {
      ctx.beginPath()
      ctx.arc(CX, CY, d * RING, 0, 2 * Math.PI)
      if (d <= currentDepth) {
        // Gradient fill for active blast zone
        const grad = ctx.createRadialGradient(CX, CY, (d - 1) * RING, CX, CY, d * RING)
        const intensity = 0.06 * (maxHops - d + 1)
        grad.addColorStop(0, `rgba(239, 68, 68, ${intensity})`)
        grad.addColorStop(1, `rgba(239, 68, 68, ${intensity * 0.3})`)
        ctx.fillStyle = grad
        ctx.fill()
        // Glowing ring border
        ctx.strokeStyle = `rgba(239, 68, 68, ${0.2 + 0.1 * (maxHops - d)})`
        ctx.lineWidth = 1.5
        ctx.shadowColor = "rgba(239, 68, 68, 0.3)"
        ctx.shadowBlur = 8
      } else {
        ctx.strokeStyle = isDark ? "rgba(63, 63, 70, 0.12)" : "rgba(0, 0, 0, 0.06)"
        ctx.lineWidth = 0.5
        ctx.shadowBlur = 0
      }
      ctx.stroke()
      ctx.shadowBlur = 0
    }

    // Draw subtle grid dots in background
    for (let x = 0; x < rect.width; x += 40) {
      for (let y = 0; y < rect.height; y += 40) {
        ctx.beginPath()
        ctx.arc(x, y, 0.5, 0, 2 * Math.PI)
        ctx.fillStyle = isDark ? "rgba(63, 63, 70, 0.15)" : "rgba(0, 0, 0, 0.05)"
        ctx.fill()
      }
    }

    // ID→node index
    const nodeIndex = new Map<string, ImpactNode>()
    impactNodes.forEach((n) => nodeIndex.set(n.id, n))

    // Scale positions to canvas
    const scaledNodes = impactNodes.map((n) => ({
      ...n,
      sx: CX + (n.x - 400) * (rect.width / 800),
      sy: CY + (n.y - 300) * (rect.height / 600),
    }))
    const scaledIndex = new Map(scaledNodes.map((n) => [n.id, n]))

    // Draw edges with curved lines
    impactEdges.forEach(([src, tgt]) => {
      const a = scaledIndex.get(src)
      const b = scaledIndex.get(tgt)
      if (!a || !b) return
      const midX = (a.sx + b.sx) / 2
      const midY = (a.sy + b.sy) / 2
      // Slight curve offset
      const dx = b.sx - a.sx
      const dy = b.sy - a.sy
      const curveX = midX - dy * 0.1
      const curveY = midY + dx * 0.1

      ctx.beginPath()
      ctx.moveTo(a.sx, a.sy)
      ctx.quadraticCurveTo(curveX, curveY, b.sx, b.sy)

      const isImpacted = a.depth <= currentDepth && b.depth <= currentDepth
      if (isImpacted) {
        const grad = ctx.createLinearGradient(a.sx, a.sy, b.sx, b.sy)
        grad.addColorStop(0, "rgba(239, 68, 68, 0.25)")
        grad.addColorStop(1, "rgba(239, 68, 68, 0.08)")
        ctx.strokeStyle = grad
        ctx.lineWidth = 1
      } else {
        ctx.strokeStyle = "rgba(239, 68, 68, 0.06)"
        ctx.lineWidth = 0.5
      }
      ctx.stroke()
    })

    // Draw nodes with glow orb style
    scaledNodes.forEach((n) => {
      const isImpacted = n.depth <= currentDepth
      const isOrigin = n.depth === 0

      // Outer glow ring for impacted nodes
      if (isImpacted && !isOrigin) {
        ctx.beginPath()
        ctx.arc(n.sx, n.sy, 18, 0, 2 * Math.PI)
        const grad = ctx.createRadialGradient(n.sx, n.sy, 4, n.sx, n.sy, 18)
        const opacity = 0.3 * (1 - n.depth * 0.15)
        grad.addColorStop(0, `rgba(239, 68, 68, ${opacity})`)
        grad.addColorStop(0.5, `rgba(239, 68, 68, ${opacity * 0.3})`)
        grad.addColorStop(1, "rgba(239, 68, 68, 0)")
        ctx.fillStyle = grad
        ctx.fill()
      }

      // Origin has extra glow
      if (isOrigin) {
        ctx.beginPath()
        ctx.arc(n.sx, n.sy, 26, 0, 2 * Math.PI)
        const grad = ctx.createRadialGradient(n.sx, n.sy, 6, n.sx, n.sy, 26)
        grad.addColorStop(0, "rgba(239, 68, 68, 0.4)")
        grad.addColorStop(0.5, "rgba(239, 68, 68, 0.1)")
        grad.addColorStop(1, "rgba(239, 68, 68, 0)")
        ctx.fillStyle = grad
        ctx.fill()
      }

      // Node orb
      const r = isOrigin ? 12 : 7
      ctx.beginPath()
      ctx.arc(n.sx, n.sy, r, 0, 2 * Math.PI)

      if (isOrigin) {
        const grad = ctx.createRadialGradient(n.sx - 2, n.sy - 2, 1, n.sx, n.sy, r)
        grad.addColorStop(0, "#ff6b6b")
        grad.addColorStop(1, "#ef4444")
        ctx.fillStyle = grad
        ctx.shadowColor = "rgba(239, 68, 68, 0.6)"
        ctx.shadowBlur = 12
        ctx.strokeStyle = "#fca5a5"
        ctx.lineWidth = 2
      } else if (isImpacted) {
        const opacity = 1 - n.depth * 0.15
        const grad = ctx.createRadialGradient(n.sx - 1, n.sy - 1, 1, n.sx, n.sy, r)
        grad.addColorStop(0, `rgba(255, 107, 107, ${opacity})`)
        grad.addColorStop(1, `rgba(239, 68, 68, ${opacity * 0.8})`)
        ctx.fillStyle = grad
        ctx.strokeStyle = `rgba(239, 68, 68, ${opacity * 0.4})`
        ctx.lineWidth = 1
        ctx.shadowColor = `rgba(239, 68, 68, ${opacity * 0.3})`
        ctx.shadowBlur = 6
      } else {
        ctx.fillStyle = isDark ? "rgba(63, 63, 70, 0.25)" : "rgba(0, 0, 0, 0.1)"
        ctx.strokeStyle = isDark ? "rgba(63, 63, 70, 0.15)" : "rgba(0, 0, 0, 0.06)"
        ctx.lineWidth = 1
        ctx.shadowBlur = 0
      }
      ctx.fill()
      ctx.stroke()
      ctx.shadowBlur = 0

      // Alert indicator with glow
      if (n.hasAlerts) {
        ctx.beginPath()
        ctx.arc(n.sx + r + 2, n.sy - r - 1, 4, 0, 2 * Math.PI)
        ctx.fillStyle = "#f59e0b"
        ctx.shadowColor = "rgba(245, 158, 11, 0.5)"
        ctx.shadowBlur = 6
        ctx.fill()
        ctx.shadowBlur = 0
        // inner dot
        ctx.beginPath()
        ctx.arc(n.sx + r + 2, n.sy - r - 1, 2, 0, 2 * Math.PI)
        ctx.fillStyle = "#fbbf24"
        ctx.fill()
      }

      // Label with background
      const label = n.name.slice(0, 14)
      ctx.font = `${isOrigin ? "bold " : ""}${isOrigin ? 10 : 9}px system-ui, sans-serif`
      const labelWidth = ctx.measureText(label).width
      if (isImpacted || isOrigin) {
        ctx.fillStyle = isDark ? "rgba(9, 9, 11, 0.7)" : "rgba(255, 255, 255, 0.7)"
        ctx.beginPath()
        const lx = n.sx - labelWidth / 2 - 4
        const ly = n.sy + r + 6
        ctx.roundRect(lx, ly, labelWidth + 8, 14, 3)
        ctx.fill()
      }
      ctx.fillStyle = isImpacted
        ? (isDark ? "rgba(255,255,255,0.85)" : "rgba(9,9,11,0.85)")
        : (isDark ? "rgba(255,255,255,0.25)" : "rgba(9,9,11,0.25)")
      ctx.textAlign = "center"
      ctx.fillText(label, n.sx, n.sy + r + 16)
    })
  }, [impactNodes, impactEdges, maxHops, animating, animatedDepth, isDark])

  /* ── Animation ───────────────────────────────────────── */
  const runAnimation = useCallback(() => {
    setAnimatedDepth(0)
    setAnimating(true)

    let depth = 0
    const iv = setInterval(() => {
      depth++
      setAnimatedDepth(depth)
      if (depth >= maxHops) {
        clearInterval(iv)
        setTimeout(() => setAnimating(false), 600)
      }
    }, 500)
  }, [maxHops])

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center h-9 w-9 rounded-lg bg-red-500/10 border border-red-500/20">
            <Crosshair size={18} className="text-red-400" />
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-tight">Blast Radius Simulator</h1>
            <p className="text-xs text-muted-foreground">"What if this agent is compromised?" — impact visualization</p>
          </div>          <button onClick={() => setShowGuide(!showGuide)} className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"><HelpCircle size={14} />{showGuide ? "Hide Guide" : "How does this work?"}</button>        </div>

        <div className="flex items-center gap-2">
          {/* Hop slider */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-surface-1/50 border border-border/30">
            <Layers size={13} className="text-muted-foreground" />
            <span className="text-xs text-muted-foreground">Hops:</span>
            {[1, 2, 3, 4].map((h) => (
              <button
                key={h}
                onClick={() => setMaxHops(h)}
                className={cn(
                  "w-6 h-6 rounded text-xs font-bold transition-all cursor-pointer",
                  maxHops === h ? "bg-primary/15 text-primary border border-primary/20" : "text-muted-foreground hover:text-foreground",
                )}
              >
                {h}
              </button>
            ))}
          </div>

          {selectedOrigin && (
            <>
              <Button size="sm" variant="outline" onClick={runAnimation}>
                <Play size={12} className="mr-1" /> Simulate
              </Button>
              <Button size="sm" variant="outline" onClick={() => { setSelectedOrigin(null); setAnimating(false) }}>
                <RotateCcw size={12} className="mr-1" /> Reset
              </Button>
            </>
          )}
        </div>
      </div>

      <div className="grid grid-cols-12 gap-4">
        {/* Agent picker */}
        <div className="col-span-3 space-y-3">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs">Select Origin Agent</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <div className="relative">
                <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search agents..."
                  className="w-full pl-8 pr-3 py-1.5 text-xs border border-border/50 rounded-lg bg-surface-1 focus:outline-none focus:ring-1 focus:ring-primary/30"
                />
              </div>
              <div className="max-h-[460px] overflow-y-auto space-y-1">
                {agentList.map((a) => (
                  <button
                    key={a.id}
                    onClick={() => { setSelectedOrigin(a.id); setAnimating(false) }}
                    className={cn(
                      "w-full text-left px-3 py-2 rounded-lg text-xs transition-all cursor-pointer flex items-center gap-2",
                      selectedOrigin === a.id
                        ? "bg-severity-critical/10 border border-severity-critical/20 text-severity-critical"
                        : "hover:bg-surface-1 text-foreground",
                    )}
                  >
                    <CircleDot size={10} className={selectedOrigin === a.id ? "text-severity-critical" : "text-muted-foreground"} />
                    <span className="truncate">{a.name}</span>
                    {alertAgents.has(a.id) && <AlertTriangle size={10} className="ml-auto text-severity-high" />}
                  </button>
                ))}
                {agentList.length === 0 && (
                  <div className="text-center py-4 text-muted-foreground text-xs">No agents found</div>
                )}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Blast radius canvas */}
        <div className="col-span-6">
          <Card className="p-0 overflow-hidden relative">
            {/* Background gradient accent */}
            <div className="absolute inset-0 bg-gradient-to-br from-red-500/[0.02] via-transparent to-orange-500/[0.02] pointer-events-none" />
            <div ref={containerRef} className="relative" style={{ height: 520 }}>
              <canvas
                ref={canvasRef}
                className="w-full h-full"
                style={{ width: "100%", height: "100%" }}
              />
              {!selectedOrigin && (
                <div className="absolute inset-0 flex flex-col items-center justify-center text-muted-foreground backdrop-blur-[1px]">
                  <div className="relative">
                    <div className="absolute inset-0 rounded-full bg-red-500/5 blur-2xl scale-150" />
                    <Crosshair size={56} className="mb-4 opacity-10 relative" />
                  </div>
                  <div className="text-sm font-medium">Select an agent to simulate</div>
                  <div className="text-xs opacity-50 mt-1">Pick an origin from the left panel</div>
                </div>
              )}
              {animating && (
                <div className="absolute top-3 left-1/2 -translate-x-1/2 px-5 py-2 rounded-xl bg-severity-critical/10 border border-severity-critical/20 backdrop-blur-md shadow-lg shadow-red-500/10">
                  <span className="text-xs font-bold text-severity-critical animate-pulse flex items-center gap-2">
                    <Zap size={14} className="text-severity-critical" />
                    Propagating — Hop {animatedDepth} of {maxHops}
                  </span>
                </div>
              )}
            </div>
          </Card>
        </div>

        {/* Impact stats */}
        <div className="col-span-3 space-y-3">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs flex items-center gap-2">
                <Zap size={12} /> Impact Summary
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {selectedOrigin ? (
                <>
                  <div className="text-center">
                    <div className="text-4xl font-bold text-severity-critical tabular-nums">
                      {stats.total}
                    </div>
                    <div className="text-[10px] text-muted-foreground">Reachable Entities</div>
                  </div>

                  <div className="h-px bg-border/20" />

                  {/* By depth */}
                  <div className="space-y-2">
                    <div className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">By Hop Distance</div>
                    {stats.byDepth.map((count, depth) => (
                      <div key={depth} className="flex items-center gap-2">
                        <span className="text-xs text-muted-foreground w-14">Hop {depth}</span>
                        <div className="flex-1 h-2 rounded-full bg-surface-2 overflow-hidden">
                          <div
                            className="h-full rounded-full transition-all duration-500"
                            style={{
                              width: `${Math.min(100, (count / Math.max(1, stats.total)) * 100)}%`,
                              backgroundColor: depth === 0 ? "#ef4444" : `rgba(239, 68, 68, ${1 - depth * 0.2})`,
                            }}
                          />
                        </div>
                        <span className="text-xs font-bold tabular-nums w-6 text-right">{count}</span>
                      </div>
                    ))}
                  </div>

                  <div className="h-px bg-border/20" />

                  {/* Avg trust */}
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-muted-foreground flex items-center gap-1"><Shield size={11} /> Avg Trust</span>
                    <span className={cn(
                      "font-bold tabular-nums",
                      stats.avgTrust >= 0.7 ? "text-status-active" :
                      stats.avgTrust >= 0.4 ? "text-severity-medium" : "text-severity-critical",
                    )}>
                      {(stats.avgTrust * 100).toFixed(0)}%
                    </span>
                  </div>

                  {/* Risk assessment */}
                  <div className="p-3 rounded-lg bg-severity-critical/5 border border-severity-critical/10">
                    <div className="text-[10px] font-bold text-severity-critical mb-1">Risk Assessment</div>
                    <div className="text-[10px] text-muted-foreground">
                      {stats.total > 10
                        ? "High blast radius — compromise could cascade to many entities. Consider reducing trust scope."
                        : stats.total > 5
                          ? "Moderate blast radius — some entities at risk. Review trust boundaries."
                          : "Contained blast radius — limited propagation path."}
                    </div>
                  </div>
                </>
              ) : (
                <div className="py-8 text-center text-muted-foreground">
                  <Shield size={24} className="mx-auto mb-2 opacity-20" />
                  <div className="text-xs">Select an agent to see impact analysis</div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Legend */}
          <Card>
            <CardContent className="py-3 space-y-2">
              <div className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">Legend</div>
              {[
                { color: "#ef4444", label: "Compromised (origin)" },
                { color: "rgba(239,68,68,0.6)", label: "Directly impacted" },
                { color: "rgba(239,68,68,0.3)", label: "Transitively reachable" },
                { color: "#f59e0b", label: "Has active alerts", icon: true },
              ].map((l) => (
                <div key={l.label} className="flex items-center gap-2 text-[10px]">
                  {l.icon ? (
                    <AlertTriangle size={10} className="text-severity-high" />
                  ) : (
                    <div className="w-3 h-3 rounded-full" style={{ backgroundColor: l.color }} />
                  )}
                  <span className="text-muted-foreground">{l.label}</span>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>

      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5 space-y-3 text-sm text-muted-foreground">
          <h3 className="text-base font-semibold text-foreground">How does the Blast Radius Simulator work?</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Trust Graph Data</p>
              <p>Built on <code className="text-xs bg-white/5 px-1 rounded">useTrustGraph</code> which fetches the Neo4j trust graph (14 nodes, 13 edges observed). Nodes represent agents, tools, data stores, and services. Edges represent trust relationships and data flows.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Hop-based Propagation</p>
              <p>Select an agent as the "compromised origin" and set max hops (1-5). The simulator traces all reachable nodes through trust edges. Depth coloring shows direct impact (red) vs. transitive reach (faded red) — like a network contagion model.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Alert Overlay</p>
              <p>Active alerts from <code className="text-xs bg-white/5 px-1 rounded">useAlerts</code> are overlaid on impacted nodes. Nodes with active alerts get amber warning indicators. This shows which compromised-path nodes already have security events.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Risk Assessment</p>
              <p>The side panel computes impact stats: total nodes affected, alert count on path, and a qualitative risk assessment. Use this to justify trust boundary tightening or agent isolation policies.</p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
