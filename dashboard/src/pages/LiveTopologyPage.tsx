// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Live Agent Topology Map.
 *
 * 2.5D force-directed graph showing agents, MCP servers, tools, and data
 * flows in real-time. Nodes pulse on activity, edges glow red on anomalies.
 *
 * Data sources:
 *   - GET /api/v1/agents → agent nodes
 *   - GET /api/v1/trust/graph → relationships/edges
 *   - GET /api/v1/alerts (open) → anomaly highlighting
 *
 * @module pages/LiveTopologyPage
 */

import { useEffect, useRef, useMemo, useState, useCallback } from "react"
import {
  Network,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Eye,
  Layers,
  Activity,
  Pin,
  HelpCircle,
} from "lucide-react"
import {
  forceSimulation,
  forceLink,
  forceManyBody,
  forceCenter,
  forceCollide,
  forceRadial,
  forceX,
  forceY,
  type SimulationNodeDatum,
  type SimulationLinkDatum,
} from "d3-force"
import { useAgents } from "@/api/agents"
import { useTrustGraph } from "@/api/trust"
import { useAlerts } from "@/api/alerts"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"
import { useThemeStore } from "@/stores/themeStore"
import type { AgentSummary, AgentStatus, TrustGraphNode, TrustGraphEdge, Severity } from "@/types"

/* ── Node / Edge types ─────────────────────────────────────── */

interface TopoNode extends SimulationNodeDatum {
  id: string
  label: string
  type: "gateway" | "agent" | "tool" | "mcp" | "network" | "file"
  status?: AgentStatus
  trustScore?: number
  hasAlert?: boolean
  alertSeverity?: Severity
  framework?: string
  metadata?: Record<string, string>
}

interface TopoLink extends SimulationLinkDatum<TopoNode> {
  id: string
  edgeType: string
  weight: number
  hasAnomaly: boolean
}

/* ── Visual config ─────────────────────────────────────────── */

const NODE_COLORS: Record<string, { fill: string; stroke: string; glow: string }> = {
  gateway: { fill: "#10b981", stroke: "#059669", glow: "rgba(16,185,129,0.4)" },
  agent: { fill: "#3b82f6", stroke: "#2563eb", glow: "rgba(59,130,246,0.3)" },
  tool: { fill: "#8b5cf6", stroke: "#7c3aed", glow: "rgba(139,92,246,0.3)" },
  mcp: { fill: "#f59e0b", stroke: "#d97706", glow: "rgba(245,158,11,0.3)" },
  network: { fill: "#06b6d4", stroke: "#0891b2", glow: "rgba(6,182,212,0.3)" },
  file: { fill: "#6b7280", stroke: "#4b5563", glow: "rgba(107,114,128,0.2)" },
}

const SEVERITY_GLOW: Record<string, string> = {
  critical: "rgba(239,68,68,0.6)",
  high: "rgba(249,115,22,0.5)",
  medium: "rgba(234,179,8,0.3)",
  low: "rgba(59,130,246,0.2)",
}

const NODE_RADIUS: Record<string, number> = {
  gateway: 32,
  agent: 22,
  tool: 14,
  mcp: 18,
  network: 16,
  file: 12,
}

/* Radial tiers — distance from center gateway */
const RADIAL_TIER: Record<string, number> = {
  gateway: 0,
  agent: 180,
  mcp: 300,
  tool: 380,
  network: 320,
  file: 420,
}

const NODE_ICONS: Record<string, string> = {
  gateway: "⬡",
  agent: "◈",
  tool: "⚙",
  mcp: "⬢",
  network: "◎",
  file: "◻",
}

/* ── Filter types ──────────────────────────────────────────── */
type NodeTypeFilter = "all" | "agent" | "tool" | "mcp" | "network" | "file"

/* ── Component ─────────────────────────────────────────────── */

export default function LiveTopologyPage() {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const animRef = useRef<number>(0)
  const simRef = useRef<ReturnType<typeof forceSimulation<TopoNode>> | null>(null)
  const nodesRef = useRef<TopoNode[]>([])
  const linksRef = useRef<TopoLink[]>([])

  const [size, setSize] = useState({ w: 1200, h: 700 })
  const [zoom, setZoom] = useState(1)
  const [pan, setPan] = useState({ x: 0, y: 0 })
  const [hovered, setHovered] = useState<TopoNode | null>(null)
  const [selected, setSelected] = useState<TopoNode | null>(null)
  const [typeFilter, setTypeFilter] = useState<NodeTypeFilter>("all")
  const [showLabels, setShowLabels] = useState(true)
  const [showGuide, setShowGuide] = useState(false)
  const isDark = useThemeStore((s) => s.resolved === "dark")

  /* ── Stable refs for the rAF draw loop ───────────────
   *  Reading from refs inside rAF avoids recreating the draw
   *  callback on every React state change.  Pulse is incremented
   *  once per animation frame (~60 Hz) rather than via setInterval
   *  + setState (which was triggering 20 full re-renders/sec).     */
  const pulseRef = useRef(0)
  const drawStateRef = useRef<{
    zoom: number; pan: { x: number; y: number }
    typeFilter: NodeTypeFilter; showLabels: boolean
    hovered: TopoNode | null; selected: TopoNode | null
    size: { w: number; h: number }; isDark: boolean
  }>({ zoom: 1, pan: { x: 0, y: 0 }, typeFilter: "all", showLabels: true, hovered: null, selected: null, size: { w: 1200, h: 700 }, isDark: false })
  drawStateRef.current = { zoom, pan, typeFilter, showLabels, hovered, selected, size, isDark }
  /* ── Stable node pool — preserves simulation x/y across SWR refetches ── */
  const stableNodePool = useRef(new Map<string, TopoNode>())
  const prevTopoKey = useRef("")

  /* ── Data ────────────────────────────────────────────── */
  const { data: agentsData } = useAgents({ limit: 100 })
  const { data: graphData } = useTrustGraph({ depth: 3 })
  const { data: alertsData } = useAlerts({ status: "open", limit: 50 }, 8_000)

  const agents = useMemo(() => agentsData?.items ?? [], [agentsData?.items])
  const graphNodes = useMemo(() => graphData?.nodes ?? [], [graphData?.nodes])
  const graphEdges = useMemo(() => graphData?.edges ?? [], [graphData?.edges])
  const openAlerts = useMemo(() => alertsData?.items ?? [], [alertsData?.items])

  /* Pulse is driven by the rAF draw loop — no React state needed */

  /* ── Build graph data ────────────────────────────────── */
  const { nodes, links, stats } = useMemo(() => {
    const nodeMap = new Map<string, TopoNode>()
    const alertAgentMap = new Map<string, Severity>()

    openAlerts.forEach((a) => {
      if (a.agent_id) {
        const existing = alertAgentMap.get(a.agent_id)
        const sevRank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
        if (!existing || (sevRank[a.severity] ?? 0) > (sevRank[existing] ?? 0)) {
          alertAgentMap.set(a.agent_id, a.severity)
        }
      }
    })

    // Central gateway
    nodeMap.set("gateway", {
      id: "gateway",
      label: "Phantex Gateway",
      type: "gateway",
      trustScore: 1.0,
      fx: size.w / 2,
      fy: size.h / 2,
    })

    // Agent nodes from real data
    agents.forEach((a: AgentSummary) => {
      nodeMap.set(a.id, {
        id: a.id,
        label: a.name ?? `Agent-${a.paid.slice(0, 8)}`,
        type: "agent",
        status: a.status,
        framework: a.framework ?? undefined,
        trustScore: undefined,
        hasAlert: alertAgentMap.has(a.id),
        alertSeverity: alertAgentMap.get(a.id),
      })
    })

    // Trust graph nodes (tools, mcp servers, etc.)
    graphNodes.forEach((n: TrustGraphNode) => {
      if (!nodeMap.has(n.id)) {
        const nType = (["agent", "tool", "file", "network"].includes(n.entity_type)
          ? n.entity_type
          : "mcp") as TopoNode["type"]
        nodeMap.set(n.id, {
          id: n.id,
          label: n.metadata?.name ?? n.id.slice(0, 12),
          type: nType,
          trustScore: n.trust_score,
          metadata: n.metadata,
        })
      } else {
        const existing = nodeMap.get(n.id)!
        existing.trustScore = n.trust_score
      }
    })

    // Build links
    const linkArr: TopoLink[] = []

    // Each agent links to gateway
    agents.forEach((a: AgentSummary) => {
      linkArr.push({
        id: `gw-${a.id}`,
        source: "gateway",
        target: a.id,
        edgeType: "reports_to",
        weight: 1,
        hasAnomaly: alertAgentMap.has(a.id),
      })
    })

    // Trust graph edges
    graphEdges.forEach((e: TrustGraphEdge) => {
      if (nodeMap.has(e.source_id) && nodeMap.has(e.target_id)) {
        linkArr.push({
          id: `${e.source_id}-${e.target_id}`,
          source: e.source_id,
          target: e.target_id,
          edgeType: e.edge_type,
          weight: e.weight,
          hasAnomaly: false,
        })
      }
    })

    /* ── Stable-node pool: reuse existing node objects so the
     *    D3 simulation keeps its computed x/y/vx/vy across SWR
     *    refetches.  Only truly new IDs get fresh objects. ──── */
    const pool = stableNodePool.current
    const freshIds = new Set<string>()
    const nodesArr: TopoNode[] = []

    nodeMap.forEach((desired, id) => {
      freshIds.add(id)
      const existing = pool.get(id)
      if (existing) {
        // Patch mutable display props — keep x/y/vx/vy intact
        existing.label = desired.label
        existing.type = desired.type
        existing.status = desired.status
        existing.trustScore = desired.trustScore
        existing.hasAlert = desired.hasAlert
        existing.alertSeverity = desired.alertSeverity
        existing.framework = desired.framework
        existing.metadata = desired.metadata
        if (id === "gateway") { existing.fx = desired.fx; existing.fy = desired.fy }
        nodesArr.push(existing)
      } else {
        pool.set(id, desired)
        nodesArr.push(desired)
      }
    })
    // Prune removed nodes from pool
    pool.forEach((_, id) => { if (!freshIds.has(id)) pool.delete(id) })

    const stats = {
      totalNodes: nodesArr.length,
      agents: nodesArr.filter((n) => n.type === "agent").length,
      tools: nodesArr.filter((n) => n.type === "tool").length,
      mcpServers: nodesArr.filter((n) => n.type === "mcp").length,
      activeAlerts: openAlerts.length,
      connections: linkArr.length,
    }

    return { nodes: nodesArr, links: linkArr, stats }
  }, [agents, graphNodes, graphEdges, openAlerts, size])

  /* ── D3 force simulation ─────────────────────────────── *
   *  Only tear-down / recreate when the topology *structure*
   *  changes (node IDs or link IDs differ).  Property-only
   *  updates (trust scores, alerts) are patched in-place above
   *  so the simulation keeps its computed positions.            */
  useEffect(() => {
    const cX = size.w / 2
    const cY = size.h / 2

    const topoKey = nodes.map((n) => n.id).sort().join(",") + "|" + links.map((l) => l.id).sort().join(",")
    const structureChanged = topoKey !== prevTopoKey.current
    prevTopoKey.current = topoKey

    if (!structureChanged && simRef.current) {
      // Same topology — hot-patch the simulation data without restarting
      simRef.current.nodes(nodes)
      const lf = simRef.current.force("link") as ReturnType<typeof forceLink<TopoNode, TopoLink>> | undefined
      if (lf) lf.links(links)
      nodesRef.current = nodes
      linksRef.current = links
      // Gentle reheat so updated alert glows settle quickly
      simRef.current.alpha(Math.max(simRef.current.alpha(), 0.05)).restart()
      return
    }

    // Full simulation creation (first mount or structural change)
    simRef.current?.stop()

    const nCount = nodes.length
    // Scale forces for large graphs: weaker charge, tighter radial
    const chargeSt = nCount > 80 ? -200 : nCount > 40 ? -300 : -400
    const radialSt = nCount > 60 ? 0.55 : 0.4

    const sim = forceSimulation<TopoNode>(nodes)
      .force("link", forceLink<TopoNode, TopoLink>(links).id((d) => d.id).distance(nCount > 60 ? 70 : 100).strength(0.15))
      .force("charge", forceManyBody().strength(chargeSt).distanceMax(500))
      .force("center", forceCenter(cX, cY).strength(0.05))
      .force("radial", forceRadial<TopoNode>((d) => RADIAL_TIER[d.type] ?? 250, cX, cY).strength(radialSt))
      .force("collide", forceCollide<TopoNode>().radius((d) => (NODE_RADIUS[d.type] ?? 14) + (nCount > 60 ? 8 : 16)).strength(0.8))
      .force("spreadX", forceX<TopoNode>(cX).strength(0.02))
      .force("spreadY", forceY<TopoNode>(cY).strength(0.02))
      .alpha(0.8)
      .alphaDecay(0.02)          // settle faster
      .alphaMin(0.001)           // stop ticking when cool
      .velocityDecay(0.35)       // more damping → less jitter

    simRef.current = sim
    nodesRef.current = nodes
    linksRef.current = links

    sim.on("tick", () => {
      /* keep refs up-to-date; canvas re-draws in anim loop */
    })

    return () => { sim.stop() }
  }, [nodes, links, size])

  /* ── Canvas rendering ────────────────────────────────── *
   *  draw() is called from a single persistent rAF loop.  It
   *  reads ALL volatile values from refs so the callback identity
   *  never changes → no rAF teardown/restart churn.              */
  const draw = useCallback(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext("2d")
    if (!ctx) return

    // Advance pulse inside the rAF loop (no React state involved)
    pulseRef.current = (pulseRef.current + 0.35) % 60

    // Read all volatile state from refs
    const { zoom, pan, typeFilter, showLabels, hovered, selected, size, isDark } = drawStateRef.current
    const pulse = pulseRef.current
    const totalNodes = nodesRef.current.length
    const useLOD = totalNodes > 40  // simplified rendering for large graphs

    const dpr = window.devicePixelRatio || 1
    const needsResize = canvas.width !== size.w * dpr || canvas.height !== size.h * dpr
    if (needsResize) {
      canvas.width = size.w * dpr
      canvas.height = size.h * dpr
    }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0)

    ctx.clearRect(0, 0, size.w, size.h)
    ctx.save()
    ctx.translate(pan.x, pan.y)
    ctx.scale(zoom, zoom)

    const pulsePhase = Math.sin((pulse / 60) * Math.PI * 2)
    const filteredNodes = typeFilter === "all"
      ? nodesRef.current
      : nodesRef.current.filter((n) => n.type === typeFilter || n.type === "gateway")
    const nodeIds = new Set(filteredNodes.map((n) => n.id))
    const filteredLinks = linksRef.current.filter(
      (l) => nodeIds.has((l.source as TopoNode).id) && nodeIds.has((l.target as TopoNode).id),
    )

    // Draw concentric radial ring guides
    const ringCenter = { x: size.w / 2, y: size.h / 2 }
    const ringRadii = [180, 300, 380, 420]
    const ringLabels = ["Agents", "MCP", "Tools", "Files"]
    ringRadii.forEach((r, i) => {
      ctx.beginPath()
      ctx.arc(ringCenter.x, ringCenter.y, r, 0, Math.PI * 2)
      ctx.strokeStyle = isDark ? "rgba(63,63,70,0.12)" : "rgba(0,0,0,0.04)"
      ctx.lineWidth = 1
      ctx.setLineDash([4, 8])
      ctx.stroke()
      ctx.setLineDash([])
      // Ring label
      ctx.fillStyle = isDark ? "rgba(161,161,170,0.2)" : "rgba(0,0,0,0.08)"
      ctx.font = "9px Inter, sans-serif"
      ctx.textAlign = "left"
      ctx.fillText(ringLabels[i] ?? "", ringCenter.x + r * 0.71 + 4, ringCenter.y - r * 0.71 - 4)
    })

    // Draw links — curved Bezier with animated data flow dots
    filteredLinks.forEach((l) => {
      const src = l.source as TopoNode
      const tgt = l.target as TopoNode
      if (src.x == null || src.y == null || tgt.x == null || tgt.y == null) return

      // Compute quadratic bezier control point (slight curve)
      const dx = tgt.x - src.x
      const dy = tgt.y - src.y
      const dist = Math.sqrt(dx * dx + dy * dy)
      const curveFactor = Math.min(0.12, 20 / dist) // Subtle curve
      const mx = (src.x + tgt.x) / 2 - dy * curveFactor
      const my = (src.y + tgt.y) / 2 + dx * curveFactor

      ctx.beginPath()
      ctx.moveTo(src.x, src.y)
      ctx.quadraticCurveTo(mx, my, tgt.x, tgt.y)

      if (l.hasAnomaly) {
        ctx.strokeStyle = `rgba(239,68,68,${0.3 + pulsePhase * 0.3})`
        ctx.lineWidth = 2.5
        ctx.setLineDash([6, 4])
      } else {
        ctx.strokeStyle = isDark ? "rgba(63,63,70,0.25)" : "rgba(0,0,0,0.10)"
        ctx.lineWidth = 1
        ctx.setLineDash([])
      }
      ctx.stroke()
      ctx.setLineDash([])

      // Animated data flow dot traveling along the curve
      const t = ((pulse + (src.x * 0.05 + src.y * 0.03)) % 60) / 60
      const dotX = (1 - t) * (1 - t) * src.x + 2 * (1 - t) * t * mx + t * t * tgt.x
      const dotY = (1 - t) * (1 - t) * src.y + 2 * (1 - t) * t * my + t * t * tgt.y
      const dotColor = l.hasAnomaly ? "rgba(239,68,68,0.7)" : (NODE_COLORS[src.type]?.fill ?? "#3b82f6")
      ctx.beginPath()
      ctx.arc(dotX, dotY, 2.5, 0, Math.PI * 2)
      ctx.fillStyle = dotColor
      ctx.fill()
      // Glow around flowing dot (skip in LOD mode)
      if (!useLOD) {
        ctx.beginPath()
        ctx.arc(dotX, dotY, 5, 0, Math.PI * 2)
        ctx.fillStyle = dotColor.replace(")", ",0.2)").replace("rgb(", "rgba(").replace("rgba(", "rgba(")
        ctx.fill()
      }
    })

    // ── Helper: rounded rect path ──
    const roundedRect = (x: number, y: number, w: number, h: number, rad: number) => {
      ctx.beginPath()
      ctx.moveTo(x + rad, y)
      ctx.lineTo(x + w - rad, y)
      ctx.quadraticCurveTo(x + w, y, x + w, y + rad)
      ctx.lineTo(x + w, y + h - rad)
      ctx.quadraticCurveTo(x + w, y + h, x + w - rad, y + h)
      ctx.lineTo(x + rad, y + h)
      ctx.quadraticCurveTo(x, y + h, x, y + h - rad)
      ctx.lineTo(x, y + rad)
      ctx.quadraticCurveTo(x, y, x + rad, y)
      ctx.closePath()
    }

    // Draw nodes — card-style rounded rects
    filteredNodes.forEach((n) => {
      if (n.x == null || n.y == null) return
      const r = NODE_RADIUS[n.type] ?? 14
      const cfg = NODE_COLORS[n.type] ?? NODE_COLORS.agent
      const isHov = hovered?.id === n.id
      const isSel = selected?.id === n.id
      const isGateway = n.type === "gateway"

      // Card dimensions
      const cardW = isGateway ? r * 2.8 : r * 2.4
      const cardH = isGateway ? r * 2.8 : r * 2
      const cardX = n.x - cardW / 2
      const cardY = n.y - cardH / 2
      const cornerR = isGateway ? 16 : 10

      // Anomaly outer glow (skip expensive shadow in LOD mode)
      if (n.hasAlert && n.alertSeverity && !useLOD) {
        const spread = 6 + pulsePhase * 4
        ctx.shadowColor = SEVERITY_GLOW[n.alertSeverity] ?? "transparent"
        ctx.shadowBlur = spread + 8
        roundedRect(cardX - spread, cardY - spread, cardW + spread * 2, cardH + spread * 2, cornerR + 4)
        ctx.fillStyle = "transparent"
        ctx.fill()
        ctx.shadowBlur = 0
        ctx.shadowColor = "transparent"
      }

      // Selection / hover glow
      if (isHov || isSel) {
        ctx.shadowColor = cfg.glow
        ctx.shadowBlur = 16
      }

      // Card background — gradient fill (flat fill in LOD mode)
      const nodeColor = n.status === "stale" ? "#eab308"
        : n.status === "terminated" ? "#52525b"
          : cfg.fill

      roundedRect(cardX, cardY, cardW, cardH, cornerR)
      if (useLOD) {
        ctx.fillStyle = isDark ? "rgba(24,24,27,0.88)" : "rgba(255,255,255,0.88)"
      } else {
        const bgGrad = ctx.createLinearGradient(cardX, cardY, cardX, cardY + cardH)
        bgGrad.addColorStop(0, isDark ? "rgba(24,24,27,0.92)" : "rgba(255,255,255,0.92)")
        bgGrad.addColorStop(1, isDark ? "rgba(24,24,27,0.78)" : "rgba(255,255,255,0.78)")
        ctx.fillStyle = bgGrad
      }
      ctx.fill()

      // Card border
      ctx.strokeStyle = isHov || isSel ? nodeColor : (isDark ? "rgba(63,63,70,0.4)" : "rgba(0,0,0,0.12)")
      ctx.lineWidth = isHov || isSel ? 2 : 1
      ctx.stroke()
      ctx.shadowBlur = 0
      ctx.shadowColor = "transparent"

      // Color accent bar at top of card
      roundedRect(cardX, cardY, cardW, 4, cornerR)
      ctx.save()
      ctx.clip()
      ctx.fillStyle = nodeColor
      ctx.fillRect(cardX, cardY, cardW, 4)
      ctx.restore()

      // Icon
      ctx.fillStyle = nodeColor
      ctx.font = `${isGateway ? 18 : 14}px sans-serif`
      ctx.textAlign = "center"
      ctx.textBaseline = "middle"
      ctx.fillText(NODE_ICONS[n.type] ?? "●", n.x, n.y - (isGateway ? 4 : 2))

      // Label inside card
      if (showLabels) {
        ctx.fillStyle = isDark ? "rgba(250,250,250,0.85)" : "rgba(9,9,11,0.8)"
        ctx.font = `${isGateway ? 10 : 8}px Inter, sans-serif`
        ctx.fillText(n.label.slice(0, 16), n.x, n.y + (isGateway ? 16 : 10))
      }

      // Trust score mini bar at bottom of card
      if (n.trustScore != null && n.type !== "gateway") {
        const ts = n.trustScore
        const barColor = ts > 0.7 ? "#22c55e" : ts > 0.4 ? "#eab308" : "#ef4444"
        const barW = cardW - 12
        const barX = cardX + 6
        const barY = cardY + cardH - 6

        // Bar background
        roundedRect(barX, barY, barW, 3, 1.5)
        ctx.fillStyle = isDark ? "rgba(63,63,70,0.3)" : "rgba(0,0,0,0.08)"
        ctx.fill()

        // Bar fill
        roundedRect(barX, barY, barW * ts, 3, 1.5)
        ctx.fillStyle = barColor
        ctx.fill()
      }

      // Pin indicator for dragged/fixed nodes
      if (n.fx != null && n.fy != null && n.type !== "gateway") {
        ctx.fillStyle = isDark ? "rgba(250,250,250,0.7)" : "rgba(9,9,11,0.6)"
        ctx.font = "8px sans-serif"
        ctx.textAlign = "center"
        ctx.fillText("📌", n.x + r + 2, n.y - r + 2)
      }
    })

    ctx.restore()
    animRef.current = requestAnimationFrame(draw)
  }, [])   // stable — reads everything from refs

  useEffect(() => {
    animRef.current = requestAnimationFrame(draw)
    return () => cancelAnimationFrame(animRef.current)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])   // mount-once: draw identity is stable

  /* ── Resize observer ─────────────────────────────────── */
  useEffect(() => {
    const el = containerRef.current
    if (!el) return
    const ro = new ResizeObserver((entries) => {
      const rect = entries[0]?.contentRect
      if (rect) setSize({ w: Math.floor(rect.width), h: Math.max(500, Math.floor(rect.height)) })
    })
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  /* ── Mouse interaction ───────────────────────────────── */
  const getNodeAt = useCallback((mx: number, my: number) => {
    const x = (mx - pan.x) / zoom
    const y = (my - pan.y) / zoom
    return nodesRef.current.find((n) => {
      if (n.x == null || n.y == null) return false
      const r = NODE_RADIUS[n.type] ?? 14
      const isGW = n.type === "gateway"
      const hw = (isGW ? r * 1.4 : r * 1.2) + 4
      const hh = (isGW ? r * 1.4 : r) + 4
      return Math.abs(n.x - x) < hw && Math.abs(n.y - y) < hh
    }) ?? null
  }, [pan, zoom])

  /* ── Drag state — supports both node dragging and canvas panning ──── */
  const dragRef = useRef<{
    mode: "pan" | "node"
    startX: number
    startY: number
    panX: number
    panY: number
    node?: TopoNode
  } | null>(null)

  const onMouseMove = useCallback((e: React.MouseEvent) => {
    const rect = canvasRef.current?.getBoundingClientRect()
    if (!rect) return
    const mx = e.clientX - rect.left
    const my = e.clientY - rect.top

    // Handle active drag
    if (dragRef.current) {
      if (dragRef.current.mode === "node" && dragRef.current.node) {
        // Node dragging — update fixed positions
        const node = dragRef.current.node
        node.fx = (mx - pan.x) / zoom
        node.fy = (my - pan.y) / zoom
        // Reheat simulation gently for smooth dragging
        if (simRef.current) simRef.current.alpha(0.3).restart()
        return
      }
      if (dragRef.current.mode === "pan") {
        setPan({
          x: dragRef.current.panX + (e.clientX - dragRef.current.startX),
          y: dragRef.current.panY + (e.clientY - dragRef.current.startY),
        })
        return
      }
    }

    // Hover detection
    setHovered(getNodeAt(mx, my))
  }, [getNodeAt, pan, zoom])

  const onMouseDown = useCallback((e: React.MouseEvent) => {
    if (e.button !== 0) return
    const rect = canvasRef.current?.getBoundingClientRect()
    if (!rect) return
    const mx = e.clientX - rect.left
    const my = e.clientY - rect.top
    const node = getNodeAt(mx, my)

    if (node && node.type !== "gateway") {
      // Start dragging a node — fix it in place during drag
      node.fx = node.x
      node.fy = node.y
      dragRef.current = {
        mode: "node",
        startX: e.clientX,
        startY: e.clientY,
        panX: pan.x,
        panY: pan.y,
        node,
      }
      if (simRef.current) simRef.current.alphaTarget(0.1).restart()
    } else if (!node) {
      // Start panning
      dragRef.current = {
        mode: "pan",
        startX: e.clientX,
        startY: e.clientY,
        panX: pan.x,
        panY: pan.y,
      }
    }
  }, [getNodeAt, pan])

  const onMouseUp = useCallback((e: React.MouseEvent) => {
    if (dragRef.current) {
      if (dragRef.current.mode === "node" && dragRef.current.node) {
        const node = dragRef.current.node
        const dist = Math.hypot(e.clientX - dragRef.current.startX, e.clientY - dragRef.current.startY)
        if (dist < 5) {
          // Clicked without dragging much — select + unpin
          setSelected(node)
          node.fx = null
          node.fy = null
        }
        // If dragged far, leave pinned (user positioned it deliberately)
        // Restore alpha target
        if (simRef.current) simRef.current.alphaTarget(0)
      } else if (dragRef.current.mode === "pan") {
        const dist = Math.hypot(e.clientX - dragRef.current.startX, e.clientY - dragRef.current.startY)
        if (dist < 3) {
          // Clicked on empty space — deselect
          setSelected(null)
        }
      }
      dragRef.current = null
    }
  }, [])

  const onMouseLeave = useCallback(() => {
    if (dragRef.current?.mode === "node" && dragRef.current.node) {
      // Release node if cursor leaves canvas
      if (simRef.current) simRef.current.alphaTarget(0)
    }
    dragRef.current = null
    setHovered(null)
  }, [])

  const onWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault()
    const rect = canvasRef.current?.getBoundingClientRect()
    if (!rect) return
    // Mouse position relative to canvas
    const mx = e.clientX - rect.left
    const my = e.clientY - rect.top
    setZoom((prevZoom) => {
      const newZoom = Math.max(0.3, Math.min(3, prevZoom - e.deltaY * 0.001))
      const scale = newZoom / prevZoom
      // Adjust pan so the point under the cursor stays fixed
      setPan((prevPan) => ({
        x: mx - scale * (mx - prevPan.x),
        y: my - scale * (my - prevPan.y),
      }))
      return newZoom
    })
  }, [])

  const resetView = useCallback(() => {
    setZoom(1)
    setPan({ x: 0, y: 0 })
    setSelected(null)
  }, [])

  const unpinAll = useCallback(() => {
    nodesRef.current.forEach((n) => {
      if (n.type !== "gateway") {
        n.fx = null
        n.fy = null
      }
    })
    if (simRef.current) simRef.current.alpha(0.5).restart()
  }, [])

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center h-9 w-9 rounded-lg bg-primary/10 border border-primary/20">
            <Network size={18} className="text-primary" />
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-tight">Live Topology</h1>
            <p className="text-xs text-muted-foreground">Real-time agent & MCP topology — radial force-directed graph</p>
          </div>
          <button onClick={() => setShowGuide(!showGuide)} className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"><HelpCircle size={14} />{showGuide ? "Hide Guide" : "How does this work?"}</button>
        </div>
        <div className="flex items-center gap-2">
          {/* Type filter */}
          <div className="flex items-center gap-1 bg-surface-1 border border-border/50 rounded-lg p-0.5">
            {(["all", "agent", "tool", "mcp"] as NodeTypeFilter[]).map((t) => (
              <button
                key={t}
                onClick={() => setTypeFilter(t)}
                className={cn(
                  "px-2.5 py-1 rounded-md text-xs font-medium capitalize transition-all cursor-pointer",
                  typeFilter === t
                    ? "bg-primary/15 text-primary border border-primary/20"
                    : "text-muted-foreground hover:text-foreground",
                )}
              >
                {t}
              </button>
            ))}
          </div>
          <Button variant="ghost" size="icon" onClick={() => setShowLabels(!showLabels)} title="Toggle labels">
            <Eye size={16} className={showLabels ? "text-primary" : ""} />
          </Button>
          <Button variant="ghost" size="icon" onClick={unpinAll} title="Unpin all nodes">
            <Pin size={16} />
          </Button>
          <Button variant="ghost" size="icon" onClick={() => setZoom((z) => Math.min(3, z + 0.2))}>
            <ZoomIn size={16} />
          </Button>
          <Button variant="ghost" size="icon" onClick={() => setZoom((z) => Math.max(0.3, z - 0.2))}>
            <ZoomOut size={16} />
          </Button>
          <Button variant="ghost" size="icon" onClick={resetView}>
            <Maximize2 size={16} />
          </Button>
        </div>
      </div>

      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5 space-y-3 text-sm text-muted-foreground">
          <h3 className="text-base font-semibold text-foreground">How does Live Topology work?</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Graph Data</p>
              <p>Combines data from <code className="text-xs bg-white/5 px-1 rounded">useAgents</code>, <code className="text-xs bg-white/5 px-1 rounded">useTrustGraph</code> (Neo4j — 14 nodes, 13 edges), and <code className="text-xs bg-white/5 px-1 rounded">useAlerts</code>. Nodes represent agents, tools, MCP servers, and data stores. Edges represent trust relationships and data flows.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Force-Directed Layout</p>
              <p>Uses D3 force simulation with radial positioning. Nodes are color-coded by type (blue=agent, amber=MCP, purple=tool). The simulation runs on a canvas for GPU-accelerated rendering at 60fps even with hundreds of nodes.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Interactions</p>
              <p>Zoom with scroll wheel, pan by dragging background, pin nodes by dragging them. Click a node to see its detail panel with trust score, framework, status, and alerts. Type filter narrows to agents, tools, or MCP servers.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Alert Overlay</p>
              <p>Nodes with active alerts show pulsing red rings. Anomalous edges (unusual trust relationships) glow red. This gives instant visual threat awareness — compromised or suspicious entities stand out immediately.</p>
            </div>
          </div>
        </div>
      )}

      {/* Stats bar */}
      <div className="flex gap-3">
        {[
          { label: "Nodes", value: stats.totalNodes, icon: <Layers size={13} /> },
          { label: "Agents", value: stats.agents, icon: <Activity size={13} />, color: "text-blue-400" },
          { label: "MCP Servers", value: stats.mcpServers, color: "text-amber-400" },
          { label: "Tools", value: stats.tools, color: "text-purple-400" },
          { label: "Connections", value: stats.connections },
          { label: "Active Alerts", value: stats.activeAlerts, color: stats.activeAlerts > 0 ? "text-severity-critical" : "" },
        ].map((s) => (
          <div key={s.label} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-1/50 border border-border/30 text-xs">
            {s.icon}
            <span className="text-muted-foreground">{s.label}</span>
            <span className={cn("font-bold tabular-nums", s.color)}>{s.value}</span>
          </div>
        ))}
      </div>

      <div className="flex gap-4">
        {/* Canvas */}
        <div ref={containerRef} className="flex-1 relative rounded-xl bg-surface-0 border border-border/30 overflow-hidden" style={{ minHeight: 500 }}>
          <canvas
            ref={canvasRef}
            style={{
              width: size.w,
              height: size.h,
              cursor: dragRef.current?.mode === "node"
                ? "grabbing"
                : hovered
                  ? "pointer"
                  : dragRef.current?.mode === "pan"
                    ? "grabbing"
                    : "grab",
            }}
            onMouseMove={onMouseMove}
            onWheel={onWheel}
            onMouseDown={onMouseDown}
            onMouseUp={onMouseUp}
            onMouseLeave={onMouseLeave}
          />

          {/* Zoom indicator */}
          <div className="absolute bottom-3 left-3 px-2 py-1 rounded bg-surface-1/80 border border-border/30 text-[10px] text-muted-foreground font-mono">
            {Math.round(zoom * 100)}%
          </div>

          {/* Empty state overlay when no real data  */}
          {stats.agents === 0 && stats.tools === 0 && stats.mcpServers === 0 && (
            <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
              <div className="text-center space-y-2 p-6 rounded-xl bg-surface-1/60 backdrop-blur-sm border border-border/30">
                <Network size={36} className="mx-auto text-muted-foreground/30" />
                <div className="text-sm font-medium text-muted-foreground">No agents or MCP servers detected</div>
                <div className="text-xs text-muted-foreground/60 max-w-[280px]">
                  Deploy a sensor and register agents to see the live topology graph populate with real data.
                </div>
              </div>
            </div>
          )}

          {/* Hover tooltip */}
          {hovered && hovered.x != null && hovered.y != null && (
            <div
              className="absolute pointer-events-none z-50 glass-user-card rounded-lg p-3 border border-border/50 shadow-2xl min-w-[180px]"
              style={{ left: hovered.x * zoom + pan.x + 20, top: hovered.y * zoom + pan.y - 30 }}
            >
              <div className="flex items-center gap-2 mb-1.5">
                <span className="text-lg">{NODE_ICONS[hovered.type]}</span>
                <span className="text-xs font-bold text-foreground">{hovered.label}</span>
              </div>
              <div className="space-y-1 text-[10px] text-muted-foreground">
                <div>Type: <span className="text-foreground capitalize">{hovered.type}</span></div>
                {hovered.status && <div>Status: <span className={cn(hovered.status === "active" ? "text-status-active" : hovered.status === "stale" ? "text-status-stale" : "text-muted-foreground")}>{hovered.status}</span></div>}
                {hovered.framework && <div>Framework: <span className="text-foreground">{hovered.framework}</span></div>}
                {hovered.trustScore != null && <div>Trust: <span className={cn(hovered.trustScore > 0.7 ? "text-status-active" : hovered.trustScore > 0.4 ? "text-severity-medium" : "text-severity-critical")}>{(hovered.trustScore * 100).toFixed(0)}%</span></div>}
                {hovered.hasAlert && <div className="text-severity-critical font-medium">⚠ Active Alert</div>}
              </div>
            </div>
          )}

          {/* Legend */}
          <div className="absolute top-3 right-3 glass-user-card rounded-lg p-2.5 border border-border/50 space-y-1.5">
            <div className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider mb-1">Legend</div>
            {Object.entries(NODE_COLORS).map(([type, cfg]) => (
              <div key={type} className="flex items-center gap-2 text-[10px]">
                <span className="w-3 h-3 rounded-full" style={{ backgroundColor: cfg.fill }} />
                <span className="text-muted-foreground capitalize">{type}</span>
              </div>
            ))}
            <div className="flex items-center gap-2 text-[10px] pt-1 border-t border-border/30">
              <span className="w-3 h-0.5 bg-red-500" style={{ boxShadow: "0 0 4px rgba(239,68,68,0.5)" }} />
              <span className="text-severity-critical">Anomaly</span>
            </div>
          </div>
        </div>

        {/* Detail panel */}
        {selected && (
          <Card className="w-72 flex-shrink-0">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <span className="text-xl">{NODE_ICONS[selected.type]}</span>
                {selected.label}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid grid-cols-2 gap-2 text-xs">
                <span className="text-muted-foreground">Type</span>
                <span className="font-medium capitalize">{selected.type}</span>
                {selected.status && (
                  <>
                    <span className="text-muted-foreground">Status</span>
                    <Badge variant={selected.status}>{selected.status}</Badge>
                  </>
                )}
                {selected.framework && (
                  <>
                    <span className="text-muted-foreground">Framework</span>
                    <span className="font-medium">{selected.framework}</span>
                  </>
                )}
                {selected.trustScore != null && (
                  <>
                    <span className="text-muted-foreground">Trust Score</span>
                    <div className="flex items-center gap-1.5">
                      <div className="flex-1 h-1.5 rounded-full bg-surface-2 overflow-hidden">
                        <div
                          className="h-full rounded-full transition-all"
                          style={{
                            width: `${selected.trustScore * 100}%`,
                            backgroundColor: selected.trustScore > 0.7 ? "#22c55e" : selected.trustScore > 0.4 ? "#eab308" : "#ef4444",
                          }}
                        />
                      </div>
                      <span className="text-[10px] font-mono">{(selected.trustScore * 100).toFixed(0)}%</span>
                    </div>
                  </>
                )}
              </div>
              {selected.hasAlert && (
                <div className="flex items-center gap-2 px-2.5 py-2 rounded-lg bg-severity-critical/10 border border-severity-critical/20 text-xs text-severity-critical">
                  <span className="relative flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-severity-critical opacity-50" />
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-severity-critical" />
                  </span>
                  Active {selected.alertSeverity} alert
                </div>
              )}
              {selected.type === "agent" && (
                <a
                  href={`/agents/${selected.id}`}
                  className="flex items-center gap-1.5 text-xs text-primary hover:underline"
                >
                  View agent details →
                </a>
              )}
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  )
}
