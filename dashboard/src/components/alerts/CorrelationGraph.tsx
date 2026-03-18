// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — CorrelationGraph: SVG force-directed alert correlation mini-graph.
 *
 * Renders alerts as nodes and correlation edges using d3-force simulation.
 * Nodes sized by severity, colored by severity palette. Click node → onNodeClick.
 * Capped at 500 nodes for browser safety.
 *
 * @module components/alerts/CorrelationGraph
 */

import {
  useRef,
  useEffect,
  useState,
  useCallback,
  type MouseEvent as ReactMouseEvent,
} from "react"
import {
  forceSimulation,
  forceLink,
  forceManyBody,
  forceCenter,
  forceCollide,
  type SimulationNodeDatum,
  type SimulationLinkDatum,
} from "d3-force"
import type { CorrelationNode, CorrelationEdge, CorrelationReason } from "@/hooks/useAlertCorrelation"
import type { AlertSummary, Severity } from "@/types"

/* ── Types ─────────────────────────────────────────────────────────────────── */

interface SimNode extends SimulationNodeDatum {
  id: string
  alert: AlertSummary
}

interface SimLink extends SimulationLinkDatum<SimNode> {
  reason: CorrelationReason
}

interface CorrelationGraphProps {
  nodes: CorrelationNode[]
  edges: CorrelationEdge[]
  /** Width of the SVG. */
  width?: number
  /** Height of the SVG. */
  height?: number
  /** Called when a node is clicked. */
  onNodeClick?: (alert: AlertSummary) => void
  /** Currently highlighted alert ID. */
  highlightId?: string | null
}

/* ── Severity visual constants ─────────────────────────────────────────────── */

const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
  info: "#6b7280",
}

const SEVERITY_RADIUS: Record<Severity, number> = {
  critical: 10,
  high: 8,
  medium: 7,
  low: 6,
  info: 5,
}

const EDGE_COLOR: Record<CorrelationReason, string> = {
  same_rule: "rgba(139, 92, 246, 0.35)",    // violet
  same_agent: "rgba(59, 130, 246, 0.3)",     // blue
  same_class: "rgba(234, 179, 8, 0.25)",     // amber
}

/* ── Component ─────────────────────────────────────────────────────────────── */

export function CorrelationGraph({
  nodes,
  edges,
  width = 400,
  height = 300,
  onNodeClick,
  highlightId,
}: CorrelationGraphProps) {
  const svgRef = useRef<SVGSVGElement>(null)
  const [simNodes, setSimNodes] = useState<SimNode[]>([])
  const [simLinks, setSimLinks] = useState<SimLink[]>([])
  const [hoveredNode, setHoveredNode] = useState<string | null>(null)
  const simulationRef = useRef<ReturnType<typeof forceSimulation<SimNode>> | null>(null)

  // Build simulation when nodes/edges change
  useEffect(() => {
    if (nodes.length === 0) return

    // Create simulation-compatible data (d3-force mutates these objects)
    const sNodes: SimNode[] = nodes.map((n) => ({
      id: n.id,
      alert: n.alert,
      x: width / 2 + (Math.random() - 0.5) * 100,
      y: height / 2 + (Math.random() - 0.5) * 100,
    }))

    const nodeIdSet = new Set(sNodes.map((n) => n.id))
    const sLinks: SimLink[] = edges
      .filter((e) => nodeIdSet.has(e.source) && nodeIdSet.has(e.target))
      .map((e) => ({
        source: e.source,
        target: e.target,
        reason: e.reason,
      }))

    // Stop any existing simulation
    if (simulationRef.current) {
      simulationRef.current.stop()
    }

    const simulation = forceSimulation<SimNode>(sNodes)
      .force(
        "link",
        forceLink<SimNode, SimLink>(sLinks)
          .id((d) => d.id)
          .distance(60)
          .strength(0.4),
      )
      .force("charge", forceManyBody().strength(-80))
      .force("center", forceCenter(width / 2, height / 2))
      .force("collide", forceCollide<SimNode>((d) => SEVERITY_RADIUS[d.alert.severity] + 4))
      .alphaDecay(0.03)

    simulationRef.current = simulation

    simulation.on("tick", () => {
      // Clamp nodes within bounds
      for (const node of sNodes) {
        const r = SEVERITY_RADIUS[node.alert.severity] + 2
        node.x = Math.max(r, Math.min(width - r, node.x ?? width / 2))
        node.y = Math.max(r, Math.min(height - r, node.y ?? height / 2))
      }
      setSimNodes([...sNodes])
      setSimLinks([...sLinks])
    })

    return () => {
      simulation.stop()
    }
  }, [nodes, edges, width, height])

  const handleNodeClick = useCallback(
    (e: ReactMouseEvent, alert: AlertSummary) => {
      e.stopPropagation()
      onNodeClick?.(alert)
    },
    [onNodeClick],
  )

  if (nodes.length === 0) return null

  // Build a set of edges connected to hovered/highlighted node
  const activeId = hoveredNode ?? highlightId
  const connectedIds = new Set<string>()
  if (activeId) {
    connectedIds.add(activeId)
    for (const link of simLinks) {
      const src = typeof link.source === "string" ? link.source : (link.source as SimNode).id
      const tgt = typeof link.target === "string" ? link.target : (link.target as SimNode).id
      if (src === activeId) connectedIds.add(tgt)
      if (tgt === activeId) connectedIds.add(src)
    }
  }

  return (
    <svg
      ref={svgRef}
      width={width}
      height={height}
      className="rounded-lg bg-surface-2/30 border border-border/30"
      style={{ cursor: "default" }}
    >
      {/* Edges */}
      <g>
        {simLinks.map((link, i) => {
          const src = link.source as SimNode
          const tgt = link.target as SimNode
          if (src.x == null || src.y == null || tgt.x == null || tgt.y == null) return null

          const isActive = activeId
            ? connectedIds.has(src.id) && connectedIds.has(tgt.id)
            : true

          return (
            <line
              key={i}
              x1={src.x}
              y1={src.y}
              x2={tgt.x}
              y2={tgt.y}
              stroke={EDGE_COLOR[link.reason]}
              strokeWidth={isActive ? 2 : 1}
              opacity={activeId ? (isActive ? 1 : 0.15) : 0.6}
            />
          )
        })}
      </g>

      {/* Nodes */}
      <g>
        {simNodes.map((node) => {
          if (node.x == null || node.y == null) return null

          const r = SEVERITY_RADIUS[node.alert.severity]
          const color = SEVERITY_COLOR[node.alert.severity]
          const isActive = activeId ? connectedIds.has(node.id) : true
          const isHighlighted = node.id === activeId

          return (
            <g key={node.id}>
              {/* Glow for highlighted */}
              {isHighlighted && (
                <circle
                  cx={node.x}
                  cy={node.y}
                  r={r + 6}
                  fill="none"
                  stroke={color}
                  strokeWidth={2}
                  opacity={0.3}
                />
              )}
              <circle
                cx={node.x}
                cy={node.y}
                r={r}
                fill={color}
                opacity={activeId ? (isActive ? 0.9 : 0.2) : 0.8}
                stroke={isHighlighted ? "#fff" : "rgba(255,255,255,0.1)"}
                strokeWidth={isHighlighted ? 2 : 1}
                className="cursor-pointer transition-opacity duration-150"
                onClick={(e) => handleNodeClick(e, node.alert)}
                onMouseEnter={() => setHoveredNode(node.id)}
                onMouseLeave={() => setHoveredNode(null)}
              />
              {/* Tooltip text for hovered node */}
              {hoveredNode === node.id && (
                <text
                  x={node.x}
                  y={node.y - r - 6}
                  textAnchor="middle"
                  fill="rgba(255,255,255,0.85)"
                  fontSize={10}
                  fontWeight={500}
                  className="pointer-events-none select-none"
                >
                  {node.alert.title.length > 30
                    ? node.alert.title.slice(0, 30) + "…"
                    : node.alert.title}
                </text>
              )}
            </g>
          )
        })}
      </g>

      {/* Legend */}
      <g transform={`translate(8, ${height - 48})`}>
        <text fill="rgba(255,255,255,0.4)" fontSize={9} fontWeight={500}>
          Edges:
        </text>
        {(["same_rule", "same_agent"] as CorrelationReason[]).map((reason, i) => (
          <g key={reason} transform={`translate(0, ${14 + i * 14})`}>
            <line x1={0} y1={0} x2={16} y2={0} stroke={EDGE_COLOR[reason]} strokeWidth={2} />
            <text x={20} fill="rgba(255,255,255,0.35)" fontSize={8}>
              {reason === "same_rule" ? "Same rule" : "Same agent"}
            </text>
          </g>
        ))}
      </g>
    </svg>
  )
}
