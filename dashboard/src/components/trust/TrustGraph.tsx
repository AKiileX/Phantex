// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — TrustGraph: force-directed trust visualisation (O4).
 *
 * Renders agents, tools, files, and network destinations as nodes in an
 * interactive SVG force-directed graph.  Nodes are sized by trust score,
 * coloured on a red→yellow→green gradient. Low-trust nodes (< 0.3)
 * pulsate red. Edges show usage relationships.
 *
 * Reuses d3-force from O2 (no new dependencies).
 *
 * Security:
 *   - Capped at 2 000 nodes (server enforces; client enforces too)
 *   - All text rendered via React (auto-escaped)
 *   - No trust data in DOM attributes that might leak via CSS selectors
 *
 * @module components/trust/TrustGraph
 */

import {
  useRef,
  useEffect,
  useState,
  useCallback,
  useMemo,
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
import type { TrustGraphNode, TrustGraphEdge } from "@/types"

/* ── Types ─────────────────────────────────────────────────────────────────── */

interface SimNode extends SimulationNodeDatum {
  id: string
  entity_type: string
  trust_score: number
  metadata: Record<string, string>
}

interface SimLink extends SimulationLinkDatum<SimNode> {
  edge_type: string
  count: number
  weight: number
}

interface TrustGraphProps {
  nodes: TrustGraphNode[]
  edges: TrustGraphEdge[]
  width: number
  height: number
  /** Currently selected node ID. */
  selectedId?: string | null
  /** Called when a node is clicked. */
  onNodeClick?: (node: TrustGraphNode) => void
}

/* ── Visual constants ──────────────────────────────────────────────────────── */

const MAX_CLIENT_NODES = 2_000

/** Entity type → node shape/size base. */
const ENTITY_RADIUS: Record<string, number> = {
  agent: 10,
  tool: 7,
  file: 6,
  network: 6,
  tenant: 14,
}

/** Entity type → icon labels. */
const ENTITY_LABEL: Record<string, string> = {
  agent: "A",
  tool: "T",
  file: "F",
  network: "N",
  tenant: "●",
}

const EDGE_TYPE_COLOR: Record<string, string> = {
  uses: "rgba(139, 92, 246, 0.25)",
  accesses: "rgba(59, 130, 246, 0.25)",
  communicates: "rgba(234, 179, 8, 0.2)",
  trusts: "rgba(16, 185, 129, 0.25)",
}

/** Trust score → colour (red=0 → yellow=0.5 → green=1). */
function trustColor(score: number): string {
  const s = Math.max(0, Math.min(1, score))
  if (s < 0.5) {
    // Red→Yellow
    const t = s / 0.5
    const r = 239
    const g = Math.round(68 + t * (180 - 68))
    const b = Math.round(68 * (1 - t))
    return `rgb(${r},${g},${b})`
  }
  // Yellow→Green
  const t = (s - 0.5) / 0.5
  const r = Math.round(239 - t * (239 - 34))
  const g = Math.round(180 + t * (197 - 180))
  const b = Math.round(0 + t * 94)
  return `rgb(${r},${g},${b})`
}

/** Node radius scaled by trust score (higher trust = slightly larger). */
function nodeRadius(node: SimNode): number {
  const base = ENTITY_RADIUS[node.entity_type] ?? 7
  return base + node.trust_score * 3
}

/* ── Component ─────────────────────────────────────────────────────────────── */

export function TrustGraph({
  nodes,
  edges,
  width,
  height,
  selectedId,
  onNodeClick,
}: TrustGraphProps) {
  const svgRef = useRef<SVGSVGElement>(null)
  const [simNodes, setSimNodes] = useState<SimNode[]>([])
  const [simLinks, setSimLinks] = useState<SimLink[]>([])
  const [hoveredNode, setHoveredNode] = useState<string | null>(null)
  const simulationRef = useRef<ReturnType<typeof forceSimulation<SimNode>> | null>(null)

  // Cap nodes client-side
  const cappedNodes = useMemo(
    () => (nodes.length > MAX_CLIENT_NODES ? nodes.slice(0, MAX_CLIENT_NODES) : nodes),
    [nodes],
  )

  useEffect(() => {
    if (cappedNodes.length === 0) return

    const sNodes: SimNode[] = cappedNodes.map((n) => ({
      id: n.id,
      entity_type: n.entity_type,
      trust_score: n.trust_score,
      metadata: n.metadata,
      x: width / 2 + (Math.random() - 0.5) * width * 0.6,
      y: height / 2 + (Math.random() - 0.5) * height * 0.6,
    }))

    const nodeIdSet = new Set(sNodes.map((n) => n.id))
    const sLinks: SimLink[] = edges
      .filter((e) => nodeIdSet.has(e.source_id) && nodeIdSet.has(e.target_id))
      .map((e) => ({
        source: e.source_id,
        target: e.target_id,
        edge_type: e.edge_type,
        count: e.count,
        weight: e.weight,
      }))

    if (simulationRef.current) simulationRef.current.stop()

    const simulation = forceSimulation<SimNode>(sNodes)
      .force(
        "link",
        forceLink<SimNode, SimLink>(sLinks)
          .id((d) => d.id)
          .distance(80)
          .strength(0.3),
      )
      .force("charge", forceManyBody().strength(-120))
      .force("center", forceCenter(width / 2, height / 2))
      .force("collide", forceCollide<SimNode>((d) => nodeRadius(d) + 5))
      .alphaDecay(0.02)

    simulationRef.current = simulation

    simulation.on("tick", () => {
      for (const node of sNodes) {
        const r = nodeRadius(node) + 2
        node.x = Math.max(r, Math.min(width - r, node.x ?? width / 2))
        node.y = Math.max(r, Math.min(height - r, node.y ?? height / 2))
      }
      setSimNodes([...sNodes])
      setSimLinks([...sLinks])
    })

    return () => { simulation.stop() }
  }, [cappedNodes, edges, width, height])

  const handleNodeClick = useCallback(
    (e: ReactMouseEvent, node: SimNode) => {
      e.stopPropagation()
      onNodeClick?.({
        id: node.id,
        entity_type: node.entity_type,
        trust_score: node.trust_score,
        metadata: node.metadata,
      })
    },
    [onNodeClick],
  )

  // Active node (hovered or selected) + connected nodes
  const activeId = hoveredNode ?? selectedId
  const connectedIds = useMemo(() => {
    const set = new Set<string>()
    if (!activeId) return set
    set.add(activeId)
    for (const link of simLinks) {
      const src = typeof link.source === "string" ? link.source : (link.source as SimNode).id
      const tgt = typeof link.target === "string" ? link.target : (link.target as SimNode).id
      if (src === activeId) set.add(tgt)
      if (tgt === activeId) set.add(src)
    }
    return set
  }, [activeId, simLinks])

  if (cappedNodes.length === 0) {
    return (
      <div className="flex items-center justify-center rounded-lg bg-surface-2/30 border border-border/30"
        style={{ width, height }}>
        <span className="text-sm text-muted-foreground">No trust data available</span>
      </div>
    )
  }

  return (
    <svg
      ref={svgRef}
      width={width}
      height={height}
      className="rounded-lg bg-card border border-border/50 shadow-[0_0_0_1px_rgba(255,255,255,0.03)]"
    >
      {/* Pulsate animation for low-trust nodes */}
      <defs>
        <style>{`
          @keyframes pulsate {
            0%, 100% { r: var(--base-r); opacity: 0.9; }
            50% { r: calc(var(--base-r) + 4px); opacity: 0.6; }
          }
          .trust-pulsate { animation: pulsate 2s ease-in-out infinite; }
        `}</style>
      </defs>

      {/* Edges */}
      <g>
        {simLinks.map((link, i) => {
          const src = link.source as SimNode
          const tgt = link.target as SimNode
          if (src.x == null || src.y == null || tgt.x == null || tgt.y == null) return null

          const isActive = activeId
            ? connectedIds.has(src.id) && connectedIds.has(tgt.id)
            : true
          const color = EDGE_TYPE_COLOR[link.edge_type] ?? "rgba(255,255,255,0.1)"

          return (
            <line
              key={i}
              x1={src.x}
              y1={src.y}
              x2={tgt.x}
              y2={tgt.y}
              stroke={color}
              strokeWidth={Math.max(1, Math.min(4, link.weight * 2))}
              opacity={activeId ? (isActive ? 0.8 : 0.1) : 0.5}
            />
          )
        })}
      </g>

      {/* Nodes */}
      <g>
        {simNodes.map((node) => {
          if (node.x == null || node.y == null) return null

          const r = nodeRadius(node)
          const color = trustColor(node.trust_score)
          const isActive = activeId ? connectedIds.has(node.id) : true
          const isSelected = node.id === selectedId
          const isLowTrust = node.trust_score < 0.3

          return (
            <g key={node.id}>
              {/* Low-trust pulsate glow */}
              {isLowTrust && (
                <circle
                  cx={node.x}
                  cy={node.y}
                  r={r + 6}
                  fill="none"
                  stroke="rgba(239, 68, 68, 0.4)"
                  strokeWidth={2}
                  className="trust-pulsate"
                  style={{ "--base-r": `${r + 4}px` } as React.CSSProperties}
                />
              )}

              {/* Selection ring */}
              {isSelected && (
                <circle
                  cx={node.x}
                  cy={node.y}
                  r={r + 5}
                  fill="none"
                  stroke="#fff"
                  strokeWidth={2}
                  opacity={0.5}
                />
              )}

              {/* Main node */}
              <circle
                cx={node.x}
                cy={node.y}
                r={r}
                fill={color}
                opacity={activeId ? (isActive ? 0.9 : 0.15) : 0.85}
                stroke={isSelected ? "#fff" : "rgba(0,0,0,0.3)"}
                strokeWidth={isSelected ? 2 : 1}
                className="cursor-pointer transition-opacity duration-150"
                onClick={(e) => handleNodeClick(e, node)}
                onMouseEnter={() => setHoveredNode(node.id)}
                onMouseLeave={() => setHoveredNode(null)}
              />

              {/* Entity type icon */}
              <text
                x={node.x}
                y={node.y}
                textAnchor="middle"
                dominantBaseline="central"
                fill="rgba(0,0,0,0.7)"
                fontSize={r * 0.9}
                fontWeight={700}
                className="pointer-events-none select-none"
              >
                {ENTITY_LABEL[node.entity_type] ?? "?"}
              </text>

              {/* Tooltip on hover */}
              {hoveredNode === node.id && (
                <g>
                  <rect
                    x={node.x - 60}
                    y={node.y - r - 28}
                    width={120}
                    height={22}
                    rx={4}
                    fill="rgba(0,0,0,0.85)"
                  />
                  <text
                    x={node.x}
                    y={node.y - r - 14}
                    textAnchor="middle"
                    fill="rgba(255,255,255,0.9)"
                    fontSize={10}
                    fontWeight={500}
                    className="pointer-events-none select-none"
                  >
                    {(node.metadata.name ?? node.id.slice(0, 12))} · {node.trust_score.toFixed(2)}
                  </text>
                </g>
              )}
            </g>
          )
        })}
      </g>

      {/* Legend */}
      <g transform={`translate(12, ${height - 70})`}>
        <rect x={-4} y={-4} width={140} height={65} rx={6} fill="rgba(0,0,0,0.5)" />
        <text fill="rgba(255,255,255,0.5)" fontSize={9} fontWeight={600} y={8}>
          Trust Score
        </text>
        {/* Gradient bar */}
        <defs>
          <linearGradient id="trust-gradient" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor={trustColor(0)} />
            <stop offset="50%" stopColor={trustColor(0.5)} />
            <stop offset="100%" stopColor={trustColor(1)} />
          </linearGradient>
        </defs>
        <rect x={0} y={14} width={100} height={6} rx={3} fill="url(#trust-gradient)" />
        <text x={0} y={30} fill="rgba(255,255,255,0.35)" fontSize={8}>0.0</text>
        <text x={88} y={30} fill="rgba(255,255,255,0.35)" fontSize={8}>1.0</text>

        {/* Entity types */}
        <g transform="translate(0, 36)">
          {(["agent", "tool", "file", "network"] as const).map((type, i) => (
            <g key={type} transform={`translate(${i * 32}, 0)`}>
              <circle cx={5} cy={5} r={4} fill="rgba(255,255,255,0.3)" />
              <text x={5} y={5} textAnchor="middle" dominantBaseline="central"
                fill="rgba(255,255,255,0.6)" fontSize={6} fontWeight={700}>
                {ENTITY_LABEL[type]}
              </text>
              <text x={5} y={16} textAnchor="middle" fill="rgba(255,255,255,0.3)" fontSize={7}>
                {type}
              </text>
            </g>
          ))}
        </g>
      </g>
    </svg>
  )
}
