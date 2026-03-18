// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Enterprise Agent Topology Graph (v2 — modernised).
 *
 * Force-directed / radial SVG visualisation inspired by CrowdStrike Falcon.
 * Central gateway hub surrounded by agent card-nodes laid out in concentric
 * orbits grouped by status (active closest, stale mid, terminated outer).
 *
 * v2 changes:
 *   - Larger card-nodes with gradient fills, subtle glow, status LED pulse
 *   - Animated dashed data-flow lines
 *   - Orbit rings with soft gradient strokes
 *   - Hub has animated rotating ring + dual circles
 *   - Glassmorphism legend
 */

import { useMemo, useState, useCallback, useId, useRef, useEffect } from "react"
import type { AgentSummary, AgentStatus } from "@/types"

interface TopologyGraphProps {
  agents: AgentSummary[]
  width?: number
  height?: number
  onNodeClick?: (agentId: string) => void
}

/* ── Status → visual config ───────────────────────────────── */
const STATUS_CFG = {
  active:      { color: "#22c55e", bg: "rgba(34,197,94,0.08)",  border: "rgba(34,197,94,0.35)", ring: 0.30, label: "Active",      glow: true },
  stale:       { color: "#eab308", bg: "rgba(234,179,8,0.06)",  border: "rgba(234,179,8,0.30)", ring: 0.50, label: "Stale",       glow: false },
  offline:     { color: "#52525b", bg: "rgba(82,82,91,0.06)",   border: "rgba(82,82,91,0.25)", ring: 0.68, label: "Offline",      glow: false },
  terminated:  { color: "#52525b", bg: "rgba(82,82,91,0.06)",   border: "rgba(82,82,91,0.25)", ring: 0.68, label: "Terminated",   glow: false },
  quarantined: { color: "#ef4444", bg: "rgba(239,68,68,0.08)",  border: "rgba(239,68,68,0.35)", ring: 0.55, label: "Quarantined", glow: false },
} as const

const FRAMEWORK_ABBR: Record<string, string> = {
  crewai: "CR", langchain: "LC", autogen: "AG", langgraph: "LG",
  openai: "OA", custom: "CU",
}

interface LayoutNode {
  id: string
  label: string
  sublabel: string
  framework: string
  fwAbbr: string
  status: AgentStatus
  x: number
  y: number
}

/* ── Layout engine ───────────────────────────────────────── */
function computeLayout(agents: AgentSummary[], w: number, h: number): LayoutNode[] {
  const cx = w / 2
  const cy = h / 2
  const minDim = Math.min(w, h)

  const groups: Record<string, AgentSummary[]> = { active: [], stale: [], offline: [], terminated: [], quarantined: [] }
  agents.forEach((a) => (groups[a.status] ?? groups.terminated).push(a))

  const nodes: LayoutNode[] = []

  for (const [status, list] of Object.entries(groups)) {
    const cfg = STATUS_CFG[status as keyof typeof STATUS_CFG]
    const baseRadius = cfg.ring * minDim * 0.5
    const count = list.length

    list.forEach((agent, i) => {
      const baseAngle = -Math.PI / 2
      const angle = baseAngle + (i / Math.max(count, 1)) * Math.PI * 2
      const jitter = count === 1 ? 0 : (Math.sin(i * 2.7) * 8)
      const radius = baseRadius + jitter
      const fw = agent.framework ?? "unknown"

      nodes.push({
        id: agent.id,
        label: agent.name ?? `Agent-${agent.paid.slice(0, 8)}`,
        sublabel: agent.paid.slice(0, 12),
        framework: fw,
        fwAbbr: FRAMEWORK_ABBR[fw.toLowerCase()] ?? fw.slice(0, 2).toUpperCase(),
        status: agent.status,
        x: cx + Math.cos(angle) * radius,
        y: cy + Math.sin(angle) * radius,
      })
    })
  }

  return nodes
}

export function TopologyGraph({ agents, width = 960, height = 560, onNodeClick }: TopologyGraphProps) {
  const [hovered, setHovered] = useState<string | null>(null)
  const uid = useId()
  const svgRef = useRef<SVGSVGElement>(null)

  // Zoom/pan state
  const [zoom, setZoom] = useState(1)
  const [pan, setPan] = useState({ x: 0, y: 0 })
  const [isPanning, setIsPanning] = useState(false)
  const panStart = useRef({ x: 0, y: 0, panX: 0, panY: 0 })

  const cx = width / 2
  const cy = height / 2
  const nodes = useMemo(() => computeLayout(agents, width, height), [agents, width, height])

  const handleClick = useCallback((id: string) => onNodeClick?.(id), [onNodeClick])

  // Zoom controls
  const zoomIn = useCallback(() => setZoom(z => Math.min(z * 1.3, 5)), [])
  const zoomOut = useCallback(() => setZoom(z => Math.max(z / 1.3, 0.3)), [])
  const resetView = useCallback(() => { setZoom(1); setPan({ x: 0, y: 0 }) }, [])

  // Wheel zoom
  useEffect(() => {
    const svg = svgRef.current
    if (!svg) return
    const handleWheel = (e: WheelEvent) => {
      e.preventDefault()
      const factor = e.deltaY < 0 ? 1.1 : 1 / 1.1
      setZoom(z => Math.min(Math.max(z * factor, 0.3), 5))
    }
    svg.addEventListener("wheel", handleWheel, { passive: false })
    return () => svg.removeEventListener("wheel", handleWheel)
  }, [])

  // Pan handlers
  const onPointerDown = useCallback((e: React.PointerEvent) => {
    if (e.button !== 0) return
    setIsPanning(true)
    panStart.current = { x: e.clientX, y: e.clientY, panX: pan.x, panY: pan.y }
    ;(e.target as Element).setPointerCapture?.(e.pointerId)
  }, [pan])

  const onPointerMove = useCallback((e: React.PointerEvent) => {
    if (!isPanning) return
    const dx = (e.clientX - panStart.current.x) / zoom
    const dy = (e.clientY - panStart.current.y) / zoom
    setPan({ x: panStart.current.panX + dx, y: panStart.current.panY + dy })
  }, [isPanning, zoom])

  const onPointerUp = useCallback(() => setIsPanning(false), [])

  if (agents.length === 0) return null

  const nodeW = 130
  const nodeH = 56

  return (
    <div className="relative">
    <svg ref={svgRef} viewBox={`0 0 ${width} ${height}`} className="w-full h-full select-none" style={{ minHeight: 440, cursor: isPanning ? "grabbing" : "grab" }}
      onPointerDown={onPointerDown} onPointerMove={onPointerMove} onPointerUp={onPointerUp} onPointerLeave={onPointerUp}>
      <g transform={`translate(${width / 2 + pan.x * zoom}, ${height / 2 + pan.y * zoom}) scale(${zoom}) translate(${-width / 2}, ${-height / 2})`}>
      <defs>
        <filter id={`${uid}-glow`} x="-60%" y="-60%" width="220%" height="220%">
          <feGaussianBlur in="SourceGraphic" stdDeviation="6" result="blur" />
          <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
        <filter id={`${uid}-hub-glow`} x="-100%" y="-100%" width="300%" height="300%">
          <feGaussianBlur in="SourceGraphic" stdDeviation="10" result="blur" />
          <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
        <radialGradient id={`${uid}-hub-fill`} cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="rgba(16,185,129,0.15)" />
          <stop offset="100%" stopColor="rgba(16,185,129,0.02)" />
        </radialGradient>
        <linearGradient id={`${uid}-card-active`} x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="rgba(18,18,21,0.96)" />
          <stop offset="100%" stopColor="rgba(24,28,24,0.96)" />
        </linearGradient>
        <linearGradient id={`${uid}-card-stale`} x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="rgba(18,18,21,0.96)" />
          <stop offset="100%" stopColor="rgba(28,26,18,0.96)" />
        </linearGradient>
        <linearGradient id={`${uid}-card-term`} x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="rgba(18,18,21,0.92)" />
          <stop offset="100%" stopColor="rgba(22,22,25,0.92)" />
        </linearGradient>
        <style>{`
          @keyframes dash-flow { to { stroke-dashoffset: -24; } }
          @keyframes orbit-spin { to { transform: rotate(360deg); } }
          @keyframes pulse-led { 0%,100%{opacity:.9;r:3.5}50%{opacity:.5;r:5} }
          .topo-flow { animation: dash-flow 1.5s linear infinite; }
          .topo-orbit { animation: orbit-spin 40s linear infinite; transform-origin: ${cx}px ${cy}px; }
          .topo-led { animation: pulse-led 2s ease-in-out infinite; }
        `}</style>
      </defs>

      {/* ── Orbit rings ──────────────────────────────────── */}
      {[0.18, 0.30, 0.50, 0.68].map((r, i) => (
        <circle
          key={r} cx={cx} cy={cy}
          r={Math.min(width, height) * r * 0.5}
          fill="none"
          stroke={`rgba(63,63,70,${0.08 + i * 0.02})`}
          strokeWidth="0.8" strokeDasharray="4 8"
          className={i === 0 ? "topo-orbit" : undefined}
        />
      ))}

      {/* Crosshair */}
      <line x1={cx - 30} y1={cy} x2={cx + 30} y2={cy} stroke="rgba(63,63,70,0.12)" strokeWidth="0.5" />
      <line x1={cx} y1={cy - 30} x2={cx} y2={cy + 30} stroke="rgba(63,63,70,0.12)" strokeWidth="0.5" />

      {/* ── Connection lines ─────────────────────────────── */}
      {nodes.map((node) => {
        const isHov = hovered === node.id
        const cfg = STATUS_CFG[node.status]
        return (
          <g key={`edge-${node.id}`}>
            <line x1={cx} y1={cy} x2={node.x} y2={node.y}
              stroke={isHov ? `${cfg.color}40` : "rgba(63,63,70,0.08)"}
              strokeWidth={isHov ? 3 : 1.5} strokeLinecap="round"
              style={{ transition: "all 0.3s ease", filter: isHov ? "blur(4px)" : undefined }}
            />
            <line x1={cx} y1={cy} x2={node.x} y2={node.y}
              stroke={isHov ? cfg.color : node.status === "active" ? "rgba(34,197,94,0.18)" : "rgba(63,63,70,0.12)"}
              strokeWidth={isHov ? 1.5 : 0.8} strokeDasharray="6 6" strokeLinecap="round"
              className={node.status === "active" || isHov ? "topo-flow" : undefined}
              opacity={hovered && !isHov ? 0.2 : 1}
              style={{ transition: "opacity 0.3s ease" }}
            />
          </g>
        )
      })}

      {/* ── Central hub ──────────────────────────────────── */}
      <g>
        <circle cx={cx} cy={cy} r={36} fill={`url(#${uid}-hub-fill)`} stroke="rgba(16,185,129,0.2)" strokeWidth="1" filter={`url(#${uid}-hub-glow)`} />
        <circle cx={cx} cy={cy} r={30} fill="none" stroke="rgba(16,185,129,0.15)" strokeWidth="1.5" strokeDasharray="8 12" className="topo-orbit" />
        <circle cx={cx} cy={cy} r={22} fill="rgba(9,9,11,0.97)" stroke="rgba(16,185,129,0.5)" strokeWidth="1.5" />
        <text x={cx} y={cy - 2} textAnchor="middle" dominantBaseline="central" fill="#10b981" fontSize="12" fontWeight="800" fontFamily="var(--font-mono)">GW</text>
        <text x={cx} y={cy + 48} textAnchor="middle" fill="#52525b" fontSize="9" fontWeight="700" letterSpacing="0.12em" fontFamily="var(--font-sans)">PHANTEX GATEWAY</text>
      </g>

      {/* ── Agent card-nodes ─────────────────────────────── */}
      {nodes.map((node) => {
        const isHov = hovered === node.id
        const cfg = STATUS_CFG[node.status]
        const nx = node.x - nodeW / 2
        const ny = node.y - nodeH / 2
        const cardFill = node.status === "active" ? `url(#${uid}-card-active)` : node.status === "stale" ? `url(#${uid}-card-stale)` : `url(#${uid}-card-term)`

        return (
          <g key={node.id}
            onMouseEnter={() => setHovered(node.id)} onMouseLeave={() => setHovered(null)}
            onClick={() => handleClick(node.id)} className="cursor-pointer"
            opacity={hovered && !isHov ? 0.4 : 1} style={{ transition: "opacity 0.3s ease" }}>
            {isHov && <rect x={nx - 2} y={ny - 2} width={nodeW + 4} height={nodeH + 4} rx={12} fill="none" stroke={cfg.color} strokeWidth="1" opacity={0.3} filter={`url(#${uid}-glow)`} />}
            <rect x={nx} y={ny} width={nodeW} height={nodeH} rx={10}
              fill={isHov ? "rgba(28,28,32,0.98)" : cardFill}
              stroke={isHov ? cfg.color : cfg.border} strokeWidth={isHov ? 1.5 : 0.8}
              style={{ transition: "all 0.25s ease" }} />
            <line x1={nx + 10} y1={ny} x2={nx + (isHov ? nodeW - 10 : 40)} y2={ny}
              stroke={cfg.color} strokeWidth="2" strokeLinecap="round"
              opacity={isHov ? 0.8 : 0.4} style={{ transition: "all 0.3s ease" }} />
            <circle cx={nx + 14} cy={node.y - 6} r={3.5} fill={cfg.color}
              opacity={node.status === "terminated" ? 0.3 : 0.9}
              className={node.status === "active" ? "topo-led" : undefined} />
            <rect x={nx + nodeW - 32} y={ny + 5} width={26} height={16} rx={4}
              fill={`${cfg.color}12`} stroke={`${cfg.color}30`} strokeWidth="0.6" />
            <text x={nx + nodeW - 19} y={ny + 16} textAnchor="middle" fill={cfg.color}
              fontSize="7.5" fontWeight="800" fontFamily="var(--font-mono)">{node.fwAbbr}</text>
            <text x={nx + 26} y={node.y - 5} fill={isHov ? "#fafafa" : "#d4d4d8"}
              fontSize="10" fontWeight="700" fontFamily="var(--font-sans)">
              {node.label.length > 13 ? node.label.slice(0, 12) + "…" : node.label}
            </text>
            <text x={nx + 14} y={node.y + 14} fill="#52525b" fontSize="8" fontFamily="var(--font-mono)">{node.sublabel}</text>
          </g>
        )
      })}

      {/* ── Legend ────────────────────────────────────────── */}
      <g transform={`translate(16, ${height - 68})`}>
        <rect x={-4} y={-8} width={100} height={58} rx={8} fill="rgba(9,9,11,0.7)" stroke="rgba(63,63,70,0.2)" strokeWidth="0.5" />
        <text fill="#52525b" fontSize="8" fontWeight="800" letterSpacing="0.12em" fontFamily="var(--font-sans)">STATUS</text>
        {(Object.entries(STATUS_CFG) as [string, (typeof STATUS_CFG)[keyof typeof STATUS_CFG]][]).map(
          ([, cfg], i) => (
            <g key={cfg.label} transform={`translate(0, ${14 + i * 14})`}>
              <circle cx={6} cy={-2} r={3.5} fill={cfg.color} />
              <text x={16} y={1} fill="#a1a1aa" fontSize="8.5" fontWeight="500" fontFamily="var(--font-sans)">{cfg.label}</text>
            </g>
          ),
        )}
      </g>

      {/* Node count badge */}
      <g transform={`translate(${width - 130}, ${height - 28})`}>
        <rect x={0} y={-4} width={120} height={20} rx={6} fill="rgba(9,9,11,0.7)" stroke="rgba(63,63,70,0.2)" strokeWidth="0.5" />
        <text x={60} y={9} textAnchor="middle" fill="#52525b" fontSize="8.5" fontWeight="600" fontFamily="var(--font-mono)">
          {agents.length} AGENT{agents.length !== 1 ? "S" : ""} · {agents.filter((a) => a.status === "active").length} ONLINE
        </text>
      </g>
      </g>
    </svg>

    {/* Zoom controls overlay */}
    <div className="absolute top-3 right-3 flex flex-col gap-1">
      <button onClick={zoomIn} className="w-8 h-8 flex items-center justify-center rounded-md bg-card/80 border border-border/50 text-foreground/70 hover:bg-card hover:text-foreground transition-colors text-sm font-bold" title="Zoom in">+</button>
      <button onClick={zoomOut} className="w-8 h-8 flex items-center justify-center rounded-md bg-card/80 border border-border/50 text-foreground/70 hover:bg-card hover:text-foreground transition-colors text-sm font-bold" title="Zoom out">−</button>
      <button onClick={resetView} className="w-8 h-8 flex items-center justify-center rounded-md bg-card/80 border border-border/50 text-foreground/70 hover:bg-card hover:text-foreground transition-colors" title="Reset view">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 12a9 9 0 1 0 9-9 9.1 9.1 0 0 0-6.36 2.64L3 8"/><path d="M3 3v5h5"/></svg>
      </button>
    </div>
    <div className="absolute bottom-3 right-3 text-[10px] text-muted-foreground font-mono">
      {Math.round(zoom * 100)}%
    </div>
    </div>
  )
}
