// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — System Nerve Center Page (v2).
 *
 * Real-time animated pipeline monitoring dashboard with:
 *   - Zoom & pan on the SVG pipeline diagram (wheel + drag)
 *   - Pipe-style gradient connections with animated flow
 *   - Alert banners for unhealthy/degraded components
 *   - Component health indicators with latency chips
 *   - Stats row with throughput counters
 *   - Responsive layout
 *
 * @module pages/NerveCenterPage
 */

import { useState, useRef, useCallback, useMemo, useEffect } from "react"
import {
  Activity,
  AlertTriangle,
  Database,
  HardDrive,
  Cpu,
  Radio,
  Globe,
  Server,
  Zap,
  ArrowRight,
  CheckCircle2,
  XCircle,
  Clock,
  Gauge,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Bell,
  Info,
  Layers,
  ChevronDown,
  ChevronUp,
  Shield,
  Monitor,
  Link2,
  Wrench,
  RotateCcw,
  HelpCircle,
} from "lucide-react"
import { useNerveCenter, useThroughput } from "@/api/system"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import type { ComponentHealth, PipelineNode } from "@/types"

/* ── Layout constants ──────────────────────────────────────────────── */

const SVG_W = 1440
const SVG_H = 640
const NODE_R = 38
const MIN_ZOOM = 0.4
const MAX_ZOOM = 3

/* Default node positions — spread out for readability.
 * Users can drag nodes to rearrange; positions persist in localStorage.
 *
 *   [MCP] ──┐
 *           ↓
 *   [Sensor] → [Gateway] → [Kafka] → [Consumers] → [Backend] → [Dashboard]
 *                                        │              │
 *                                        ↓              ↓
 *                          [TrustEngine] [Postgres] [ClickHouse] [Neo4j] [Redis]
 */
const DEFAULT_NODE_POS: Record<string, { x: number; y: number }> = {
  mcp:          { x: 80,   y: 60  },
  sensor:       { x: 160,  y: 200 },
  gateway:      { x: 360,  y: 200 },
  kafka:        { x: 560,  y: 200 },
  consumers:    { x: 780,  y: 200 },
  backend:      { x: 1020, y: 200 },
  dashboard:    { x: 1300, y: 100 },
  trust_engine: { x: 560,  y: 480 },
  postgres:     { x: 760,  y: 480 },
  clickhouse:   { x: 960,  y: 480 },
  neo4j:        { x: 1160, y: 480 },
  redis:        { x: 1300, y: 330 },
}

/** localStorage key for persisting user's custom node layout */
const LAYOUT_STORAGE_KEY = "phantex-nerve-center-layout"

function loadSavedPositions(): Record<string, { x: number; y: number }> {
  try {
    const raw = localStorage.getItem(LAYOUT_STORAGE_KEY)
    if (raw) {
      const parsed = JSON.parse(raw)
      // Validate shape
      if (typeof parsed === "object" && parsed !== null) {
        const result = { ...DEFAULT_NODE_POS }
        for (const [k, v] of Object.entries(parsed)) {
          if (k in DEFAULT_NODE_POS && typeof (v as {x?: number}).x === "number" && typeof (v as {y?: number}).y === "number") {
            result[k] = v as { x: number; y: number }
          }
        }
        return result
      }
    }
  } catch { /* ignore corrupt data */ }
  return { ...DEFAULT_NODE_POS }
}

function savePosToStorage(positions: Record<string, { x: number; y: number }>) {
  try {
    localStorage.setItem(LAYOUT_STORAGE_KEY, JSON.stringify(positions))
  } catch { /* quota exceeded, ignore */ }
}

const NODE_ICONS: Record<string, React.ElementType> = {
  mcp:          Link2,
  sensor:       Radio,
  gateway:      Globe,
  kafka:        Zap,
  consumers:    Layers,
  backend:      Server,
  dashboard:    Monitor,
  trust_engine: Shield,
  postgres:     Database,
  clickhouse:   HardDrive,
  neo4j:        Activity,
  redis:        Cpu,
}

const NODE_COLORS: Record<string, string> = {
  mcp:          "#a855f7",
  sensor:       "#3b82f6",
  gateway:      "#8b5cf6",
  kafka:        "#f59e0b",
  consumers:    "#14b8a6",
  backend:      "#06b6d4",
  dashboard:    "#6366f1",
  trust_engine: "#f43f5e",
  postgres:     "#10b981",
  clickhouse:   "#ef4444",
  neo4j:        "#ec4899",
  redis:        "#f97316",
}

/* Map pipeline node IDs to component health keys (mismatches only) */
const HEALTH_KEY_MAP: Record<string, string> = {
  mcp: "mcp_servers",
}
function healthKey(nodeId: string): string {
  return HEALTH_KEY_MAP[nodeId] ?? nodeId
}

/* ── Remediation tips for degraded / unhealthy components ── */
const REMEDIATION_TIPS: Record<string, { degraded: string; unhealthy: string }> = {
  consumers: {
    degraded: "Consumer lag detected or Kafka-UI API unavailable. Check consumer containers: docker ps | grep writer",
    unhealthy: "Consumer service unreachable. Restart: docker restart phantex-storage-writer",
  },
  kafka: {
    degraded: "Kafka cluster partially available. Check broker logs: docker logs phantex-kafka --tail 50",
    unhealthy: "Kafka broker down. Restart: docker restart phantex-kafka",
  },
  postgres: {
    degraded: "PostgreSQL connection pool under pressure. Monitor pool_checked_out / pool_size ratio.",
    unhealthy: "PostgreSQL unreachable. Check: docker logs phantex-postgres --tail 30",
  },
  clickhouse: {
    degraded: "ClickHouse responding slowly. Check disk usage and memory pressure.",
    unhealthy: "ClickHouse unreachable. Restart: docker restart phantex-clickhouse",
  },
  neo4j: {
    degraded: "Neo4j degraded. Check heap usage and active queries in Neo4j Browser (port 7474).",
    unhealthy: "Neo4j unreachable. Restart: docker restart phantex-neo4j",
  },
  redis: {
    degraded: "Redis high memory usage. Consider flushing stale keys or increasing maxmemory.",
    unhealthy: "Redis unreachable. Restart: docker restart phantex-redis",
  },
  gateway: {
    degraded: "Gateway partially responsive. Verify gRPC port 50051 is open.",
    unhealthy: "Gateway down. Restart: docker restart phantex-gateway",
  },
  backend: {
    degraded: "Backend API degraded. Check memory (memory_rss_mb) and thread count.",
    unhealthy: "Backend API unreachable. Check: docker logs phantex-backend --tail 50",
  },
  trust_engine: {
    degraded: "Trust Engine slow. Check gRPC health on port 50052 and graph size.",
    unhealthy: "Trust Engine unreachable. Restart: docker restart phantex-trust-engine",
  },
  mcp_servers: {
    degraded: "MCP registry query slow. Check PostgreSQL performance.",
    unhealthy: "MCP server registry table unavailable. Run migrations.",
  },
}

/* ── Status helpers ────────────────────────────────────────── */

function statusColor(status: string): string {
  switch (status) {
    case "healthy": return "#10b981"
    case "degraded": return "#f59e0b"
    case "unhealthy": case "error": return "#ef4444"
    default: return "#6b7280"
  }
}

function statusGlow(status: string): string {
  switch (status) {
    case "healthy": return "drop-shadow(0 0 8px rgba(16,185,129,0.4))"
    case "degraded": return "drop-shadow(0 0 8px rgba(245,158,11,0.4))"
    case "unhealthy": case "error": return "drop-shadow(0 0 10px rgba(239,68,68,0.5))"
    default: return "none"
  }
}

function overallBadge(status: string) {
  switch (status) {
    case "operational":
      return <Badge className="bg-emerald-500/20 text-emerald-400 border-emerald-500/30 gap-1"><CheckCircle2 size={12}/>Operational</Badge>
    case "degraded":
      return <Badge className="bg-amber-500/20 text-amber-400 border-amber-500/30 gap-1"><AlertTriangle size={12}/>Degraded</Badge>
    default:
      return <Badge className="bg-red-500/20 text-red-400 border-red-500/30 gap-1"><XCircle size={12}/>Partial</Badge>
  }
}

/* ── Pipe connection (gradient tube with animated flow) ───── */

function PipeConnection({
  from,
  to,
  color,
  targetStatus,
  idx,
}: {
  from: { x: number; y: number }
  to: { x: number; y: number }
  color: string
  targetStatus?: string
  idx: number
}) {
  const dx = to.x - from.x
  const dy = to.y - from.y
  const dist = Math.sqrt(dx * dx + dy * dy)
  const nx = -dy / dist
  const ny = dx / dist
  const curveMag = dist * 0.12
  const cx = (from.x + to.x) / 2 + nx * curveMag
  const cy = (from.y + to.y) / 2 + ny * curveMag

  const pathD = `M ${from.x} ${from.y} Q ${cx} ${cy} ${to.x} ${to.y}`
  const gradId = `pipe-grad-${idx}`
  const glowId = `pipe-glow-${idx}`
  const particleId = `pipe-path-${idx}`

  const isHealthy = !targetStatus || targetStatus === "healthy"
  const isDegraded = targetStatus === "degraded"
  const isUnhealthy = targetStatus === "unhealthy" || targetStatus === "error"
  const pipeColor = isHealthy ? color : (isDegraded ? "#f59e0b" : "#ef4444")

  return (
    <g>
      <defs>
        <linearGradient id={gradId} x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor={pipeColor} stopOpacity={0.6} />
          <stop offset="50%" stopColor={pipeColor} stopOpacity={0.3} />
          <stop offset="100%" stopColor={pipeColor} stopOpacity={0.6} />
        </linearGradient>
        <filter id={glowId}>
          <feGaussianBlur stdDeviation="3" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
        <path id={particleId} d={pathD} />
      </defs>

      {/* Pipe outer glow */}
      <path
        d={pathD}
        fill="none"
        stroke={pipeColor}
        strokeWidth={isUnhealthy ? 14 : 10}
        strokeOpacity={isUnhealthy ? 0.12 : 0.06}
        strokeLinecap="round"
      >
        {/* Flicker effect for unhealthy pipes */}
        {isUnhealthy && (
          <animate attributeName="stroke-opacity" values="0.15;0.03;0.15;0.08;0.15" dur="0.6s" repeatCount="indefinite" />
        )}
        {isDegraded && (
          <animate attributeName="stroke-opacity" values="0.08;0.02;0.08" dur="1.5s" repeatCount="indefinite" />
        )}
      </path>

      {/* Pipe body — thick gradient tube */}
      <path
        d={pathD}
        fill="none"
        stroke={`url(#${gradId})`}
        strokeWidth={isUnhealthy ? 6 : 5}
        strokeLinecap="round"
        strokeOpacity={0.5}
      >
        {isUnhealthy && (
          <animate attributeName="stroke-opacity" values="0.7;0.15;0.7;0.3;0.7" dur="0.6s" repeatCount="indefinite" />
        )}
        {isDegraded && (
          <animate attributeName="stroke-opacity" values="0.5;0.2;0.5" dur="1.5s" repeatCount="indefinite" />
        )}
      </path>

      {/* Pipe inner highlight */}
      <path
        d={pathD}
        fill="none"
        stroke={pipeColor}
        strokeWidth={1.5}
        strokeOpacity={0.4}
        strokeLinecap="round"
      >
        {isUnhealthy && (
          <animate attributeName="stroke-opacity" values="0.6;0.1;0.6" dur="0.6s" repeatCount="indefinite" />
        )}
      </path>

      {/* Animated flow particle 1 — stops for unhealthy */}
      {!isUnhealthy && (
        <circle r={4} fill={pipeColor} opacity={0.9} filter={`url(#${glowId})`}>
          <animateMotion dur={`${isDegraded ? 4 : 2.2 + idx * 0.3}s`} begin={`${idx * 0.4}s`} repeatCount="indefinite">
            <mpath href={`#${particleId}`} />
          </animateMotion>
        </circle>
      )}

      {/* Animated flow particle 2 (offset) — stops for unhealthy */}
      {!isUnhealthy && (
        <circle r={2.5} fill={pipeColor} opacity={0.6}>
          <animateMotion dur={`${isDegraded ? 5 : 2.8 + idx * 0.2}s`} begin={`${idx * 0.4 + 1.3}s`} repeatCount="indefinite">
            <mpath href={`#${particleId}`} />
          </animateMotion>
        </circle>
      )}

      {/* Glow trail — stops for unhealthy */}
      {!isUnhealthy && (
        <circle r={8} fill={pipeColor} opacity={0.15}>
          <animateMotion dur={`${isDegraded ? 4 : 2.2 + idx * 0.3}s`} begin={`${idx * 0.4}s`} repeatCount="indefinite">
            <mpath href={`#${particleId}`} />
          </animateMotion>
        </circle>
      )}

      {/* Static warning indicator on unhealthy pipes */}
      {isUnhealthy && (
        <g>
          {/* Midpoint X */}
          <circle cx={cx} cy={cy} r={10} fill="#ef4444" opacity={0.9}>
            <animate attributeName="opacity" values="0.9;0.4;0.9" dur="0.8s" repeatCount="indefinite" />
          </circle>
          <text x={cx} y={cy + 4} textAnchor="middle" fill="white" className="text-[10px] font-bold">✕</text>
        </g>
      )}

      {/* Degraded warning diamond on pipe midpoint */}
      {isDegraded && (
        <g>
          <circle cx={cx} cy={cy} r={8} fill="#f59e0b" opacity={0.8}>
            <animate attributeName="opacity" values="0.8;0.3;0.8" dur="1.5s" repeatCount="indefinite" />
          </circle>
          <text x={cx} y={cy + 3.5} textAnchor="middle" fill="white" className="text-[8px] font-bold">!</text>
        </g>
      )}
    </g>
  )
}

/* ── Pipeline node SVG component ───────────────────────── */

function PipelineNodeSVG({
  node,
  health,
  pos,
  isSelected,
}: {
  node: PipelineNode
  health?: ComponentHealth
  pos: { x: number; y: number }
  isSelected: boolean
}) {
  const Icon = NODE_ICONS[node.id] ?? Server
  const baseColor = NODE_COLORS[node.id] ?? "#6b7280"
  const status = health?.status ?? "unknown"
  const sColor = statusColor(status)
  const latency = health?.latency_ms ?? 0

  return (
    <g transform={`translate(${pos.x}, ${pos.y})`}>
      {/* Selection ring */}
      {isSelected && (
        <circle
          r={NODE_R + 10}
          fill="none"
          stroke="#6366f1"
          strokeWidth={2}
          strokeDasharray="6 3"
          opacity={0.6}
        >
          <animateTransform
            attributeName="transform"
            type="rotate"
            values="0;360"
            dur="12s"
            repeatCount="indefinite"
          />
        </circle>
      )}

      {/* Outer status ring */}
      <circle
        r={NODE_R + 4}
        fill="none"
        stroke={sColor}
        strokeWidth={2.5}
        opacity={0.7}
        style={{ filter: statusGlow(status) }}
      >
        {status === "healthy" && (
          <animate attributeName="stroke-opacity" values="0.7;0.3;0.7" dur="3s" repeatCount="indefinite" />
        )}
        {(status === "unhealthy" || status === "error") && (
          <animate attributeName="stroke-opacity" values="0.9;0.4;0.9" dur="0.8s" repeatCount="indefinite" />
        )}
      </circle>

      {/* Inner circle bg */}
      <circle r={NODE_R} fill={baseColor} fillOpacity={0.12} stroke={baseColor} strokeWidth={1} strokeOpacity={0.3} />

      {/* Icon */}
      <foreignObject x={-12} y={-18} width={24} height={24} className="pointer-events-none">
        <div className="flex items-center justify-center" style={{ color: baseColor }}>
          <Icon size={20} />
        </div>
      </foreignObject>

      {/* Label */}
      <text y={NODE_R + 18} textAnchor="middle" className="fill-foreground text-[11px] font-medium">
        {node.label}
      </text>

      {/* Latency chip */}
      {health && (
        <g transform={`translate(0, ${-NODE_R - 14})`}>
          <rect x={-22} y={-8} width={44} height={16} rx={8} fill={sColor} fillOpacity={0.2} stroke={sColor} strokeWidth={0.5} strokeOpacity={0.3} />
          <text textAnchor="middle" y={4} className="text-[9px] font-mono tabular-nums" fill={sColor}>
            {latency < 1 ? "<1" : latency.toFixed(0)}ms
          </text>
        </g>
      )}

      {/* Status dot */}
      <circle cx={NODE_R - 4} cy={-NODE_R + 4} r={5} fill={sColor}>
        {(status === "unhealthy" || status === "error") && (
          <animate attributeName="r" values="5;8;5" dur="0.8s" repeatCount="indefinite" />
        )}
      </circle>

      {/* Alert exclamation for unhealthy */}
      {(status === "unhealthy" || status === "error") && (
        <g transform={`translate(${-NODE_R + 4}, ${-NODE_R + 4})`}>
          <circle r={8} fill="#ef4444" />
          <text textAnchor="middle" y={4} fill="white" className="text-[10px] font-bold">!</text>
        </g>
      )}
    </g>
  )
}

/* ── Alert Banner ──────────────────────────────────────── */

function AlertBanner({ issues }: { issues: { name: string; status: string; error?: string; diagnostic?: string; troubleshooting?: string[] }[] }) {
  if (issues.length === 0) return null

  const hasCritical = issues.some(i => i.status === "unhealthy" || i.status === "error")
  const bgClass = hasCritical
    ? "bg-red-500/10 border-red-500/30 text-red-400"
    : "bg-amber-500/10 border-amber-500/30 text-amber-400"
  const IconEl = hasCritical ? XCircle : AlertTriangle

  return (
    <div className={`flex flex-col gap-2 rounded-lg border px-4 py-3 ${bgClass}`}>
      <div className="flex items-start gap-3">
        <IconEl size={18} className="mt-0.5 flex-shrink-0" />
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium">
            {hasCritical ? "System Alert" : "Degraded Components"} — {issues.length} component{issues.length > 1 ? "s" : ""} need{issues.length === 1 ? "s" : ""} attention
          </p>
          <div className="flex flex-col gap-2 mt-2">
            {issues.map(i => (
              <div key={i.name} className="rounded-md bg-black/20 px-3 py-2 border border-current/10">
                <div className="flex items-center gap-2 mb-1">
                  <span className="h-2 w-2 rounded-full" style={{ backgroundColor: i.status === "unhealthy" || i.status === "error" ? "#ef4444" : "#f59e0b" }} />
                  <span className="text-xs font-mono font-semibold capitalize">{i.name.replace(/_/g, " ")}</span>
                  <span className="text-[10px] opacity-50 uppercase">{i.status}</span>
                </div>
                {/* Diagnostic message — the key enhancement */}
                {i.diagnostic && (
                  <p className="text-[11px] leading-relaxed opacity-80 mb-1.5">
                    {i.diagnostic}
                  </p>
                )}
                {/* Fallback to raw error if no diagnostic */}
                {!i.diagnostic && i.error && (
                  <p className="text-[10px] font-mono opacity-50 truncate mb-1">
                    {i.error}
                  </p>
                )}
                {/* Troubleshooting steps */}
                {i.troubleshooting && i.troubleshooting.length > 0 && (
                  <div className="flex flex-col gap-0.5 mt-1 border-t border-current/10 pt-1.5">
                    <span className="text-[9px] uppercase tracking-wider opacity-40 font-semibold flex items-center gap-1">
                      <Wrench size={8} /> Investigation Steps
                    </span>
                    {i.troubleshooting.map((step, si) => (
                      <div key={si} className="flex items-start gap-1.5 text-[10px] opacity-60">
                        <span className="text-[8px] mt-0.5 opacity-50">{si + 1}.</span>
                        <code className="font-mono break-all">{step}</code>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
        <Bell size={14} className="opacity-40 mt-1 flex-shrink-0 animate-pulse" />
      </div>

      {/* Recommended Fixes (from REMEDIATION_TIPS — kept as fallback) */}
      {issues.some(i => !i.diagnostic && REMEDIATION_TIPS[i.name]) && (
        <div className="ml-[30px] flex flex-col gap-1.5 border-t border-current/10 pt-2">
          <p className="text-[10px] uppercase tracking-wider opacity-50 font-semibold flex items-center gap-1">
            <Wrench size={10} /> Quick Fixes
          </p>
          {issues.filter(i => !i.diagnostic).map(i => {
            const tips = REMEDIATION_TIPS[i.name]
            const statusKey = (i.status === "unhealthy" || i.status === "error") ? "unhealthy" : "degraded"
            const tip = tips?.[statusKey as keyof typeof tips]
            if (!tip) return null
            return (
              <div key={`fix-${i.name}`} className="flex items-start gap-2 text-[11px]">
                <ArrowRight size={10} className="mt-0.5 flex-shrink-0 opacity-60" />
                <span>
                  <span className="capitalize font-semibold opacity-80">{i.name.replace(/_/g, " ")}:</span>{" "}
                  <span className="opacity-70">{tip}</span>
                </span>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

/* ── Connection label ──────────────────────────────────── */

function ConnectionLabel({ from, to, label }: { from: { x: number; y: number }; to: { x: number; y: number }; label: string }) {
  const midX = (from.x + to.x) / 2
  const midY = (from.y + to.y) / 2
  const dx = to.x - from.x
  const dy = to.y - from.y
  const dist = Math.sqrt(dx * dx + dy * dy)
  const nx = -dy / dist * 18
  const ny = dx / dist * 18

  return (
    <g>
      <rect
        x={midX + nx - 32}
        y={midY + ny - 7}
        width={64}
        height={14}
        rx={4}
        fill="currentColor"
        className="text-background"
        fillOpacity={0.6}
      />
      <text
        x={midX + nx}
        y={midY + ny + 3}
        textAnchor="middle"
        className="fill-muted-foreground text-[7px]"
        opacity={0.6}
      >
        {label}
      </text>
    </g>
  )
}

/* ── Component detail panel ────────────────────────────── */

function ComponentDetail({ name, health }: { name: string; health: ComponentHealth }) {
  const entries = Object.entries(health).filter(([k]) => !["status", "error", "diagnostic", "troubleshooting"].includes(k))
  const { diagnostic, troubleshooting } = health

  return (
    <Card className="bg-card/80 backdrop-blur-sm border-primary/10">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm capitalize">{name.replace(/_/g, " ")}</CardTitle>
          <Badge
            className={
              health.status === "healthy"
                ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/30"
                : health.status === "degraded"
                  ? "bg-amber-500/20 text-amber-400 border-amber-500/30"
                  : "bg-red-500/20 text-red-400 border-red-500/30"
            }
          >
            {health.status}
          </Badge>
        </div>
      </CardHeader>
      <CardContent>
        {/* Diagnostic banner */}
        {diagnostic && (
          <div className={`rounded-md px-3 py-2 mb-3 text-[11px] leading-relaxed border ${
            health.status === "healthy"
              ? "bg-blue-500/5 border-blue-500/20 text-blue-300"
              : health.status === "degraded"
                ? "bg-amber-500/10 border-amber-500/20 text-amber-300"
                : "bg-red-500/10 border-red-500/20 text-red-300"
          }`}>
            <div className="flex items-start gap-2">
              <Info size={12} className="mt-0.5 flex-shrink-0" />
              <span>{diagnostic}</span>
            </div>
          </div>
        )}

        {/* Metrics grid */}
        <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
          {entries.map(([key, val]) => (
            <div key={key} className="flex justify-between">
              <span className="text-muted-foreground">{key.replace(/_/g, " ")}</span>
              <span className="font-mono tabular-nums text-foreground">
                {typeof val === "number" ? val.toLocaleString() : String(val ?? "—")}
              </span>
            </div>
          ))}
        </div>

        {/* Raw error */}
        {health.error && (
          <p className="mt-2 text-[10px] text-destructive font-mono bg-destructive/10 rounded p-2 break-all">
            {health.error}
          </p>
        )}

        {/* Troubleshooting steps */}
        {troubleshooting && troubleshooting.length > 0 && (
          <div className="mt-3 border-t border-border/30 pt-2">
            <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold flex items-center gap-1 mb-1.5">
              <Wrench size={10} /> Investigation Steps
            </p>
            <div className="flex flex-col gap-1">
              {troubleshooting.map((step, i) => (
                <div key={i} className="flex items-start gap-2 text-[11px]">
                  <span className="text-muted-foreground text-[9px] mt-0.5 w-3 text-right flex-shrink-0">{i + 1}.</span>
                  <code className="font-mono text-foreground/70 break-all bg-muted/30 rounded px-1.5 py-0.5 text-[10px]">{step}</code>
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

/* ── Page ───────────────────────────────────────────────── */

export default function NerveCenterPage() {
  const { data, isLoading, error } = useNerveCenter()
  const { data: throughput } = useThroughput()
  const [selected, setSelected] = useState<string | null>(null)
  const [now, setNow] = useState(Date.now)

  // — Periodic clock update for "Xs ago" displays
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(id)
  }, [])

  // — Draggable node positions (persisted in localStorage)
  const [nodePositions, setNodePositions] = useState<Record<string, { x: number; y: number }>>(loadSavedPositions)
  const nodeDragRef = useRef<{ nodeId: string; startX: number; startY: number; origPosX: number; origPosY: number } | null>(null)

  // Persist positions when they change
  useEffect(() => {
    savePosToStorage(nodePositions)
  }, [nodePositions])

  const resetLayout = useCallback(() => {
    setNodePositions({ ...DEFAULT_NODE_POS })
    localStorage.removeItem(LAYOUT_STORAGE_KEY)
  }, [])

  // — Zoom & Pan state
  const [zoom, setZoom] = useState(1)
  const [pan, setPan] = useState({ x: 0, y: 0 })
  const dragRef = useRef<{ startX: number; startY: number; panX: number; panY: number } | null>(null)
  const [isDragging, setIsDragging] = useState(false)
  const [showGuide, setShowGuide] = useState(false)
  const svgContainerRef = useRef<HTMLDivElement>(null)
  const svgRef = useRef<SVGSVGElement>(null)

  const onWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setZoom(z => Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, z - e.deltaY * 0.001)))
  }, [])

  const onMouseDown = useCallback((e: React.MouseEvent) => {
    if (e.button !== 0) return
    // Don't start canvas drag if a node drag is active
    if (nodeDragRef.current) return
    dragRef.current = { startX: e.clientX, startY: e.clientY, panX: pan.x, panY: pan.y }
    setIsDragging(true)
  }, [pan])

  const onMouseMove = useCallback((e: React.MouseEvent) => {
    // Handle node dragging (higher priority than canvas pan)
    if (nodeDragRef.current) {
      const svg = svgRef.current
      if (!svg) return
      const rect = svg.getBoundingClientRect()
      const scaleX = SVG_W / rect.width
      const scaleY = SVG_H / rect.height
      const dx = (e.clientX - nodeDragRef.current.startX) * scaleX / zoom
      const dy = (e.clientY - nodeDragRef.current.startY) * scaleY / zoom
      const newX = Math.max(NODE_R, Math.min(SVG_W - NODE_R, nodeDragRef.current.origPosX + dx))
      const newY = Math.max(NODE_R, Math.min(SVG_H - NODE_R, nodeDragRef.current.origPosY + dy))
      // Capture nodeId before the async state updater — by the time React
      // calls the callback, onMouseUp may have already nulled the ref.
      const draggedNodeId = nodeDragRef.current.nodeId
      setNodePositions(prev => ({
        ...prev,
        [draggedNodeId]: { x: newX, y: newY },
      }))
      return
    }
    // Handle canvas pan
    if (!dragRef.current) return
    setPan({
      x: dragRef.current.panX + (e.clientX - dragRef.current.startX),
      y: dragRef.current.panY + (e.clientY - dragRef.current.startY),
    })
  }, [zoom])

  const onMouseUp = useCallback(() => {
    dragRef.current = null
    nodeDragRef.current = null
    setIsDragging(false)
  }, [])

  const resetView = useCallback(() => {
    setZoom(1)
    setPan({ x: 0, y: 0 })
  }, [])

  // — Derived: issues for alert banner
  const issues = useMemo(() => {
    if (!data) return []
    return Object.entries(data.components)
      .filter(([, h]) => h.status !== "healthy")
      .map(([name, h]) => ({
        name,
        status: h.status,
        error: h.error,
        diagnostic: h.diagnostic,
        troubleshooting: h.troubleshooting,
      }))
  }, [data])

  /* ── Loading / Error ─────────────────────────────────── */
  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-24">
        <div className="h-6 w-6 animate-spin rounded-full border-2 border-primary/20 border-t-primary" />
      </div>
    )
  }

  if (error || !data) {
    return (
      <div className="flex flex-col items-center justify-center py-24 gap-3">
        <AlertTriangle className="h-8 w-8 text-amber-400" />
        <p className="text-sm text-muted-foreground">
          Failed to load system health. The nerve center endpoints may not be deployed yet.
        </p>
      </div>
    )
  }

  const tp = throughput ?? data.throughput
  const components = data.components

  return (
    <div className="flex flex-col gap-5 p-6">
      {/* ── Header ──────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center h-9 w-9 rounded-lg bg-primary/10 border border-primary/20">
            <Cpu size={18} className="text-primary" />
          </div>
          <div>
            <h1 className="text-lg font-semibold">System Nerve Center</h1>
            <p className="text-xs text-muted-foreground">Real-time pipeline health monitoring</p>
          </div>
          <button onClick={() => setShowGuide(!showGuide)} className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"><HelpCircle size={14} />{showGuide ? "Hide Guide" : "How does this work?"}</button>
        </div>
        <div className="flex items-center gap-3">
          {overallBadge(data.status)}
          <span className="text-[10px] text-muted-foreground font-mono tabular-nums">
            Uptime {formatUptime(tp.uptime_seconds)}
          </span>
        </div>
      </div>

      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5 space-y-3 text-sm text-muted-foreground">
          <h3 className="text-base font-semibold text-foreground">How does the System Nerve Center work?</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Pipeline Monitoring</p>
              <p>Fetches real-time health from <code className="text-xs bg-white/5 px-1 rounded">/api/nerve-center</code>. Tracks 10 components (Kafka, ClickHouse, PostgreSQL, Neo4j, Redis, Gateway, Backend, ML Engine, Trust Engine, Sensor). All components report status, latency, and throughput.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Interactive Topology</p>
              <p>The pipeline topology is a draggable, zoomable graph. Nodes represent components, edges show data flow with animated throughput indicators. Click any node to see detailed metrics, error rates, and recent issues.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Event Pipeline</p>
              <p>Tracks events/sec, total ingested, processed, and dropped counts. The pipeline flows: Sensor → Gateway → Kafka → ClickHouse (storage) + Backend (processing) → Alerts. Data types per pipeline stage are expandable.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Issue Detection</p>
              <p>Alert banners surface degraded or failing components instantly. Color-coded status: green (healthy), yellow (degraded), red (unhealthy). Uptime counter tracks continuous healthy operation time.</p>
            </div>
          </div>
        </div>
      )}

      {/* ── Alert Banner ────────────────────────────────── */}
      <AlertBanner issues={issues} />

      {/* ── Stats Row ───────────────────────────────────── */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
        <StatCard label="Events/sec" value={tp.events_per_sec.toFixed(1)} icon={Gauge} color="emerald" idle={tp.events_per_sec === 0} />
        <StatCard label="Ingested" value={tp.events_ingested.toLocaleString()} icon={ArrowRight} color="blue" idle={tp.events_ingested === 0} />
        <StatCard label="Processed" value={tp.events_processed.toLocaleString()} icon={CheckCircle2} color="cyan" idle={tp.events_processed === 0} />
        <StatCard label="Dropped" value={tp.events_dropped.toLocaleString()} icon={XCircle} color="red" idle={tp.events_dropped === 0} />
        <StatCard
          label="Components"
          value={`${Object.values(components).filter(c => c.status === "healthy").length}/${Object.keys(components).length}`}
          icon={Server}
          color="violet"
        />
        <StatCard
          label="Last Event"
          value={tp.last_event_at ? `${Math.round((now / 1000 - tp.last_event_at))}s ago` : "—"}
          icon={Clock}
          color="amber"
          idle={!tp.last_event_at}
        />
      </div>

      {/* ── Pipeline Data Intelligence ──────────────────── */}
      <PipelineDataTypes
        isIdle={tp.events_per_sec === 0 && tp.events_ingested === 0}
      />

      {/* ── Pipeline Diagram (zoomable) ──────────────────── */}
      <Card className="overflow-hidden">
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm">Pipeline Flow</CardTitle>
            <div className="flex items-center gap-1">
              <span className="text-[10px] text-muted-foreground mr-2">
                Drag nodes to rearrange · Scroll to zoom · Drag bg to pan
              </span>
              <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => setZoom(z => Math.min(MAX_ZOOM, z + 0.2))} title="Zoom In">
                <ZoomIn size={14} />
              </Button>
              <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => setZoom(z => Math.max(MIN_ZOOM, z - 0.2))} title="Zoom Out">
                <ZoomOut size={14} />
              </Button>
              <Button variant="ghost" size="icon" className="h-7 w-7" onClick={resetView} title="Reset View">
                <Maximize2 size={14} />
              </Button>
              <Button variant="ghost" size="icon" className="h-7 w-7" onClick={resetLayout} title="Reset Node Layout">
                <RotateCcw size={14} />
              </Button>
              <span className="text-[10px] text-muted-foreground font-mono ml-1 w-10 text-right">
                {Math.round(zoom * 100)}%
              </span>
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <div
            ref={svgContainerRef}
            className="overflow-hidden cursor-grab active:cursor-grabbing"
            onWheel={onWheel}
            onMouseDown={onMouseDown}
            onMouseMove={onMouseMove}
            onMouseUp={onMouseUp}
            onMouseLeave={onMouseUp}
          >
            <svg
              ref={svgRef}
              viewBox={`0 0 ${SVG_W} ${SVG_H}`}
              className="w-full h-auto min-h-[360px]"
              style={{
                background: "radial-gradient(ellipse at center, rgba(99,102,241,0.02), transparent 70%)",
                transform: `scale(${zoom}) translate(${pan.x / zoom}px, ${pan.y / zoom}px)`,
                transformOrigin: "center center",
                transition: isDragging ? "none" : "transform 0.15s ease-out",
              }}
            >
              {/* Grid pattern */}
              <defs>
                <pattern id="ncgrid" x="0" y="0" width="30" height="30" patternUnits="userSpaceOnUse">
                  <circle cx="15" cy="15" r="0.5" fill="currentColor" className="text-border/20" />
                </pattern>
              </defs>
              <rect width={SVG_W} height={SVG_H} fill="url(#ncgrid)" />

              {/* Pipe connections */}
              {data.connections.map((conn, i) => {
                const from = nodePositions[conn.from]
                const to = nodePositions[conn.to]
                if (!from || !to) return null
                const color = NODE_COLORS[conn.from] ?? "#6b7280"
                const targetHealth = components[healthKey(conn.to)]
                return (
                  <PipeConnection
                    key={`pipe-${conn.from}-${conn.to}`}
                    from={from}
                    to={to}
                    color={color}
                    targetStatus={targetHealth?.status}
                    idx={i}
                  />
                )
              })}

              {/* Connection labels */}
              {data.connections.map((conn) => {
                const from = nodePositions[conn.from]
                const to = nodePositions[conn.to]
                if (!from || !to) return null
                return (
                  <ConnectionLabel
                    key={`label-${conn.from}-${conn.to}`}
                    from={from}
                    to={to}
                    label={conn.label}
                  />
                )
              })}

              {/* Pipeline nodes (draggable) */}
              {data.pipeline.map((node) => {
                const pos = nodePositions[node.id]
                if (!pos) return null
                return (
                  <g
                    key={node.id}
                    onMouseDown={(e) => {
                      e.stopPropagation()
                      // Start node drag
                      nodeDragRef.current = {
                        nodeId: node.id,
                        startX: e.clientX,
                        startY: e.clientY,
                        origPosX: pos.x,
                        origPosY: pos.y,
                      }
                    }}
                    onClick={(e) => {
                      e.stopPropagation()
                      // Only select if not dragged (minimal movement)
                      if (nodeDragRef.current) {
                        const moved = Math.abs(e.clientX - nodeDragRef.current.startX) + Math.abs(e.clientY - nodeDragRef.current.startY)
                        if (moved > 5) return // was a drag, not a click
                      }
                      setSelected(selected === node.id ? null : node.id)
                    }}
                    className="cursor-grab active:cursor-grabbing"
                  >
                    <PipelineNodeSVG
                      node={node}
                      health={components[healthKey(node.id)]}
                      pos={pos}
                      isSelected={selected === node.id}
                    />
                  </g>
                )
              })}
            </svg>
          </div>
        </CardContent>
      </Card>

      {/* ── Component Details ───────────────────────────── */}
      {selected && (components[healthKey(selected)] || components[selected]) && (
        <ComponentDetail name={selected} health={components[healthKey(selected)] || components[selected]} />
      )}

      {/* ── Component Grid ──────────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
        {Object.entries(components).map(([name, health]) => (
          <Card
            key={name}
            className={`cursor-pointer transition-all hover:bg-white/[0.03] ${
              selected === name ? "ring-1 ring-primary/30" : ""
            } ${
              health.status === "unhealthy" || health.status === "error"
                ? "border-red-500/30 shadow-[0_0_12px_rgba(239,68,68,0.1)]"
                : health.status === "degraded"
                  ? "border-amber-500/20"
                  : ""
            }`}
            onClick={() => setSelected(selected === name ? null : name)}
          >
            <CardContent className="p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-medium capitalize">{name}</span>
                <span
                  className="h-2.5 w-2.5 rounded-full"
                  style={{ backgroundColor: statusColor(health.status) }}
                />
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-lg font-bold tabular-nums" style={{ color: statusColor(health.status) }}>
                  {health.latency_ms < 1 ? "<1" : health.latency_ms.toFixed(0)}
                  <span className="text-[10px] font-normal ml-0.5">ms</span>
                </span>
                {health.events_per_sec != null && (
                  <span className="text-[10px] text-muted-foreground">
                    {health.events_per_sec.toFixed(1)} evt/s
                  </span>
                )}
              </div>
              {health.error && (
                <p className="text-[9px] text-destructive mt-1 truncate">{health.error}</p>
              )}
              {health.diagnostic && !health.error && (
                <p className="text-[9px] text-amber-400/70 mt-1 truncate">{health.diagnostic}</p>
              )}
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  )
}

/* ── Pipeline Data Types component ─────────────────────── */

const PIPELINE_SEGMENTS: {
  from: string
  to: string
  icon: React.ElementType
  dataType: string
  description: string
  color: string
}[] = [
  {
    from: "Sensor",
    to: "Gateway",
    icon: Radio,
    dataType: "eBPF Telemetry",
    description: "Raw syscall traces, network captures, process events, file-system operations collected by kernel-level eBPF probes",
    color: "#3b82f6",
  },
  {
    from: "Gateway",
    to: "Kafka",
    icon: Globe,
    dataType: "Normalized Events (gRPC)",
    description: "Protobuf-encoded security events — validated, deduplicated, and enriched with agent metadata via gRPC stream",
    color: "#8b5cf6",
  },
  {
    from: "Kafka",
    to: "Backend",
    icon: Zap,
    dataType: "Event Batches",
    description: "Partitioned Kafka topics delivering ordered event batches for rule evaluation, ML scoring, and alert generation",
    color: "#f59e0b",
  },
  {
    from: "Backend",
    to: "Postgres",
    icon: Database,
    dataType: "Alert Records & Metadata",
    description: "Detection alerts, agent registrations, rule configurations, user sessions, and audit logs (structured relational data)",
    color: "#10b981",
  },
  {
    from: "Backend",
    to: "ClickHouse",
    icon: HardDrive,
    dataType: "Time-Series Telemetry",
    description: "High-volume event logs, behavioral metrics, and replay-ready timelines for threat investigation and analytics",
    color: "#ef4444",
  },
  {
    from: "Backend",
    to: "Neo4j",
    icon: Activity,
    dataType: "Graph Relationships",
    description: "Trust scores, attack-chain edges, lateral-movement paths, agent-to-agent relationships, and blast-radius topology",
    color: "#ec4899",
  },
  {
    from: "Backend",
    to: "Redis",
    icon: Cpu,
    dataType: "Cache & Real-time State",
    description: "Rule-engine state, session tokens, rate-limit counters, live dashboard subscriptions, and deduplication keys",
    color: "#f97316",
  },
]

function PipelineDataTypes({ isIdle }: { isIdle: boolean }) {
  const [expanded, setExpanded] = useState(isIdle) // auto-expand when idle

  return (
    <Card className="overflow-hidden relative group">
      {/* Top accent gradient */}
      <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-blue-500 via-violet-500 to-amber-500 opacity-60" />

      <CardHeader className="pb-1 pt-4 cursor-pointer" onClick={() => setExpanded(!expanded)}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="flex items-center justify-center h-7 w-7 rounded-md bg-indigo-500/10 border border-indigo-500/20">
              <Layers size={14} className="text-indigo-400" />
            </div>
            <div>
              <CardTitle className="text-sm">Pipeline Data Intelligence</CardTitle>
              <p className="text-[10px] text-muted-foreground">
                {isIdle
                  ? "Pipeline idle — see what data types each component handles"
                  : "Data types flowing through each pipeline segment"}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {isIdle && (
              <Badge className="bg-amber-500/15 text-amber-400 border-amber-500/25 text-[10px] gap-1">
                <Info size={10} /> Idle
              </Badge>
            )}
            <Button variant="ghost" size="icon" className="h-7 w-7">
              {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
            </Button>
          </div>
        </div>
      </CardHeader>

      {expanded && (
        <CardContent className="pt-2 pb-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            {PIPELINE_SEGMENTS.map((seg) => {
              const SegIcon = seg.icon
              return (
                <div
                  key={`${seg.from}-${seg.to}`}
                  className="flex items-start gap-3 rounded-lg border border-border/50 bg-card/40 p-3 hover:bg-card/70 transition-colors"
                >
                  {/* Connection icon */}
                  <div
                    className="flex items-center justify-center h-8 w-8 rounded-lg border flex-shrink-0 mt-0.5"
                    style={{
                      borderColor: `${seg.color}30`,
                      backgroundColor: `${seg.color}10`,
                      color: seg.color,
                    }}
                  >
                    <SegIcon size={14} />
                  </div>

                  <div className="flex-1 min-w-0">
                    {/* Route label */}
                    <div className="flex items-center gap-1.5 mb-0.5">
                      <span className="text-[10px] font-mono font-medium" style={{ color: seg.color }}>
                        {seg.from}
                      </span>
                      <ArrowRight size={10} className="text-muted-foreground/50" />
                      <span className="text-[10px] font-mono font-medium text-foreground/80">
                        {seg.to}
                      </span>
                    </div>
                    {/* Data type badge */}
                    <span
                      className="inline-block text-[10px] font-medium px-1.5 py-0.5 rounded-md mb-1"
                      style={{
                        backgroundColor: `${seg.color}15`,
                        color: seg.color,
                        border: `1px solid ${seg.color}25`,
                      }}
                    >
                      {seg.dataType}
                    </span>
                    {/* Description */}
                    <p className="text-[10px] leading-relaxed text-muted-foreground">
                      {seg.description}
                    </p>
                  </div>
                </div>
              )
            })}
          </div>
          {isIdle && (
            <div className="mt-3 flex items-start gap-2 rounded-md bg-indigo-500/5 border border-indigo-500/10 px-3 py-2">
              <Info size={12} className="text-indigo-400 mt-0.5 flex-shrink-0" />
              <p className="text-[10px] text-indigo-300/70 leading-relaxed">
                No events are currently flowing. Deploy sensors or start the agent simulator to see live throughput.
                The pipeline architecture above shows what each component processes when active.
              </p>
            </div>
          )}
        </CardContent>
      )}
    </Card>
  )
}

/* ── Small helpers ─────────────────────────────────────── */

function StatCard({
  label,
  value,
  icon: Icon,
  color,
  idle,
}: {
  label: string
  value: string
  icon: React.ElementType
  color: string
  idle?: boolean
}) {
  const colorMap: Record<string, string> = {
    emerald: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
    blue: "text-blue-400 bg-blue-500/10 border-blue-500/20",
    cyan: "text-cyan-400 bg-cyan-500/10 border-cyan-500/20",
    red: "text-red-400 bg-red-500/10 border-red-500/20",
    violet: "text-violet-400 bg-violet-500/10 border-violet-500/20",
    amber: "text-amber-400 bg-amber-500/10 border-amber-500/20",
  }
  const cls = colorMap[color] ?? colorMap.blue

  return (
    <Card className={idle ? "opacity-60" : ""}>
      <CardContent className="p-3 flex items-center gap-3">
        <div className={`rounded-lg p-2 border ${cls}`}>
          <Icon size={14} />
        </div>
        <div>
          <p className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</p>
          <div className="flex items-center gap-1.5">
            <p className="text-sm font-bold tabular-nums">{value}</p>
            {idle && <span className="text-[8px] text-muted-foreground/50 uppercase tracking-wider">idle</span>}
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`
  return `${Math.floor(seconds / 86400)}d ${Math.floor((seconds % 86400) / 3600)}h`
}
