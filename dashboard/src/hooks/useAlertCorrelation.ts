// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — useAlertCorrelation: compute alert correlation edges.
 *
 * Builds a correlation graph from a flat list of alerts by linking
 * alerts that share attack characteristics within a time window:
 *   1. Same rule_id within 10-min window  → "same_rule" edge
 *   2. Same agent_id within 10-min window → "same_agent" edge
 *   3. Same event_type (attack class)     → "same_class" edge
 *
 * Used by the CorrelationPanel to render a force-directed mini-graph.
 *
 * Security:
 *   - All data already tenant-scoped (API returns only tenant's alerts)
 *   - Client-side cap: 500 nodes max (prevent browser DoS)
 *
 * @module hooks/useAlertCorrelation
 */

import { useMemo } from "react"
import type { AlertSummary, Severity } from "@/types"

/* ── Types ─────────────────────────────────────────────────────────────────── */

export type CorrelationReason = "same_rule" | "same_agent" | "same_class"

export interface CorrelationNode {
  id: string
  alert: AlertSummary
  /** x/y are set by the force simulation — start undefined. */
  x?: number
  y?: number
}

export interface CorrelationEdge {
  source: string
  target: string
  reason: CorrelationReason
}

export interface CorrelationGroup {
  /** Unique ID for this correlation cluster. */
  id: string
  /** Alert IDs in this cluster. */
  alertIds: string[]
  /** All alerts in this cluster. */
  alerts: AlertSummary[]
  /** Highest severity in the cluster. */
  severity: Severity
  /** Human-readable label. */
  label: string
  /** Number of correlation edges within the cluster. */
  edgeCount: number
}

export interface CorrelationResult {
  /** Graph nodes (capped at MAX_NODES). */
  nodes: CorrelationNode[]
  /** Graph edges. */
  edges: CorrelationEdge[]
  /** Connected clusters of correlated alerts. */
  groups: CorrelationGroup[]
  /** Total number of correlation edges found. */
  totalEdges: number
  /** Whether the result was truncated due to node cap. */
  truncated: boolean
}

/* ── Constants ─────────────────────────────────────────────────────────────── */

/** Maximum nodes rendered in the graph (security cap). */
const MAX_NODES = 500

/** Time window for temporal correlation (10 minutes). */
const CORRELATION_WINDOW_MS = 10 * 60 * 1000

const SEVERITY_ORDER: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
}

/* ── Helpers ───────────────────────────────────────────────────────────────── */

function higherSev(a: Severity, b: Severity): Severity {
  return (SEVERITY_ORDER[a] ?? 0) >= (SEVERITY_ORDER[b] ?? 0) ? a : b
}

/**
 * Union-Find for building connected components.
 */
class UnionFind {
  private parent: Map<string, string> = new Map()
  private rank: Map<string, number> = new Map()

  find(x: string): string {
    if (!this.parent.has(x)) {
      this.parent.set(x, x)
      this.rank.set(x, 0)
    }
    let root = x
    while (this.parent.get(root) !== root) {
      root = this.parent.get(root)!
    }
    // Path compression
    let curr = x
    while (curr !== root) {
      const next = this.parent.get(curr)!
      this.parent.set(curr, root)
      curr = next
    }
    return root
  }

  union(a: string, b: string): void {
    const ra = this.find(a)
    const rb = this.find(b)
    if (ra === rb) return
    const rankA = this.rank.get(ra) ?? 0
    const rankB = this.rank.get(rb) ?? 0
    if (rankA < rankB) {
      this.parent.set(ra, rb)
    } else if (rankA > rankB) {
      this.parent.set(rb, ra)
    } else {
      this.parent.set(rb, ra)
      this.rank.set(ra, rankA + 1)
    }
  }

  components(): Map<string, string[]> {
    const groups = new Map<string, string[]>()
    for (const key of this.parent.keys()) {
      const root = this.find(key)
      const arr = groups.get(root) ?? []
      arr.push(key)
      groups.set(root, arr)
    }
    return groups
  }
}

/* ── Core correlation logic ────────────────────────────────────────────────── */

function computeCorrelation(alerts: AlertSummary[]): CorrelationResult {
  // Cap input
  const capped = alerts.length > MAX_NODES ? alerts.slice(0, MAX_NODES) : alerts
  const truncated = alerts.length > MAX_NODES

  const edges: CorrelationEdge[] = []
  const edgeSet = new Set<string>()

  const addEdge = (a: string, b: string, reason: CorrelationReason) => {
    const key = a < b ? `${a}:${b}:${reason}` : `${b}:${a}:${reason}`
    if (edgeSet.has(key)) return
    edgeSet.add(key)
    edges.push({ source: a, target: b, reason })
  }

  // Sort by time for windowed comparison
  const sorted = [...capped].sort(
    (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime(),
  )

  // 1. Same rule_id within time window
  const ruleGroups = new Map<string, AlertSummary[]>()
  for (const alert of sorted) {
    if (!alert.rule_id) continue
    const arr = ruleGroups.get(alert.rule_id) ?? []
    arr.push(alert)
    ruleGroups.set(alert.rule_id, arr)
  }
  for (const group of ruleGroups.values()) {
    for (let i = 0; i < group.length; i++) {
      for (let j = i + 1; j < group.length; j++) {
        const dt = Math.abs(
          new Date(group[j].created_at).getTime() -
          new Date(group[i].created_at).getTime(),
        )
        if (dt <= CORRELATION_WINDOW_MS) {
          addEdge(group[i].id, group[j].id, "same_rule")
        }
      }
    }
  }

  // 2. Same agent_id within time window (different rules → coordinated attack)
  const agentGroups = new Map<string, AlertSummary[]>()
  for (const alert of sorted) {
    if (!alert.agent_id) continue
    const arr = agentGroups.get(alert.agent_id) ?? []
    arr.push(alert)
    agentGroups.set(alert.agent_id, arr)
  }
  for (const group of agentGroups.values()) {
    for (let i = 0; i < group.length; i++) {
      for (let j = i + 1; j < group.length; j++) {
        if (group[i].rule_id === group[j].rule_id) continue // already covered by rule correlation
        const dt = Math.abs(
          new Date(group[j].created_at).getTime() -
          new Date(group[i].created_at).getTime(),
        )
        if (dt <= CORRELATION_WINDOW_MS) {
          addEdge(group[i].id, group[j].id, "same_agent")
        }
      }
    }
  }

  // Build connected components via Union-Find
  const uf = new UnionFind()
  for (const alert of capped) uf.find(alert.id) // ensure all nodes exist
  for (const edge of edges) {
    uf.union(edge.source, edge.target)
  }

  const alertMap = new Map<string, AlertSummary>()
  for (const alert of capped) alertMap.set(alert.id, alert)

  const components = uf.components()
  const groups: CorrelationGroup[] = []

  for (const [root, ids] of components) {
    // Only include groups with correlations (> 1 alert)
    if (ids.length < 2) continue

    const groupAlerts = ids
      .map((id) => alertMap.get(id)!)
      .filter(Boolean)
      .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())

    let severity: Severity = "info"
    for (const a of groupAlerts) severity = higherSev(severity, a.severity)

    // Count edges within this component
    const idSet = new Set(ids)
    const groupEdgeCount = edges.filter(
      (e) => idSet.has(e.source) && idSet.has(e.target),
    ).length

    // Build label from the most common rule
    const ruleCounts = new Map<string, number>()
    for (const a of groupAlerts) {
      if (a.rule_id) {
        ruleCounts.set(a.rule_id, (ruleCounts.get(a.rule_id) ?? 0) + 1)
      }
    }
    const topRule = [...ruleCounts.entries()].sort((a, b) => b[1] - a[1])[0]
    const label = topRule
      ? `${topRule[0]} (${groupAlerts.length} alerts)`
      : `${groupAlerts.length} correlated alerts`

    groups.push({
      id: root,
      alertIds: ids,
      alerts: groupAlerts,
      severity,
      label,
      edgeCount: groupEdgeCount,
    })
  }

  // Sort groups: most alerts first, then highest severity
  groups.sort((a, b) => {
    const sevDiff = (SEVERITY_ORDER[b.severity] ?? 0) - (SEVERITY_ORDER[a.severity] ?? 0)
    if (sevDiff !== 0) return sevDiff
    return b.alerts.length - a.alerts.length
  })

  const nodes: CorrelationNode[] = capped.map((alert) => ({
    id: alert.id,
    alert,
  }))

  return {
    nodes,
    edges,
    groups,
    totalEdges: edges.length,
    truncated,
  }
}

/* ── Hook ──────────────────────────────────────────────────────────────────── */

interface UseAlertCorrelationOptions {
  /** Whether correlation computation is enabled. Default true. */
  enabled?: boolean
}

/**
 * Computes a correlation graph from a list of alerts.
 *
 * Returns nodes, edges, and connected groups for rendering a force-directed
 * graph and a correlation panel. Memoized — only recomputes when alerts change.
 */
export function useAlertCorrelation(
  alerts: AlertSummary[],
  options: UseAlertCorrelationOptions = {},
) {
  const { enabled = true } = options

  const result = useMemo<CorrelationResult | null>(() => {
    if (!enabled || alerts.length === 0) return null
    return computeCorrelation(alerts)
  }, [alerts, enabled])

  return {
    /** Full correlation result (null if disabled or no alerts). */
    correlation: result,
    /** Correlated groups (clusters of 2+ linked alerts). */
    groups: result?.groups ?? [],
    /** Whether any correlations were found. */
    hasCorrelations: (result?.groups.length ?? 0) > 0,
    /** Total edges in the graph. */
    edgeCount: result?.totalEdges ?? 0,
  }
}
