// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — useAlertGrouping: client-side alert grouping by rule + agent.
 *
 * Groups alerts with the same rule_id + agent_id within a configurable
 * time window (default 5 minutes) into a single group row.
 *
 * Used by AlertsPage to reduce visual noise during alert floods.
 *
 * @module hooks/useAlertGrouping
 */

import { useMemo } from "react"
import type { AlertSummary, Severity } from "@/types"

/* ── Types ─────────────────────────────────────────────────────────────────── */

export interface AlertGroup {
  /** Unique group key (rule_id:agent_id:windowStart). */
  id: string
  /** The rule that fired. */
  rule_id: string | null
  /** The agent that triggered. */
  agent_id: string | null
  /** Title from the first alert in group. */
  title: string
  /** Highest severity in the group. */
  severity: Severity
  /** Status of the most recent alert. */
  status: string
  /** Number of alerts in this group. */
  count: number
  /** Timestamp of the first alert. */
  first_at: string
  /** Timestamp of the most recent alert. */
  last_at: string
  /** The individual alerts in this group. */
  alerts: AlertSummary[]
}

/* ── Severity ordering (for "highest in group") ───────────────────────────── */

const SEVERITY_ORDER: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
}

function higherSeverity(a: Severity, b: Severity): Severity {
  return (SEVERITY_ORDER[a] ?? 0) >= (SEVERITY_ORDER[b] ?? 0) ? a : b
}

/* ── Options ───────────────────────────────────────────────────────────────── */

interface UseAlertGroupingOptions {
  /** Time window in milliseconds for grouping. Default 300_000 (5 min). */
  windowMs?: number
  /** Whether grouping is enabled. Default true. */
  enabled?: boolean
}

/* ── Hook ──────────────────────────────────────────────────────────────────── */

/**
 * Groups a flat list of alerts into groups by rule_id + agent_id
 * within a time window. Returns groups sorted by most recent alert (desc).
 */
export function useAlertGrouping(
  alerts: AlertSummary[],
  options: UseAlertGroupingOptions = {},
) {
  const { windowMs = 300_000, enabled = true } = options

  const groups = useMemo(() => {
    if (!enabled) return null

    const groupMap = new Map<string, AlertGroup>()

    // Process alerts by time (newest first is typical, but handle any order)
    const sorted = [...alerts].sort(
      (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime(),
    )

    for (const alert of sorted) {
      const ts = new Date(alert.created_at).getTime()
      // Window start: quantize to windowMs intervals
      const windowStart = Math.floor(ts / windowMs) * windowMs
      const key = `${alert.rule_id ?? "unknown"}:${alert.agent_id ?? "unknown"}:${windowStart}`

      const existing = groupMap.get(key)
      if (existing) {
        existing.count += 1
        existing.severity = higherSeverity(existing.severity, alert.severity)
        existing.status = alert.status // most recent status
        existing.last_at = alert.created_at
        existing.alerts.push(alert)
      } else {
        groupMap.set(key, {
          id: key,
          rule_id: alert.rule_id,
          agent_id: alert.agent_id,
          title: alert.title,
          severity: alert.severity,
          status: alert.status,
          count: 1,
          first_at: alert.created_at,
          last_at: alert.created_at,
          alerts: [alert],
        })
      }
    }

    // Sort groups by most recent alert (descending)
    return Array.from(groupMap.values()).sort(
      (a, b) => new Date(b.last_at).getTime() - new Date(a.last_at).getTime(),
    )
  }, [alerts, windowMs, enabled])

  return {
    /** Grouped alerts (null if grouping is disabled). */
    groups,
    /** Total number of groups. */
    groupCount: groups?.length ?? 0,
    /** Whether grouping actually reduced the count. */
    isGrouped: groups != null && groups.length < alerts.length,
  }
}
