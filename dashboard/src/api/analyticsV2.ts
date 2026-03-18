// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Advanced Analytics API
 *
 * Wraps /api/v1/analytics/v2 endpoints with TanStack Query hooks.
 */

import { useQuery } from "@tanstack/react-query"
import apiClient from "./client"

export type ValidRange = "1h" | "6h" | "12h" | "24h" | "7d" | "30d" | "90d"

export interface KpiSummary {
  total_events: number
  total_alerts: number
  active_agents: number
  attack_classes: number
  critical: number
  high: number
  medium: number
  low: number
  bytes_sent: number
  bytes_recv: number
  range: string
}

export function useKpiSummary(range: ValidRange = "24h") {
  return useQuery({
    queryKey: ["analytics-v2", "kpi", range],
    queryFn: () => apiClient.get<KpiSummary>("/analytics/v2/kpi", { params: { range } }).then(r => r.data),
  })
}

export function useSeverityTrend(range: ValidRange = "30d") {
  return useQuery({
    queryKey: ["analytics-v2", "severity-trend", range],
    queryFn: () => apiClient.get<{ day: string; severity: string; count: number }[]>("/analytics/v2/severity-trend", { params: { range } }).then(r => r.data),
  })
}

export function useAttackTrend(range: ValidRange = "30d") {
  return useQuery({
    queryKey: ["analytics-v2", "attack-trend", range],
    queryFn: () => apiClient.get<{ day: string; attack_class: string; count: number; agents: number }[]>("/analytics/v2/attack-trend", { params: { range } }).then(r => r.data),
  })
}

export function useTopAgentsRisk(range: ValidRange = "7d", limit = 20) {
  return useQuery({
    queryKey: ["analytics-v2", "top-agents-risk", range, limit],
    queryFn: () => apiClient.get<{ agent_id: string; total_events: number; critical: number; high: number; medium: number; low: number; attacks: number }[]>("/analytics/v2/top-agents-risk", { params: { range, limit } }).then(r => r.data),
  })
}

export function useToolHeatmap(range: ValidRange = "7d") {
  return useQuery({
    queryKey: ["analytics-v2", "tool-heatmap", range],
    queryFn: () => apiClient.get<{ tool: string; hour: string; calls: number; duration_ms: number }[]>("/analytics/v2/tool-heatmap", { params: { range } }).then(r => r.data),
  })
}

export function useFrameworkBreakdown(range: ValidRange = "30d") {
  return useQuery({
    queryKey: ["analytics-v2", "framework", range],
    queryFn: () => apiClient.get<{ framework: string; count: number; agents: number }[]>("/analytics/v2/framework-breakdown", { params: { range } }).then(r => r.data),
  })
}

export function useDataVolumeTrend(range: ValidRange = "7d") {
  return useQuery({
    queryKey: ["analytics-v2", "data-volume", range],
    queryFn: () => apiClient.get<{ hour: string; events: number; bytes_sent: number; bytes_recv: number; agents: number }[]>("/analytics/v2/data-volume", { params: { range } }).then(r => r.data),
  })
}

export function useDrillDown(params: {
  dimension1: string
  dimension2?: string
  metric?: string
  range?: ValidRange
  limit?: number
  severity?: string
  attack_class?: string
  event_type?: string
}, enabled = true) {
  return useQuery({
    queryKey: ["analytics-v2", "drill-down", params],
    queryFn: () => apiClient.get("/analytics/v2/drill-down", { params }).then(r => r.data),
    enabled,
  })
}

/** Trigger authenticated CSV download */
export async function downloadCsv(queryType: string, range: ValidRange = "7d") {
  const resp = await apiClient.get("/analytics/v2/export/csv", {
    params: { query_type: queryType, range },
    responseType: "blob",
  })
  const url = URL.createObjectURL(resp.data)
  const a = document.createElement("a")
  a.href = url
  a.download = `phantex-analytics-${queryType}.csv`
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

/** Trigger authenticated PDF download */
export async function downloadPdf(range: ValidRange = "7d") {
  const resp = await apiClient.get("/analytics/v2/export/pdf", {
    params: { range },
    responseType: "blob",
  })
  const url = URL.createObjectURL(resp.data)
  const a = document.createElement("a")
  a.href = url
  a.download = "phantex-analytics-report.pdf"
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}
