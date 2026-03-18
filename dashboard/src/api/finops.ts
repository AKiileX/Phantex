// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — FinOps API hooks.
 *
 * Wraps /api/v1/finops endpoints with TanStack Query hooks.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import apiClient from "./client"

/* ── Types ──────────────────────────────────────────────── */

export interface CostSummary {
  total_cost_usd: number
  total_tokens: number
  total_requests: number
  unique_agents: number
  range: string
}

export interface AgentCost {
  agent_id: string
  cost_usd: number
  total_tokens: number
  requests: number
}

export interface ModelCost {
  provider: string
  model: string
  cost_usd: number
  total_tokens: number
  requests: number
}

export interface CostTrendPoint {
  hour: string
  cost_usd: number
  total_tokens: number
  requests: number
}

export interface CostProjection {
  last_7d_usd: number
  projected_monthly_usd: number
}

export interface CostAnomaly {
  agent_id: string
  anomaly_type: string
  severity: string
  description: string
  cost_usd: number
  baseline_usd: number
  deviation_factor: number
  correlated_alert_id: string | null
  timestamp: string
}

export interface BudgetConfig {
  id: string
  scope: string
  scope_id: string
  budget_usd: number
  hard_cap: boolean
  enabled: boolean
}

export interface BudgetStatus {
  id: string
  scope: string
  scope_id: string
  budget_usd: number
  spent_usd: number
  pct_used: number
  remaining_usd: number
  breached_thresholds: number[]
  capped: boolean
}

/* ── Hooks ──────────────────────────────────────────────── */

export function useCostSummary(range = "24h") {
  return useQuery({
    queryKey: ["finops", "summary", range],
    queryFn: () =>
      apiClient.get<CostSummary>("/finops/summary", { params: { range } }).then(r => r.data),
    staleTime: 30_000,
  })
}

export function useCostByAgent(range = "24h") {
  return useQuery({
    queryKey: ["finops", "by-agent", range],
    queryFn: () =>
      apiClient.get<AgentCost[]>("/finops/by-agent", { params: { range } }).then(r => r.data),
    staleTime: 30_000,
  })
}

export function useCostByModel(range = "24h") {
  return useQuery({
    queryKey: ["finops", "by-model", range],
    queryFn: () =>
      apiClient.get<ModelCost[]>("/finops/by-model", { params: { range } }).then(r => r.data),
    staleTime: 30_000,
  })
}

export function useCostTrend(range = "7d") {
  return useQuery({
    queryKey: ["finops", "trend", range],
    queryFn: () =>
      apiClient.get<CostTrendPoint[]>("/finops/trend", { params: { range } }).then(r => r.data),
    staleTime: 30_000,
  })
}

export function useCostProjection() {
  return useQuery({
    queryKey: ["finops", "projection"],
    queryFn: () =>
      apiClient.get<CostProjection>("/finops/projection").then(r => r.data),
    staleTime: 60_000,
  })
}

export function useCostAnomalies(hours = 24) {
  return useQuery({
    queryKey: ["finops", "anomalies", hours],
    queryFn: () =>
      apiClient.get<CostAnomaly[]>("/finops/anomalies", { params: { hours } }).then(r => r.data),
    staleTime: 30_000,
  })
}

export function useRunAnomalyScan() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () =>
      apiClient.post<{ anomalies_found: number; anomalies: CostAnomaly[] }>("/finops/anomalies/scan").then(r => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["finops", "anomalies"] })
    },
  })
}

export function useBudgets() {
  return useQuery({
    queryKey: ["finops", "budgets"],
    queryFn: () =>
      apiClient.get<BudgetConfig[]>("/finops/budgets").then(r => r.data),
    staleTime: 30_000,
  })
}

export function useCreateBudget() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (payload: { scope: string; scope_id: string; budget_usd: number; hard_cap: boolean }) =>
      apiClient.post("/finops/budgets", payload).then(r => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["finops", "budgets"] })
    },
  })
}

export function useBudgetStatus() {
  return useQuery({
    queryKey: ["finops", "budgets", "status"],
    queryFn: () =>
      apiClient.get<BudgetStatus[]>("/finops/budgets/status").then(r => r.data),
    staleTime: 30_000,
  })
}

/** Trigger authenticated FinOps CSV download */
export async function downloadFinopsCsv(queryType: string, range = "24h") {
  const resp = await apiClient.get("/finops/export/csv", {
    params: { query_type: queryType, range },
    responseType: "blob",
  })
  const url = URL.createObjectURL(resp.data)
  const a = document.createElement("a")
  a.href = url
  a.download = `phantex-finops-${queryType}.csv`
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

/** Trigger authenticated FinOps PDF download */
export async function downloadFinopsPdf(range = "24h") {
  const resp = await apiClient.get("/finops/export/pdf", {
    params: { range },
    responseType: "blob",
  })
  const url = URL.createObjectURL(resp.data)
  const a = document.createElement("a")
  a.href = url
  a.download = "phantex-finops-report.pdf"
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}
