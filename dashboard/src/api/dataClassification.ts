// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Data Classification API hooks.
 *
 * Wraps /api/v1/data-classification endpoints with TanStack Query hooks.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import apiClient from "./client"

/* ── Types ──────────────────────────────────────────────── */

export interface ClassificationMatch {
  data_type: string
  redacted_value: string
  offset: number
  length: number
  confidence: number
  context: string
}

export interface ClassifyResult {
  labels: string[]
  matches: ClassificationMatch[]
  sensitivity: string
  compliance_tags: string[]
  processing_time_ms: number
}

export interface RedactToken {
  token: string
  data_type: string
  offset: number
  length: number
  encrypted_value: string
}

export interface RedactResult {
  redacted_text: string
  token_count: number
  tokens: RedactToken[]
  sensitivity: string
  labels: string[]
  compliance_tags: string[]
}

export interface ClassificationStats {
  tenant_id: string
  total_events_classified: number
  by_label: Record<string, number>
  by_sensitivity: Record<string, number>
  compliance_coverage: Record<string, number>
  avg_latency_ms: number
}

export interface FlowEntry {
  agent_id: string
  data_types: string[]
  sensitivity: string
  destinations: string[]
  event_count: number
}

export interface FlowMapResult {
  flows: FlowEntry[]
  total_agents: number
  total_events: number
}

/* ── Hooks ──────────────────────────────────────────────── */

export function useClassificationStats() {
  return useQuery({
    queryKey: ["data-classification", "stats"],
    queryFn: () =>
      apiClient.get<ClassificationStats>("/data-classification/stats").then(r => r.data),
    staleTime: 30_000,
  })
}

export function useFlowMap() {
  return useQuery({
    queryKey: ["data-classification", "flow-map"],
    queryFn: () =>
      apiClient.get<FlowMapResult>("/data-classification/flow-map").then(r => r.data),
    staleTime: 30_000,
  })
}

export function useClassifyText() {
  return useMutation({
    mutationFn: (payload: { text: string }) =>
      apiClient.post<ClassifyResult>("/data-classification/classify", payload).then(r => r.data),
  })
}

export function useRedactText() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (payload: { text: string }) =>
      apiClient.post<RedactResult>("/data-classification/redact", payload).then(r => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["data-classification", "stats"] })
    },
  })
}
