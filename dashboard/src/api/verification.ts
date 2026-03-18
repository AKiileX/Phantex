// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Formal Verification API hooks
 *
 * Wraps /api/v1/verification endpoints with TanStack Query hooks.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import apiClient from "./client"

/* ── Types ──────────────────────────────────────────────── */

export interface SpecInfo {
  tool: string
  name: string
  file: string
  properties: string[]
  description: string
}

export interface Z3Check {
  name: string
  property: string
  result: string
  elapsed_ms: number
  details: string
}

export interface Z3RunResult {
  spec: string
  tool: string
  passed: boolean
  checks_total: number
  checks_passed: number
  elapsed_ms: number
  details: Z3Check[]
  error: string | null
}

/* ── Hooks ──────────────────────────────────────────────── */

export function useVerificationSpecs() {
  return useQuery({
    queryKey: ["verification", "specs"],
    queryFn: () =>
      apiClient.get<{ specs: SpecInfo[] }>("/verification/specs").then(r => r.data.specs),
    staleTime: 60_000,
  })
}

export function useVerificationResults() {
  return useQuery({
    queryKey: ["verification", "results"],
    queryFn: () =>
      apiClient.get<{ results: Record<string, unknown> }>("/verification/results").then(r => r.data.results),
    staleTime: 30_000,
  })
}

export function useRunZ3() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () =>
      apiClient.post<Z3RunResult>("/verification/run/z3").then(r => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["verification", "results"] })
    },
  })
}

export function useSpecSource(specName: string | null) {
  return useQuery({
    queryKey: ["verification", "spec-source", specName],
    queryFn: () =>
      apiClient
        .get<{ spec_name: string; source: string }>(`/verification/spec/${specName}/source`)
        .then(r => r.data.source),
    enabled: !!specName,
    staleTime: 5 * 60_000,
  })
}
