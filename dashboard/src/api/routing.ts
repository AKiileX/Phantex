// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Alert Routing API hooks.
 *
 * TanStack Query hooks for routing rule CRUD + simulation:
 *   - useRoutingRules / useRoutingRule: queries
 *   - useCreateRoutingRule / useUpdateRoutingRule / useDeleteRoutingRule: mutations
 *   - useSimulateRouting: simulation mutation
 *
 * @module api/routing
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import apiClient from "@/api/client"
import type {
  RoutingRule,
  RoutingRuleCreate,
  RoutingRuleUpdate,
  RoutingSimulationRequest,
  RoutingSimulationResult,
} from "@/types"

/* ── Query Keys ────────────────────────────────────────────────────────────── */

export const ROUTING_KEYS = {
  all: ["routing-rules"] as const,
  list: (enabled?: boolean) => ["routing-rules", "list", enabled] as const,
  detail: (id: string) => ["routing-rules", "detail", id] as const,
}

/* ── Helpers ───────────────────────────────────────────────────────────────── */

function safePath(id: string): string {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
    throw new Error("Invalid routing rule ID format")
  }
  return encodeURIComponent(id)
}

/* ── List Routing Rules ────────────────────────────────────────────────────── */

export interface RoutingFilters {
  enabled?: boolean
}

export function useRoutingRules(filters?: RoutingFilters) {
  return useQuery<RoutingRule[]>({
    queryKey: ROUTING_KEYS.list(filters?.enabled),
    queryFn: async () => {
      const { data } = await apiClient.get("/policies/routing", {
        params: filters,
      })
      return data
    },
    staleTime: 10_000,
  })
}

/* ── Single Routing Rule ───────────────────────────────────────────────────── */

export function useRoutingRule(id: string | undefined) {
  return useQuery<RoutingRule>({
    queryKey: ROUTING_KEYS.detail(id ?? ""),
    queryFn: async () => {
      const { data } = await apiClient.get(
        `/policies/routing/${safePath(id!)}`,
      )
      return data
    },
    enabled: !!id,
    staleTime: 15_000,
  })
}

/* ── Create Routing Rule ───────────────────────────────────────────────────── */

export function useCreateRoutingRule() {
  const qc = useQueryClient()
  return useMutation<RoutingRule, Error, RoutingRuleCreate>({
    mutationFn: async (input) => {
      const { data } = await apiClient.post("/policies/routing", input)
      return data
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ROUTING_KEYS.all })
    },
  })
}

/* ── Update Routing Rule ───────────────────────────────────────────────────── */

interface UpdateRoutingInput {
  id: string
  body: RoutingRuleUpdate
}

export function useUpdateRoutingRule() {
  const qc = useQueryClient()
  return useMutation<RoutingRule, Error, UpdateRoutingInput>({
    mutationFn: async ({ id, body }) => {
      const { data } = await apiClient.put(
        `/policies/routing/${safePath(id)}`,
        body,
      )
      return data
    },
    onSuccess: (_data, { id }) => {
      qc.invalidateQueries({ queryKey: ROUTING_KEYS.all })
      qc.invalidateQueries({ queryKey: ROUTING_KEYS.detail(id) })
    },
  })
}

/* ── Delete Routing Rule ───────────────────────────────────────────────────── */

export function useDeleteRoutingRule() {
  const qc = useQueryClient()
  return useMutation<void, Error, string>({
    mutationFn: async (id) => {
      await apiClient.delete(`/policies/routing/${safePath(id)}`)
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ROUTING_KEYS.all })
    },
  })
}

/* ── Simulate Routing ──────────────────────────────────────────────────────── */

export function useSimulateRouting() {
  return useMutation<RoutingSimulationResult, Error, RoutingSimulationRequest>({
    mutationFn: async (input) => {
      const { data } = await apiClient.post("/policies/routing/simulate", input)
      return data
    },
  })
}
