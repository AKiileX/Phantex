// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Policy API hooks (O5).
 *
 * TanStack Query hooks for the policy CRUD API:
 *   - usePolicies: list with pagination
 *   - usePolicy: single policy detail
 *   - useCreatePolicy / useUpdatePolicy / useDeletePolicy: mutations
 *   - useValidatePolicy: live YAML/JSON validation
 *   - useApplyPolicy: apply policy to agents
 *   - usePolicyVersions: version history
 *
 * All mutations invalidate the policy list cache on success.
 *
 * @module api/policies
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import apiClient from "@/api/client"
import type {
  Policy,
  PolicyDefinition,
  PolicyValidationResult,
  PolicyVersion,
  PaginatedResponse,
} from "@/types"

/* ── Query Keys ────────────────────────────────────────────────────────────── */

const KEYS = {
  all: ["policies"] as const,
  list: (page: number, pageSize: number, enabledOnly: boolean) =>
    ["policies", "list", page, pageSize, enabledOnly] as const,
  detail: (id: string) => ["policies", "detail", id] as const,
  versions: (id: string) => ["policies", "versions", id] as const,
}

/* ── Helpers ───────────────────────────────────────────────────────────────── */

/** Defence-in-depth: UUID-only path segment. */
function safePath(id: string): string {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
    throw new Error("Invalid policy ID format")
  }
  return encodeURIComponent(id)
}

/* ── List Policies ─────────────────────────────────────────────────────────── */

export function usePolicies(
  { page = 1, pageSize = 20, enabledOnly = false } = {},
  enabled = true,
) {
  return useQuery<PaginatedResponse<Policy>>({
    queryKey: KEYS.list(page, pageSize, enabledOnly),
    queryFn: async () => {
      const { data } = await apiClient.get("/policies", {
        params: { page, page_size: pageSize, enabled_only: enabledOnly },
      })
      return data
    },
    enabled,
    staleTime: 10_000,
  })
}

/* ── Single Policy ─────────────────────────────────────────────────────────── */

export function usePolicy(id: string | undefined, enabled = true) {
  return useQuery<Policy>({
    queryKey: KEYS.detail(id ?? ""),
    queryFn: async () => {
      const { data } = await apiClient.get(`/policies/${safePath(id!)}`)
      return data
    },
    enabled: !!id && enabled,
    staleTime: 15_000,
  })
}

/* ── Create Policy ─────────────────────────────────────────────────────────── */

interface CreatePolicyInput {
  name: string
  description?: string
  enabled?: boolean
  definition: PolicyDefinition
}

export function useCreatePolicy() {
  const qc = useQueryClient()
  return useMutation<Policy, Error, CreatePolicyInput>({
    mutationFn: async (input) => {
      const { data } = await apiClient.post("/policies", input)
      return data
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: KEYS.all })
    },
  })
}

/* ── Update Policy ─────────────────────────────────────────────────────────── */

interface UpdatePolicyInput {
  id: string
  name?: string
  description?: string
  enabled?: boolean
  definition?: PolicyDefinition
  change_summary?: string
}

export function useUpdatePolicy() {
  const qc = useQueryClient()
  return useMutation<Policy, Error, UpdatePolicyInput>({
    mutationFn: async ({ id, ...body }) => {
      const { data } = await apiClient.put(`/policies/${safePath(id)}`, body)
      return data
    },
    onSuccess: (_data, vars) => {
      qc.invalidateQueries({ queryKey: KEYS.all })
      qc.invalidateQueries({ queryKey: KEYS.detail(vars.id) })
      qc.invalidateQueries({ queryKey: KEYS.versions(vars.id) })
    },
  })
}

/* ── Delete Policy ─────────────────────────────────────────────────────────── */

export function useDeletePolicy() {
  const qc = useQueryClient()
  return useMutation<void, Error, string>({
    mutationFn: async (id) => {
      await apiClient.delete(`/policies/${safePath(id)}`)
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: KEYS.all })
    },
  })
}

/* ── Validate Policy ───────────────────────────────────────────────────────── */

interface ValidateInput {
  yaml_content?: string
  json_content?: PolicyDefinition
}

export function useValidatePolicy() {
  return useMutation<PolicyValidationResult, Error, ValidateInput>({
    mutationFn: async (input) => {
      const { data } = await apiClient.post("/policies/validate", input)
      return data
    },
  })
}

/* ── Apply Policy ──────────────────────────────────────────────────────────── */

interface ApplyResult {
  status: string
  policy_id: string
  policy_name: string
  rules_count: number
  scope: { agent_tags: string[]; frameworks: string[] }
}

export function useApplyPolicy() {
  return useMutation<ApplyResult, Error, string>({
    mutationFn: async (id) => {
      const { data } = await apiClient.post(`/policies/${safePath(id)}/apply`)
      return data
    },
  })
}

/* ── Policy Versions ───────────────────────────────────────────────────────── */

export function usePolicyVersions(policyId: string | undefined, enabled = true) {
  return useQuery<PolicyVersion[]>({
    queryKey: KEYS.versions(policyId ?? ""),
    queryFn: async () => {
      const { data } = await apiClient.get(
        `/policies/${safePath(policyId!)}/versions`,
      )
      return data
    },
    enabled: !!policyId && enabled,
    staleTime: 30_000,
  })
}
