// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — SCIM Token Management API hooks (TanStack Query).
 *
 * Create/list/revoke SCIM bearer tokens for IdP provisioning.
 * Backend: /api/v1/scim/tokens
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import apiClient from "./client"

/* ── Types ──────────────────────────────────────────────────────────── */

export interface SCIMToken {
  id: string
  tenant_id: string
  description: string
  is_active: boolean
  created_at: string
  expires_at: string
  token?: string // only returned on creation
}

export interface SCIMTokenCreate {
  description: string
  expires_in_days: number
}

/* ── Query Keys ─────────────────────────────────────────────────────── */

const SCIM_KEYS = {
  all: ["scim"] as const,
  tokens: () => [...SCIM_KEYS.all, "tokens"] as const,
}

/* ── Hooks ──────────────────────────────────────────────────────────── */

export function useSCIMTokens() {
  return useQuery({
    queryKey: SCIM_KEYS.tokens(),
    queryFn: async () => {
      const { data } = await apiClient.get<SCIMToken[]>("/scim/tokens")
      return data
    },
  })
}

export function useCreateSCIMToken() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (input: SCIMTokenCreate) => {
      const { data } = await apiClient.post<SCIMToken>("/scim/tokens", input)
      return data
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: SCIM_KEYS.all }),
  })
}

export function useRevokeSCIMToken() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (id: string) => {
      await apiClient.delete(`/scim/tokens/${id}`)
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: SCIM_KEYS.all }),
  })
}
