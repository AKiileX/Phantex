// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — SSO Configuration API hooks (TanStack Query).
 *
 * CRUD for SSO configs (SAML + OIDC) scoped to admin tenant.
 * Backend: GET/POST/PUT/DELETE /api/v1/sso/configs
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import apiClient from "./client"

/* ── Types ──────────────────────────────────────────────────────────── */

export interface SSOConfig {
  id: string
  tenant_id: string
  provider_type: "saml" | "oidc"
  name: string
  is_enabled: boolean
  // SAML
  sp_entity_id?: string
  idp_entity_id?: string
  idp_sso_url?: string
  idp_slo_url?: string
  idp_certificate?: string
  // OIDC
  oidc_issuer?: string
  oidc_client_id?: string
  oidc_scopes?: string
  oidc_redirect_uri?: string
  // Common
  attribute_mapping?: Record<string, string>
  default_role?: string
  jit_provisioning?: boolean
  created_at: string
  updated_at: string
}

export interface SSOConfigCreate {
  provider_type: "saml" | "oidc"
  name: string
  is_enabled?: boolean
  sp_entity_id?: string
  idp_entity_id?: string
  idp_sso_url?: string
  idp_slo_url?: string
  idp_certificate?: string
  oidc_issuer?: string
  oidc_client_id?: string
  oidc_client_secret?: string
  oidc_scopes?: string
  oidc_redirect_uri?: string
  attribute_mapping?: Record<string, string>
  default_role?: string
  jit_provisioning?: boolean
}

export type SSOConfigUpdate = Partial<SSOConfigCreate>

/* ── Query Keys ─────────────────────────────────────────────────────── */

const SSO_KEYS = {
  all: ["sso"] as const,
  configs: () => [...SSO_KEYS.all, "configs"] as const,
}

/* ── Hooks ──────────────────────────────────────────────────────────── */

export function useSSOConfigs() {
  return useQuery({
    queryKey: SSO_KEYS.configs(),
    queryFn: async () => {
      const { data } = await apiClient.get<SSOConfig[]>("/sso/configs")
      return data
    },
  })
}

export function useCreateSSOConfig() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (input: SSOConfigCreate) => {
      const { data } = await apiClient.post<SSOConfig>("/sso/configs", input)
      return data
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: SSO_KEYS.all }),
  })
}

export function useUpdateSSOConfig() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ id, ...input }: SSOConfigUpdate & { id: string }) => {
      const { data } = await apiClient.put<SSOConfig>(`/sso/configs/${id}`, input)
      return data
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: SSO_KEYS.all }),
  })
}

export function useDeleteSSOConfig() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (id: string) => {
      await apiClient.delete(`/sso/configs/${id}`)
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: SSO_KEYS.all }),
  })
}
