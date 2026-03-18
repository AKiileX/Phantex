// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Tenant Management API hooks (TanStack Query).
 *
 * CRUD + lifecycle ops for platform-admin tenant management.
 * Backend: /api/v1/tenants
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import apiClient from "./client"

/* ── Types ──────────────────────────────────────────────────────────── */

export interface Tenant {
  id: string
  name: string
  slug: string
  plan: "community" | "starter" | "business" | "enterprise"
  settings: Record<string, unknown>
  is_active: boolean
  max_users: number
  max_agents: number
  max_events_per_day: number
  onboarded_at: string | null
  suspended_at: string | null
  created_at: string
  updated_at: string
}

export interface TenantUsage {
  tenant_id: string
  user_count: number
  agent_count: number
  events_today: number
  alerts_open: number
  storage_bytes: number
}

export interface TenantCreate {
  name: string
  slug: string
  plan?: string
  max_users?: number
  max_agents?: number
  max_events_per_day?: number
  admin_email: string
  admin_password: string
  admin_name?: string
}

export interface TenantUpdate {
  name?: string
  plan?: string
  settings?: Record<string, unknown>
  max_users?: number
  max_agents?: number
  max_events_per_day?: number
}

/* ── Query Keys ─────────────────────────────────────────────────────── */

const TENANT_KEYS = {
  all: ["tenants"] as const,
  list: () => [...TENANT_KEYS.all, "list"] as const,
  detail: (id: string) => [...TENANT_KEYS.all, "detail", id] as const,
  usage: (id: string) => [...TENANT_KEYS.all, "usage", id] as const,
}

/* ── Hooks ──────────────────────────────────────────────────────────── */

export function useTenants() {
  return useQuery({
    queryKey: TENANT_KEYS.list(),
    queryFn: async () => {
      const { data } = await apiClient.get<Tenant[]>("/tenants")
      return data
    },
  })
}

export function useTenant(id: string) {
  return useQuery({
    queryKey: TENANT_KEYS.detail(id),
    queryFn: async () => {
      const { data } = await apiClient.get<Tenant>(`/tenants/${id}`)
      return data
    },
    enabled: !!id,
  })
}

export function useTenantUsage(id: string) {
  return useQuery({
    queryKey: TENANT_KEYS.usage(id),
    queryFn: async () => {
      const { data } = await apiClient.get<TenantUsage>(`/tenants/${id}/usage`)
      return data
    },
    enabled: !!id,
    refetchInterval: 30_000,
  })
}

export function useCreateTenant() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (input: TenantCreate) => {
      const { data } = await apiClient.post<Tenant>("/tenants", input)
      return data
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: TENANT_KEYS.all }),
  })
}

export function useUpdateTenant() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ id, ...input }: TenantUpdate & { id: string }) => {
      const { data } = await apiClient.put<Tenant>(`/tenants/${id}`, input)
      return data
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: TENANT_KEYS.all }),
  })
}

export function useSuspendTenant() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (id: string) => {
      const { data } = await apiClient.post<Tenant>(`/tenants/${id}/suspend`)
      return data
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: TENANT_KEYS.all }),
  })
}

export function useActivateTenant() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (id: string) => {
      const { data } = await apiClient.post<Tenant>(`/tenants/${id}/activate`)
      return data
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: TENANT_KEYS.all }),
  })
}

export function useDeleteTenant() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (id: string) => {
      await apiClient.delete(`/tenants/${id}`)
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: TENANT_KEYS.all }),
  })
}
