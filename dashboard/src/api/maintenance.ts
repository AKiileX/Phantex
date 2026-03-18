// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Maintenance Windows API hooks.
 *
 * TanStack Query hooks for maintenance window CRUD + force-end:
 *   - useMaintenanceWindows / useMaintenanceWindow: queries
 *   - useCreateMaintenanceWindow / useUpdateMaintenanceWindow / useDeleteMaintenanceWindow: mutations
 *   - useForceEndMaintenanceWindow: admin-only force-end mutation
 *
 * @module api/maintenance
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import apiClient from "@/api/client"
import type {
  MaintenanceWindow,
  MaintenanceWindowCreate,
  MaintenanceWindowUpdate,
} from "@/types"

/* ── Query Keys ────────────────────────────────────────────────────────────── */

export const MAINTENANCE_KEYS = {
  all: ["maintenance-windows"] as const,
  list: (enabled?: boolean) => ["maintenance-windows", "list", enabled] as const,
  detail: (id: string) => ["maintenance-windows", "detail", id] as const,
}

/* ── Helpers ───────────────────────────────────────────────────────────────── */

function safePath(id: string): string {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
    throw new Error("Invalid maintenance window ID format")
  }
  return encodeURIComponent(id)
}

/* ── List Maintenance Windows ──────────────────────────────────────────────── */

export interface MaintenanceFilters {
  enabled?: boolean
}

export function useMaintenanceWindows(filters?: MaintenanceFilters) {
  return useQuery<MaintenanceWindow[]>({
    queryKey: MAINTENANCE_KEYS.list(filters?.enabled),
    queryFn: async () => {
      const { data } = await apiClient.get("/policies/maintenance-windows", {
        params: filters,
      })
      return data
    },
    staleTime: 10_000,
  })
}

/* ── Single Maintenance Window ─────────────────────────────────────────────── */

export function useMaintenanceWindow(id: string | undefined) {
  return useQuery<MaintenanceWindow>({
    queryKey: MAINTENANCE_KEYS.detail(id ?? ""),
    queryFn: async () => {
      const { data } = await apiClient.get(
        `/policies/maintenance-windows/${safePath(id!)}`,
      )
      return data
    },
    enabled: !!id,
    staleTime: 15_000,
  })
}

/* ── Create Maintenance Window ─────────────────────────────────────────────── */

export function useCreateMaintenanceWindow() {
  const qc = useQueryClient()
  return useMutation<MaintenanceWindow, Error, MaintenanceWindowCreate>({
    mutationFn: async (input) => {
      const { data } = await apiClient.post(
        "/policies/maintenance-windows",
        input,
      )
      return data
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: MAINTENANCE_KEYS.all })
    },
  })
}

/* ── Update Maintenance Window ─────────────────────────────────────────────── */

interface UpdateMaintenanceInput {
  id: string
  body: MaintenanceWindowUpdate
}

export function useUpdateMaintenanceWindow() {
  const qc = useQueryClient()
  return useMutation<MaintenanceWindow, Error, UpdateMaintenanceInput>({
    mutationFn: async ({ id, body }) => {
      const { data } = await apiClient.put(
        `/policies/maintenance-windows/${safePath(id)}`,
        body,
      )
      return data
    },
    onSuccess: (_data, { id }) => {
      qc.invalidateQueries({ queryKey: MAINTENANCE_KEYS.all })
      qc.invalidateQueries({ queryKey: MAINTENANCE_KEYS.detail(id) })
    },
  })
}

/* ── Delete Maintenance Window ─────────────────────────────────────────────── */

export function useDeleteMaintenanceWindow() {
  const qc = useQueryClient()
  return useMutation<void, Error, string>({
    mutationFn: async (id) => {
      await apiClient.delete(`/policies/maintenance-windows/${safePath(id)}`)
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: MAINTENANCE_KEYS.all })
    },
  })
}

/* ── Force-End Maintenance Window (admin only) ─────────────────────────────── */

export function useForceEndMaintenanceWindow() {
  const qc = useQueryClient()
  return useMutation<MaintenanceWindow, Error, string>({
    mutationFn: async (id) => {
      const { data } = await apiClient.post(
        `/policies/maintenance-windows/${safePath(id)}/force-end`,
      )
      return data
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: MAINTENANCE_KEYS.all })
    },
  })
}
