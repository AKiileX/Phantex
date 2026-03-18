// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Exemptions API hooks.
 *
 * TanStack Query hooks for exemption CRUD:
 *   - useExemptions: list all exemptions
 *   - useExemption: single exemption detail
 *   - useCreateExemption / useUpdateExemption / useDeleteExemption: mutations
 *
 * @module api/exemptions
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import apiClient from "@/api/client"
import type { Exemption, ExemptionCreate, ExemptionUpdate } from "@/types"

/* ── Query Keys ────────────────────────────────────────────────────────────── */

export const EXEMPTION_KEYS = {
  all: ["exemptions"] as const,
  list: (enabled?: boolean) => ["exemptions", "list", enabled] as const,
  detail: (id: string) => ["exemptions", "detail", id] as const,
}

/* ── Helpers ───────────────────────────────────────────────────────────────── */

function safePath(id: string): string {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
    throw new Error("Invalid exemption ID format")
  }
  return encodeURIComponent(id)
}

/* ── List Exemptions ───────────────────────────────────────────────────────── */

export interface ExemptionFilters {
  enabled?: boolean
}

export function useExemptions(filters?: ExemptionFilters) {
  return useQuery<Exemption[]>({
    queryKey: EXEMPTION_KEYS.list(filters?.enabled),
    queryFn: async () => {
      const { data } = await apiClient.get("/policies/exemptions", {
        params: filters,
      })
      return data
    },
    staleTime: 10_000,
  })
}

/* ── Single Exemption ──────────────────────────────────────────────────────── */

export function useExemption(id: string | undefined) {
  return useQuery<Exemption>({
    queryKey: EXEMPTION_KEYS.detail(id ?? ""),
    queryFn: async () => {
      const { data } = await apiClient.get(
        `/policies/exemptions/${safePath(id!)}`,
      )
      return data
    },
    enabled: !!id,
    staleTime: 15_000,
  })
}

/* ── Create Exemption ──────────────────────────────────────────────────────── */

export function useCreateExemption() {
  const qc = useQueryClient()
  return useMutation<Exemption, Error, ExemptionCreate>({
    mutationFn: async (input) => {
      const { data } = await apiClient.post("/policies/exemptions", input)
      return data
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: EXEMPTION_KEYS.all })
    },
  })
}

/* ── Update Exemption ──────────────────────────────────────────────────────── */

interface UpdateExemptionInput {
  id: string
  body: ExemptionUpdate
}

export function useUpdateExemption() {
  const qc = useQueryClient()
  return useMutation<Exemption, Error, UpdateExemptionInput>({
    mutationFn: async ({ id, body }) => {
      const { data } = await apiClient.patch(
        `/policies/exemptions/${safePath(id)}`,
        body,
      )
      return data
    },
    onSuccess: (_data, { id }) => {
      qc.invalidateQueries({ queryKey: EXEMPTION_KEYS.all })
      qc.invalidateQueries({ queryKey: EXEMPTION_KEYS.detail(id) })
    },
  })
}

/* ── Delete Exemption ──────────────────────────────────────────────────────── */

export function useDeleteExemption() {
  const qc = useQueryClient()
  return useMutation<void, Error, string>({
    mutationFn: async (id) => {
      await apiClient.delete(`/policies/exemptions/${safePath(id)}`)
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: EXEMPTION_KEYS.all })
    },
  })
}
