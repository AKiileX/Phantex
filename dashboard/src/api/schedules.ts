// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — PDR Export Schedule API hooks.
 *
 * TanStack Query hooks for scheduled export CRUD + run-now:
 *   - useExportSchedules: list all schedules
 *   - useCreateExportSchedule: create a new schedule
 *   - useUpdateExportSchedule: update schedule settings
 *   - useDeleteExportSchedule: delete a schedule
 *   - useRunExportSchedule: trigger immediate execution
 *
 * @module api/schedules
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import apiClient from "@/api/client"
import type {
  PDRScheduleListResponse,
  PDRScheduleResponse,
  PDRScheduleCreate,
  PDRScheduleUpdate,
} from "@/types"

/* ── Query Keys ────────────────────────────────────────────────────────────── */

export const SCHEDULE_KEYS = {
  all: ["export-schedules"] as const,
  list: () => ["export-schedules", "list"] as const,
  detail: (id: string) => ["export-schedules", "detail", id] as const,
}

/* ── Validators ────────────────────────────────────────────────────────────── */

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

function safeId(id: string): string {
  if (!UUID_RE.test(id)) {
    throw new Error("Invalid schedule ID format")
  }
  return encodeURIComponent(id)
}

/* ── List Schedules ────────────────────────────────────────────────────────── */

export function useExportSchedules() {
  return useQuery<PDRScheduleListResponse>({
    queryKey: SCHEDULE_KEYS.list(),
    queryFn: async () => {
      const { data } = await apiClient.get("/exports/schedules")
      return data
    },
    staleTime: 30_000,
  })
}

/* ── Create ────────────────────────────────────────────────────────────────── */

export function useCreateExportSchedule() {
  const qc = useQueryClient()
  return useMutation<PDRScheduleResponse, Error, PDRScheduleCreate>({
    mutationFn: async (body) => {
      const { data } = await apiClient.post("/exports/schedules", body)
      return data
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: SCHEDULE_KEYS.list() })
    },
  })
}

/* ── Update ────────────────────────────────────────────────────────────────── */

export function useUpdateExportSchedule() {
  const qc = useQueryClient()
  return useMutation<
    PDRScheduleResponse,
    Error,
    { id: string; body: PDRScheduleUpdate }
  >({
    mutationFn: async ({ id, body }) => {
      const { data } = await apiClient.patch(
        `/exports/schedules/${safeId(id)}`,
        body,
      )
      return data
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: SCHEDULE_KEYS.list() })
    },
  })
}

/* ── Delete ────────────────────────────────────────────────────────────────── */

export function useDeleteExportSchedule() {
  const qc = useQueryClient()
  return useMutation<void, Error, string>({
    mutationFn: async (id) => {
      await apiClient.delete(`/exports/schedules/${safeId(id)}`)
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: SCHEDULE_KEYS.list() })
    },
  })
}

/* ── Run Now ───────────────────────────────────────────────────────────────── */

export function useRunExportSchedule() {
  const qc = useQueryClient()
  return useMutation<{ success: boolean; events_exported: number }, Error, string>({
    mutationFn: async (id) => {
      const { data } = await apiClient.post(
        `/exports/schedules/${safeId(id)}/run`,
      )
      return data
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: SCHEDULE_KEYS.list() })
    },
  })
}
