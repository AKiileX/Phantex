// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — PDR Export Channels API hooks (O9).
 *
 * TanStack Query hooks for OCSF/PDR export channel CRUD:
 *   - useExportChannelTypes: available channel types metadata
 *   - useExportChannels: list all channels
 *   - useExportChannel: single channel detail
 *   - useCreateExportChannel / useUpdateExportChannel / useDeleteExportChannel
 *   - useTestExportChannel: connectivity test
 *
 * @module api/exports
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import apiClient from "@/api/client"
import type {
  PDRChannelTypesResponse,
  PDRChannelListResponse,
  PDRChannelResponse,
  PDRChannelCreate,
  PDRChannelUpdate,
  PDRTestResult,
} from "@/types"

/* ── Query Keys ────────────────────────────────────────────────────────────── */

export const EXPORT_KEYS = {
  all: ["exports"] as const,
  types: () => ["exports", "channel-types"] as const,
  list: () => ["exports", "list"] as const,
  detail: (id: string) => ["exports", "detail", id] as const,
}

/* ── Validators ────────────────────────────────────────────────────────────── */

/** Validate channel ID: UUID format */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

function safeChannelId(id: string): string {
  if (!UUID_RE.test(id)) {
    throw new Error("Invalid channel ID format")
  }
  return encodeURIComponent(id)
}

/* ── Channel Types ─────────────────────────────────────────────────────────── */

export function useExportChannelTypes() {
  return useQuery<PDRChannelTypesResponse>({
    queryKey: EXPORT_KEYS.types(),
    queryFn: async () => {
      const { data } = await apiClient.get("/exports/channel-types")
      return data
    },
    staleTime: 5 * 60_000, // static metadata, 5 min stale
  })
}

/* ── List Channels ─────────────────────────────────────────────────────────── */

export function useExportChannels() {
  return useQuery<PDRChannelListResponse>({
    queryKey: EXPORT_KEYS.list(),
    queryFn: async () => {
      const { data } = await apiClient.get("/exports/")
      return data
    },
    staleTime: 30_000,
  })
}

/* ── Single Channel ────────────────────────────────────────────────────────── */

export function useExportChannel(id: string | undefined) {
  return useQuery<PDRChannelResponse>({
    queryKey: EXPORT_KEYS.detail(id ?? ""),
    queryFn: async () => {
      const { data } = await apiClient.get(
        `/exports/${safeChannelId(id!)}`,
      )
      return data
    },
    enabled: !!id,
    staleTime: 30_000,
  })
}

/* ── Create ────────────────────────────────────────────────────────────────── */

export function useCreateExportChannel() {
  const qc = useQueryClient()
  return useMutation<PDRChannelResponse, Error, PDRChannelCreate>({
    mutationFn: async (body) => {
      const { data } = await apiClient.post("/exports/", body)
      return data
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: EXPORT_KEYS.list() })
    },
  })
}

/* ── Update ────────────────────────────────────────────────────────────────── */

export function useUpdateExportChannel() {
  const qc = useQueryClient()
  return useMutation<
    PDRChannelResponse,
    Error,
    { id: string; body: PDRChannelUpdate }
  >({
    mutationFn: async ({ id, body }) => {
      const { data } = await apiClient.patch(
        `/exports/${safeChannelId(id)}`,
        body,
      )
      return data
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: EXPORT_KEYS.list() })
    },
  })
}

/* ── Delete ────────────────────────────────────────────────────────────────── */

export function useDeleteExportChannel() {
  const qc = useQueryClient()
  return useMutation<void, Error, string>({
    mutationFn: async (id) => {
      await apiClient.delete(`/exports/${safeChannelId(id)}`)
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: EXPORT_KEYS.list() })
    },
  })
}

/* ── Test Connection ───────────────────────────────────────────────────────── */

export function useTestExportChannel() {
  return useMutation<PDRTestResult, Error, string>({
    mutationFn: async (id) => {
      const { data } = await apiClient.post(
        `/exports/${safeChannelId(id)}/test`,
      )
      return data
    },
  })
}
