// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Telemetry Admin API hooks (O10).
 *
 * TanStack Query hooks for anonymized telemetry export:
 *   - useTelemetryConfig: read current config
 *   - useUpdateTelemetryConfig: enable/disable + epsilon
 *   - useTelemetryStatus: runtime health metrics
 *   - useTelemetryViewer: inspect recently exported payloads
 *
 * @module api/telemetry
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import apiClient from "@/api/client"
import type {
  TelemetryConfigResponse,
  TelemetryConfigUpdate,
  TelemetryStatusResponse,
  TelemetryViewerResponse,
} from "@/types"

/* ── Query Keys ────────────────────────────────────────────────────────────── */

export const TELEMETRY_KEYS = {
  all: ["telemetry"] as const,
  config: () => ["telemetry", "config"] as const,
  status: () => ["telemetry", "status"] as const,
  viewer: (limit?: number) => ["telemetry", "viewer", limit] as const,
}

/* ── Config ────────────────────────────────────────────────────────────────── */

export function useTelemetryConfig() {
  return useQuery<TelemetryConfigResponse>({
    queryKey: TELEMETRY_KEYS.config(),
    queryFn: async () => {
      const { data } = await apiClient.get("/telemetry/config")
      return data
    },
    staleTime: 30_000,
  })
}

export function useUpdateTelemetryConfig() {
  const qc = useQueryClient()
  return useMutation<TelemetryConfigResponse, Error, TelemetryConfigUpdate>({
    mutationFn: async (body) => {
      const { data } = await apiClient.post("/telemetry/config", body)
      return data
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: TELEMETRY_KEYS.config() })
      qc.invalidateQueries({ queryKey: TELEMETRY_KEYS.status() })
    },
  })
}

/* ── Status ────────────────────────────────────────────────────────────────── */

export function useTelemetryStatus() {
  return useQuery<TelemetryStatusResponse>({
    queryKey: TELEMETRY_KEYS.status(),
    queryFn: async () => {
      const { data } = await apiClient.get("/telemetry/status")
      return data
    },
    staleTime: 15_000, // refresh frequently for live metrics
    refetchInterval: 30_000, // auto-refresh every 30s
  })
}

/* ── Viewer ────────────────────────────────────────────────────────────────── */

export function useTelemetryViewer(limit: number = 50) {
  return useQuery<TelemetryViewerResponse>({
    queryKey: TELEMETRY_KEYS.viewer(limit),
    queryFn: async () => {
      const { data } = await apiClient.get("/telemetry/viewer", {
        params: { limit },
      })
      return data
    },
    staleTime: 15_000,
  })
}
