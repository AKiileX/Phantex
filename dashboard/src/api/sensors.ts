// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Sensor API hooks (TanStack Query).
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import apiClient from "./client"
import type { SensorSummary, SensorDetail, CursorPage } from "@/types"

export interface SensorFilters {
  status?: string
  search?: string
  cursor?: string
  limit?: number
}

export function useSensors(filters?: SensorFilters, refetchMs = 5_000) {
  return useQuery({
    queryKey: ["sensors", filters],
    queryFn: async () => {
      const { data } = await apiClient.get<CursorPage<SensorSummary>>(
        "/sensors",
        { params: filters },
      )
      return data
    },
    refetchInterval: refetchMs,
  })
}

function safePath(id: string): string {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
    throw new Error("Invalid sensor ID format")
  }
  return encodeURIComponent(id)
}

export function useSensor(id: string) {
  return useQuery({
    queryKey: ["sensors", id],
    queryFn: async () => {
      const { data } = await apiClient.get<SensorDetail>(`/sensors/${safePath(id)}`)
      return data
    },
    enabled: !!id,
    refetchInterval: 10_000,
  })
}

export function useDecommissionSensor() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ id, reason }: { id: string; reason: string }) => {
      const { data } = await apiClient.post<SensorDetail>(
        `/sensors/${safePath(id)}/decommission`,
        { reason },
      )
      return data
    },
    onSuccess: (_data, { id }) => {
      qc.invalidateQueries({ queryKey: ["sensors"] })
      qc.invalidateQueries({ queryKey: ["sensors", id] })
    },
  })
}
