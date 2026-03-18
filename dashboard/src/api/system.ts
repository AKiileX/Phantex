// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — System Nerve Center API hooks.
 *
 * TanStack Query hooks for the real-time pipeline monitoring page:
 *   - useNerveCenter: Full pipeline health snapshot (all components + throughput)
 *   - useThroughput: Lightweight throughput-only counter (high-frequency polling)
 *
 * @module api/system
 */

import { useQuery } from "@tanstack/react-query"
import apiClient from "@/api/client"
import type { NerveCenterResponse, ThroughputResponse } from "@/types"

/* ── Query Keys ────────────────────────────────────────────────────────────── */

export const SYSTEM_KEYS = {
  all: ["system"] as const,
  nerveCenter: () => ["system", "nerve-center"] as const,
  throughput: () => ["system", "throughput"] as const,
}

/* ── Hooks ─────────────────────────────────────────────────────────────────── */

/** Full pipeline health snapshot — polls every 15s */
export function useNerveCenter() {
  return useQuery<NerveCenterResponse>({
    queryKey: SYSTEM_KEYS.nerveCenter(),
    queryFn: async () => {
      const { data } = await apiClient.get("/system/nerve-center")
      return data
    },
    staleTime: 10_000,
    refetchInterval: 15_000,
  })
}

/** Lightweight throughput counters — polls every 5s */
export function useThroughput() {
  return useQuery<ThroughputResponse>({
    queryKey: SYSTEM_KEYS.throughput(),
    queryFn: async () => {
      const { data } = await apiClient.get("/system/throughput")
      return data
    },
    staleTime: 3_000,
    refetchInterval: 5_000,
  })
}
