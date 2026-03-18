// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Agent API hooks (TanStack Query).
 *
 * List uses cursor-based pagination (CursorPage<AgentSummary>).
 * Detail returns full Agent (AgentResponse).
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import apiClient from "./client"
import type { Agent, AgentSummary, CursorPage } from "@/types"

export interface AgentFilters {
  status?: string
  framework?: string
  search?: string
  cursor?: string
  limit?: number
}

export function useAgents(filters?: AgentFilters) {
  return useQuery({
    queryKey: ["agents", filters],
    queryFn: async () => {
      const { data } = await apiClient.get<CursorPage<AgentSummary>>(
        "/agents",
        { params: filters },
      )
      return data
    },
    refetchInterval: 5_000, // Auto-refresh every 5s (dev); bump to 30s for prod
  })
}

/** Defence-in-depth: UUID-only path segment. */
function safePath(id: string): string {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
    throw new Error("Invalid agent ID format")
  }
  return encodeURIComponent(id)
}

export function useAgent(id: string) {
  return useQuery({
    queryKey: ["agents", id],
    queryFn: async () => {
      const { data } = await apiClient.get<Agent>(`/agents/${safePath(id)}`)
      return data
    },
    enabled: !!id,
  })
}

export function useRemoveAgent() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (id: string) => {
      await apiClient.patch(`/agents/${safePath(id)}`, { status: "terminated" })
    },
    onSuccess: (_data, id) => {
      queryClient.invalidateQueries({ queryKey: ["agents"] })
      queryClient.invalidateQueries({ queryKey: ["agents", id] })
    },
  })
}
