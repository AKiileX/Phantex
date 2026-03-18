// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Event API hooks (TanStack Query).
 *
 * useEvents: standard paginated query (legacy — badges, lightweight views).
 * useInfiniteEvents: infinite query for virtual scrolling with cursor pagination.
 */

import { useQuery, useInfiniteQuery } from "@tanstack/react-query"
import apiClient from "./client"
import type { SecurityEvent, EventSummary, CursorPage } from "@/types"

export interface EventFilters {
  agent_id?: string
  event_type?: string
  severity?: string
  since?: string
  until?: string
  agent_only?: boolean
  cursor?: string
  limit?: number
}

export function useEvents(filters?: EventFilters, refetchMs = 3_000) {
  return useQuery({
    queryKey: ["events", filters],
    queryFn: async () => {
      const { data } = await apiClient.get<CursorPage<EventSummary>>(
        "/events",
        { params: filters },
      )
      return data
    },
    refetchInterval: refetchMs,
  })
}

/**
 * Infinite query for virtual scrolling — fetches pages on demand via cursor.
 */
export function useInfiniteEvents(
  filters?: Omit<EventFilters, "cursor">,
  refetchMs = 10_000,
) {
  return useInfiniteQuery({
    queryKey: ["events", "infinite", filters],
    queryFn: async ({ pageParam }: { pageParam: string | undefined }) => {
      const params = { ...filters, cursor: pageParam }
      const { data } = await apiClient.get<CursorPage<EventSummary>>(
        "/events",
        { params },
      )
      return data
    },
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) =>
      lastPage.has_more ? (lastPage.next_cursor ?? undefined) : undefined,
    refetchInterval: refetchMs,
    refetchOnWindowFocus: false,
  })
}

export function useEvent(id: string) {
  return useQuery({
    queryKey: ["events", id],
    queryFn: async () => {
      const { data } = await apiClient.get<SecurityEvent>(`/events/${id}`)
      return data
    },
    enabled: !!id,
  })
}
