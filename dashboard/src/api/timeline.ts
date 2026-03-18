// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Timeline API hooks (TanStack Query).
 *
 * Hooks for fetching investigation timelines:
 *   - useAgentTimeline: agent activity timeline with range/limit/cursor
 *   - useAlertTimeline: events ±5 min around an alert
 *
 * Backend endpoints:
 *   GET /api/v1/timeline/agent/{agent_id}?range=24h&limit=200&cursor=...
 *   GET /api/v1/timeline/alert/{alert_id}?limit=200
 *
 * @module api/timeline
 */

import { useQuery, useInfiniteQuery } from "@tanstack/react-query"
import apiClient from "./client"
import type { TimelineResponse } from "@/types"

export type TimelineRange = "1h" | "6h" | "12h" | "24h" | "48h" | "72h"

/**
 * Strict ID pattern — accepts UUID v4 or PAID (ptx-...) format.
 * Blocks path-traversal payloads in URL params.
 * Defence-in-depth: even if ProtectedRoute passes, the API call is safe.
 */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const PAID_RE = /^ptx-[a-z0-9][a-z0-9-]{0,62}-[a-z0-9][a-z0-9-]{0,30}-[0-9a-f]{12}$/

function safePath(segment: string): string {
  if (!UUID_RE.test(segment) && !PAID_RE.test(segment)) {
    throw new Error(`Invalid ID format: expected UUID or PAID, got "${segment.slice(0, 40)}"`);
  }
  return encodeURIComponent(segment);
}

interface AgentTimelineParams {
  agentId: string
  range?: TimelineRange
  limit?: number
}

interface AlertTimelineParams {
  alertId: string
  limit?: number
}

/**
 * Fetch agent investigation timeline with infinite pagination.
 */
export function useAgentTimeline(
  { agentId, range = "24h", limit = 200 }: AgentTimelineParams,
  enabled = true,
) {
  return useInfiniteQuery({
    queryKey: ["timeline", "agent", agentId, range, limit],
    queryFn: async ({ pageParam }: { pageParam: string | undefined }) => {
      const params: Record<string, string | number> = { range, limit }
      if (pageParam) params.cursor = pageParam
      const { data } = await apiClient.get<TimelineResponse>(
        `/timeline/agent/${safePath(agentId)}`,
        { params },
      )
      return data
    },
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) =>
      lastPage.has_more ? (lastPage.next_cursor ?? undefined) : undefined,
    enabled: enabled && !!agentId,
    refetchOnWindowFocus: false,
  })
}

/**
 * Fetch alert investigation timeline (events ±5 min around alert).
 */
export function useAlertTimeline(
  { alertId, limit = 200 }: AlertTimelineParams,
  enabled = true,
) {
  return useQuery({
    queryKey: ["timeline", "alert", alertId, limit],
    queryFn: async () => {
      const { data } = await apiClient.get<TimelineResponse>(
        `/timeline/alert/${safePath(alertId)}`,
        { params: { limit } },
      )
      return data
    },
    enabled: enabled && !!alertId,
    refetchOnWindowFocus: false,
  })
}
