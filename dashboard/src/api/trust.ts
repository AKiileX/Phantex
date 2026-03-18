// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Trust Graph API hooks (TanStack Query).
 *
 * Hooks for fetching trust graph data:
 *   - useTrustGraph: tenant trust graph (force-directed rendering)
 *   - useTrustScore: single entity trust score + factor breakdown
 *
 * Backend endpoints:
 *   GET /api/v1/trust/graph?depth=2&entity_id=...
 *   GET /api/v1/trust/score/{entity_id}?entity_type=agent
 *
 * Security:
 *   - Entity IDs validated as UUID before API call (defence-in-depth)
 *   - No trust data cached in localStorage/sessionStorage (sensitive)
 *
 * @module api/trust
 */

import { useQuery } from "@tanstack/react-query"
import apiClient from "./client"
import type { TrustGraphResponse, TrustScore } from "@/types"

/**
 * Strict UUID v4 — blocks path-traversal payloads in URL params.
 */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

function safePath(segment: string): string {
  if (!UUID_RE.test(segment)) {
    throw new Error(`Invalid ID format: expected UUID, got "${segment.slice(0, 40)}"`)
  }
  return encodeURIComponent(segment)
}

/* ── useTrustGraph ─────────────────────────────────────────────────────────── */

interface TrustGraphParams {
  /** Optional: centre graph on this entity. Omit for full-tenant view. */
  entityId?: string
  /** Neighbourhood depth (1–5). Default 2. */
  depth?: number
}

/**
 * Fetch the tenant trust graph for force-directed visualisation.
 * Polls every 15s to pick up trust score changes.
 */
export function useTrustGraph(
  params: TrustGraphParams = {},
  enabled = true,
) {
  const { entityId, depth = 2 } = params

  return useQuery({
    queryKey: ["trust", "graph", entityId, depth],
    queryFn: async () => {
      const queryParams: Record<string, string | number> = { depth }
      if (entityId) {
        queryParams.entity_id = safePath(entityId)
      }
      const { data } = await apiClient.get<TrustGraphResponse>(
        "/trust/graph",
        { params: queryParams },
      )
      return data
    },
    enabled,
    refetchInterval: 15_000,
    refetchOnWindowFocus: false,
    // Sensitive data — keep only in memory (TanStack Query default)
    gcTime: 60_000,
  })
}

/* ── useTrustScore ─────────────────────────────────────────────────────────── */

interface TrustScoreParams {
  entityId: string
  entityType?: string
}

/**
 * Fetch the full trust score breakdown for a single entity.
 * Used by the TrustBreakdown detail panel.
 */
export function useTrustScore(
  { entityId, entityType = "agent" }: TrustScoreParams,
  enabled = true,
) {
  return useQuery({
    queryKey: ["trust", "score", entityId, entityType],
    queryFn: async () => {
      const { data } = await apiClient.get<TrustScore>(
        `/trust/score/${safePath(entityId)}`,
        { params: { entity_type: entityType } },
      )
      return data
    },
    enabled: enabled && !!entityId,
    refetchInterval: 10_000,
    refetchOnWindowFocus: false,
    gcTime: 30_000,
  })
}
