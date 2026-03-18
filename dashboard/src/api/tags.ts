// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Agent Tags API hooks.
 *
 * TanStack Query hooks for agent tag management:
 *   - useAgentTags: fetch tags for a single agent
 *   - useUpdateAgentTags: PATCH mutation to set tags
 *
 * @module api/tags
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import apiClient from "@/api/client"
import type { AgentTagsResponse } from "@/types"

/* ── Query Keys ────────────────────────────────────────────────────────────── */

export const TAG_KEYS = {
  all: ["agent-tags"] as const,
  detail: (agentId: string) => ["agent-tags", agentId] as const,
}

/* ── Helpers ───────────────────────────────────────────────────────────────── */

function safePath(id: string): string {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
    throw new Error("Invalid agent ID format")
  }
  return encodeURIComponent(id)
}

/* ── Fetch Agent Tags ──────────────────────────────────────────────────────── */

export function useAgentTags(agentId: string | undefined) {
  return useQuery<AgentTagsResponse>({
    queryKey: TAG_KEYS.detail(agentId ?? ""),
    queryFn: async () => {
      const { data } = await apiClient.get(`/agents/${safePath(agentId!)}/tags`)
      return data
    },
    enabled: !!agentId,
    staleTime: 15_000,
  })
}

/* ── Update Agent Tags ─────────────────────────────────────────────────────── */

interface UpdateTagsInput {
  agentId: string
  tags: Record<string, string>
}

export function useUpdateAgentTags() {
  const qc = useQueryClient()
  return useMutation<AgentTagsResponse, Error, UpdateTagsInput>({
    mutationFn: async ({ agentId, tags }) => {
      const { data } = await apiClient.patch(
        `/agents/${safePath(agentId)}/tags`,
        { tags },
      )
      return data
    },
    onSuccess: (_data, { agentId }) => {
      qc.invalidateQueries({ queryKey: TAG_KEYS.detail(agentId) })
      qc.invalidateQueries({ queryKey: ["agents", agentId] })
    },
  })
}
