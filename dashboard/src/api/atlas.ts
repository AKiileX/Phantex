// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — MITRE ATLAS API hooks (O8).
 *
 * TanStack Query hooks for ATLAS coverage data:
 *   - useAtlasCoverage: full coverage matrix
 *   - useAtlasTechnique: single technique detail
 *   - useAtlasRuleMapping: rule → technique mapping
 *
 * @module api/atlas
 */

import { useQuery } from "@tanstack/react-query"
import apiClient from "@/api/client"
import type {
  AtlasCoverageResponse,
  AtlasTechniqueDetail,
  AtlasRuleMappingResponse,
} from "@/types"

/* ── Query Keys ────────────────────────────────────────────────────────────── */

export const ATLAS_KEYS = {
  all: ["atlas"] as const,
  coverage: () => ["atlas", "coverage"] as const,
  technique: (id: string) => ["atlas", "technique", id] as const,
  rule: (name: string) => ["atlas", "rule", name] as const,
}

/* ── Helpers ───────────────────────────────────────────────────────────────── */

/** Validate ATLAS technique ID format: AML.T0000 or AML.T0000.000 */
function safeTechniqueId(id: string): string {
  if (!/^AML\.T\d{4}(\.\d{1,3})?$/.test(id)) {
    throw new Error("Invalid ATLAS technique ID format")
  }
  return encodeURIComponent(id)
}

/** Validate rule name: alphanumeric + underscores, max 128 */
function safeRuleName(name: string): string {
  if (!/^[a-zA-Z0-9_]{1,128}$/.test(name)) {
    throw new Error("Invalid rule name format")
  }
  return encodeURIComponent(name)
}

/* ── Coverage Matrix ───────────────────────────────────────────────────────── */

export function useAtlasCoverage() {
  return useQuery<AtlasCoverageResponse>({
    queryKey: ATLAS_KEYS.coverage(),
    queryFn: async () => {
      const { data } = await apiClient.get("/atlas/coverage")
      return data
    },
    staleTime: 60_000, // ATLAS data is relatively static
  })
}

/* ── Technique Detail ──────────────────────────────────────────────────────── */

export function useAtlasTechnique(id: string | undefined) {
  return useQuery<AtlasTechniqueDetail>({
    queryKey: ATLAS_KEYS.technique(id ?? ""),
    queryFn: async () => {
      const { data } = await apiClient.get(
        `/atlas/technique/${safeTechniqueId(id!)}`,
      )
      return data
    },
    enabled: !!id,
    staleTime: 60_000,
  })
}

/* ── Rule Mapping ──────────────────────────────────────────────────────────── */

export function useAtlasRuleMapping(ruleName: string | undefined) {
  return useQuery<AtlasRuleMappingResponse>({
    queryKey: ATLAS_KEYS.rule(ruleName ?? ""),
    queryFn: async () => {
      const { data } = await apiClient.get(
        `/atlas/rule/${safeRuleName(ruleName!)}`,
      )
      return data
    },
    enabled: !!ruleName,
    staleTime: 60_000,
  })
}
