// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Copilot AI Settings API hooks.
 *
 * TanStack Query hooks for the Copilot configuration endpoints:
 *   - useCopilotConfig: get current config
 *   - useUpdateCopilotConfig: save configuration
 *   - useTestCopilotConnection: test endpoint + auto-detect
 *   - useCopilotModels: list models from configured endpoint
 *
 * @module api/copilotSettings
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import apiClient from "@/api/client"

/* ── Types ─────────────────────────────────────────────────────────────────── */

export interface CopilotConfig {
  provider: string           // "local" | "openai" | "anthropic" | "custom"
  base_url: string
  model: string
  api_key_masked: string     // e.g. "sk-abc...xyz"
  has_api_key: boolean
  max_tokens: number
  temperature: number
  data_policy: string        // "local_only" | "allow_cloud"
  enabled: boolean
  endpoint_type: string      // "private" | "public"
  updated_at: string | null
}

export interface CopilotConfigUpdate {
  provider: string
  base_url: string
  model: string
  api_key?: string | null    // null = keep current
  max_tokens: number
  temperature: number
  data_policy: string
  enabled: boolean
}

export interface TestConnectionResult {
  reachable: boolean
  detected_server: string    // "lm_studio" | "ollama" | "vllm" | "openai" | "anthropic" | "unknown"
  available_models: string[]
  endpoint_type: string      // "private" | "public"
  latency_ms: number
  error: string | null
  server_version: string | null
}

/* ── Query Keys ────────────────────────────────────────────────────────────── */

export const COPILOT_CONFIG_KEYS = {
  config: () => ["copilot-config"] as const,
  models: () => ["copilot-models"] as const,
}

/* ── Get config ────────────────────────────────────────────────────────────── */

export function useCopilotConfig() {
  return useQuery<CopilotConfig>({
    queryKey: COPILOT_CONFIG_KEYS.config(),
    queryFn: async () => {
      const { data } = await apiClient.get("/settings/copilot")
      return data
    },
    staleTime: 60_000,
    retry: 1,
  })
}

/* ── Update config ─────────────────────────────────────────────────────────── */

export function useUpdateCopilotConfig() {
  const qc = useQueryClient()
  return useMutation<CopilotConfig, Error, CopilotConfigUpdate>({
    mutationFn: async (req) => {
      const { data } = await apiClient.put("/settings/copilot", req)
      return data
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: COPILOT_CONFIG_KEYS.config() })
      qc.invalidateQueries({ queryKey: ["copilot", "health"] })
    },
  })
}

/* ── Test connection ───────────────────────────────────────────────────────── */

export function useTestCopilotConnection() {
  return useMutation<TestConnectionResult, Error, { base_url: string; api_key?: string; model?: string }>({
    mutationFn: async (req) => {
      const { data } = await apiClient.post("/settings/copilot/test", req)
      return data
    },
  })
}

/* ── List available models ─────────────────────────────────────────────────── */

export function useCopilotModels(enabled = true) {
  return useQuery<{ models: string[] }>({
    queryKey: COPILOT_CONFIG_KEYS.models(),
    queryFn: async () => {
      const { data } = await apiClient.get("/settings/copilot/models")
      return data
    },
    staleTime: 30_000,
    enabled,
    retry: 1,
  })
}
