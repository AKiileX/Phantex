// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Auto-Response API hooks (TanStack Query).
 *
 * Backend prefix: /api/v1/response
 *
 * Provides hooks for: kill switch, shadow mode, response policies,
 * escalation states, action log, human override, and engine config.
 */

import {
  useQuery,
  useMutation,
  useQueryClient,
} from "@tanstack/react-query"
import apiClient from "./client"

// ── Types ────────────────────────────────────────────────────────────────────

export interface KillSwitchStatus {
  kill_switch: boolean
  reason: string
  set_by: string | null
  set_at: string | null
}

export interface ShadowStatus {
  shadow_mode: boolean
  expires_at: string | null
  set_by: string | null
  updated_at: string | null
  effective: boolean
}

export interface ResponsePolicy {
  id: string
  name: string
  description: string
  severity: string[]
  attack_class: string[]
  event_type: string[]
  min_confidence: number
  action: string
  action_params: Record<string, unknown>
  enabled: boolean
  priority: number
  cooldown_sec: number
  require_shadow: boolean
  created_by: string | null
  created_at: string | null
  updated_at: string | null
}

export interface EscalationState {
  agent_id: string
  current_level: number
  offense_count: number
  first_offense: string | null
  last_offense: string | null
  reset_at: string | null
}

export interface ActionLogEntry {
  id: string
  alert_id: string | null
  policy_id: string | null
  agent_id: string | null
  action: string
  action_params: Record<string, unknown>
  decision: string
  escalation_level: number | null
  alert_severity: string | null
  alert_confidence: number | null
  attack_class: string | null
  event_type: string | null
  overridden_by: string | null
  override_reason: string
  created_at: string | null
  executed_at: string | null
}

export interface ResponseConfig {
  exists: boolean
  kill_switch: boolean
  shadow_mode: boolean
  escalation_enabled?: boolean
  escalation_window?: number
  escalation_steps?: Array<{ level: number; action: string; label?: string; params?: Record<string, unknown> }>
  max_actions_per_hour?: number
  kill_switch_reason?: string
  shadow_expires_at?: string | null
  updated_at?: string | null
}

// ── Kill Switch ──────────────────────────────────────────────────────────────

export function useKillSwitch() {
  return useQuery<KillSwitchStatus>({
    queryKey: ["response", "kill-switch"],
    queryFn: async () => {
      const { data } = await apiClient.get("/response/kill-switch")
      return data
    },
    refetchInterval: 10_000,
  })
}

export function useToggleKillSwitch() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (body: { active: boolean; reason?: string }) => {
      const { data } = await apiClient.post("/response/kill-switch", body)
      return data
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["response"] })
    },
  })
}

// ── Shadow Mode ──────────────────────────────────────────────────────────────

export function useShadowStatus() {
  return useQuery<ShadowStatus>({
    queryKey: ["response", "shadow"],
    queryFn: async () => {
      const { data } = await apiClient.get("/response/shadow")
      return data
    },
    refetchInterval: 10_000,
  })
}

export function useEnableShadow() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (body: { duration_hours?: number }) => {
      const { data } = await apiClient.post("/response/shadow/enable", body)
      return data
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["response"] })
    },
  })
}

export function useDisableShadow() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async () => {
      const { data } = await apiClient.post("/response/shadow/disable")
      return data
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["response"] })
    },
  })
}

// ── Response Policies ────────────────────────────────────────────────────────

export function useResponsePolicies(enabledOnly = false) {
  return useQuery<{ policies: ResponsePolicy[]; total: number }>({
    queryKey: ["response", "policies", { enabledOnly }],
    queryFn: async () => {
      const { data } = await apiClient.get("/response/policies", {
        params: { enabled_only: enabledOnly },
      })
      return data
    },
  })
}

export function useCreatePolicy() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (body: Omit<ResponsePolicy, "id" | "created_by" | "created_at" | "updated_at">) => {
      const { data } = await apiClient.post("/response/policies", body)
      return data
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["response", "policies"] })
    },
  })
}

export function useUpdatePolicy() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ id, ...body }: ResponsePolicy) => {
      const { data } = await apiClient.put(`/response/policies/${id}`, body)
      return data
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["response", "policies"] })
    },
  })
}

export function useDeletePolicy() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (id: string) => {
      const { data } = await apiClient.delete(`/response/policies/${id}`)
      return data
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["response", "policies"] })
    },
  })
}

// ── Escalation ───────────────────────────────────────────────────────────────

export function useEscalationStates(agentId?: string) {
  return useQuery<{ states: EscalationState[] }>({
    queryKey: ["response", "escalation", agentId],
    queryFn: async () => {
      const { data } = await apiClient.get("/response/escalation", {
        params: agentId ? { agent_id: agentId } : undefined,
      })
      return data
    },
    refetchInterval: 15_000,
  })
}

export function useResetEscalation() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (agentId: string) => {
      const { data } = await apiClient.delete(`/response/escalation/${agentId}`)
      return data
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["response", "escalation"] })
    },
  })
}

// ── Action Log ───────────────────────────────────────────────────────────────

export function useActionLog(params?: { decision?: string; agent_id?: string; limit?: number; offset?: number }) {
  return useQuery<{ entries: ActionLogEntry[]; total: number; limit: number; offset: number }>({
    queryKey: ["response", "log", params],
    queryFn: async () => {
      const { data } = await apiClient.get("/response/log", { params })
      return data
    },
    refetchInterval: 10_000,
  })
}

// ── Human Override ───────────────────────────────────────────────────────────

export function useOverrideAction() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ logId, reason }: { logId: string; reason: string }) => {
      const { data } = await apiClient.post(`/response/override/${logId}`, { reason })
      return data
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["response", "log"] })
    },
  })
}

// ── Config ───────────────────────────────────────────────────────────────────

export function useResponseConfig() {
  return useQuery<ResponseConfig>({
    queryKey: ["response", "config"],
    queryFn: async () => {
      const { data } = await apiClient.get("/response/config")
      return data
    },
  })
}

export function useUpdateConfig() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (body: {
      escalation_enabled?: boolean
      escalation_window?: number
      escalation_steps?: Array<{ level: number; action: string; label?: string }>
      max_actions_per_hour?: number
    }) => {
      const { data } = await apiClient.put("/response/config", body)
      return data
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["response"] })
    },
  })
}
