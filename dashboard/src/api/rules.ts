// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Rule API hooks (TanStack Query).
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import apiClient from "./client"
import type { Rule, PaginatedResponse } from "@/types"

interface RuleFilters {
  enabled?: boolean
  severity?: string
  search?: string
  page?: number
  page_size?: number
}

export function useRules(filters?: RuleFilters) {
  return useQuery({
    queryKey: ["rules", filters],
    queryFn: async () => {
      const { data } = await apiClient.get<PaginatedResponse<Rule>>("/rules", {
        params: filters,
      })
      return data
    },
  })
}

export function useRule(id: string) {
  return useQuery({
    queryKey: ["rules", id],
    queryFn: async () => {
      const { data } = await apiClient.get<Rule>(`/rules/${id}`)
      return data
    },
    enabled: !!id,
  })
}

interface CreateRuleInput {
  name: string
  prl_source: string
  severity: string
  description?: string
  attack_class?: string
}

export function useCreateRule() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async (input: CreateRuleInput) => {
      const { data } = await apiClient.post<Rule>("/rules", input)
      return data
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["rules"] })
    },
  })
}

interface UpdateRuleInput {
  name?: string
  prl_source?: string
  severity?: string
  description?: string
  attack_class?: string
  enabled?: boolean
}

export function useUpdateRule() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async ({ id, ...input }: UpdateRuleInput & { id: string }) => {
      const { data } = await apiClient.patch<Rule>(`/rules/${id}`, input)
      return data
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["rules"] })
    },
  })
}

export function useToggleRule() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async ({ id, enabled }: { id: string; enabled: boolean }) => {
      const { data } = await apiClient.patch<Rule>(`/rules/${id}`, { enabled })
      return data
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["rules"] })
    },
  })
}

export function useDeleteRule() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async (id: string) => {
      const { data } = await apiClient.delete<Rule>(`/rules/${id}`)
      return data
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["rules"] })
    },
  })
}
