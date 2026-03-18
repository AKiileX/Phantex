// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Alert API hooks (TanStack Query).
 *
 * Backend returns CursorPage<AlertSummary> for list, AlertResponse for detail.
 * PATCH /alerts/{id} returns AlertResponse and requires admin|analyst role.
 *
 * O1: Added useInfiniteAlerts for virtual scrolling with cursor-based pagination.
 */

import {
  useQuery,
  useInfiniteQuery,
  useMutation,
  useQueryClient,
} from "@tanstack/react-query"
import apiClient from "./client"
import type { Alert, AlertSummary, AlertStatus, CursorPage } from "@/types"

/* ── Helpers ────────────────────────────────────────────────────────────────── */

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

function safePath(id: string): string {
  if (!UUID_RE.test(id)) throw new Error("Invalid alert ID format")
  return encodeURIComponent(id)
}

export interface AlertFilters {
  status?: AlertStatus
  severity?: string
  agent_id?: string
  since?: string
  search?: string
  cursor?: string
  limit?: number
}

/**
 * Standard paginated alert query (legacy — used for simple views & badge counts).
 */
export function useAlerts(filters?: AlertFilters, refetchMs = 3_000) {
  return useQuery({
    queryKey: ["alerts", filters],
    queryFn: async () => {
      const { data } = await apiClient.get<CursorPage<AlertSummary>>(
        "/alerts",
        { params: filters },
      )
      return data
    },
    refetchInterval: refetchMs,
  })
}

/**
 * Infinite query for virtual scrolling — fetches pages on demand.
 * Returns all pages flattened into a single items array.
 */
export function useInfiniteAlerts(
  filters?: Omit<AlertFilters, "cursor">,
  refetchMs = 10_000,
) {
  return useInfiniteQuery({
    queryKey: ["alerts", "infinite", filters],
    queryFn: async ({ pageParam }: { pageParam: string | undefined }) => {
      const params = { ...filters, cursor: pageParam }
      const { data } = await apiClient.get<CursorPage<AlertSummary>>(
        "/alerts",
        { params },
      )
      return data
    },
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) =>
      lastPage.has_more ? (lastPage.next_cursor ?? undefined) : undefined,
    refetchInterval: refetchMs,
    // Only refetch the first page to pick up new alerts
    refetchOnWindowFocus: false,
  })
}

export function useAlert(id: string) {
  return useQuery({
    queryKey: ["alerts", id],
    queryFn: async () => {
      const { data } = await apiClient.get<Alert>(`/alerts/${safePath(id)}`)
      return data
    },
    enabled: !!id,
  })
}

export function useUpdateAlertStatus() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async ({
      id,
      status,
    }: {
      id: string
      status: AlertStatus
    }) => {
      const { data } = await apiClient.patch<Alert>(`/alerts/${safePath(id)}`, {
        status,
      })
      return data
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["alerts"] })
    },
  })
}

/**
 * Acknowledge all open alerts in a single backend call.
 * POST /api/v1/alerts/bulk-acknowledge
 */
export function useBulkAcknowledge() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async () => {
      const { data } = await apiClient.post<{ acknowledged: number }>(
        "/alerts/bulk-acknowledge",
      )
      return data
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["alerts"] })
    },
  })
}

/**
 * Bulk update status for selected alerts.
 * POST /api/v1/alerts/bulk-update
 */
export function useBulkUpdateStatus() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async ({
      alertIds,
      status,
    }: {
      alertIds: string[]
      status: AlertStatus
    }) => {
      const { data } = await apiClient.post<{ updated: number; status: string }>(
        "/alerts/bulk-update",
        { alert_ids: alertIds, status },
      )
      return data
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["alerts"] })
    },
  })
}

// ── Response actions ─────────────────────────────────────────────────────────

export type ResponseAction =
  | "isolate_agent"
  | "block_ip"
  | "quarantine_file"
  | "kill_process"
  | "disable_user"
  | "collect_forensics"

export interface ResponseActionPayload {
  action: ResponseAction
  parameters?: Record<string, unknown>
  reason?: string
}

export interface ResponseActionResult {
  alert_id: string
  action: string
  status: string
  message: string
  action_id: string
}

export function useExecuteResponseAction() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async ({
      alertId,
      ...body
    }: ResponseActionPayload & { alertId: string }) => {
      const { data } = await apiClient.post<ResponseActionResult>(
        `/alerts/${safePath(alertId)}/actions`,
        body,
      )
      return data
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["alerts"] })
    },
  })
}

// ── ML Feedback ──────────────────────────────────────────────────────────────

export type AnalystVerdict = "true_positive" | "false_positive" | "benign" | "needs_tuning"

export interface FeedbackPayload {
  alertId: string
  verdict: AnalystVerdict
  confidence?: number
  notes?: string
}

export function useRecordFeedback() {
  return useMutation({
    mutationFn: async ({ alertId, ...body }: FeedbackPayload) => {
      const { data } = await apiClient.post(`/alerts/${safePath(alertId)}/feedback`, body)
      return data
    },
  })
}
