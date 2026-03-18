// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Compliance API hooks
 *
 * TanStack Query hooks for compliance endpoints:
 *   - useComplianceScore: quick scorecard
 *   - useComplianceHistory: paginated report list
 *   - useComplianceReport: single stored report
 *   - useGenerateReport: generate new report (JSON)
 *   - useGenerateReportPDF: generate PDF download
 *   - useTriggerScan: on-demand compliance scan
 *   - useScanStatus: scanner configuration
 *   - useUpdateScanConfig: update scanner settings
 *
 * @module api/compliance
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import apiClient from "@/api/client"

/* ── Types ─────────────────────────────────────────────────────────────────── */

export interface FrameworkScore {
  framework: string
  overall_score: number
  total_items: number
  satisfied: number
  partial: number
  gaps: number
}

export interface ComplianceScorecard {
  tenant_id: string
  generated_at: string
  frameworks: FrameworkScore[]
}

export interface ComplianceReportMeta {
  id: string
  tenant_id: string
  frameworks: string[]
  overall_score: number
  created_at: string
  created_by: string | null
}

export interface ComplianceReportFull {
  id: string | null
  tenant_id: string
  generated_at: string
  frameworks: Record<string, unknown>[]
  cross_reference: Record<string, string>[]
}

export interface ComplianceHistoryResponse {
  items: ComplianceReportMeta[]
  total: number
}

export interface ScanStatus {
  enabled: boolean
  quick_scan_cron: string | null
  full_scan_cron: string | null
  drift_threshold: number
  last_quick_scan: string | null
  last_full_scan: string | null
  next_quick_scan: string | null
  next_full_scan: string | null
}

export interface GenerateReportRequest {
  frameworks?: string[]
  period_start?: string
  period_end?: string
}

/* ── Query Keys ────────────────────────────────────────────────────────────── */

export const COMPLIANCE_KEYS = {
  all: ["compliance"] as const,
  score: () => ["compliance", "score"] as const,
  history: (page: number) => ["compliance", "history", page] as const,
  report: (id: string) => ["compliance", "report", id] as const,
  scan: () => ["compliance", "scan"] as const,
}

/* ── Scorecard ─────────────────────────────────────────────────────────────── */

export function useComplianceScore() {
  return useQuery<ComplianceScorecard>({
    queryKey: COMPLIANCE_KEYS.score(),
    queryFn: async () => {
      const { data } = await apiClient.get("/compliance/score")
      return data
    },
    staleTime: 60_000,
  })
}

/* ── History ───────────────────────────────────────────────────────────────── */

export function useComplianceHistory(page = 0, limit = 20) {
  return useQuery<ComplianceHistoryResponse>({
    queryKey: COMPLIANCE_KEYS.history(page),
    queryFn: async () => {
      const { data } = await apiClient.get("/compliance/history", {
        params: { offset: page * limit, limit },
      })
      return data
    },
    staleTime: 30_000,
  })
}

/* ── Single Report ─────────────────────────────────────────────────────────── */

export function useComplianceReport(id: string) {
  return useQuery<ComplianceReportFull>({
    queryKey: COMPLIANCE_KEYS.report(id),
    queryFn: async () => {
      const { data } = await apiClient.get(`/compliance/report/${encodeURIComponent(id)}`)
      return data
    },
    enabled: !!id,
    staleTime: 5 * 60_000,
  })
}

/* ── Generate Report ───────────────────────────────────────────────────────── */

export function useGenerateReport() {
  const qc = useQueryClient()
  return useMutation<ComplianceReportFull, Error, GenerateReportRequest>({
    mutationFn: async (body) => {
      const { data } = await apiClient.post("/compliance/report", body)
      return data
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: COMPLIANCE_KEYS.all })
    },
  })
}

/* ── Generate PDF ──────────────────────────────────────────────────────────── */

export function useGenerateReportPDF() {
  return useMutation<Blob, Error, GenerateReportRequest>({
    mutationFn: async (body) => {
      const { data } = await apiClient.post("/compliance/report/pdf", body, {
        responseType: "blob",
      })
      return data
    },
  })
}

/* ── Trigger Scan ──────────────────────────────────────────────────────────── */

export function useTriggerScan() {
  const qc = useQueryClient()
  return useMutation<{ status: string; report_id: string }, Error, void>({
    mutationFn: async () => {
      const { data } = await apiClient.post("/compliance/scan/trigger")
      return data
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: COMPLIANCE_KEYS.all })
    },
  })
}

/* ── Scanner Status ────────────────────────────────────────────────────────── */

export function useScanStatus() {
  return useQuery<ScanStatus>({
    queryKey: COMPLIANCE_KEYS.scan(),
    queryFn: async () => {
      const { data } = await apiClient.get("/compliance/scan/status")
      return data
    },
    staleTime: 60_000,
  })
}

/* ── Update Scan Config ────────────────────────────────────────────────────── */

export function useUpdateScanConfig() {
  const qc = useQueryClient()
  return useMutation<ScanStatus, Error, Partial<ScanStatus>>({
    mutationFn: async (body) => {
      const { data } = await apiClient.put("/compliance/scan/config", body)
      return data
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: COMPLIANCE_KEYS.scan() })
    },
  })
}
