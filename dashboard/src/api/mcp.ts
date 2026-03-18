// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — MCP Supply Chain API hooks (TanStack Query).
 *
 * Hooks for MCP server inventory, package scanning, anomalies, and risk:
 *   - useMCPServers:    list MCP servers (supports trust/risk filters)
 *   - useMCPServer:     single MCP server detail
 *   - useMCPScans:      list package scan results
 *   - useMCPAnomalies:  list behavioral/protocol anomalies
 *   - useMCPRisk:       risk assessment for a server
 *   - useMCPStats:      supply chain dashboard stats
 *   - useBlockMCPServer / useUnblockMCPServer: mutations
 *   - useScanMCPServer: trigger a package scan
 *
 * Backend endpoints under /api/v1/mcp/*
 *
 * @module api/mcp
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import apiClient from "./client"
import type {
  MCPServerListResponse,
  MCPServerSummary,
  MCPScanListResponse,
  MCPScanResult,
  MCPAnomalyListResponse,
  MCPRiskAssessment,
  MCPSupplyChainStats,
} from "@/types"

/* ── Types ─────────────────────────────────────────────────────────────── */

export interface MCPAlert {
  id: string
  severity: string
  title: string
  description: string | null
  status: string
  created_at: string
  updated_at: string
  agent_id: string | null
  event_id: string | null
  rule_id: string | null
  mcp_server_id: string
  tool_name: string
  tool_category: string
}

export interface MCPAlertListResponse {
  items: MCPAlert[]
  total: number
}

/* ── Keys ──────────────────────────────────────────────────────────────── */

const KEYS = {
  servers: ["mcp", "servers"] as const,
  server: (id: string) => ["mcp", "servers", id] as const,
  scans: ["mcp", "scans"] as const,
  anomalies: ["mcp", "anomalies"] as const,
  risk: (id: string) => ["mcp", "risk", id] as const,
  stats: ["mcp", "stats"] as const,
  alerts: ["mcp", "alerts"] as const,
}

/* ── useMCPServers ─────────────────────────────────────────────────────── */

interface MCPServersParams {
  trustLevel?: string
  riskLevel?: string
  limit?: number
  offset?: number
}

export function useMCPServers(params: MCPServersParams = {}, pollMs = 15_000) {
  return useQuery({
    queryKey: [...KEYS.servers, params],
    queryFn: async () => {
      const qp: Record<string, string | number> = {}
      if (params.trustLevel) qp.trust_level = params.trustLevel
      if (params.riskLevel) qp.risk_level = params.riskLevel
      if (params.limit) qp.limit = params.limit
      if (params.offset) qp.offset = params.offset
      const { data } = await apiClient.get<MCPServerListResponse>("/mcp/servers", { params: qp })
      return data
    },
    refetchInterval: pollMs,
    refetchOnWindowFocus: false,
  })
}

/* ── useMCPServer ──────────────────────────────────────────────────────── */

export function useMCPServer(serverId: string, enabled = true) {
  return useQuery({
    queryKey: KEYS.server(serverId),
    queryFn: async () => {
      const { data } = await apiClient.get<MCPServerSummary>(`/mcp/servers/${encodeURIComponent(serverId)}`)
      return data
    },
    enabled: !!serverId && enabled,
  })
}

/* ── useMCPScans ───────────────────────────────────────────────────────── */

export function useMCPScans(serverId?: string, limit = 50) {
  return useQuery({
    queryKey: [...KEYS.scans, serverId, limit],
    queryFn: async () => {
      const qp: Record<string, string | number> = { limit }
      if (serverId) qp.server_id = serverId
      const { data } = await apiClient.get<MCPScanListResponse>("/mcp/scans", { params: qp })
      return data
    },
    refetchInterval: 30_000,
  })
}

/* ── useMCPAnomalies ───────────────────────────────────────────────────── */

export function useMCPAnomalies(serverId?: string, severity?: string, limit = 50) {
  return useQuery({
    queryKey: [...KEYS.anomalies, serverId, severity, limit],
    queryFn: async () => {
      const qp: Record<string, string | number> = { limit }
      if (serverId) qp.server_id = serverId
      if (severity) qp.severity = severity
      const { data } = await apiClient.get<MCPAnomalyListResponse>("/mcp/anomalies", { params: qp })
      return data
    },
    refetchInterval: 15_000,
  })
}

/* ── useMCPRisk ────────────────────────────────────────────────────────── */

export function useMCPRisk(serverId: string, enabled = true) {
  return useQuery({
    queryKey: KEYS.risk(serverId),
    queryFn: async () => {
      const { data } = await apiClient.get<MCPRiskAssessment>(`/mcp/servers/${encodeURIComponent(serverId)}/risk`)
      return data
    },
    enabled: !!serverId && enabled,
  })
}

/* ── useMCPStats ───────────────────────────────────────────────────────── */

export function useMCPStats(pollMs = 15_000) {
  return useQuery({
    queryKey: KEYS.stats,
    queryFn: async () => {
      const { data } = await apiClient.get<MCPSupplyChainStats>("/mcp/stats")
      return data
    },
    refetchInterval: pollMs,
    refetchOnWindowFocus: false,
  })
}

/* ── useBlockMCPServer ─────────────────────────────────────────────────── */

export function useBlockMCPServer() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ serverId, reason }: { serverId: string; reason: string }) => {
      const { data } = await apiClient.post<MCPServerSummary>(
        `/mcp/servers/${encodeURIComponent(serverId)}/block`,
        { reason },
      )
      return data
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: KEYS.servers })
      qc.invalidateQueries({ queryKey: KEYS.stats })
    },
  })
}

/* ── useUnblockMCPServer ───────────────────────────────────────────────── */

export function useUnblockMCPServer() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (serverId: string) => {
      const { data } = await apiClient.post<MCPServerSummary>(
        `/mcp/servers/${encodeURIComponent(serverId)}/unblock`,
      )
      return data
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: KEYS.servers })
      qc.invalidateQueries({ queryKey: KEYS.stats })
    },
  })
}

/* ── useScanMCPServer ──────────────────────────────────────────────────── */

export function useScanMCPServer() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({
      serverId,
      ecosystem,
      packages,
    }: {
      serverId: string
      ecosystem: "npm" | "pypi"
      packages: string[]
    }) => {
      const { data } = await apiClient.post<MCPScanResult>(
        `/mcp/servers/${encodeURIComponent(serverId)}/scan`,
        { ecosystem, packages },
      )
      return data
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: KEYS.scans })
      qc.invalidateQueries({ queryKey: KEYS.stats })
    },
  })
}

/* ── useMCPAlerts ──────────────────────────────────────────────────────── */

interface MCPAlertFilters {
  severity?: string
  status?: string
  limit?: number
  offset?: number
}

export function useMCPAlerts(filters: MCPAlertFilters = {}, pollMs = 8_000) {
  return useQuery({
    queryKey: [...KEYS.alerts, filters],
    queryFn: async () => {
      const params: Record<string, string | number> = {}
      if (filters.severity) params.severity = filters.severity
      if (filters.status) params.status = filters.status
      if (filters.limit) params.limit = filters.limit
      if (filters.offset) params.offset = filters.offset
      const { data } = await apiClient.get<MCPAlertListResponse>("/mcp/alerts", { params })
      return data
    },
    refetchInterval: pollMs,
    refetchOnWindowFocus: false,
  })
}
