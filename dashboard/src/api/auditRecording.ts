// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Audit & DVR Recording API hooks.
 *
 * TanStack Query hooks for the /api/v1/audit-recording/* endpoints.
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import api from "./client";

// ── Types ────────────────────────────────────────────────────────────────────

export interface RecordingConfig {
  tenant_id: string;
  agent_id: string | null;
  level: 1 | 2 | 3;
  enabled: boolean;
}

export interface RecordingEvent {
  id: string;
  level: number;
  tenant_id: string;
  audit?: {
    timestamp: string;
    agent_id: string;
    event_type: string;
    tool_name?: string;
    result: string;
    data_classification: string;
    trust_score: number;
    rule_matched?: string;
    bytes_transferred: number;
  };
  extended?: Record<string, unknown>;
  dvr?: Record<string, unknown>;
}

export interface ReplayStep {
  index: number;
  step_type: "input" | "decision" | "action" | "result" | "blocked";
  timestamp: string;
  agent_id: string;
  summary: string;
  details: Record<string, unknown>;
  rule_matched?: string;
  trust_score?: number;
  duration_us?: number;
}

export interface ReplaySession {
  session_id: string;
  tenant_id: string;
  agent_id: string;
  created_at: string;
  step_count: number;
  duration_total_us: number;
  blocked_count: number;
  steps: ReplayStep[];
  metadata: Record<string, unknown>;
}

export interface LegalHold {
  agent_id: string;
  reason: string;
  held_by: string;
  held_at: string;
  released_at?: string;
  active: boolean;
}

export interface ChainEntry {
  id: string;
  action: string;
  timestamp: string;
  tenant_id: string;
  actor: string;
  agent_id?: string;
  details: Record<string, unknown>;
  entry_hash: string;
  previous_hash: string;
}

export interface ChainVerification {
  valid: boolean;
  entries_checked: number;
  message: string;
  broken_at_index?: number;
  entry_id?: string;
}

export interface ComplianceExport {
  export_id: string;
  tenant_id: string;
  framework: string;
  generated_at: string;
  generated_by: string;
  period_start?: string;
  period_end?: string;
  chain_verification: ChainVerification;
  recording_configs: RecordingConfig[];
  legal_holds: LegalHold[];
  audit_entry_count: number;
  recording_stats: Record<string, unknown>;
  summary: Record<string, unknown>;
}

// ── Query keys ───────────────────────────────────────────────────────────────

const KEYS = {
  configs: ["audit-recording", "configs"] as const,
  events: (params?: Record<string, unknown>) => ["audit-recording", "events", params] as const,
  timeline: (agentId: string) => ["audit-recording", "timeline", agentId] as const,
  stats: ["audit-recording", "stats"] as const,
  replays: ["audit-recording", "replays"] as const,
  replay: (id: string) => ["audit-recording", "replay", id] as const,
  chain: (params?: Record<string, unknown>) => ["audit-recording", "chain", params] as const,
  legalHolds: ["audit-recording", "legal-holds"] as const,
  exports: ["audit-recording", "exports"] as const,
};

// ── Configuration hooks ──────────────────────────────────────────────────────

export function useRecordingConfigs() {
  return useQuery({
    queryKey: KEYS.configs,
    queryFn: () => api.get("/audit-recording/config").then((r) => r.data.configs as RecordingConfig[]),
  });
}

export function useSetRecordingConfig() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { agent_id?: string; level: number }) =>
      api.put("/audit-recording/config", body).then((r) => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: KEYS.configs });
      qc.invalidateQueries({ queryKey: KEYS.stats });
    },
  });
}

// ── Events hooks ─────────────────────────────────────────────────────────────

export function useRecordingEvents(params?: { agent_id?: string; event_type?: string; limit?: number }) {
  return useQuery({
    queryKey: KEYS.events(params),
    queryFn: () =>
      api.get("/audit-recording/events", { params }).then((r) => r.data as { events: RecordingEvent[]; count: number }),
  });
}

export function useAgentTimeline(agentId: string) {
  return useQuery({
    queryKey: KEYS.timeline(agentId),
    queryFn: () =>
      api.get(`/audit-recording/timeline/${encodeURIComponent(agentId)}`).then((r) => r.data),
    enabled: !!agentId,
  });
}

export function useRecordingStats() {
  return useQuery({
    queryKey: KEYS.stats,
    queryFn: () => api.get("/audit-recording/stats").then((r) => r.data),
  });
}

// ── Replay hooks ─────────────────────────────────────────────────────────────

export function useReplaySessions() {
  return useQuery({
    queryKey: KEYS.replays,
    queryFn: () =>
      api.get("/audit-recording/replay").then((r) => r.data as { sessions: ReplaySession[]; count: number }),
  });
}

export function useReplaySession(sessionId: string) {
  return useQuery({
    queryKey: KEYS.replay(sessionId),
    queryFn: () =>
      api.get(`/audit-recording/replay/${encodeURIComponent(sessionId)}`).then((r) => r.data as ReplaySession),
    enabled: !!sessionId,
  });
}

export function useBuildReplay() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { agent_id: string; limit?: number }) =>
      api.post("/audit-recording/replay", body).then((r) => r.data as ReplaySession),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEYS.replays }),
  });
}

export function useCompareReplays() {
  return useMutation({
    mutationFn: (body: { session_a_id: string; session_b_id: string }) =>
      api.post("/audit-recording/replay/compare", body).then((r) => r.data),
  });
}

// ── Chain hooks ──────────────────────────────────────────────────────────────

export function useChainEntries(params?: { action?: string; agent_id?: string; since?: string; limit?: number }) {
  return useQuery({
    queryKey: KEYS.chain(params),
    queryFn: () =>
      api.get("/audit-recording/chain", { params }).then((r) => r.data as { entries: ChainEntry[]; count: number }),
  });
}

export function useVerifyChain() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api.post("/audit-recording/chain/verify").then((r) => r.data as ChainVerification),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEYS.stats }),
  });
}

// ── Legal hold hooks ─────────────────────────────────────────────────────────

export function useLegalHolds(activeOnly = true) {
  return useQuery({
    queryKey: KEYS.legalHolds,
    queryFn: () =>
      api.get("/audit-recording/legal-hold", { params: { active_only: activeOnly } }).then((r) => r.data as { holds: LegalHold[]; count: number }),
  });
}

export function useSetLegalHold() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { agent_id: string; reason: string }) =>
      api.post("/audit-recording/legal-hold", body).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEYS.legalHolds }),
  });
}

export function useReleaseLegalHold() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { agent_id: string }) =>
      api.delete("/audit-recording/legal-hold", { data: body }).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEYS.legalHolds }),
  });
}

// ── Export hooks ─────────────────────────────────────────────────────────────

export function useComplianceExports() {
  return useQuery({
    queryKey: KEYS.exports,
    queryFn: () =>
      api.get("/audit-recording/export").then((r) => r.data as { exports: ComplianceExport[]; count: number }),
  });
}

export function useGenerateExport() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { framework: string; period_start?: string; period_end?: string }) =>
      api.post("/audit-recording/export", body).then((r) => r.data as ComplianceExport),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEYS.exports }),
  });
}
