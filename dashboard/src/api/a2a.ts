// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — A2A Protocol Monitoring API hooks.
 *
 * TanStack Query hooks for the /api/v1/a2a/* endpoints.
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import api from "./client";

// ── Types ────────────────────────────────────────────────────────────────────

export interface AgentCard {
  card_id: string;
  name: string;
  url: string;
  capabilities: string[];
  status: "verified" | "unverified" | "revoked";
  fingerprint: string;
  description?: string;
  version?: string;
  registered_at?: string;
}

export interface A2ATask {
  task_id: string;
  source_agent: string;
  target_agent: string;
  capability: string;
  status: string;
  chain_depth: number;
  parent_task_id?: string;
  created_at: string;
}

export interface CommGraph {
  nodes: { id: string; label: string; task_count: number }[];
  edges: { source: string; target: string; weight: number }[];
}

export interface CorrelationFinding {
  id: string;
  a2a_task_id: string;
  mcp_tool: string;
  severity: string;
  description: string;
  timestamp: string;
}

export interface FingerprintResult {
  conformance_score: number;
  message_type: string;
  deviations: string[];
  warnings: string[];
  suspicious: boolean;
}

export interface A2AStats {
  registry: Record<string, number>;
  tracker: Record<string, number>;
  correlator: Record<string, number>;
}

// ── Query keys ───────────────────────────────────────────────────────────────

const K = {
  cards: ["a2a", "cards"] as const,
  card: (id: string) => ["a2a", "cards", id] as const,
  tasks: ["a2a", "tasks"] as const,
  graph: ["a2a", "graph"] as const,
  correlations: ["a2a", "correlations"] as const,
  stats: ["a2a", "stats"] as const,
};

// ── Cards ────────────────────────────────────────────────────────────────────

export function useA2ACards(status?: string, capability?: string) {
  return useQuery({
    queryKey: [...K.cards, { status, capability }],
    queryFn: () => {
      const params = new URLSearchParams();
      if (status) params.set("status", status);
      if (capability) params.set("capability", capability);
      const qs = params.toString();
      return api.get(`/a2a/cards${qs ? `?${qs}` : ""}`).then(r => r.data as AgentCard[]);
    },
  });
}

export function useA2ACard(cardId: string) {
  return useQuery({
    queryKey: K.card(cardId),
    queryFn: () => api.get(`/a2a/cards/${encodeURIComponent(cardId)}`).then(r => r.data as AgentCard),
    enabled: !!cardId,
  });
}

export function useRegisterCard() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { name: string; url: string; capabilities: string[]; description?: string }) =>
      api.post("/a2a/cards", body).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: K.cards }),
  });
}

export function useVerifyCard() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (cardId: string) => api.post(`/a2a/cards/${encodeURIComponent(cardId)}/verify`).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: K.cards }),
  });
}

export function useRevokeCard() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (cardId: string) => api.post(`/a2a/cards/${encodeURIComponent(cardId)}/revoke`).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: K.cards }),
  });
}

// ── Tasks ────────────────────────────────────────────────────────────────────

export function useA2ATasks(status?: string, limit = 100) {
  return useQuery({
    queryKey: [...K.tasks, { status, limit }],
    queryFn: () => {
      const params = new URLSearchParams();
      if (status) params.set("status", status);
      params.set("limit", String(limit));
      return api.get(`/a2a/tasks?${params}`).then(r => r.data as A2ATask[]);
    },
  });
}

export function useCommGraph() {
  return useQuery({
    queryKey: K.graph,
    queryFn: () => api.get("/a2a/tasks/graph").then(r => {
      const raw = r.data as { nodes: { id: string; delegations_out?: number; delegations_in?: number; label?: string; task_count?: number }[]; edges: CommGraph["edges"] };
      return {
        nodes: raw.nodes.map(n => ({ id: n.id, label: n.label ?? n.id, task_count: n.task_count ?? (n.delegations_out ?? 0) + (n.delegations_in ?? 0) })),
        edges: raw.edges,
      } as CommGraph;
    }),
  });
}

// ── Correlations ─────────────────────────────────────────────────────────────

export function useA2ACorrelations(severity?: string, limit = 50) {
  return useQuery({
    queryKey: [...K.correlations, { severity, limit }],
    queryFn: () => {
      const params = new URLSearchParams();
      if (severity) params.set("severity", severity);
      params.set("limit", String(limit));
      return api.get(`/a2a/correlations?${params}`).then(r => {
        const d = r.data;
        if (Array.isArray(d)) return d as CorrelationFinding[];
        return (d as { findings?: CorrelationFinding[] }).findings ?? [];
      });
    },
  });
}

// ── Fingerprinting ───────────────────────────────────────────────────────────

export function useFingerprintMessage() {
  return useMutation({
    mutationFn: (body: { message: Record<string, unknown>; message_type?: string }) =>
      api.post("/a2a/fingerprint", body).then(r => r.data as FingerprintResult),
  });
}

// ── Stats ────────────────────────────────────────────────────────────────────

export function useA2AStats() {
  return useQuery({
    queryKey: K.stats,
    queryFn: () => api.get("/a2a/stats").then(r => r.data as A2AStats),
    refetchInterval: 30_000,
  });
}
