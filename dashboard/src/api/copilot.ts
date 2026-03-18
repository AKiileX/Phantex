// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Copilot API hooks (Block U + AB).
 *
 * TanStack Query hooks + mutations for the AI copilot:
 *   - useCopilotChat: send a message (non-streaming)
 *   - useCopilotTriage: batch alert triage
 *   - useCopilotSuggestRule: NL → PRL generation
 *   - useCopilotRefineRule: refine an existing rule
 *   - useCopilotHealth: LLM provider health check
 *   - useCopilotWsTicket: get WebSocket ticket for streaming
 *   - useCopilotBriefing: generate threat briefing
 *   - useCopilotPlaybooks: list IR playbooks
 *   - useCopilotPlaybook: get single playbook
 *   - useCopilotSessions: CRUD for multi-turn sessions
 *
 * @module api/copilot
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import apiClient from "@/api/client"

/* ── Types ─────────────────────────────────────────────────────────────────── */

export interface CopilotMessage {
  role: "user" | "assistant" | "system"
  content: string
}

export interface CopilotChatRequest {
  message: string
  history?: CopilotMessage[]
  context?: Record<string, unknown>
  session_id?: string
}

export interface CopilotChatResponse {
  response: string
  tool_calls: string[]
  usage: {
    prompt_tokens?: number
    completion_tokens?: number
    total_tokens?: number
    estimated_cost_usd?: number
    latency_ms?: number
    model?: string
    provider?: string
  }
  firewall_findings?: string[]
}

export interface TriageResult {
  alert_id: string
  classification: "true_positive" | "false_positive" | "needs_investigation"
  confidence: number
  reasoning: string
  suggested_action: string
  priority: number
}

export interface TriageResponse {
  results: TriageResult[]
  usage: Record<string, unknown>
}

export interface RuleSuggestion {
  rule_text: string
  name: string
  severity: string
  is_valid: boolean
  validation_errors: string[]
  confidence: number
  usage: Record<string, unknown>
}

export interface CopilotHealthResponse {
  copilot_status: string
  provider: string
  model: string
  available_models: string[]
  firewall: string
  features: string[]
}

/* ── Query Keys ────────────────────────────────────────────────────────────── */

export const COPILOT_KEYS = {
  all: ["copilot"] as const,
  health: () => ["copilot", "health"] as const,
  playbooks: () => ["copilot", "playbooks"] as const,
  playbook: (cls: string) => ["copilot", "playbook", cls] as const,
  sessions: () => ["copilot", "sessions"] as const,
}

/* ── Health Check ──────────────────────────────────────────────────────────── */

export function useCopilotHealth(enabled = true) {
  return useQuery<CopilotHealthResponse>({
    queryKey: COPILOT_KEYS.health(),
    queryFn: async () => {
      const { data } = await apiClient.get("/copilot/health")
      return data
    },
    staleTime: 60_000,
    refetchInterval: 120_000,
    enabled,
    retry: 1,
  })
}

/* ── Chat Mutation ─────────────────────────────────────────────────────────── */

export function useCopilotChat() {
  return useMutation<CopilotChatResponse, Error, CopilotChatRequest>({
    mutationFn: async (req) => {
      const { data } = await apiClient.post("/copilot/chat", req)
      return data
    },
  })
}

/* ── Triage Mutation ───────────────────────────────────────────────────────── */

export function useCopilotTriage() {
  const qc = useQueryClient()
  return useMutation<TriageResponse, Error, { alert_ids: string[] }>({
    mutationFn: async (req) => {
      const { data } = await apiClient.post("/copilot/triage", req)
      return data
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["alerts"] })
    },
  })
}

/* ── Rule Generation ───────────────────────────────────────────────────────── */

export function useCopilotSuggestRule() {
  return useMutation<RuleSuggestion, Error, { description: string; severity_hint?: string }>({
    mutationFn: async (req) => {
      const { data } = await apiClient.post("/copilot/suggest-rule", req)
      return data
    },
  })
}

/* ── Rule Refinement ───────────────────────────────────────────────────────── */

export function useCopilotRefineRule() {
  return useMutation<RuleSuggestion, Error, { original_rule: string; feedback: string }>({
    mutationFn: async (req) => {
      const { data } = await apiClient.post("/copilot/refine-rule", req)
      return data
    },
  })
}

/* ── WebSocket Ticket ──────────────────────────────────────────────────────── */

export async function getCopilotWsTicket(): Promise<string> {
  const { data } = await apiClient.post("/copilot/ws/ticket")
  return data.ticket
}

/* ── Streaming helper ──────────────────────────────────────────────────────── */

export interface CopilotStreamCallbacks {
  onToken: (content: string) => void
  onDone: (toolCalls: string[]) => void
  onError: (detail: string) => void
  onConnected?: (info: { copilot_status: string; provider: string; model: string }) => void
}

/**
 * Open a WebSocket connection for streaming copilot chat.
 *
 * Returns a controller object with send() and close() methods.
 */
export function connectCopilotStream(callbacks: CopilotStreamCallbacks) {
  let ws: WebSocket | null = null
  let closed = false

  const connect = async () => {
    try {
      const ticket = await getCopilotWsTicket()
      const proto = window.location.protocol === "https:" ? "wss:" : "ws:"
      const wsUrl = `${proto}//${window.location.host}/ws/copilot?ticket=${encodeURIComponent(ticket)}`

      ws = new WebSocket(wsUrl)

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data)
          switch (msg.type) {
            case "connected":
              callbacks.onConnected?.(msg)
              break
            case "token":
              callbacks.onToken(msg.content ?? "")
              break
            case "done":
              callbacks.onDone(msg.tool_calls ?? [])
              break
            case "error":
              callbacks.onError(msg.detail ?? "Unknown error")
              break
            case "pong":
              break
          }
        } catch {
          // ignore parse errors
        }
      }

      ws.onerror = () => {
        callbacks.onError("WebSocket connection error")
      }

      ws.onclose = () => {
        if (!closed) {
          callbacks.onError("Connection closed")
        }
      }
    } catch (err) {
      callbacks.onError(err instanceof Error ? err.message : "Failed to connect")
    }
  }

  connect()

  return {
    send(message: string, history: CopilotMessage[] = [], context?: Record<string, unknown>) {
      if (ws?.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "chat", message, history, context }))
      }
    },
    close() {
      closed = true
      ws?.close()
    },
    get connected() {
      return ws?.readyState === WebSocket.OPEN
    },
  }
}

/* ── Briefing Types & Hook ─────────────────────────────────────────────────── */

export interface BriefingResponse {
  briefing: string
  data: Record<string, unknown>
  generated_at: string
  usage: Record<string, unknown>
}

export function useCopilotBriefing() {
  return useMutation<BriefingResponse, Error, { hours?: number; use_llm?: boolean }>({
    mutationFn: async (req) => {
      const { data } = await apiClient.post("/copilot/briefing", req)
      return data
    },
  })
}

/* ── Playbook Types & Hooks ────────────────────────────────────────────────── */

export interface PlaybookStep {
  order: number
  title: string
  detail: string
  automated: boolean
  response_action: string | null
}

export interface PlaybookPhase {
  name: string
  steps: PlaybookStep[]
}

export interface PlaybookSummary {
  attack_class: string
  name: string
  severity: string
  description: string
}

export interface PlaybookDetail extends PlaybookSummary {
  phases: PlaybookPhase[]
  mitre_refs: string[]
  markdown: string
}

export function useCopilotPlaybooks(enabled = true) {
  return useQuery<{ playbooks: PlaybookSummary[] }>({
    queryKey: COPILOT_KEYS.playbooks(),
    queryFn: async () => {
      const { data } = await apiClient.get("/copilot/playbooks")
      return data
    },
    staleTime: 300_000,
    enabled,
  })
}

export function useCopilotPlaybook(attackClass: string, enabled = true) {
  return useQuery<PlaybookDetail>({
    queryKey: COPILOT_KEYS.playbook(attackClass),
    queryFn: async () => {
      const { data } = await apiClient.get(`/copilot/playbook/${encodeURIComponent(attackClass)}`)
      return data
    },
    staleTime: 300_000,
    enabled: enabled && !!attackClass,
  })
}

export function useCopilotContextualise() {
  return useMutation<{ playbook: string; contextualised: string }, Error, { attack_class: string; alert_id: string }>({
    mutationFn: async ({ attack_class, alert_id }) => {
      const { data } = await apiClient.post(`/copilot/playbook/${encodeURIComponent(attack_class)}/contextualise`, { alert_id })
      return data
    },
  })
}

/* ── Session Types & Hooks ─────────────────────────────────────────────────── */

export interface CopilotSession {
  session_id: string
  title: string
  created_at: string
  message_count: number
}

export function useCopilotSessions(enabled = true) {
  return useQuery<{ sessions: CopilotSession[] }>({
    queryKey: COPILOT_KEYS.sessions(),
    queryFn: async () => {
      const { data } = await apiClient.get("/copilot/sessions")
      return data
    },
    staleTime: 30_000,
    enabled,
  })
}

export function useCopilotCreateSession() {
  const qc = useQueryClient()
  return useMutation<CopilotSession, Error, { title?: string }>({
    mutationFn: async (req) => {
      const { data } = await apiClient.post("/copilot/sessions", req)
      return data
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: COPILOT_KEYS.sessions() })
    },
  })
}

export function useCopilotDeleteSession() {
  const qc = useQueryClient()
  return useMutation<void, Error, string>({
    mutationFn: async (sessionId) => {
      await apiClient.delete(`/copilot/sessions/${encodeURIComponent(sessionId)}`)
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: COPILOT_KEYS.sessions() })
    },
  })
}
