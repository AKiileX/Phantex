// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Event notification provider.
 *
 * Polls for new important events (medium+ severity) and shows toast
 * notifications globally, regardless of which page the user is on.
 *
 * Complements WsAlertProvider: alerts come via WebSocket in real-time,
 * while events use lightweight polling (every 5s) for lifecycle events
 * like agent discovery/termination and sensor status changes.
 */

import { useEffect, useRef, useCallback, type ReactNode } from "react"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import apiClient from "@/api/client"
import { useToast } from "@/components/ui/toast"
import { useAuthStore } from "@/stores/authStore"
import type { CursorPage, EventSummary, Severity } from "@/types"

/* ── Event-type display labels ─────────────────────────────────────────────── */

const EVENT_LABELS: Record<string, { title: string; icon: string }> = {
  AGENT_DISCOVERED: { title: "New AI Agent Detected", icon: "🔍" },
  AGENT_TERMINATED: { title: "AI Agent Terminated", icon: "⚠️" },
  SENSOR_DISCONNECTED: { title: "Sensor Disconnected", icon: "🔌" },
  SENSOR_DEGRADED: { title: "Sensor Degraded", icon: "⚡" },
}

/* ── Severity → toast variant ──────────────────────────────────────────────── */

function severityToVariant(severity: Severity) {
  if (severity === "critical" || severity === "high") return "error" as const
  if (severity === "medium") return "warning" as const
  return "default" as const
}

/* ── Constants ─────────────────────────────────────────────────────────────── */

const POLL_INTERVAL = 5_000
const IMPORTANT_SEVERITIES = "medium,high,critical"
const IMPORTANT_TYPES = "AGENT_DISCOVERED,AGENT_TERMINATED,SENSOR_DISCONNECTED,SENSOR_DEGRADED"

/* ── Provider ──────────────────────────────────────────────────────────────── */

export function EventNotificationProvider({ children }: { children: ReactNode }) {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  const lastSeenRef = useRef<string>(new Date().toISOString())
  const initializedRef = useRef(false)

  const showEventToast = useCallback(
    (event: EventSummary) => {
      const label = EVENT_LABELS[event.event_type]
      const title = label
        ? `${label.icon} ${label.title}`
        : event.event_type.replace(/_/g, " ")
      const safeAgentId = event.agent_id
        ? event.agent_id.replace(/[^\w\s.:-]/g, "").slice(0, 64)
        : undefined
      const description = safeAgentId ? `Agent: ${safeAgentId}` : undefined

      toast({
        title,
        description,
        variant: severityToVariant(event.severity),
        duration: event.severity === "critical" ? 8000 : 5000,
      })
    },
    [toast],
  )

  const { data } = useQuery({
    queryKey: ["event-notifications"],
    queryFn: async () => {
      const { data } = await apiClient.get<CursorPage<EventSummary>>(
        "/events",
        {
          params: {
            severity: IMPORTANT_SEVERITIES,
            event_type: IMPORTANT_TYPES,
            since: lastSeenRef.current,
            limit: 10,
          },
        },
      )
      return data
    },
    enabled: isAuthenticated,
    refetchInterval: POLL_INTERVAL,
  })

  // Process new events in an effect — never inside select/render
  useEffect(() => {
    const items = data?.items ?? []
    if (items.length === 0) return

    // Skip toasts on first fetch (don't alert on historical events)
    if (!initializedRef.current) {
      initializedRef.current = true
      lastSeenRef.current = items[0].timestamp
      return
    }

    // Only process events newer than our watermark
    const newItems = items.filter(
      (e) => e.timestamp > lastSeenRef.current,
    )
    if (newItems.length === 0) return

    // Advance watermark
    lastSeenRef.current = newItems[0].timestamp

    // Show toasts (cap at 3 to avoid spam)
    const toShow = newItems.slice(0, 3)
    for (const event of toShow) {
      showEventToast(event)
    }
    if (newItems.length > 3) {
      toast({
        title: `+${newItems.length - 3} more events`,
        description: "Check the events page for details",
        variant: "warning",
      })
    }

    // Notify events page to refresh if it's open (without forcing a spinner)
    queryClient.invalidateQueries({ queryKey: ["events"], refetchType: "none" })
  }, [data, showEventToast, toast, queryClient])

  return <>{children}</>
}
