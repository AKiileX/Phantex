// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — WebSocket alert provider.
 *
 * Connects to the backend WS endpoint (via useWebSocket) and:
 *   1. Pushes toast notifications for new alerts
 *   2. Exposes a live open-alert count via context
 *   3. Invalidates TanStack Query alert cache on new data
 */

import {
  createContext,
  useContext,
  useCallback,
  useState,
  useRef,
  type ReactNode,
} from "react"
import { useQueryClient } from "@tanstack/react-query"
import { useWebSocket } from "@/hooks/useWebSocket"
import { useToast } from "@/components/ui/toast"
import { notifyAlert, canNotify } from "@/lib/notifications"
import type { WsMessage } from "@/types"

/* ── Context ───────────────────────────────────────────────────────────────── */

interface WsAlertContextValue {
  /** Number of live open alerts received via WS since connection. */
  liveOpenCount: number | null
  /** Whether WS is currently connected. */
  connected: boolean
}

const WsAlertContext = createContext<WsAlertContextValue>({
  liveOpenCount: null,
  connected: false,
})

// eslint-disable-next-line react-refresh/only-export-components
export function useWsAlerts() {
  return useContext(WsAlertContext)
}

/* ── Severity → toast variant mapping ──────────────────────────────────────── */

function severityToVariant(severity?: string) {
  if (severity === "critical" || severity === "high") return "error" as const
  if (severity === "medium") return "warning" as const
  return "default" as const
}

/** Pick the highest-priority variant from a set of severities. */
function maxVariant(a: ReturnType<typeof severityToVariant>, b: ReturnType<typeof severityToVariant>) {
  const order = { error: 3, warning: 2, default: 1 } as const
  return order[a] >= order[b] ? a : b
}

/* ── Constants ─────────────────────────────────────────────────────────────── */

/** Minimum milliseconds between two toast popups. */
const TOAST_THROTTLE_MS = 5_000

/* ── Provider ──────────────────────────────────────────────────────────────── */

export function WsAlertProvider({ children }: { children: ReactNode }) {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [connected, setConnected] = useState(false)
  const [liveOpenCount, setLiveOpenCount] = useState<number | null>(null)

  // ── Throttle / batch state (refs to avoid re-renders) ──────────────
  const pendingCountRef = useRef(0)
  const lastToastTimeRef = useRef(0)
  const pendingTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const highestVariantRef = useRef<ReturnType<typeof severityToVariant>>("default")

  /** Flush batched alerts into a single toast. */
  const flushPending = useCallback(() => {
    const count = pendingCountRef.current
    if (count === 0) return

    const variant = highestVariantRef.current
    toast({
      title: count === 1 ? "New Alert" : `${count} New Alerts`,
      description: count === 1 ? undefined : "Check the alerts page for details",
      variant,
      duration: 4000,
    })

    pendingCountRef.current = 0
    highestVariantRef.current = "default"
    lastToastTimeRef.current = Date.now()
    pendingTimerRef.current = null
  }, [toast])

  const handleMessage = useCallback(
    (msg: WsMessage) => {
      switch (msg.type) {
        case "welcome":
          setConnected(true)
          break

        case "alert": {
          // Invalidate all alert queries so lists/badges refresh
          queryClient.invalidateQueries({ queryKey: ["alerts"] })

          // Extract alert info
          const data = msg.data as {
            title?: string
            rule_name?: string
            severity?: string
            open_count?: number
          } | undefined

          if (data?.open_count != null) {
            setLiveOpenCount(data.open_count)
          }

          // ── Throttled toast batching ───────────────────────────────
          const variant = severityToVariant(data?.severity)
          pendingCountRef.current += 1
          highestVariantRef.current = maxVariant(highestVariantRef.current, variant)

          const elapsed = Date.now() - lastToastTimeRef.current
          if (elapsed >= TOAST_THROTTLE_MS) {
            // Enough time has passed — flush immediately
            if (pendingTimerRef.current) {
              clearTimeout(pendingTimerRef.current)
              pendingTimerRef.current = null
            }
            flushPending()
          } else if (!pendingTimerRef.current) {
            // Schedule a flush after the remaining throttle window
            pendingTimerRef.current = setTimeout(
              flushPending,
              TOAST_THROTTLE_MS - elapsed,
            )
          }

          // Push notification for critical/high alerts (when tab is not focused)
          if (
            canNotify() &&
            document.hidden &&
            (data?.severity === "critical" || data?.severity === "high")
          ) {
            notifyAlert({
              id: (msg.data as { id?: string })?.id ?? "",
              title: data?.title ?? data?.rule_name ?? "Security Alert",
              severity: data.severity,
              agent_id: (msg.data as { agent_id?: string })?.agent_id,
            })
          }
          break
        }

        case "heartbeat":
          setConnected(true)
          break

        case "error":
          setConnected(false)
          break
      }
    },
    [queryClient, flushPending],
  )

  useWebSocket(handleMessage)

  return (
    <WsAlertContext.Provider value={{ liveOpenCount, connected }}>
      {children}
    </WsAlertContext.Provider>
  )
}
