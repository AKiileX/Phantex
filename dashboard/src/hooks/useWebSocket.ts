// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

import { useEffect, useLayoutEffect, useRef, useCallback } from "react"
import { useAuthStore } from "@/stores/authStore"
import type { WsMessage } from "@/types"

interface UseWebSocketOptions {
  /** Whether to connect. Defaults to true when authenticated. */
  enabled?: boolean
  /** Initial reconnect delay in ms. Defaults to 1000. */
  reconnectDelay?: number
  /** Max reconnect delay in ms. Defaults to 30000. */
  maxReconnectDelay?: number
}

/**
 * Fetch a single-use WebSocket ticket from the backend.
 * Falls back to legacy token-in-URL if ticket endpoint fails.
 * Accepts an AbortSignal to cancel stale requests on unmount/reconnect.
 */
async function fetchWSTicket(token: string, signal?: AbortSignal): Promise<string | null> {
  try {
    const resp = await fetch("/api/v1/ws/ticket", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      signal,
    })
    if (!resp.ok) return null
    const data = await resp.json()
    return data.ticket ?? null
  } catch {
    return null
  }
}

export function useWebSocket(
  onMessage: (msg: WsMessage) => void,
  options: UseWebSocketOptions = {},
) {
  const {
    enabled = true,
    reconnectDelay = 1_000,
    maxReconnectDelay = 30_000,
  } = options
  const token = useAuthStore((s) => s.token)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const attemptRef = useRef(0)
  const closedIntentionally = useRef(false)
  const ticketAbortRef = useRef<AbortController | null>(null)
  const onMessageRef = useRef(onMessage)
  useLayoutEffect(() => { onMessageRef.current = onMessage })

  const connectRef = useRef<() => void>(() => undefined)

  const connect = useCallback(() => {
    if (!token || !enabled) return

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:"
    const host = window.location.host

    // AbortController prevents stale ticket fetches from opening duplicate WS
    ticketAbortRef.current?.abort()
    const controller = new AbortController()
    ticketAbortRef.current = controller

    // Phase 2: ticket-based auth (no JWT in URL)
    fetchWSTicket(token, controller.signal).then((ticket) => {
      if (closedIntentionally.current || controller.signal.aborted) return

      let url: string
      if (ticket) {
        url = `${protocol}//${host}/ws/alerts?ticket=${ticket}`
      } else {
        // Fallback to legacy token-in-URL (deprecated)
        url = `${protocol}//${host}/ws/alerts?token=${token}`
      }

      const ws = new WebSocket(url)

      ws.onopen = () => {
        attemptRef.current = 0
      }

      ws.onmessage = (event) => {
        try {
          const msg: WsMessage = JSON.parse(event.data as string)
          onMessageRef.current(msg)
        } catch {
          /* ignore malformed messages */
        }
      }

      ws.onclose = () => {
        wsRef.current = null
        if (closedIntentionally.current) return
        const delay = Math.min(
          reconnectDelay * 2 ** attemptRef.current,
          maxReconnectDelay,
        )
        attemptRef.current += 1
        reconnectTimer.current = setTimeout(() => connectRef.current(), delay)
      }

      ws.onerror = () => {
        ws.close()
      }

      wsRef.current = ws
    })
  }, [token, enabled, reconnectDelay, maxReconnectDelay])

  // Keep the ref pointing at the latest connect callback
  useLayoutEffect(() => { connectRef.current = connect })

  useEffect(() => {
    closedIntentionally.current = false
    connect()
    return () => {
      closedIntentionally.current = true
      ticketAbortRef.current?.abort()
      clearTimeout(reconnectTimer.current ?? undefined)
      wsRef.current?.close()
      wsRef.current = null
    }
  }, [connect])

  return wsRef
}