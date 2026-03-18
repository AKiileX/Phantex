// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — useDebouncedAlerts: batches WebSocket alert updates.
 *
 * Problem: Under alert flood (1000+ alerts/sec), updating React state
 * per-message causes frame drops and UI freeze.
 *
 * Solution: Collect incoming alerts in a buffer and flush them into
 * the alert list on a 500ms interval using requestAnimationFrame.
 *
 * Features:
 *   - 500ms debounce window (configurable)
 *   - Deduplicates by alert.id within the buffer
 *   - Caps accumulated items at maxItems (default 100K)
 *   - Returns a stable `pushAlert` callback for the WebSocket handler
 *   - Provides `liveAlerts` array (newest first) and `clear` function
 *
 * @module hooks/useDebouncedAlerts
 */

import { useRef, useState, useCallback, useEffect } from "react"
import type { AlertSummary } from "@/types"

interface UseDebouncedAlertsOptions {
  /** Flush interval in milliseconds. Default 500. */
  interval?: number
  /** Maximum items to retain. Default 100_000. */
  maxItems?: number
}

interface UseDebouncedAlertsReturn {
  /** Accumulated live alerts (newest first). */
  liveAlerts: AlertSummary[]
  /** Push a new alert into the buffer (call from WS handler). */
  pushAlert: (alert: AlertSummary) => void
  /** Push multiple alerts at once. */
  pushAlerts: (alerts: AlertSummary[]) => void
  /** Clear all accumulated alerts. */
  clear: () => void
  /** Number of alerts buffered but not yet flushed. */
  pendingCount: number
}

export function useDebouncedAlerts(
  options: UseDebouncedAlertsOptions = {},
): UseDebouncedAlertsReturn {
  const { interval = 500, maxItems = 100_000 } = options

  // Flushed alerts visible to the UI
  const [liveAlerts, setLiveAlerts] = useState<AlertSummary[]>([])

  // Buffer: alerts collected between flushes (not in React state — avoids re-renders)
  const bufferRef = useRef<AlertSummary[]>([])
  const seenIdsRef = useRef<Set<string>>(new Set())
  const [pendingCount, setPendingCount] = useState(0)
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // Flush buffer into state
  const flush = useCallback(() => {
    if (bufferRef.current.length === 0) return

    const newAlerts = bufferRef.current.slice()
    bufferRef.current = []
    setPendingCount(0)

    setLiveAlerts((prev) => {
      // Prepend new alerts (newest first)
      const merged = [...newAlerts, ...prev]

      // Enforce max items
      if (merged.length > maxItems) {
        // Remove oldest (at the end) and clean up seenIds
        const removed = merged.splice(maxItems)
        for (const r of removed) {
          seenIdsRef.current.delete(r.id)
        }
      }

      return merged
    })
  }, [maxItems])

  // Start/stop the flush timer
  useEffect(() => {
    timerRef.current = setInterval(() => {
      // Use requestAnimationFrame to avoid flushing during expensive paint
      requestAnimationFrame(() => flush())
    }, interval)

    return () => {
      if (timerRef.current) clearInterval(timerRef.current)
    }
  }, [interval, flush])

  // Push a single alert into the buffer
  const pushAlert = useCallback((alert: AlertSummary) => {
    // Deduplicate by ID within the buffer and flushed list
    if (seenIdsRef.current.has(alert.id)) return
    seenIdsRef.current.add(alert.id)

    bufferRef.current.push(alert)
    setPendingCount((c) => c + 1)
  }, [])

  // Push multiple alerts at once
  const pushAlerts = useCallback(
    (alerts: AlertSummary[]) => {
      for (const a of alerts) {
        pushAlert(a)
      }
    },
    [pushAlert],
  )

  // Clear everything
  const clear = useCallback(() => {
    bufferRef.current = []
    seenIdsRef.current.clear()
    setPendingCount(0)
    setLiveAlerts([])
  }, [])

  return { liveAlerts, pushAlert, pushAlerts, clear, pendingCount }
}
