// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Session Timeout Hook.
 *
 * Enforces a 1-hour inactivity timeout.
 * User activity (mouse, keyboard, touch) resets the idle timer.
 * When timeout fires, tokens are cleared and user is redirected to /login.
 *
 * @module hooks/useSessionTimeout
 */

import { useEffect, useRef, useCallback } from "react"
import { useAuthStore } from "@/stores/authStore"

/** Idle timeout in milliseconds — 1 hour. */
const SESSION_TIMEOUT_MS = 60 * 60 * 1000

/** Activity events that reset the idle timer. */
const ACTIVITY_EVENTS: (keyof WindowEventMap)[] = [
  "mousedown",
  "keydown",
  "touchstart",
  "scroll",
]

export function useSessionTimeout() {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  const clearAuth = useAuthStore((s) => s.clearAuth)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const resetTimer = useCallback(() => {
    if (timerRef.current) clearTimeout(timerRef.current)
    timerRef.current = setTimeout(() => {
      clearAuth()
      window.location.href = "/login?reason=timeout"
    }, SESSION_TIMEOUT_MS)
  }, [clearAuth])

  useEffect(() => {
    if (!isAuthenticated) return

    resetTimer()

    for (const event of ACTIVITY_EVENTS) {
      window.addEventListener(event, resetTimer, { passive: true })
    }

    return () => {
      if (timerRef.current) clearTimeout(timerRef.current)
      for (const event of ACTIVITY_EVENTS) {
        window.removeEventListener(event, resetTimer)
      }
    }
  }, [isAuthenticated, resetTimer])
}
