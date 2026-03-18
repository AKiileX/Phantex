// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Session Hydrator.
 *
 * With Zustand persist middleware, the full auth state is rehydrated from
 * sessionStorage automatically. This component now simply waits for that
 * rehydration to complete before rendering the app.
 *
 * If the persisted access token is stale, the axios response interceptor
 * will handle refresh transparently on the first 401.
 */

import { useEffect, useRef, useCallback, useSyncExternalStore } from "react"
import { useAuthStore } from "@/stores/authStore"

interface Props {
  children: React.ReactNode
}

export function SessionHydrator({ children }: Props) {
  const subscribe = useCallback((callback: () => void) => {
    return useAuthStore.persist.onFinishHydration(callback)
  }, [])
  const getSnapshot = useCallback(() => useAuthStore.persist.hasHydrated(), [])
  const ready = useSyncExternalStore(subscribe, getSnapshot, () => false)

  // Log hydration result once
  const loggedRef = useRef(false)
  useEffect(() => {
    if (ready && !loggedRef.current) {
      loggedRef.current = true
      const { isAuthenticated } = useAuthStore.getState()
      console.debug(
        "[SessionHydrator]",
        isAuthenticated ? "session restored from sessionStorage" : "no session found",
      )
    }
  }, [ready])

  if (!ready) {
    return (
      <div className="flex h-screen w-screen items-center justify-center bg-background">
        <div className="flex flex-col items-center gap-3">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-primary border-t-transparent" />
          <p className="text-sm text-muted-foreground">Restoring session…</p>
        </div>
      </div>
    )
  }

  return <>{children}</>
}
