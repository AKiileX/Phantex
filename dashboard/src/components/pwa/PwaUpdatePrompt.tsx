// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — PWA Update Prompt
 *
 * Detects when a new service worker is available and prompts
 * the user to reload for the latest version.
 */

import { useState, useEffect, useCallback } from "react"
import { RefreshCw } from "lucide-react"

export function PwaUpdatePrompt() {
  const [needsUpdate, setNeedsUpdate] = useState(false)
  const [registration, setRegistration] = useState<ServiceWorkerRegistration | null>(null)

  useEffect(() => {
    if (!("serviceWorker" in navigator)) return

    const checkForUpdate = async () => {
      const reg = await navigator.serviceWorker.getRegistration()
      if (!reg) return

      setRegistration(reg)

      reg.addEventListener("updatefound", () => {
        const newWorker = reg.installing
        if (!newWorker) return

        newWorker.addEventListener("statechange", () => {
          if (
            newWorker.state === "installed" &&
            navigator.serviceWorker.controller
          ) {
            setNeedsUpdate(true)
          }
        })
      })
    }

    void checkForUpdate()
  }, [])

  const handleUpdate = useCallback(() => {
    if (registration?.waiting) {
      registration.waiting.postMessage({ type: "SKIP_WAITING" })
    }
    window.location.reload()
  }, [registration])

  if (!needsUpdate) return null

  return (
    <div className="fixed top-4 left-4 right-4 z-50 mx-auto max-w-md animate-in slide-in-from-top-4 duration-300">
      <div className="flex items-center gap-3 rounded-xl border border-blue-500/30 bg-blue-500/10 backdrop-blur-md p-4 shadow-xl">
        <RefreshCw size={18} className="text-blue-400 shrink-0" />
        <p className="text-sm text-white flex-1">
          A new version of PhanTeX is available.
        </p>
        <button
          onClick={handleUpdate}
          className="shrink-0 px-3 py-1.5 rounded-lg bg-blue-600 text-white text-xs font-medium hover:bg-blue-500 active:scale-95 transition-all"
        >
          Update
        </button>
      </div>
    </div>
  )
}
