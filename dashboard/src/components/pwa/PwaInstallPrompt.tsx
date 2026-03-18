// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — PWA Install Prompt
 *
 * Shows a dismissible banner prompting users to install the PWA.
 * Uses the beforeinstallprompt event to trigger native install.
 */

import { useState, useEffect, useCallback } from "react"
import { Download, X } from "lucide-react"

interface BeforeInstallPromptEvent extends Event {
  prompt(): Promise<void>
  userChoice: Promise<{ outcome: "accepted" | "dismissed" }>
}

export function PwaInstallPrompt() {
  const [deferredPrompt, setDeferredPrompt] =
    useState<BeforeInstallPromptEvent | null>(null)
  const [dismissed, setDismissed] = useState(
    () => sessionStorage.getItem("pwa-install-dismissed") === "1",
  )

  useEffect(() => {
    if (dismissed) return

    const handler = (e: Event) => {
      e.preventDefault()
      setDeferredPrompt(e as BeforeInstallPromptEvent)
    }

    window.addEventListener("beforeinstallprompt", handler)
    return () => window.removeEventListener("beforeinstallprompt", handler)
  }, [dismissed])

  const handleInstall = useCallback(async () => {
    if (!deferredPrompt) return
    await deferredPrompt.prompt()
    const { outcome } = await deferredPrompt.userChoice
    if (outcome === "accepted") {
      setDeferredPrompt(null)
    }
  }, [deferredPrompt])

  const handleDismiss = useCallback(() => {
    setDismissed(true)
    sessionStorage.setItem("pwa-install-dismissed", "1")
  }, [])

  if (!deferredPrompt || dismissed) return null

  return (
    <div className="fixed bottom-4 left-4 right-4 z-50 mx-auto max-w-md animate-in slide-in-from-bottom-4 duration-300 md:left-auto md:right-4 md:max-w-sm">
      <div className="flex items-center gap-3 rounded-xl border border-purple-500/30 bg-purple-500/10 backdrop-blur-md p-4 shadow-xl">
        <div className="shrink-0 rounded-lg bg-purple-500/20 p-2">
          <Download size={20} className="text-purple-400" />
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-white">Install PhanTeX</p>
          <p className="text-xs text-muted-foreground mt-0.5">
            Get instant alerts on your home screen
          </p>
        </div>
        <button
          onClick={handleInstall}
          className="shrink-0 px-3 py-1.5 rounded-lg bg-purple-600 text-white text-xs font-medium hover:bg-purple-500 active:scale-95 transition-all"
        >
          Install
        </button>
        <button
          onClick={handleDismiss}
          className="shrink-0 p-1 rounded-lg hover:bg-white/5 active:scale-90 transition-transform"
        >
          <X size={14} className="text-muted-foreground" />
        </button>
      </div>
    </div>
  )
}
