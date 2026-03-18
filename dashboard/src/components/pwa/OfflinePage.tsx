// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Offline fallback page
 *
 * Shown when the user is offline and the requested page
 * is not available in the service worker cache.
 */

import { WifiOff, RefreshCw } from "lucide-react"

export function OfflinePage() {
  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-background px-6 text-center">
      <div className="rounded-2xl bg-slate-500/10 p-6 mb-6">
        <WifiOff size={48} className="text-slate-400" />
      </div>
      <h1 className="text-2xl font-bold text-white mb-2">You're Offline</h1>
      <p className="text-muted-foreground max-w-xs mb-8">
        PhanTeX needs an internet connection to fetch live security data.
        Cached pages may still be available.
      </p>
      <button
        onClick={() => window.location.reload()}
        className="flex items-center gap-2 px-6 py-3 rounded-xl bg-purple-600 text-white font-medium hover:bg-purple-500 active:scale-95 transition-all"
      >
        <RefreshCw size={16} />
        Try Again
      </button>
    </div>
  )
}
