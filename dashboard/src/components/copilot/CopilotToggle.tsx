// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Copilot toggle button (bottom-right FAB).
 *
 * Floating action button that opens the Copilot panel.
 * Only visible to users with copilot.use permission.
 * Pulses gently when LLM is connected and healthy.
 */

import { Sparkles } from "lucide-react"
import { cn } from "@/lib/utils"
import { toggleCopilot } from "@/components/copilot/copilotState"
import { usePermissionStore } from "@/stores/permissionStore"
import { useCopilotHealth } from "@/api/copilot"

export function CopilotToggle() {
  const perms = usePermissionStore((s) => s.permissions)
  const canUse = perms.has("copilot.use") || perms.has("*")
  const { data: health } = useCopilotHealth(canUse)

  if (!canUse) return null

  const isHealthy = health?.copilot_status === "healthy"

  return (
    <button
      onClick={toggleCopilot}
      title="Phantex Copilot (Ctrl+K)"
      className={cn(
        "fixed bottom-6 right-6 z-40 flex items-center gap-2 rounded-full shadow-lg transition-all duration-200",
        "px-4 py-3",
        "bg-gradient-to-br from-emerald-600 to-cyan-600 text-white",
        "hover:from-emerald-500 hover:to-cyan-500 hover:shadow-emerald-500/30 hover:shadow-xl hover:scale-105",
        "active:scale-95",
        "ring-2 ring-emerald-400/20",
        isHealthy && "animate-pulse-subtle",
      )}
    >
      <Sparkles size={20} />
      <span className="text-sm font-medium tracking-wide">Copilot</span>
    </button>
  )
}
