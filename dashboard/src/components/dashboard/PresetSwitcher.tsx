// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Dashboard preset view selector.
 *
 * Switches between three curated dashboard layouts:
 *   • Executive  — high-level posture, KPIs, risk summary
 *   • SOC Analyst — detections, alert triage, activity feed
 *   • Threat Hunter — events, ATLAS mapping, topology link
 *
 * Persists choice to localStorage so it survives refresh.
 */

import { LayoutDashboard, ShieldCheck, Crosshair } from "lucide-react"
import { PRESETS, useDashboardPreset } from "./presetStore"

const PRESET_ICONS: Record<string, React.ReactNode> = {
  executive: <LayoutDashboard size={13} />,
  soc: <ShieldCheck size={13} />,
  hunter: <Crosshair size={13} />,
}

/* ── Preset tab bar component ──────────────────────────────── */
export function PresetSwitcher() {
  const { preset, setPreset } = useDashboardPreset()

  return (
    <div className="flex items-center gap-1 p-0.5 rounded-lg bg-white/[0.03] border border-border/30">
      {PRESETS.map((p) => {
        const active = p.id === preset
        return (
          <button
            key={p.id}
            type="button"
            onClick={() => setPreset(p.id)}
            title={p.description}
            className={`
              flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium
              transition-all cursor-pointer
              ${
                active
                  ? "bg-primary/10 text-primary shadow-sm"
                  : "text-muted-foreground hover:text-foreground hover:bg-white/[0.04]"
              }
            `}
          >
            {PRESET_ICONS[p.id]}
            {p.label}
          </button>
        )
      })}
    </div>
  )
}
