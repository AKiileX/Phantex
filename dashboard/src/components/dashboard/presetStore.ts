// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Dashboard preset definitions and Zustand store.
 * Separated from PresetSwitcher component to avoid react-refresh full reloads.
 */

import { create } from "zustand"

export type DashboardPreset = "executive" | "soc" | "hunter"

export interface PresetInfo {
  id: DashboardPreset
  label: string
  description: string
}

export const PRESETS: PresetInfo[] = [
  {
    id: "executive",
    label: "Executive",
    description: "KPIs & posture overview",
  },
  {
    id: "soc",
    label: "SOC Analyst",
    description: "Alerts, triage & live feed",
  },
  {
    id: "hunter",
    label: "Threat Hunter",
    description: "Events, patterns & ATLAS",
  },
]

const STORAGE_KEY = "phantex_dashboard_preset"

const initial: DashboardPreset = (() => {
  try {
    const v = localStorage.getItem(STORAGE_KEY)
    if (v === "executive" || v === "soc" || v === "hunter") return v
  } catch {
    /* safe */
  }
  return "soc"
})()

interface PresetState {
  preset: DashboardPreset
  setPreset: (p: DashboardPreset) => void
}

export const useDashboardPreset = create<PresetState>((set) => ({
  preset: initial,
  setPreset: (p) => {
    try {
      localStorage.setItem(STORAGE_KEY, p)
    } catch {
      /* safe */
    }
    set({ preset: p })
  },
}))
