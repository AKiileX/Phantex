// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Theme store (Zustand).
 *
 * Supports dark / light / system modes with localStorage persistence.
 * Applies `dark` or `light` class to <html> and sets data-theme attribute.
 */

import { create } from "zustand"

export type ThemeMode = "dark" | "light" | "system"

const STORAGE_KEY = "phantex_theme"

function getSystemPref(): "dark" | "light" {
  if (typeof window === "undefined") return "dark"
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"
}

function applyTheme(mode: ThemeMode) {
  const resolved = mode === "system" ? getSystemPref() : mode
  const root = document.documentElement
  root.classList.remove("dark", "light")
  root.classList.add(resolved)
  root.setAttribute("data-theme", resolved)
  root.style.colorScheme = resolved

  // Update <meta name="color-scheme"> so browsers / Dark Reader honour it
  const meta = document.querySelector('meta[name="color-scheme"]')
  if (meta) meta.setAttribute("content", resolved)
}

const initial: ThemeMode = (() => {
  try {
    const v = localStorage.getItem(STORAGE_KEY)
    if (v === "light" || v === "dark" || v === "system") return v
  } catch {
    /* safe */
  }
  return "dark"
})()

// Apply immediately on module load
applyTheme(initial)

interface ThemeState {
  mode: ThemeMode
  resolved: "dark" | "light"
  setMode: (m: ThemeMode) => void
}

export const useThemeStore = create<ThemeState>((set) => ({
  mode: initial,
  resolved: initial === "system" ? getSystemPref() : initial,
  setMode: (m) => {
    try {
      localStorage.setItem(STORAGE_KEY, m)
    } catch {
      /* safe */
    }
    applyTheme(m)
    set({ mode: m, resolved: m === "system" ? getSystemPref() : m })
  },
}))

// Listen for system preference changes
if (typeof window !== "undefined") {
  window
    .matchMedia("(prefers-color-scheme: dark)")
    .addEventListener("change", () => {
      const { mode } = useThemeStore.getState()
      if (mode === "system") {
        applyTheme("system")
        useThemeStore.setState({ resolved: getSystemPref() })
      }
    })
}
