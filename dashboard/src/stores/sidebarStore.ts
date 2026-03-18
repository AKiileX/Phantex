// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Sidebar state (Zustand).
 *
 * Controls collapsed/expanded state with localStorage persistence.
 * Keyboard shortcut: [ to toggle.
 */

import { create } from "zustand"

const STORAGE_KEY = "phantex_sidebar_collapsed"

interface SidebarState {
  collapsed: boolean
  toggle: () => void
  setCollapsed: (v: boolean) => void
}

const initial = (() => {
  try {
    return localStorage.getItem(STORAGE_KEY) === "true"
  } catch {
    return false
  }
})()

export const useSidebarStore = create<SidebarState>((set) => ({
  collapsed: initial,
  toggle: () =>
    set((s) => {
      const next = !s.collapsed
      try {
        localStorage.setItem(STORAGE_KEY, String(next))
      } catch {
        /* safe */
      }
      return { collapsed: next }
    }),
  setCollapsed: (v) => {
    try {
      localStorage.setItem(STORAGE_KEY, String(v))
    } catch {
      /* safe */
    }
    set({ collapsed: v })
  },
}))
