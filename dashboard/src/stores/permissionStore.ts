// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Permission Store (Zustand).
 *
 * Holds the current user's effective permission set.
 * Fetched from GET /api/v1/auth/me/permissions on login and periodically.
 * Used by <Can>, usePermissions(), ProtectedRoute, and Sidebar
 * to drive granular UI visibility.
 */

import { create } from "zustand"

interface PermissionState {
  /** Set of "resource.action" strings the current user holds */
  permissions: Set<string>
  /** Whether the initial fetch has completed */
  loaded: boolean
  /** Timestamp of last successful fetch */
  fetchedAt: number | null

  // Actions
  setPermissions: (perms: string[]) => void
  clear: () => void
  /** Check single permission */
  has: (permission: string) => boolean
  /** Check ANY of the provided permissions (OR logic) */
  hasAny: (...permissions: string[]) => boolean
  /** Check ALL of the provided permissions (AND logic) */
  hasAll: (...permissions: string[]) => boolean
}

export const usePermissionStore = create<PermissionState>()((set, get) => ({
  permissions: new Set<string>(),
  loaded: false,
  fetchedAt: null,

  setPermissions: (perms: string[]) => {
    set({ permissions: new Set(perms), loaded: true, fetchedAt: Date.now() })
  },

  clear: () => {
    set({ permissions: new Set<string>(), loaded: false, fetchedAt: null })
  },

  has: (permission: string) => get().permissions.has(permission),

  hasAny: (...permissions: string[]) => {
    const current = get().permissions
    return permissions.some((p) => current.has(p))
  },

  hasAll: (...permissions: string[]) => {
    const current = get().permissions
    return permissions.every((p) => current.has(p))
  },
}))

/* ── Selectors ───────────────────────────────────────────────────────────── */

/** Select the raw permission set */
export const selectPermissions = (s: PermissionState) => s.permissions

/** Select whether permissions have been loaded */
export const selectPermissionsLoaded = (s: PermissionState) => s.loaded
