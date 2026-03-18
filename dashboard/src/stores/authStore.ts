// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Auth Store (Zustand)
 *
 * Full session (token + refreshToken + user) persisted in sessionStorage
 * via Zustand persist middleware. This means page reloads are instant —
 * no round-trip to /auth/refresh needed on every F5.
 *
 * sessionStorage is scoped to the browser tab, so closing the tab
 * clears the session automatically. XSS risk is minimal: if an attacker
 * has script execution, they can already read in-memory state anyway.
 */

import { create } from "zustand"
import { persist, createJSONStorage } from "zustand/middleware"
import type { User, Role } from "@/types"

interface AuthState {
  /* ── State ──────────────────────── */
  token: string | null
  refreshToken: string | null
  user: User | null
  isAuthenticated: boolean

  /* ── Actions ────────────────────── */
  setAuth: (token: string, refreshToken: string, user: User) => void
  updateTokens: (token: string, refreshToken: string) => void
  clearAuth: () => void
  /** Clear the must_change_password flag after successful password change. */
  clearMustChangePassword: () => void
  /** Compat shim — returns the persisted refresh token. */
  hydrateRefreshToken: () => string | null
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      token: null,
      refreshToken: null,
      user: null,
      isAuthenticated: false,

      setAuth: (token, refreshToken, user) => {
        set({ token, refreshToken, user, isAuthenticated: true })
      },

      updateTokens: (token, refreshToken) => {
        set({ token, refreshToken })
      },

      clearAuth: () => {
        set({ token: null, refreshToken: null, user: null, isAuthenticated: false })
      },

      clearMustChangePassword: () => {
        const user = get().user
        if (user) {
          set({ user: { ...user, must_change_password: false } })
        }
      },

      hydrateRefreshToken: () => {
        return get().refreshToken
      },
    }),
    {
      name: "phantex-auth",
      storage: createJSONStorage(() => sessionStorage),
      // Only persist what we need for rehydration
      partialize: (state) => ({
        token: state.token,
        refreshToken: state.refreshToken,
        user: state.user,
        isAuthenticated: state.isAuthenticated,
      }),
    },
  ),
)

/* ── Selectors (for convenience) ─────────────────────────────────────────── */

export const selectIsAdmin = (state: AuthState): boolean =>
  state.user?.role === "admin"

export const selectRole = (state: AuthState): Role | null =>
  state.user?.role ?? null
