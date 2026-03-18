// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Auth hook (login, logout, refresh, current user check).
 */

import { useCallback } from "react"
import { useNavigate } from "react-router-dom"
import { useAuthStore } from "@/stores/authStore"
import { usePermissionStore } from "@/stores/permissionStore"
import { login as apiLogin, fetchMe, refreshTokens } from "@/api/auth"

export function useAuth() {
  const { user, isAuthenticated, setAuth, updateTokens, clearAuth } =
    useAuthStore()
  const clearPermissions = usePermissionStore((s) => s.clear)
  const navigate = useNavigate()

  const login = useCallback(
    async (email: string, password: string) => {
      const tokens = await apiLogin(email, password)
      // Fetch user profile with the new token
      const me = await fetchMe(tokens.access_token)
      // Merge must_change_password from token response into user object
      if (tokens.must_change_password) {
        me.must_change_password = true
      }
      setAuth(tokens.access_token, tokens.refresh_token, me)
      navigate("/")
    },
    [setAuth, navigate],
  )

  const logout = useCallback(() => {
    clearAuth()
    clearPermissions()
    // Clear PWA runtime caches to prevent stale data leaking between sessions
    if ("caches" in window) {
      void caches.delete("api-data")
      void caches.delete("api-health")
    }
    navigate("/login")
  }, [clearAuth, clearPermissions, navigate])

  const refresh = useCallback(async () => {
    const rt = useAuthStore.getState().refreshToken
    if (!rt) {
      clearAuth()
      return false
    }
    try {
      const tokens = await refreshTokens(rt)
      updateTokens(tokens.access_token, tokens.refresh_token)
      return true
    } catch {
      clearAuth()
      return false
    }
  }, [clearAuth, updateTokens])

  return { user, isAuthenticated, login, logout, refresh }
}
