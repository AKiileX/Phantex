// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — usePermissions hook.
 *
 * Fetches the current user's permissions from GET /api/v1/auth/me/permissions
 * and stores them in the permission store. Re-fetches every 30 seconds.
 *
 * Also handles clearing permissions on logout.
 *
 * Usage:
 *   const { can, canAny, canAll, loaded } = usePermissions()
 *   if (can("alerts.acknowledge")) { ... }
 */

import { useEffect, useCallback } from "react"
import { useAuthStore } from "@/stores/authStore"
import { usePermissionStore } from "@/stores/permissionStore"
import apiClient from "@/api/client"

/** How often to re-fetch permissions (ms) */
const REFETCH_INTERVAL = 30_000

interface PermissionsAPI {
  permissions: string[]
}

export function usePermissions() {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  const setPermissions = usePermissionStore((s) => s.setPermissions)
  const clear = usePermissionStore((s) => s.clear)
  const loaded = usePermissionStore((s) => s.loaded)
  const has = usePermissionStore((s) => s.has)
  const hasAny = usePermissionStore((s) => s.hasAny)
  const hasAll = usePermissionStore((s) => s.hasAll)

  const fetchPermissions = useCallback(async () => {
    try {
      const { data } = await apiClient.get<PermissionsAPI>("/auth/me/permissions")
      setPermissions(data.permissions)
    } catch {
      // On 401 the axios interceptor will handle refresh/logout
      // On other errors, keep stale permissions rather than clearing
    }
  }, [setPermissions])

  // Fetch on mount + interval while authenticated
  useEffect(() => {
    if (!isAuthenticated) {
      clear()
      return
    }

    // Initial fetch
    fetchPermissions()

    // Periodic refresh
    const interval = setInterval(fetchPermissions, REFETCH_INTERVAL)
    return () => clearInterval(interval)
  }, [isAuthenticated, fetchPermissions, clear])

  return {
    /** Check a single permission */
    can: has,
    /** Check if user has ANY of the given permissions (OR) */
    canAny: hasAny,
    /** Check if user has ALL of the given permissions (AND) */
    canAll: hasAll,
    /** Whether the permission set has been fetched at least once */
    loaded,
  }
}

/**
 * Static (non-hook) permission check — reads directly from the store.
 * Use in event handlers or non-component code.
 */
export function checkPermission(permission: string): boolean {
  return usePermissionStore.getState().has(permission)
}
