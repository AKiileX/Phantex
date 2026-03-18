// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Protected route wrapper.
 *
 * Redirects to /login if not authenticated.
 * Supports BOTH legacy role checks AND granular permission checks.
 *
 * Priority:
 *   1. requiredPermissions — checked against the user's effective permission set (ABAC)
 *   2. allowedRoles — legacy fallback for backward compatibility
 */

import { Navigate, Outlet, useLocation } from "react-router-dom"
import { useAuthStore } from "@/stores/authStore"
import { usePermissionStore } from "@/stores/permissionStore"
import { ForceChangePasswordModal } from "@/components/ForceChangePasswordModal"
import type { Role } from "@/types"

interface ProtectedRouteProps {
  /** Legacy: user must have one of these roles. */
  allowedRoles?: Role[]
  /** Granular: user must have ANY of these permissions (OR logic). */
  requiredPermissions?: string[]
}

export function ProtectedRoute({ allowedRoles, requiredPermissions }: ProtectedRouteProps) {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  const userRole = useAuthStore((s) => s.user?.role)
  const location = useLocation()
  const permissions = usePermissionStore((s) => s.permissions)
  const permissionsLoaded = usePermissionStore((s) => s.loaded)

  const mustChangePassword = useAuthStore((s) => s.user?.must_change_password)

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />
  }

  // Block all navigation until password is changed
  if (mustChangePassword) {
    return <ForceChangePasswordModal />
  }

  // If permission-based gate is specified, use it (takes priority)
  if (requiredPermissions && requiredPermissions.length > 0) {
    // Wait until permissions are loaded before deciding
    if (!permissionsLoaded) {
      return (
        <div className="flex items-center justify-center py-24">
          <div className="h-6 w-6 animate-spin rounded-full border-2 border-primary/20 border-t-primary" />
        </div>
      )
    }
    const hasPermission = requiredPermissions.some((p) => permissions.has(p))
    if (!hasPermission) {
      return <Navigate to="/" replace />
    }
  }

  // Legacy role-based gate (backward compat)
  if (allowedRoles && userRole && !allowedRoles.includes(userRole)) {
    return <Navigate to="/" replace />
  }

  return <Outlet />
}
