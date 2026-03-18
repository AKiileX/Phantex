// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — <Can> Permission Gate Component.
 *
 * Conditionally renders children based on the current user's permissions.
 * Reads from the permission store (populated by usePermissions hook).
 *
 * Usage:
 *   <Can permission="alerts.acknowledge">
 *     <Button>Acknowledge</Button>
 *   </Can>
 *
 *   <Can anyOf={["rules.write", "rules.delete"]}>
 *     <EditSection />
 *   </Can>
 *
 *   <Can permission="alerts.delete" fallback={<span>No access</span>}>
 *     <Button variant="destructive">Delete</Button>
 *   </Can>
 */

import type { ReactNode } from "react"
import { usePermissionStore } from "@/stores/permissionStore"

interface CanProps {
  /** Single permission to check */
  permission?: string
  /** User must have ANY of these (OR logic) */
  anyOf?: string[]
  /** User must have ALL of these (AND logic) */
  allOf?: string[]
  /** Content to show if user has the permission(s) */
  children: ReactNode
  /** Content to show if user lacks the permission(s) */
  fallback?: ReactNode
}

export function Can({ permission, anyOf, allOf, children, fallback = null }: CanProps) {
  const permissions = usePermissionStore((s) => s.permissions)
  const loaded = usePermissionStore((s) => s.loaded)

  // Don't render anything until permissions are loaded
  if (!loaded) return null

  let allowed = false

  if (permission) {
    allowed = permissions.has(permission)
  } else if (anyOf) {
    allowed = anyOf.some((p) => permissions.has(p))
  } else if (allOf) {
    allowed = allOf.every((p) => permissions.has(p))
  }

  return <>{allowed ? children : fallback}</>
}
