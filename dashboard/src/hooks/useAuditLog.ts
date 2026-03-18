// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Audit Logger.
 *
 * Fire-and-forget client-side audit logging that sends user actions
 * to the backend audit trail. Used for admin-sensitive operations
 * (config changes, retrain triggers, export channel mutations, etc.)
 *
 * The hook returns a `logAction` function. Failures are silently
 * swallowed — audit logs must never block the UI.
 *
 * @module hooks/useAuditLog
 */

import { useCallback } from "react"
import apiClient from "@/api/client"
import { useAuthStore } from "@/stores/authStore"

export interface AuditEntry {
  /** e.g. "telemetry.config.update", "export.channel.create" */
  action: string
  /** The entity being acted upon (channel id, model version, etc.) */
  target?: string
  /** Arbitrary metadata */
  details?: Record<string, unknown>
}

/**
 * Returns a stable `logAction` function scoped to the current user.
 *
 * Usage:
 *   const logAction = useAuditLog()
 *   logAction({ action: "telemetry.config.update", details: { enabled: true } })
 */
export function useAuditLog() {
  const userId = useAuthStore((s) => s.user?.id)

  return useCallback(
    (entry: AuditEntry) => {
      apiClient
        .post("/audit/log", {
          ...entry,
          user_id: userId,
          timestamp: new Date().toISOString(),
        })
        .catch(() => {
          /* audit failures are silently swallowed — never block UI */
        })
    },
    [userId],
  )
}
