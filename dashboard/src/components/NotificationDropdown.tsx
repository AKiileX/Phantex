// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Notification dropdown panel.
 *
 * Shows recent alerts in a slide-down panel from the header bell icon.
 * Includes severity badges, time ago, link to alert detail, and
 * "Clear All" action to acknowledge all open alerts.
 */

import { useState, useRef, useEffect, useCallback } from "react"
import { useNavigate } from "react-router-dom"
import { Bell, ExternalLink, CheckCheck, X } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { useAlerts, useUpdateAlertStatus, useBulkAcknowledge } from "@/api/alerts"
import { timeAgo } from "@/lib/utils"

export function NotificationDropdown() {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  const navigate = useNavigate()

  const { data: openAlerts } = useAlerts({ status: "open" })
  const alerts = openAlerts?.items?.slice(0, 8) ?? []
  const totalOpen = openAlerts?.items?.length ?? 0
  const updateAlert = useUpdateAlertStatus()
  const bulkAck = useBulkAcknowledge()

  // Close on outside click
  useEffect(() => {
    if (!open) return
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false)
      }
    }
    document.addEventListener("mousedown", handler)
    return () => document.removeEventListener("mousedown", handler)
  }, [open])

  // Close on Escape
  useEffect(() => {
    if (!open) return
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false)
    }
    window.addEventListener("keydown", handler)
    return () => window.removeEventListener("keydown", handler)
  }, [open])

  const handleClearAll = useCallback(() => {
    bulkAck.mutate()
  }, [bulkAck])

  const handleDismiss = useCallback(
    (e: React.MouseEvent, alertId: string) => {
      e.stopPropagation()
      updateAlert.mutate({ id: alertId, status: "acknowledged" })
    },
    [updateAlert],
  )

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen((v) => !v)}
        className="relative flex h-8 w-8 items-center justify-center rounded-lg text-muted-foreground hover:text-foreground hover:bg-white/[0.04] transition-colors cursor-pointer"
        title="Notifications"
      >
        <Bell size={15} />
        {totalOpen > 0 && (
          <span className="absolute -top-0.5 -right-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-severity-critical px-1 text-[9px] font-bold text-white animate-pulse">
            {totalOpen > 9 ? "9+" : totalOpen}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-2 w-[400px] rounded-xl border border-border/50 glass-user-card shadow-2xl shadow-black/40 z-50 animate-slide-up overflow-hidden">
          {/* Header */}
          <div className="flex items-center justify-between px-4 py-3 border-b border-border/30">
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold text-foreground">Notifications</h3>
              {totalOpen > 0 && (
                <span className="flex h-5 min-w-5 items-center justify-center rounded-full bg-severity-critical/20 px-1.5 text-[10px] font-bold text-severity-critical">
                  {totalOpen}
                </span>
              )}
            </div>
            <div className="flex items-center gap-2">
              {totalOpen > 0 && (
                <button
                  onClick={handleClearAll}
                  className="flex items-center gap-1 px-2 py-1 rounded-md text-[11px] font-medium text-muted-foreground hover:text-foreground hover:bg-white/[0.06] transition-all cursor-pointer"
                  title="Acknowledge all open alerts"
                >
                  <CheckCheck size={12} />
                  Clear all
                </button>
              )}
              <button
                onClick={() => {
                  navigate("/alerts")
                  setOpen(false)
                }}
                className="text-[11px] font-medium text-primary/80 hover:text-primary transition-colors cursor-pointer"
              >
                View all
              </button>
            </div>
          </div>

          {/* Alert list */}
          <div className="max-h-[380px] overflow-y-auto">
            {alerts.length === 0 ? (
              <div className="px-4 py-10 text-center">
                <div className="flex h-12 w-12 items-center justify-center rounded-full bg-white/[0.03] mx-auto mb-3">
                  <Bell size={20} className="text-muted-foreground/30" />
                </div>
                <p className="text-sm font-medium text-foreground/60">All clear</p>
                <p className="text-xs text-muted-foreground mt-1">No open alerts right now</p>
              </div>
            ) : (
              <div className="divide-y divide-border/20">
                {alerts.map((alert) => (
                  <div
                    key={alert.id}
                    className="group relative flex items-start gap-3 w-full px-4 py-3 text-left hover:bg-white/[0.03] transition-colors"
                  >
                    <button
                      onClick={() => {
                        navigate(`/alerts/${alert.id}`)
                        setOpen(false)
                      }}
                      className="flex items-start gap-3 flex-1 min-w-0 cursor-pointer"
                    >
                      <Badge
                        variant={alert.severity as "critical" | "high" | "medium" | "low"}
                        className="mt-0.5 flex-shrink-0"
                      >
                        {alert.severity}
                      </Badge>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm text-foreground/90 font-medium truncate">
                          {alert.title}
                        </p>
                        <p className="text-[11px] text-muted-foreground mt-0.5">
                          Agent {alert.agent_id?.slice(0, 8) ?? "—"} · {timeAgo(alert.created_at)}
                        </p>
                      </div>
                      <ExternalLink
                        size={12}
                        className="mt-1 flex-shrink-0 text-muted-foreground/0 group-hover:text-muted-foreground/50 transition-colors"
                      />
                    </button>
                    {/* Dismiss single alert */}
                    <button
                      onClick={(e) => handleDismiss(e, alert.id)}
                      className="absolute top-2 right-2 flex h-6 w-6 items-center justify-center rounded-md opacity-0 group-hover:opacity-100 text-muted-foreground/50 hover:text-foreground hover:bg-white/[0.06] transition-all cursor-pointer"
                      title="Dismiss"
                    >
                      <X size={12} />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Footer hint */}
          {totalOpen > 8 && (
            <div className="border-t border-border/20 px-4 py-2 text-center">
              <span className="text-[11px] text-muted-foreground">
                +{totalOpen - 8} more alert{totalOpen - 8 !== 1 ? "s" : ""}
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
