// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Mobile Alert Triage View
 *
 * Card-based, touch-friendly alert triage for mobile/PWA:
 *   - Stacked alert cards with severity color coding
 *   - Swipe-action buttons: Acknowledge, Resolve, False Positive
 *   - Pull-to-refresh via pointer events
 *   - Quick-filter severity pills
 *   - Tap card → navigate to alert detail
 */

import { useState, useCallback, useRef } from "react"
import { useNavigate } from "react-router-dom"
import {
  CheckCircle2,
  XCircle,
  ShieldAlert,
  ChevronRight,
  RefreshCw,
  Bell,
  Filter,
} from "lucide-react"
import { useAlerts, useUpdateAlertStatus } from "@/api/alerts"
import type { AlertFilters } from "@/api/alerts"
import type { AlertSummary, Severity, AlertStatus } from "@/types"
import { cn, timeAgo } from "@/lib/utils"
import { Badge } from "@/components/ui/badge"

/* ── Severity config ──────────────────────────────────────── */

const SEVERITY_CONFIG: Record<
  Severity,
  { bg: string; border: string; text: string; dot: string }
> = {
  critical: {
    bg: "bg-red-500/10",
    border: "border-red-500/30",
    text: "text-red-400",
    dot: "bg-red-500",
  },
  high: {
    bg: "bg-orange-500/10",
    border: "border-orange-500/30",
    text: "text-orange-400",
    dot: "bg-orange-500",
  },
  medium: {
    bg: "bg-yellow-500/10",
    border: "border-yellow-500/30",
    text: "text-yellow-400",
    dot: "bg-yellow-500",
  },
  low: {
    bg: "bg-blue-500/10",
    border: "border-blue-500/30",
    text: "text-blue-400",
    dot: "bg-blue-500",
  },
  info: {
    bg: "bg-slate-500/10",
    border: "border-slate-500/30",
    text: "text-slate-400",
    dot: "bg-slate-500",
  },
}

const SEVERITY_FILTERS: Severity[] = ["critical", "high", "medium", "low", "info"]

/* ── Action buttons for each alert card ───────────────────── */

interface AlertActionProps {
  alertId: string
  onAction: (id: string, status: AlertStatus) => void
  isPending: boolean
}

function AlertActions({ alertId, onAction, isPending }: AlertActionProps) {
  return (
    <div className="flex gap-2 mt-3 pt-3 border-t border-white/5">
      <button
        onClick={(e) => {
          e.stopPropagation()
          onAction(alertId, "acknowledged")
        }}
        disabled={isPending}
        className="flex-1 flex items-center justify-center gap-1.5 py-2 px-3 rounded-lg bg-yellow-500/10 text-yellow-400 text-xs font-medium active:scale-95 transition-transform disabled:opacity-50"
      >
        <Bell size={14} />
        Ack
      </button>
      <button
        onClick={(e) => {
          e.stopPropagation()
          onAction(alertId, "resolved")
        }}
        disabled={isPending}
        className="flex-1 flex items-center justify-center gap-1.5 py-2 px-3 rounded-lg bg-green-500/10 text-green-400 text-xs font-medium active:scale-95 transition-transform disabled:opacity-50"
      >
        <CheckCircle2 size={14} />
        Resolve
      </button>
      <button
        onClick={(e) => {
          e.stopPropagation()
          onAction(alertId, "false_positive")
        }}
        disabled={isPending}
        className="flex-1 flex items-center justify-center gap-1.5 py-2 px-3 rounded-lg bg-slate-500/10 text-slate-400 text-xs font-medium active:scale-95 transition-transform disabled:opacity-50"
      >
        <XCircle size={14} />
        FP
      </button>
    </div>
  )
}

/* ── Alert card ───────────────────────────────────────────── */

interface AlertCardProps {
  alert: AlertSummary
  expanded: boolean
  onToggle: () => void
  onAction: (id: string, status: AlertStatus) => void
  isPending: boolean
  onNavigate: (id: string) => void
}

function AlertCard({
  alert,
  expanded,
  onToggle,
  onAction,
  isPending,
  onNavigate,
}: AlertCardProps) {
  const cfg = SEVERITY_CONFIG[alert.severity]

  return (
    <div
      className={cn(
        "rounded-xl border p-4 transition-all",
        cfg.bg,
        cfg.border,
        expanded && "ring-1 ring-white/10",
      )}
      onClick={onToggle}
    >
      {/* Header row */}
      <div className="flex items-start gap-3">
        <div className={cn("w-2.5 h-2.5 rounded-full mt-1.5 shrink-0", cfg.dot)} />
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-white truncate">{alert.title}</p>
          <div className="flex items-center gap-2 mt-1">
            <span className={cn("text-xs font-semibold uppercase", cfg.text)}>
              {alert.severity}
            </span>
            <span className="text-xs text-muted-foreground">
              {timeAgo(alert.created_at)}
            </span>
            {alert.agent_id && (
              <Badge variant="outline" className="text-[10px] px-1.5 py-0">
                {alert.agent_id.slice(0, 8)}
              </Badge>
            )}
          </div>
        </div>
        <button
          onClick={(e) => {
            e.stopPropagation()
            onNavigate(alert.id)
          }}
          className="shrink-0 p-1.5 rounded-lg hover:bg-white/5 active:scale-90 transition-transform"
        >
          <ChevronRight size={16} className="text-muted-foreground" />
        </button>
      </div>

      {/* Expanded actions */}
      {expanded && (
        <AlertActions alertId={alert.id} onAction={onAction} isPending={isPending} />
      )}
    </div>
  )
}

/* ── Pull-to-refresh indicator ────────────────────────────── */

function PullIndicator({ pulling }: { pulling: boolean }) {
  if (!pulling) return null
  return (
    <div className="flex items-center justify-center py-4">
      <RefreshCw size={20} className="text-purple-400 animate-spin" />
    </div>
  )
}

/* ── Main component ───────────────────────────────────────── */

export function MobileAlertTriage() {
  const navigate = useNavigate()
  const [severityFilter, setSeverityFilter] = useState<Severity | null>(null)
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [pulling, setPulling] = useState(false)
  const pullStartY = useRef<number | null>(null)
  const scrollRef = useRef<HTMLDivElement>(null)

  const filters: AlertFilters = {
    status: "open",
    ...(severityFilter ? { severity: severityFilter } : {}),
    limit: 50,
  }

  const { data, refetch, isLoading } = useAlerts(filters, 5_000)
  const updateStatus = useUpdateAlertStatus()

  const alerts = data?.items ?? []

  const handleAction = useCallback(
    (id: string, status: AlertStatus) => {
      updateStatus.mutate({ id, status })
      if (expandedId === id) setExpandedId(null)
    },
    [updateStatus, expandedId],
  )

  const handleNavigate = useCallback(
    (id: string) => navigate(`/alerts/${id}`),
    [navigate],
  )

  /* ── Pull-to-refresh via touch ────────────────────────── */
  const handleTouchStart = useCallback((e: React.TouchEvent) => {
    if (scrollRef.current && scrollRef.current.scrollTop === 0) {
      pullStartY.current = e.touches[0].clientY
    }
  }, [])

  const handleTouchMove = useCallback((e: React.TouchEvent) => {
    if (pullStartY.current === null) return
    const delta = e.touches[0].clientY - pullStartY.current
    if (delta > 60) setPulling(true)
  }, [])

  const handleTouchEnd = useCallback(() => {
    if (pulling) {
      void refetch()
      setPulling(false)
    }
    pullStartY.current = null
  }, [pulling, refetch])

  return (
    <div className="flex flex-col h-full bg-background">
      {/* ── Sticky header ─────────────────────────────────── */}
      <div className="sticky top-0 z-10 bg-background/95 backdrop-blur-sm border-b border-white/5 px-4 pt-4 pb-3 safe-area-top">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <ShieldAlert size={20} className="text-purple-400" />
            <h1 className="text-lg font-bold text-white">Alert Triage</h1>
          </div>
          <div className="flex items-center gap-1">
            <span className="text-xs text-muted-foreground">
              {alerts.length} open
            </span>
          </div>
        </div>

        {/* Severity filter pills */}
        <div className="flex gap-1.5 overflow-x-auto no-scrollbar">
          <button
            onClick={() => setSeverityFilter(null)}
            className={cn(
              "shrink-0 px-3 py-1.5 rounded-full text-xs font-medium transition-colors",
              severityFilter === null
                ? "bg-purple-500/20 text-purple-300 ring-1 ring-purple-500/30"
                : "bg-white/5 text-muted-foreground",
            )}
          >
            <Filter size={12} className="inline mr-1" />
            All
          </button>
          {SEVERITY_FILTERS.map((sev) => {
            const cfg = SEVERITY_CONFIG[sev]
            return (
              <button
                key={sev}
                onClick={() =>
                  setSeverityFilter(severityFilter === sev ? null : sev)
                }
                className={cn(
                  "shrink-0 px-3 py-1.5 rounded-full text-xs font-medium capitalize transition-colors",
                  severityFilter === sev
                    ? `${cfg.bg} ${cfg.text} ring-1 ${cfg.border}`
                    : "bg-white/5 text-muted-foreground",
                )}
              >
                <span className={cn("inline-block w-1.5 h-1.5 rounded-full mr-1.5", cfg.dot)} />
                {sev}
              </button>
            )
          })}
        </div>
      </div>

      {/* ── Scrollable alert list ─────────────────────────── */}
      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto px-4 py-3 space-y-3 safe-area-bottom"
        onTouchStart={handleTouchStart}
        onTouchMove={handleTouchMove}
        onTouchEnd={handleTouchEnd}
      >
        <PullIndicator pulling={pulling} />

        {isLoading && !alerts.length && (
          <div className="flex items-center justify-center py-20">
            <RefreshCw size={24} className="text-purple-400 animate-spin" />
          </div>
        )}

        {!isLoading && alerts.length === 0 && (
          <div className="flex flex-col items-center justify-center py-20 text-center">
            <CheckCircle2 size={48} className="text-green-400 mb-3" />
            <p className="text-lg font-medium text-white">All Clear</p>
            <p className="text-sm text-muted-foreground mt-1">
              No open alerts. Your agents are safe.
            </p>
          </div>
        )}

        {alerts.map((alert) => (
          <AlertCard
            key={alert.id}
            alert={alert}
            expanded={expandedId === alert.id}
            onToggle={() =>
              setExpandedId(expandedId === alert.id ? null : alert.id)
            }
            onAction={handleAction}
            isPending={updateStatus.isPending}
            onNavigate={handleNavigate}
          />
        ))}
      </div>
    </div>
  )
}
