// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Activity stream widget for the dashboard.
 *
 * Shows a real-time rolling feed of the most recent security events
 * and alerts, ordered by time, with severity indicators and relative
 * timestamps. Auto-refreshes every 8 seconds.
 */

import { useMemo } from "react"
import {
  Activity,
  ShieldAlert,
  AlertTriangle,
  Info,
  Zap,
  Eye,
} from "lucide-react"
import { useNavigate } from "react-router-dom"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { useAlerts } from "@/api/alerts"
import { useEvents } from "@/api/events"
import { timeAgo } from "@/lib/utils"

/* ── Event type → icon mapping ─────────────────────────────── */
const TYPE_ICONS: Record<string, React.ReactNode> = {
  prompt_injection: <ShieldAlert size={13} className="text-severity-critical" />,
  data_exfiltration: <AlertTriangle size={13} className="text-severity-high" />,
  tool_misuse: <Zap size={13} className="text-severity-medium" />,
  anomaly: <Eye size={13} className="text-severity-low" />,
}

const SEV_DOT: Record<string, string> = {
  critical: "bg-severity-critical",
  high: "bg-severity-high",
  medium: "bg-severity-medium",
  low: "bg-severity-low",
  info: "bg-severity-info",
}

interface StreamItem {
  id: string
  kind: "alert" | "event"
  title: string
  severity: string
  type?: string
  agentId?: string
  timestamp: string
}

export function ActivityStream() {
  const navigate = useNavigate()
  const { data: alerts } = useAlerts({ status: "open", limit: 10 }, 8_000)
  const { data: events } = useEvents({ limit: 15 }, 8_000)

  const items = useMemo<StreamItem[]>(() => {
    const merged: StreamItem[] = []

    for (const a of alerts?.items ?? []) {
      merged.push({
        id: a.id,
        kind: "alert",
        title: a.title,
        severity: a.severity,
        type: undefined,
        agentId: a.agent_id ?? undefined,
        timestamp: a.created_at,
      })
    }
    for (const e of events?.items ?? []) {
      merged.push({
        id: e.id,
        kind: "event",
        title: e.event_type ?? "Event",
        severity: e.severity ?? "info",
        type: e.event_type,
        agentId: e.agent_id ?? undefined,
        timestamp: e.timestamp,
      })
    }

    // Sort newest first, de-dup by id
    merged.sort(
      (a, b) =>
        new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
    )
    const seen = new Set<string>()
    return merged.filter((m) => {
      if (seen.has(m.id)) return false
      seen.add(m.id)
      return true
    }).slice(0, 15)
  }, [alerts?.items, events?.items])

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="flex items-center gap-1.5">
          <Activity size={14} className="text-primary" />
          Activity Stream
        </CardTitle>
        <span className="text-[10px] uppercase tracking-wider text-muted-foreground">
          Live
          <span className="inline-block ml-1.5 h-1.5 w-1.5 rounded-full bg-primary animate-pulse" />
        </span>
      </CardHeader>
      <CardContent>
        {items.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-10 text-center">
            <Activity size={22} className="text-muted-foreground mb-2" />
            <p className="text-sm text-muted-foreground">No recent activity</p>
          </div>
        ) : (
          <div className="space-y-0.5 max-h-[360px] overflow-y-auto -mx-1 px-1">
            {items.map((item, i) => (
              <button
                key={`${item.kind}-${item.id}`}
                type="button"
                onClick={() =>
                  navigate(
                    item.kind === "alert"
                      ? `/alerts/${item.id}`
                      : `/events/${item.id}`,
                  )
                }
                className="flex items-start gap-2.5 w-full text-left py-2 px-2 -mx-2 rounded-lg hover:bg-white/[0.03] transition-colors cursor-pointer"
                style={{ animationDelay: `${i * 20}ms` }}
              >
                {/* Severity dot */}
                <div className="mt-1.5 flex-shrink-0">
                  <span
                    className={`block h-1.5 w-1.5 rounded-full ${SEV_DOT[item.severity] ?? SEV_DOT.info}`}
                  />
                </div>

                {/* Icon */}
                <div className="mt-0.5 flex-shrink-0">
                  {TYPE_ICONS[item.type ?? ""] ?? (
                    <Info size={13} className="text-muted-foreground" />
                  )}
                </div>

                {/* Content */}
                <div className="flex-1 min-w-0">
                  <p className="text-[13px] text-foreground/90 truncate leading-tight">
                    {item.title}
                  </p>
                  <div className="flex items-center gap-2 mt-0.5">
                    <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground/60">
                      {item.kind}
                    </span>
                    {item.agentId && (
                      <span className="text-[10px] font-mono text-muted-foreground/50">
                        {item.agentId.slice(0, 8)}
                      </span>
                    )}
                  </div>
                </div>

                {/* Time */}
                <span className="text-[10px] text-muted-foreground whitespace-nowrap tabular-nums mt-0.5">
                  {timeAgo(item.timestamp)}
                </span>
              </button>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
