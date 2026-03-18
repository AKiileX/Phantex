// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Agent detail page (enterprise split-pane layout).
 *
 * Agent metadata cards + event timeline + alert list.
 * Dense, functional, zero decoration.
 */

import { useState } from "react"
import { useParams, Link, useNavigate } from "react-router-dom"
import { ArrowLeft, Monitor, Tag, Globe, Cpu, HelpCircle, Trash2 } from "lucide-react"
import { useAgent, useRemoveAgent } from "@/api/agents"
import { useEvents } from "@/api/events"
import { useAlerts } from "@/api/alerts"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { TagEditor } from "@/components/agents/TagEditor"
import { formatDate, timeAgo } from "@/lib/utils"

function DetailRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between py-1.5 border-b border-border last:border-0">
      <span className="text-sm text-muted-foreground">{label}</span>
      <div className="text-sm text-foreground text-right max-w-[60%] truncate">{children}</div>
    </div>
  )
}

export function AgentDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [showGuide, setShowGuide] = useState(false)
  const [confirmRemove, setConfirmRemove] = useState(false)
  const { data: agent, isLoading } = useAgent(id ?? "")
  const removeAgent = useRemoveAgent()
  // Events/alerts are keyed by PAID (text), not UUID — use paid once agent loads
  const agentKey = agent?.paid ?? id
  const { data: events } = useEvents({ agent_id: agentKey, limit: 10 })
  const { data: alerts } = useAlerts({ agent_id: agentKey })

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20 text-sm text-muted-foreground">
        Loading agent details…
      </div>
    )
  }

  if (!agent) {
    return (
      <div className="flex flex-col items-center justify-center py-20 gap-2">
        <Monitor size={28} className="text-surface-3" />
        <p className="text-sm text-muted-foreground">Agent not found</p>
      </div>
    )
  }

  return (
    <div className="space-y-4 animate-fade-in">
      {/* Back + title */}
      <div className="flex items-center gap-3">
        <Link to="/agents">
          <Button variant="ghost" size="sm" className="gap-1">
            <ArrowLeft size={14} /> Agents
          </Button>
        </Link>
        <div className="h-4 w-px bg-border" />
        <h1 className="text-xl font-semibold text-foreground">
          {agent.name ?? agent.paid}
        </h1>
        <Badge variant={agent.status as "active" | "stale" | "terminated"}>
          {agent.status}
        </Badge>
        <div className="ml-auto flex items-center gap-2">
          {agent.status !== "terminated" && (
            confirmRemove ? (
              <div className="flex items-center gap-2">
                <span className="text-xs text-muted-foreground">Remove this agent?</span>
                <Button
                  variant="destructive"
                  size="sm"
                  disabled={removeAgent.isPending}
                  onClick={() => {
                    removeAgent.mutate(agent.id, {
                      onSuccess: () => navigate("/agents"),
                    })
                  }}
                >
                  {removeAgent.isPending ? "Removing…" : "Confirm"}
                </Button>
                <Button variant="ghost" size="sm" onClick={() => setConfirmRemove(false)}>Cancel</Button>
              </div>
            ) : (
              <Button
                variant="outline"
                size="sm"
                className="gap-1.5 text-destructive border-destructive/30 hover:bg-destructive/10"
                onClick={() => setConfirmRemove(true)}
              >
                <Trash2 size={13} /> Remove Agent
              </Button>
            )
          )}
          <button onClick={() => setShowGuide(!showGuide)} className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"><HelpCircle size={14} />{showGuide ? "Hide Guide" : "How does this work?"}</button>
        </div>
      </div>

      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5 space-y-3 text-sm text-muted-foreground">
          <h3 className="text-base font-semibold text-foreground">How does Agent Detail work?</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Agent Lookup</p>
              <p>Fetches via <code className="text-xs bg-white/5 px-1 rounded">GET /api/v1/agents/{'{id}'}</code> using the UUID. The PAID (Phantex Agent ID) is a human-readable identifier like <code className="text-xs bg-white/5 px-1 rounded">ptx-default-dev-f23bb1c5b0f9</code>. Events and alerts are then queried by PAID for cross-referencing.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Enriched Metadata</p>
              <p>Shows framework detected (LangChain, AutoGen, etc.), OS type, IP/hostname from sensor discovery, trust score from the trust engine, and tags. Tags are editable and stored via the agent update endpoint.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Event Timeline</p>
              <p>Last 10 events from this specific agent, fetched via <code className="text-xs bg-white/5 px-1 rounded">GET /api/v1/events?agent_id={'{paid}'}</code>. Shows event type, severity, and relative timestamp. Click any event to see its full detail.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Alert History</p>
              <p>All alerts triggered by this agent, fetched via <code className="text-xs bg-white/5 px-1 rounded">GET /api/v1/alerts?agent_id={'{paid}'}</code>. Each alert links to its detail page for triage. Severity badges give at-a-glance risk assessment.</p>
            </div>
          </div>
        </div>
      )}

      {/* Metadata grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="pb-1">
            <CardTitle className="text-xs text-muted-foreground">Agent Identifier</CardTitle>
          </CardHeader>
          <CardContent>
            <DetailRow label="PAID">
              <span className="font-mono">{agent.paid}</span>
            </DetailRow>
            <DetailRow label="Framework">
              {agent.framework ?? "Unknown"}
            </DetailRow>
            <DetailRow label="Version">
              {agent.framework_ver ?? "—"}
            </DetailRow>
            <DetailRow label="Host ID">
              <span className="font-mono text-xs">{agent.host_id ?? "—"}</span>
            </DetailRow>
            <DetailRow label="Sensor ID">
              <span className="font-mono text-xs">{agent.sensor_id ?? "—"}</span>
            </DetailRow>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-1 flex flex-row items-center gap-2">
            <Globe size={14} className="text-muted-foreground" />
            <CardTitle className="text-xs text-muted-foreground">Host & Network</CardTitle>
          </CardHeader>
          <CardContent>
            <DetailRow label="Hostname">
              <span className="font-mono text-xs">{agent.hostname ?? "—"}</span>
            </DetailRow>
            <DetailRow label="IP Address">
              <span className="font-mono text-xs">{agent.ip_address ?? "—"}</span>
            </DetailRow>
            <DetailRow label="OS">
              <span className="capitalize">{agent.os_type ?? "—"}</span>
            </DetailRow>
            <DetailRow label="OS Version">
              <span className="text-xs">{agent.os_version ?? "—"}</span>
            </DetailRow>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-1">
            <CardTitle className="text-xs text-muted-foreground">Runtime</CardTitle>
          </CardHeader>
          <CardContent>
            <DetailRow label="Container">
              <span className="font-mono text-xs">{agent.container_id?.slice(0, 12) ?? "—"}</span>
            </DetailRow>
            <DetailRow label="Image">
              {agent.container_image ?? "—"}
            </DetailRow>
            <DetailRow label="Process PID">
              <span className="tabular-nums">{agent.process_pid ?? "—"}</span>
            </DetailRow>
            <DetailRow label="Executable">
              <span className="font-mono text-xs">{agent.exe_path ?? "—"}</span>
            </DetailRow>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-1 flex flex-row items-center gap-2">
            <Cpu size={14} className="text-muted-foreground" />
            <CardTitle className="text-xs text-muted-foreground">Resources & Activity</CardTitle>
          </CardHeader>
          <CardContent>
            <DetailRow label="CPU Usage">
              {agent.cpu_usage_pct != null ? (
                <span className={`tabular-nums ${agent.cpu_usage_pct > 80 ? 'text-destructive' : agent.cpu_usage_pct > 50 ? 'text-warning' : ''}`}>
                  {agent.cpu_usage_pct.toFixed(1)}%
                </span>
              ) : "—"}
            </DetailRow>
            <DetailRow label="Memory">
              {agent.memory_mb != null ? (
                <span className={`tabular-nums ${agent.memory_mb > 4096 ? 'text-destructive' : agent.memory_mb > 2048 ? 'text-warning' : ''}`}>
                  {agent.memory_mb >= 1024 ? `${(agent.memory_mb / 1024).toFixed(1)} GB` : `${agent.memory_mb} MB`}
                </span>
              ) : "—"}
            </DetailRow>
            <DetailRow label="Last Seen">
              {formatDate(agent.last_seen)}
            </DetailRow>
            <DetailRow label="Created">
              {formatDate(agent.first_seen)}
            </DetailRow>
            <DetailRow label="Alerts">
              <span className="tabular-nums">{alerts?.items?.length ?? 0}</span>
            </DetailRow>
          </CardContent>
        </Card>
      </div>

      {/* Agent Tags */}
      <Card>
        <CardHeader className="flex flex-row items-center gap-2 pb-1">
          <Tag size={14} className="text-muted-foreground" />
          <CardTitle className="text-xs text-muted-foreground">Agent Tags</CardTitle>
        </CardHeader>
        <CardContent>
          <TagEditor agentId={agent.id} />
        </CardContent>
      </Card>

      {/* Events + Alerts side by side */}
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle>Recent Events</CardTitle>
            <span className="text-xs text-muted-foreground">{events?.items?.length ?? 0} total</span>
          </CardHeader>
          <CardContent>
            {(events?.items?.length ?? 0) === 0 ? (
              <p className="text-xs text-muted-foreground py-6 text-center">
                No events recorded for this agent.
              </p>
            ) : (
              <div className="divide-y divide-border">
                {events?.items?.map((event) => (
                  <div key={event.id} className="flex items-center justify-between py-2">
                    <div className="flex items-center gap-2">
                      <Badge variant={event.severity as "critical" | "high" | "medium" | "low" | "info"}>
                        {event.severity}
                      </Badge>
                      <span className="text-xs font-mono">{event.event_type}</span>
                    </div>
                    <span className="text-xs text-muted-foreground">{timeAgo(event.timestamp)}</span>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle>Alerts</CardTitle>
            <span className="text-xs text-muted-foreground">{alerts?.items?.length ?? 0} total</span>
          </CardHeader>
          <CardContent>
            {(alerts?.items?.length ?? 0) === 0 ? (
              <p className="text-xs text-muted-foreground py-6 text-center">
                No alerts for this agent.
              </p>
            ) : (
              <div className="divide-y divide-border">
                {alerts?.items?.map((alert) => (
                  <Link
                    key={alert.id}
                    to={`/alerts/${alert.id}`}
                    className="flex items-center justify-between py-2 hover:bg-surface-2/50 -mx-4 px-4 transition-colors"
                  >
                    <div className="flex items-center gap-2">
                      <Badge variant={alert.severity as "critical" | "high" | "medium" | "low"}>
                        {alert.severity}
                      </Badge>
                      <Badge variant="outline" className="capitalize">
                        {alert.status}
                      </Badge>
                    </div>
                    <span className="text-xs text-muted-foreground">{timeAgo(alert.created_at)}</span>
                  </Link>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
