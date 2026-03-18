// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Agent Drift Detection + ABOM Dashboard
 *
 * Tabs:
 *   1. Overview  — stats cards + recent drift events
 *   2. Snapshots — config timeline per agent
 *   3. Drift     — drift alerts with approve/reject workflow
 *   4. ABOM      — Agent Bill of Materials viewer + risk scores
 *   5. Policy    — drift detection mode + alert settings
 *   6. Audit Log — immutable approval history
 */

import { useState, useCallback, useEffect } from "react"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import apiClient from "@/api/client"
import {
  Activity,
  AlertTriangle,
  ArrowUpDown,
  Camera,
  Check,
  ChevronDown,
  ClipboardList,
  Download,
  FileBarChart,
  GitCompareArrows,
  HelpCircle,
  Layers,
  RefreshCw,
  Settings2,
  Shield,
  ShieldAlert,
  Workflow,
  X,
} from "lucide-react"

/* ── Drift data types ────────────────────────────────────── */

interface DriftEvent {
  id: string
  agent_id: string
  drift_type: string
  field_name: string
  severity: string
  status: string
  created_at: string
  old_value?: string
  new_value?: string
}

interface DriftSnapshot {
  id: string
  agent_id: string
  version: number
  model_name?: string
  framework_name?: string
  framework_version?: string
  tool_list?: string[]
  snapshot_trigger: string
  created_at: string
}

interface AbomEntry {
  id: string
  agent_id: string
  version: number
  risk_score: number
  generated_at: string
  risk_factors?: RiskFactor[]
  components?: AbomComponents
}

interface RiskFactor {
  factor: string
  value: number
  contribution: number
}

interface AbomComponents {
  llm_model?: { provider: string; name: string }
  framework?: { name: string; version?: string }
  tools_mcp?: unknown[]
  dependencies?: unknown[]
  rag_sources?: unknown[]
  permissions?: Record<string, unknown>
  compliance_tags?: string[]
  hitl_enabled?: boolean
}

interface AuditEntry {
  id: string
  action: string
  drift_event_id: string
  user_id: string
  reason: string
  created_at: string
}

/* ── API helpers ─────────────────────────────────────────── */

const api = {
  stats:      ()                                     => apiClient.get("/drift/stats").then(r => r.data),
  snapshots:  (p: Record<string, string | number | undefined>) => apiClient.get("/drift/snapshots", { params: p }).then(r => r.data),
  agents:     ()                                     => apiClient.get("/drift/agents").then(r => r.data),
  events:     (p: Record<string, string | number | undefined>) => apiClient.get("/drift/events", { params: p }).then(r => r.data),
  pending:    (p: Record<string, string | number | undefined>) => apiClient.get("/drift/events/pending", { params: p }).then(r => r.data),
  aboms:      (p: Record<string, string | number | undefined>) => apiClient.get("/drift/abom", { params: p }).then(r => r.data),
  policy:     ()                                     => apiClient.get("/drift/policy").then(r => r.data),
  auditLog:   (p: Record<string, string | number | undefined>) => apiClient.get("/drift/audit-log", { params: p }).then(r => r.data),
  driftTypes: ()                                     => apiClient.get("/drift/drift-types").then(r => r.data),
  riskFactors:()                                     => apiClient.get("/drift/risk-factors").then(r => r.data),

  createSnapshot: (data: Record<string, unknown>)    => apiClient.post("/drift/snapshots", data).then(r => r.data),
  approve:   (id: string, data: Record<string, unknown>) => apiClient.post(`/drift/events/${encodeURIComponent(id)}/approve`, data).then(r => r.data),
  reject:    (id: string, data: Record<string, unknown>) => apiClient.post(`/drift/events/${encodeURIComponent(id)}/reject`, data).then(r => r.data),
  escalate:  (id: string, data: Record<string, unknown>) => apiClient.post(`/drift/events/${encodeURIComponent(id)}/escalate`, data).then(r => r.data),
  generateAbom: (data: Record<string, unknown>)      => apiClient.post("/drift/abom", data).then(r => r.data),
  updatePolicy: (data: Record<string, unknown>)      => apiClient.put("/drift/policy", data).then(r => r.data),
  exportCycloneDX: (id: string)                      => apiClient.get(`/drift/abom/${encodeURIComponent(id)}/cyclonedx`).then(r => r.data),
  diffSnapshots: (a: string, b: string)              => apiClient.get("/drift/snapshots/diff", { params: { snapshot_a: a, snapshot_b: b } }).then(r => r.data),
}

/* ── Severity + status colours ───────────────────────────── */

const sevColor: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high:     "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium:   "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low:      "bg-blue-500/20 text-blue-400 border-blue-500/30",
}

const statusColor: Record<string, string> = {
  open:          "bg-amber-500/20 text-amber-400 border-amber-500/30",
  approved:      "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  rejected:      "bg-red-500/20 text-red-400 border-red-500/30",
  auto_reverted: "bg-purple-500/20 text-purple-400 border-purple-500/30",
}

const modeColor: Record<string, string> = {
  strict:   "bg-red-500/20 text-red-400 border-red-500/30",
  standard: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  learning: "bg-blue-500/20 text-blue-400 border-blue-500/30",
}

/* ── Stats Card component ────────────────────────────────── */

function StatCard({ label, value, icon, colour = "text-primary" }: {
  label: string; value: number | string; icon: React.ReactNode; colour?: string
}) {
  return (
    <div className="rounded-lg border border-border/40 bg-card p-4 flex items-center gap-3">
      <div className={`shrink-0 ${colour}`}>{icon}</div>
      <div>
        <p className="text-2xl font-bold">{value}</p>
        <p className="text-xs text-muted-foreground">{label}</p>
      </div>
    </div>
  )
}

/* ── Badge helper ────────────────────────────────────────── */

function Badge({ text, colors }: { text: string; colors: string }) {
  return (
    <span className={`inline-block rounded border px-2 py-0.5 text-[11px] font-semibold uppercase leading-none tracking-wide ${colors}`}>
      {text}
    </span>
  )
}

/* ── Tab system ──────────────────────────────────────────── */

const TABS = [
  { id: "overview",   label: "Overview",   icon: <Activity size={15} /> },
  { id: "snapshots",  label: "Snapshots",  icon: <Camera size={15} /> },
  { id: "drift",      label: "Drift Alerts", icon: <AlertTriangle size={15} /> },
  { id: "abom",       label: "ABOM",       icon: <FileBarChart size={15} /> },
  { id: "policy",     label: "Policy",     icon: <Settings2 size={15} /> },
  { id: "audit",      label: "Audit Log",  icon: <ClipboardList size={15} /> },
] as const

type TabId = typeof TABS[number]["id"]

/* ═══════════════════════════════════════════════════════════
   Main page component
   ═══════════════════════════════════════════════════════════ */

export default function AgentDriftPage() {
  const [tab, setTab] = useState<TabId>("overview")
  const [showGuide, setShowGuide] = useState(false)

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div className="flex items-center gap-3">
          <GitCompareArrows size={24} className="text-primary" />
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Agent Drift & ABOM</h1>
            <p className="text-sm text-muted-foreground">
              Configuration drift detection, change approval, and Agent Bill of Materials
            </p>
          </div>
        </div>
        <button
          onClick={() => setShowGuide(!showGuide)}
          className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"
        >
          <HelpCircle size={14} />
          {showGuide ? "Hide Guide" : "How does this work?"}
        </button>
      </div>

      {/* How It Works Guide */}
      {showGuide && <DriftAbomGuide />}

      {/* Tab bar */}
      <div className="flex gap-1 border-b border-border/40 pb-px">
        {TABS.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`flex items-center gap-1.5 rounded-t-md px-3 py-2 text-sm font-medium transition-colors
              ${tab === t.id
                ? "border-b-2 border-primary text-primary"
                : "text-muted-foreground hover:text-foreground"}`}
          >
            {t.icon}
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === "overview"  && <OverviewTab />}
      {tab === "snapshots" && <SnapshotsTab />}
      {tab === "drift"     && <DriftTab />}
      {tab === "abom"      && <AbomTab />}
      {tab === "policy"    && <PolicyTab />}
      {tab === "audit"     && <AuditTab />}
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════
   OVERVIEW TAB
   ═══════════════════════════════════════════════════════════ */

function OverviewTab() {
  const { data: stats, isLoading } = useQuery({ queryKey: ["drift-stats"], queryFn: api.stats, refetchInterval: 30_000 })
  const { data: recent } = useQuery({ queryKey: ["drift-events-recent"], queryFn: () => api.events({ limit: 10 }) })

  if (isLoading) return <Spinner />

  return (
    <div className="space-y-6">
      {/* Stats grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Monitored Agents" value={stats?.monitored_agents ?? 0} icon={<Shield size={20} />} />
        <StatCard label="Total Snapshots" value={stats?.total_snapshots ?? 0} icon={<Camera size={20} />} />
        <StatCard label="Open Drift Events" value={stats?.open_drift_events ?? 0} icon={<AlertTriangle size={20} />} colour="text-amber-400" />
        <StatCard label="Critical Drifts" value={stats?.critical_drift_events ?? 0} icon={<ShieldAlert size={20} />} colour="text-red-400" />
        <StatCard label="Last 24h Events" value={stats?.drift_events_last_24h ?? 0} icon={<Activity size={20} />} />
        <StatCard label="Total Drifts" value={stats?.total_drift_events ?? 0} icon={<ArrowUpDown size={20} />} />
        <StatCard label="ABOMs Generated" value={stats?.total_aboms ?? 0} icon={<FileBarChart size={20} />} />
        <StatCard label="Policy Mode" value={(stats?.policy_mode ?? "learning").toUpperCase()} icon={<Settings2 size={20} />}
          colour={stats?.policy_mode === "strict" ? "text-red-400" : stats?.policy_mode === "standard" ? "text-amber-400" : "text-blue-400"} />
      </div>

      {/* Recent events table */}
      <div>
        <h3 className="text-sm font-semibold text-muted-foreground mb-2">Recent Drift Events</h3>
        {recent?.events?.length ? (
          <div className="rounded-lg border border-border/40 overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-muted/30">
                <tr>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">Agent</th>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">Type</th>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">Field</th>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">Severity</th>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">Status</th>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">Time</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/20">
                {recent.events.map((e: DriftEvent) => (
                  <tr key={e.id} className="hover:bg-muted/10">
                    <td className="px-3 py-2 font-mono text-xs">{e.agent_id}</td>
                    <td className="px-3 py-2 text-xs">{e.drift_type}</td>
                    <td className="px-3 py-2 text-xs text-muted-foreground">{e.field_name}</td>
                    <td className="px-3 py-2"><Badge text={e.severity} colors={sevColor[e.severity] ?? sevColor.medium} /></td>
                    <td className="px-3 py-2"><Badge text={e.status} colors={statusColor[e.status] ?? statusColor.open} /></td>
                    <td className="px-3 py-2 text-xs text-muted-foreground">{new Date(e.created_at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState message="No drift events detected yet" />
        )}
      </div>
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════
   SNAPSHOTS TAB
   ═══════════════════════════════════════════════════════════ */

function SnapshotsTab() {
  const [agentFilter, setAgentFilter] = useState("")
  const [page, setPage] = useState(0)
  const limit = 25

  const { data: agents } = useQuery({ queryKey: ["drift-agents"], queryFn: api.agents })
  const { data, isLoading, refetch } = useQuery({
    queryKey: ["drift-snapshots", agentFilter, page],
    queryFn: () => api.snapshots({ agent_id: agentFilter || undefined, limit, offset: page * limit }),
  })

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <select
          value={agentFilter}
          onChange={(e) => { setAgentFilter(e.target.value); setPage(0) }}
          className="rounded-md border border-border/50 bg-background px-3 py-1.5 text-sm"
        >
          <option value="">All agents</option>
          {agents?.agents?.map((a: string) => <option key={a} value={a}>{a}</option>)}
        </select>
        <button onClick={() => refetch()} className="flex items-center gap-1 rounded-md border border-border/50 px-3 py-1.5 text-sm hover:bg-muted/20">
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      {isLoading ? <Spinner /> : data?.snapshots?.length ? (
        <>
          <div className="rounded-lg border border-border/40 overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-muted/30">
                <tr>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">Agent</th>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">v#</th>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">Model</th>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">Framework</th>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">Tools</th>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">Trigger</th>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">Captured</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/20">
                {data.snapshots.map((s: DriftSnapshot) => (
                  <tr key={s.id} className="hover:bg-muted/10">
                    <td className="px-3 py-2 font-mono text-xs">{s.agent_id}</td>
                    <td className="px-3 py-2 text-xs font-semibold">v{s.version}</td>
                    <td className="px-3 py-2 text-xs">{s.model_name ?? "—"}</td>
                    <td className="px-3 py-2 text-xs">{s.framework_name ?? "—"} {s.framework_version ?? ""}</td>
                    <td className="px-3 py-2 text-xs">{Array.isArray(s.tool_list) ? s.tool_list.length : 0}</td>
                    <td className="px-3 py-2"><Badge text={s.snapshot_trigger} colors="bg-slate-500/20 text-slate-400 border-slate-500/30" /></td>
                    <td className="px-3 py-2 text-xs text-muted-foreground">{new Date(s.created_at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination page={page} setPage={setPage} total={data.total} limit={limit} />
        </>
      ) : <EmptyState message="No snapshots captured yet" />}
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════
   DRIFT ALERTS TAB
   ═══════════════════════════════════════════════════════════ */

function DriftTab() {
  const qc = useQueryClient()
  const [statusFilter, setStatusFilter] = useState("open")
  const [sevFilter, setSevFilter] = useState("")
  const [page, setPage] = useState(0)
  const [resolving, setResolving] = useState<string | null>(null)
  const [reason, setReason] = useState("")
  const limit = 25

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["drift-events", statusFilter, sevFilter, page],
    queryFn: () => api.events({ status: statusFilter || undefined, severity: sevFilter || undefined, limit, offset: page * limit }),
  })

  const approveMut = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) => api.approve(id, { reason }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["drift"] }); setResolving(null); setReason("") },
  })
  const rejectMut = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) => api.reject(id, { reason }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["drift"] }); setResolving(null); setReason("") },
  })

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 flex-wrap">
        <select value={statusFilter} onChange={(e) => { setStatusFilter(e.target.value); setPage(0) }}
          className="rounded-md border border-border/50 bg-background px-3 py-1.5 text-sm">
          <option value="">All statuses</option>
          <option value="open">Open</option>
          <option value="approved">Approved</option>
          <option value="rejected">Rejected</option>
          <option value="auto_reverted">Auto-reverted</option>
        </select>
        <select value={sevFilter} onChange={(e) => { setSevFilter(e.target.value); setPage(0) }}
          className="rounded-md border border-border/50 bg-background px-3 py-1.5 text-sm">
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <button onClick={() => refetch()} className="flex items-center gap-1 rounded-md border border-border/50 px-3 py-1.5 text-sm hover:bg-muted/20">
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      {isLoading ? <Spinner /> : data?.events?.length ? (
        <>
          <div className="rounded-lg border border-border/40 overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-muted/30">
                <tr>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">Agent</th>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">Drift Type</th>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">Field</th>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">Old → New</th>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">Severity</th>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">Status</th>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">Time</th>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/20">
                {data.events.map((e: DriftEvent) => (
                  <tr key={e.id} className="hover:bg-muted/10">
                    <td className="px-3 py-2 font-mono text-xs">{e.agent_id}</td>
                    <td className="px-3 py-2 text-xs">{e.drift_type}</td>
                    <td className="px-3 py-2 text-xs text-muted-foreground">{e.field_name}</td>
                    <td className="px-3 py-2 text-xs max-w-48 truncate" title={`${e.old_value ?? "null"} → ${e.new_value ?? "null"}`}>
                      <span className="text-red-400">{truncStr(e.old_value)}</span>
                      <span className="mx-1 text-muted-foreground">→</span>
                      <span className="text-emerald-400">{truncStr(e.new_value)}</span>
                    </td>
                    <td className="px-3 py-2"><Badge text={e.severity} colors={sevColor[e.severity] ?? sevColor.medium} /></td>
                    <td className="px-3 py-2"><Badge text={e.status} colors={statusColor[e.status] ?? statusColor.open} /></td>
                    <td className="px-3 py-2 text-xs text-muted-foreground">{new Date(e.created_at).toLocaleString()}</td>
                    <td className="px-3 py-2">
                      {e.status === "open" && (
                        resolving === e.id ? (
                          <div className="flex items-center gap-1">
                            <input
                              value={reason}
                              onChange={(ev) => setReason(ev.target.value)}
                              placeholder="Reason…"
                              className="w-32 rounded border border-border/50 bg-background px-2 py-1 text-xs"
                            />
                            <button
                              onClick={() => approveMut.mutate({ id: e.id, reason })}
                              disabled={!reason.trim()}
                              className="rounded bg-emerald-600 px-2 py-1 text-xs text-white hover:bg-emerald-500 disabled:opacity-40"
                            >
                              <Check size={12} />
                            </button>
                            <button
                              onClick={() => rejectMut.mutate({ id: e.id, reason })}
                              disabled={!reason.trim()}
                              className="rounded bg-red-600 px-2 py-1 text-xs text-white hover:bg-red-500 disabled:opacity-40"
                            >
                              <X size={12} />
                            </button>
                            <button
                              onClick={() => { setResolving(null); setReason("") }}
                              className="text-muted-foreground hover:text-foreground text-xs ml-1"
                            >
                              Cancel
                            </button>
                          </div>
                        ) : (
                          <button
                            onClick={() => setResolving(e.id)}
                            className="rounded border border-border/50 px-2 py-1 text-xs hover:bg-muted/20"
                          >
                            Resolve
                          </button>
                        )
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination page={page} setPage={setPage} total={data.total} limit={limit} />
        </>
      ) : <EmptyState message="No drift events matching filters" />}
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════
   ABOM TAB
   ═══════════════════════════════════════════════════════════ */

function AbomTab() {
  const [agentFilter, setAgentFilter] = useState("")
  const [page, setPage] = useState(0)
  const [expanded, setExpanded] = useState<string | null>(null)
  const limit = 25

  const { data: agents } = useQuery({ queryKey: ["drift-agents"], queryFn: api.agents })
  const { data, isLoading, refetch } = useQuery({
    queryKey: ["drift-aboms", agentFilter, page],
    queryFn: () => api.aboms({ agent_id: agentFilter || undefined, limit, offset: page * limit }),
  })

  const downloadCdx = useCallback(async (abomId: string, agentId: string) => {
    try {
      const cdx = await api.exportCycloneDX(abomId)
      const blob = new Blob([JSON.stringify(cdx, null, 2)], { type: "application/json" })
      const url = URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = url
      a.download = `abom-${agentId}-cyclonedx.json`
      a.click()
      URL.revokeObjectURL(url)
    } catch (err) {
      console.error("CycloneDX export failed", err)
    }
  }, [])

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <select
          value={agentFilter}
          onChange={(e) => { setAgentFilter(e.target.value); setPage(0) }}
          className="rounded-md border border-border/50 bg-background px-3 py-1.5 text-sm"
        >
          <option value="">All agents</option>
          {agents?.agents?.map((a: string) => <option key={a} value={a}>{a}</option>)}
        </select>
        <button onClick={() => refetch()} className="flex items-center gap-1 rounded-md border border-border/50 px-3 py-1.5 text-sm hover:bg-muted/20">
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      {isLoading ? <Spinner /> : data?.aboms?.length ? (
        <>
          <div className="space-y-3">
            {data.aboms.map((a: AbomEntry) => (
              <div key={a.id} className="rounded-lg border border-border/40 bg-card">
                <button
                  onClick={() => setExpanded(expanded === a.id ? null : a.id)}
                  className="w-full flex items-center justify-between px-4 py-3 text-left hover:bg-muted/10"
                >
                  <div className="flex items-center gap-3">
                    <FileBarChart size={16} className="text-primary" />
                    <span className="font-mono text-sm">{a.agent_id}</span>
                    <span className="text-xs text-muted-foreground">v{a.version}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <RiskBadge score={a.risk_score} />
                    <span className="text-xs text-muted-foreground">{new Date(a.generated_at).toLocaleDateString()}</span>
                    <ChevronDown size={14} className={`transition-transform ${expanded === a.id ? "rotate-180" : ""}`} />
                  </div>
                </button>

                {expanded === a.id && (
                  <div className="border-t border-border/30 px-4 py-3 space-y-3">
                    {/* Risk factors */}
                    <div>
                      <h4 className="text-xs font-semibold text-muted-foreground mb-1">Risk Factors</h4>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                        {(a.risk_factors || []).map((f: RiskFactor, i: number) => (
                          <div key={i} className="rounded border border-border/30 px-2 py-1.5">
                            <p className="text-xs font-medium">{f.factor.replace(/_/g, " ")}</p>
                            <p className="text-xs text-muted-foreground">Value: {f.value} | +{f.contribution}</p>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Components summary */}
                    <ComponentsSummary components={a.components} />

                    {/* Actions */}
                    <div className="flex gap-2">
                      <button
                        onClick={() => downloadCdx(a.id, a.agent_id)}
                        className="flex items-center gap-1 rounded-md border border-border/50 px-3 py-1.5 text-xs hover:bg-muted/20"
                      >
                        <Download size={12} /> Export CycloneDX
                      </button>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
          <Pagination page={page} setPage={setPage} total={data.total} limit={limit} />
        </>
      ) : <EmptyState message="No ABOMs generated yet" />}
    </div>
  )
}

/* ── ABOM components summary ─────────────────────────────── */

function ComponentsSummary({ components }: { components: AbomComponents | undefined }) {
  if (!components) return null

  const items = [
    { label: "LLM", value: components.llm_model?.name ? `${components.llm_model.provider}/${components.llm_model.name}` : "—" },
    { label: "Framework", value: components.framework?.name ? `${components.framework.name} ${components.framework.version ?? ""}` : "—" },
    { label: "Tools/MCP", value: `${Array.isArray(components.tools_mcp) ? components.tools_mcp.length : 0} tools` },
    { label: "Dependencies", value: `${Array.isArray(components.dependencies) ? components.dependencies.length : 0} packages` },
    { label: "RAG Sources", value: `${Array.isArray(components.rag_sources) ? components.rag_sources.length : 0} sources` },
    { label: "Permissions", value: `${Object.keys(components.permissions ?? {}).length} categories` },
    { label: "Compliance", value: (components.compliance_tags ?? []).join(", ") || "—" },
    { label: "HITL", value: components.hitl_enabled ? "✓ Enabled" : "✗ Disabled" },
  ]

  return (
    <div>
      <h4 className="text-xs font-semibold text-muted-foreground mb-1">ABOM Components</h4>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
        {items.map((it, i) => (
          <div key={i} className="rounded border border-border/30 px-2 py-1.5">
            <p className="text-[10px] uppercase tracking-wide text-muted-foreground">{it.label}</p>
            <p className="text-xs">{it.value}</p>
          </div>
        ))}
      </div>
    </div>
  )
}

/* ── Risk badge ──────────────────────────────────────────── */

function RiskBadge({ score }: { score: number }) {
  const color = score >= 70 ? "bg-red-500/20 text-red-400 border-red-500/30"
    : score >= 40 ? "bg-amber-500/20 text-amber-400 border-amber-500/30"
    : "bg-emerald-500/20 text-emerald-400 border-emerald-500/30"
  return <Badge text={`Risk ${score.toFixed(0)}`} colors={color} />
}

/* ═══════════════════════════════════════════════════════════
   POLICY TAB
   ═══════════════════════════════════════════════════════════ */

function PolicyTab() {
  const qc = useQueryClient()
  const { data: policy, isLoading } = useQuery({ queryKey: ["drift-policy"], queryFn: api.policy })

  const [mode, setMode] = useState("learning")
  const [alerts, setAlerts] = useState({
    alert_on_model_swap: true,
    alert_on_prompt_change: true,
    alert_on_tool_change: true,
    alert_on_permission_escalation: true,
    alert_on_dependency_change: false,
    alert_on_rag_change: true,
    auto_revert_enabled: false,
  })

  /* eslint-disable react-hooks/set-state-in-effect -- form hydration from API data */
  useEffect(() => {
    if (policy) {
      setMode(policy.mode ?? "learning")
      setAlerts({
        alert_on_model_swap: policy.alert_on_model_swap ?? true,
        alert_on_prompt_change: policy.alert_on_prompt_change ?? true,
        alert_on_tool_change: policy.alert_on_tool_change ?? true,
        alert_on_permission_escalation: policy.alert_on_permission_escalation ?? true,
        alert_on_dependency_change: policy.alert_on_dependency_change ?? false,
        alert_on_rag_change: policy.alert_on_rag_change ?? true,
        auto_revert_enabled: policy.auto_revert_enabled ?? false,
      })
    }
  }, [policy])
  /* eslint-enable react-hooks/set-state-in-effect */

  const saveMut = useMutation({
    mutationFn: () => api.updatePolicy({ mode, ...alerts, maintenance_windows: policy?.maintenance_windows ?? [] }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["drift-policy"] }),
  })

  if (isLoading) return <Spinner />

  return (
    <div className="max-w-2xl space-y-6">
      {/* Mode selector */}
      <div>
        <h3 className="text-sm font-semibold mb-2">Detection Mode</h3>
        <div className="flex gap-3">
          {(["learning", "standard", "strict"] as const).map((m) => (
            <button
              key={m}
              onClick={() => setMode(m)}
              className={`rounded-lg border px-4 py-2 text-sm font-medium transition-colors
                ${mode === m
                  ? `${modeColor[m]} border-current`
                  : "border-border/50 text-muted-foreground hover:text-foreground"}`}
            >
              {m.charAt(0).toUpperCase() + m.slice(1)}
            </button>
          ))}
        </div>
        <p className="text-xs text-muted-foreground mt-1">
          {mode === "strict" && "Every config change triggers a drift event."}
          {mode === "standard" && "Alerts on unexpected changes outside maintenance windows."}
          {mode === "learning" && "Silently records diffs — no drift events created."}
        </p>
      </div>

      {/* Alert toggles */}
      <div>
        <h3 className="text-sm font-semibold mb-2">Alert Settings</h3>
        <div className="space-y-2">
          {[
            { key: "alert_on_model_swap", label: "Model Swap" },
            { key: "alert_on_prompt_change", label: "Prompt Change" },
            { key: "alert_on_tool_change", label: "Tool List Change" },
            { key: "alert_on_permission_escalation", label: "Permission Escalation" },
            { key: "alert_on_dependency_change", label: "Dependency Change" },
            { key: "alert_on_rag_change", label: "RAG Source Change" },
            { key: "auto_revert_enabled", label: "Auto-revert (reject + log automatically)" },
          ].map(({ key, label }) => (
            <label key={key} className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={alerts[key as keyof typeof alerts]}
                onChange={(e) => setAlerts(prev => ({ ...prev, [key]: e.target.checked }))}
                className="rounded border-border/50"
              />
              <span className="text-sm">{label}</span>
            </label>
          ))}
        </div>
      </div>

      <button
        onClick={() => saveMut.mutate()}
        disabled={saveMut.isPending}
        className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-40"
      >
        {saveMut.isPending ? "Saving…" : "Save Policy"}
      </button>
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════
   AUDIT LOG TAB
   ═══════════════════════════════════════════════════════════ */

function AuditTab() {
  const [page, setPage] = useState(0)
  const limit = 50

  const { data, isLoading } = useQuery({
    queryKey: ["drift-audit", page],
    queryFn: () => api.auditLog({ limit, offset: page * limit }),
  })

  if (isLoading) return <Spinner />

  return (
    <div className="space-y-4">
      {data?.entries?.length ? (
        <>
          <div className="rounded-lg border border-border/40 overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-muted/30">
                <tr>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">Action</th>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">Drift Event</th>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">User</th>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">Reason</th>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">Time</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/20">
                {data.entries.map((e: AuditEntry) => (
                  <tr key={e.id} className="hover:bg-muted/10">
                    <td className="px-3 py-2"><Badge text={e.action} colors={statusColor[e.action] ?? statusColor.open} /></td>
                    <td className="px-3 py-2 font-mono text-xs truncate max-w-40">{e.drift_event_id}</td>
                    <td className="px-3 py-2 font-mono text-xs truncate max-w-32">{e.user_id}</td>
                    <td className="px-3 py-2 text-xs text-muted-foreground max-w-64 truncate">{e.reason}</td>
                    <td className="px-3 py-2 text-xs text-muted-foreground">{new Date(e.created_at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination page={page} setPage={setPage} total={data.total} limit={limit} />
        </>
      ) : <EmptyState message="No audit log entries yet" />}
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════
   Shared components
   ═══════════════════════════════════════════════════════════ */

function Spinner() {
  return (
    <div className="flex items-center justify-center py-16">
      <div className="h-6 w-6 animate-spin rounded-full border-2 border-primary/20 border-t-primary" />
    </div>
  )
}

function EmptyState({ message }: { message: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
      <GitCompareArrows size={40} className="mb-3 opacity-30" />
      <p className="text-sm">{message}</p>
    </div>
  )
}

function Pagination({ page, setPage, total, limit }: {
  page: number; setPage: (p: number) => void; total: number; limit: number
}) {
  const maxPage = Math.max(0, Math.ceil(total / limit) - 1)
  return (
    <div className="flex items-center justify-between text-xs text-muted-foreground">
      <span>{total} total</span>
      <div className="flex items-center gap-2">
        <button onClick={() => setPage(Math.max(0, page - 1))} disabled={page === 0}
          className="rounded border border-border/50 px-2 py-1 disabled:opacity-30 hover:bg-muted/20">
          Prev
        </button>
        <span>Page {page + 1} / {maxPage + 1}</span>
        <button onClick={() => setPage(Math.min(maxPage, page + 1))} disabled={page >= maxPage}
          className="rounded border border-border/50 px-2 py-1 disabled:opacity-30 hover:bg-muted/20">
          Next
        </button>
      </div>
    </div>
  )
}

function truncStr(v: string | null | undefined, max = 24): string {
  if (!v) return "null"
  return v.length > max ? v.slice(0, max - 1) + "…" : v
}

/* ═══════════════════════════════════════════════════════════
   How It Works Guide
   ═══════════════════════════════════════════════════════════ */

function DriftAbomGuide() {
  return (
    <div className="space-y-4">
      {/* Section 1 — What is Agent Drift? */}
      <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
          <GitCompareArrows size={16} className="text-primary" />
          What is Agent Drift?
        </h3>
        <p className="mt-1.5 text-xs text-muted-foreground leading-relaxed">
          AI agents run with a specific configuration — the model they use, the tools they can access, the system
          prompt that guides them, and the data sources they read from. <strong className="text-foreground">Agent Drift</strong> means
          any of these changed since the last known-good snapshot. If an attacker swaps the model, injects a new tool,
          or modifies the system prompt — drift detection catches it immediately.
        </p>
      </div>

      {/* Section 2 — What is ABOM? */}
      <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
          <FileBarChart size={16} className="text-primary" />
          What is an ABOM (Agent Bill of Materials)?
        </h3>
        <p className="mt-1.5 text-xs text-muted-foreground leading-relaxed">
          An <strong className="text-foreground">ABOM</strong> is like an ingredient list for an AI agent.
          It catalogues everything the agent is made of — model, tools, permissions, data sources, dependencies,
          and MCP servers — then assigns a <strong className="text-foreground">risk score</strong> based on
          how exposed the agent is. ABOMs can be exported in <strong className="text-foreground">CycloneDX</strong> format
          for compliance and supply-chain auditing.
        </p>
      </div>

      {/* Section 3 — Detection pipeline */}
      <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
          <Workflow size={16} className="text-primary" />
          How Drift Detection Works
        </h3>
        <p className="mt-1.5 text-xs text-muted-foreground">When an agent's configuration changes, here's what happens:</p>
        <div className="mt-3 flex flex-wrap items-center gap-1.5 text-xs font-medium">
          {[
            { label: "New snapshot captured", color: "bg-blue-500/15 text-blue-400 border border-blue-500/20" },
            { label: "→" },
            { label: "Compared against baseline", color: "bg-cyan-500/15 text-cyan-400 border border-cyan-500/20" },
            { label: "→" },
            { label: "Differences identified", color: "bg-amber-500/15 text-amber-400 border border-amber-500/20" },
            { label: "→" },
            { label: "Policy rules applied", color: "bg-orange-500/15 text-orange-400 border border-orange-500/20" },
            { label: "→" },
            { label: "Drift event created", color: "bg-red-500/15 text-red-400 border border-red-500/20" },
            { label: "→" },
            { label: "Awaits approval / auto-reverts", color: "bg-purple-500/15 text-purple-400 border border-purple-500/20" },
          ].map((step, i) =>
            step.color ? (
              <span key={i} className={`rounded-full px-2.5 py-1 ${step.color}`}>{step.label}</span>
            ) : (
              <span key={i} className="text-muted-foreground/40">{step.label}</span>
            )
          )}
        </div>
        <p className="mt-3 text-[11px] text-muted-foreground/70">
          All approvals and rejections are recorded in an immutable audit log that cannot be edited or deleted.
        </p>
      </div>

      {/* Section 4 — Drift types */}
      <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
          <AlertTriangle size={16} className="text-primary" />
          Types of Drift Detected
        </h3>
        <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          {[
            { name: "Model Swap",       desc: "The AI model was changed (e.g., GPT-4 → GPT-3.5)",      sev: "critical", color: "text-red-400 bg-red-500/10 border-red-500/20" },
            { name: "Prompt Change",     desc: "The system prompt was modified",                         sev: "high",     color: "text-orange-400 bg-orange-500/10 border-orange-500/20" },
            { name: "Tool Added",        desc: "A new tool was added to the agent's toolkit",           sev: "high",     color: "text-orange-400 bg-orange-500/10 border-orange-500/20" },
            { name: "Tool Removed",      desc: "A tool was removed from the agent's toolkit",           sev: "medium",   color: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20" },
            { name: "Permission Escalation", desc: "Agent permissions were upgraded",                    sev: "critical", color: "text-red-400 bg-red-500/10 border-red-500/20" },
            { name: "Dependency Change", desc: "A library or package version changed",                  sev: "medium",   color: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20" },
            { name: "RAG Change",        desc: "Retrieval data sources were modified",                  sev: "high",     color: "text-orange-400 bg-orange-500/10 border-orange-500/20" },
            { name: "Config Change",     desc: "Other configuration parameters changed",                sev: "low",      color: "text-blue-400 bg-blue-500/10 border-blue-500/20" },
          ].map((d) => (
            <div key={d.name} className={`rounded-lg border p-3 ${d.color}`}>
              <p className="text-xs font-semibold">{d.name}</p>
              <p className="mt-0.5 text-[11px] opacity-80">{d.desc}</p>
              <span className="mt-1.5 inline-block rounded-full bg-black/20 px-2 py-0.5 text-[9px] uppercase tracking-wider font-bold">
                {d.sev}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Section 5 — Three policy modes */}
      <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
          <Settings2 size={16} className="text-primary" />
          Three Detection Modes
        </h3>
        <div className="mt-3 grid gap-3 md:grid-cols-3">
          <div className="rounded-lg border border-red-500/20 bg-red-500/5 p-3">
            <div className="flex items-center gap-1.5 mb-1">
              <ShieldAlert size={14} className="text-red-400" />
              <span className="text-xs font-semibold text-red-400">Strict Mode</span>
            </div>
            <p className="text-[11px] text-muted-foreground leading-relaxed">
              Every configuration change generates an alert, regardless of maintenance windows. Best for
              production agents handling sensitive data.
            </p>
          </div>
          <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3">
            <div className="flex items-center gap-1.5 mb-1">
              <Shield size={14} className="text-amber-400" />
              <span className="text-xs font-semibold text-amber-400">Standard Mode</span>
            </div>
            <p className="text-[11px] text-muted-foreground leading-relaxed">
              Alerts fire for changes outside maintenance windows. Changes during approved windows are
              logged but don't trigger alerts. Recommended starting point.
            </p>
          </div>
          <div className="rounded-lg border border-blue-500/20 bg-blue-500/5 p-3">
            <div className="flex items-center gap-1.5 mb-1">
              <Activity size={14} className="text-blue-400" />
              <span className="text-xs font-semibold text-blue-400">Learning Mode</span>
            </div>
            <p className="text-[11px] text-muted-foreground leading-relaxed">
              All drift is silently recorded without generating alerts. Use this during initial setup to
              establish baselines before switching to Standard or Strict.
            </p>
          </div>
        </div>
      </div>

      {/* Section 6 — ABOM Risk Factors */}
      <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
          <Layers size={16} className="text-primary" />
          ABOM Risk Scoring
        </h3>
        <p className="mt-1.5 text-xs text-muted-foreground">
          Each ABOM receives a risk score (0–100) calculated from these weighted factors:
        </p>
        <div className="mt-3 space-y-1.5">
          {[
            { factor: "External MCP servers",     weight: 20, desc: "Agent connects to MCP servers outside the trusted boundary" },
            { factor: "Broad permissions",         weight: 20, desc: "Agent has wide-ranging permissions (admin, write-all, etc.)" },
            { factor: "Sensitive data access",     weight: 15, desc: "Agent can access PII, PHI, or financial data" },
            { factor: "Unverified RAG sources",    weight: 15, desc: "RAG data sources not in the verified allowlist" },
            { factor: "High tool count",           weight: 10, desc: "Agents with many tools have a larger attack surface" },
            { factor: "Outdated dependencies",     weight: 10, desc: "Libraries or packages with known vulnerabilities" },
            { factor: "No human-in-the-loop",      weight: 10, desc: "Agent operates fully autonomously without human checks" },
          ].map((f) => (
            <div key={f.factor} className="flex items-start gap-3 rounded-lg bg-black/10 border border-border/20 px-3 py-2">
              <span className="shrink-0 w-9 text-right text-xs font-bold text-primary">{f.weight}%</span>
              <div>
                <p className="text-xs font-semibold text-foreground">{f.factor}</p>
                <p className="text-[11px] text-muted-foreground">{f.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Section 7 — How to deal with drift */}
      <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/[0.03] p-5">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
          <Check size={16} className="text-emerald-400" />
          How to Handle Drift Events
        </h3>
        <div className="mt-3 space-y-2 text-xs text-muted-foreground leading-relaxed">
          <div className="flex gap-2">
            <span className="shrink-0 w-5 h-5 rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center text-[10px] font-bold">1</span>
            <p><strong className="text-foreground">Review the alert</strong> — Open the Drift Alerts tab and check which config element changed. Look at the severity and the detailed diff.</p>
          </div>
          <div className="flex gap-2">
            <span className="shrink-0 w-5 h-5 rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center text-[10px] font-bold">2</span>
            <p><strong className="text-foreground">Verify legitimacy</strong> — Was this an authorized deployment? Check with the team who owns the agent. If it was a planned change, approve it.</p>
          </div>
          <div className="flex gap-2">
            <span className="shrink-0 w-5 h-5 rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center text-[10px] font-bold">3</span>
            <p><strong className="text-foreground">Approve or Reject</strong> — Approve legitimate changes to update the baseline. Reject unauthorized changes to flag the agent for investigation.</p>
          </div>
          <div className="flex gap-2">
            <span className="shrink-0 w-5 h-5 rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center text-[10px] font-bold">4</span>
            <p><strong className="text-foreground">Escalate if needed</strong> — Critical drifts (model swap, permission escalation) should be escalated to the security team for deeper analysis.</p>
          </div>
          <div className="flex gap-2">
            <span className="shrink-0 w-5 h-5 rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center text-[10px] font-bold">5</span>
            <p><strong className="text-foreground">Review ABOM risks</strong> — After resolving drift, generate a fresh ABOM to see the updated risk score and ensure the agent's component inventory is acceptable.</p>
          </div>
        </div>
      </div>
    </div>
  )
}
