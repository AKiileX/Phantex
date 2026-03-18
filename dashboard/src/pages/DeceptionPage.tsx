// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Deception Technology Dashboard
 *
 * Manage deception assets that detect unauthorized AI agent interaction:
 *   1. Decoy Agents   — Fake AI agents with cryptographic identity
 *   2. Canary MCP     — Fake MCP servers advertising enticing tools
 *   3. Canary Tokens   — Planted credentials/keys that trigger on use
 *   4. Honeypot Events — Append-only event log of all deception triggers
 *
 * Security:
 *   - Admin-only route (enforced by ProtectedRoute + sidebar gate)
 *   - Token raw values shown ONCE on creation, then never again
 *   - All mutations invalidate cache to prevent stale state
 *   - XSS-safe: no dangerouslySetInnerHTML, all values rendered as text
 */

import { useState, useCallback, useMemo } from "react"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import apiClient from "@/api/client"
import {
  Ghost,
  Server,
  Key,
  AlertTriangle,
  Plus,
  Trash2,
  ToggleLeft,
  ToggleRight,
  Copy,
  CheckCircle,
  XCircle,
  RefreshCw,
  Shield,
  ChevronLeft,
  ChevronRight,
  Eye,
  EyeOff,
  HelpCircle,
  Fingerprint,
  Radio,
  ShieldAlert,
  Workflow,
} from "lucide-react"

// ── Types ────────────────────────────────────────────────────────────────────

interface DecoyAgent {
  id: string
  name: string
  description: string | null
  paid: string
  framework: string
  framework_ver: string
  public_key: string
  decoy_profile: Record<string, unknown>
  network_config: Record<string, unknown>
  enabled: boolean
  interaction_count: number
  last_triggered: string | null
  created_at: string
}

interface CanaryMCP {
  id: string
  name: string
  description: string | null
  server_url: string
  advertised_tools: ToolDef[]
  protocol: string
  tls_enabled: boolean
  rotate_identity: boolean
  rotation_interval_hours: number
  enabled: boolean
  interaction_count: number
  last_triggered: string | null
  created_at: string
}

interface ToolDef {
  name: string
  description?: string
}

interface CanaryToken {
  id: string
  name: string
  description: string | null
  token_type: string
  token_hint: string
  placement: Record<string, unknown>
  alert_on_read: boolean
  alert_on_use: boolean
  enabled: boolean
  trigger_count: number
  last_triggered: string | null
  created_at: string
}

interface HoneypotEvent {
  id: string
  source_type: string
  source_id: string
  source_name: string
  agent_id: string | null
  agent_paid: string | null
  source_ip: string | null
  interaction_type: string
  interaction_data: Record<string, unknown>
  severity: string
  attack_class: string | null
  mitre_tactic: string | null
  mitre_technique: string | null
  triggered_at: string
}

interface DeceptionStats {
  total_decoy_agents: number
  total_canary_mcp: number
  total_canary_tokens: number
  total_honeypot_events: number
  events_last_24h: number
  events_last_7d: number
  last_event_at: string | null
}

// ── Constants ────────────────────────────────────────────────────────────────

const TABS = ["Decoy Agents", "Canary MCP", "Canary Tokens", "Honeypot Events"] as const
type TabName = (typeof TABS)[number]

const FRAMEWORKS = [
  { value: "langchain", label: "LangChain" },
  { value: "autogen", label: "AutoGen" },
  { value: "crewai", label: "CrewAI" },
  { value: "openai", label: "OpenAI Agents" },
  { value: "anthropic", label: "Anthropic" },
  { value: "custom", label: "Custom" },
]

const TOKEN_TYPES = [
  { value: "api_key", label: "Fake API Key", desc: "Triggers on use in API calls" },
  { value: "credential", label: "Fake Credential", desc: "Triggers on authentication attempt" },
  { value: "pii", label: "Fake PII", desc: "Triggers on data exfiltration" },
  { value: "dns", label: "Canary DNS", desc: "Triggers when DNS name is resolved" },
  { value: "url", label: "Canary URL", desc: "Triggers when URL is fetched" },
]

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  info: "bg-gray-500/20 text-gray-400 border-gray-500/30",
}

const SOURCE_TYPE_LABELS: Record<string, string> = {
  decoy_agent: "Decoy Agent",
  canary_mcp: "Canary MCP",
  canary_token: "Canary Token",
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function fmtDate(iso: string | null): string {
  if (!iso) return "Never"
  return new Date(iso).toLocaleString()
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n) + "..." : s
}

// ── Sub-components ───────────────────────────────────────────────────────────

/** Stat card shown in the top overview row. */
function StatCard({ label, value, sub, icon }: { label: string; value: number | string; sub?: string; icon: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-border/40 bg-card/60 p-4 flex items-start gap-3 hover:border-border/60 transition-colors">
      <div className="rounded-lg bg-primary/10 p-2 text-primary">{icon}</div>
      <div>
        <p className="text-2xl font-bold tabular-nums">{value}</p>
        <p className="text-xs text-muted-foreground">{label}</p>
        {sub && <p className="text-[10px] text-muted-foreground/60 mt-0.5">{sub}</p>}
      </div>
    </div>
  )
}

/** Toggle switch pill (enabled / disabled). */
function StatusBadge({ enabled }: { enabled: boolean }) {
  return (
    <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-medium border ${enabled ? "bg-emerald-500/15 text-emerald-400 border-emerald-500/30" : "bg-zinc-500/15 text-zinc-400 border-zinc-500/30"}`}>
      {enabled ? <CheckCircle size={12} /> : <XCircle size={12} />}
      {enabled ? "Active" : "Disabled"}
    </span>
  )
}

/** Copyable text with a copy-to-clipboard button. */
function CopyField({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false)
  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(value).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }, [value])
  return (
    <div className="mt-2">
      <p className="text-[10px] uppercase tracking-wide text-muted-foreground/60 mb-1">{label}</p>
      <div className="flex items-center gap-2 rounded-lg bg-black/20 border border-border/30 px-3 py-2 font-mono text-xs break-all">
        <span className="flex-1 select-all">{value}</span>
        <button onClick={handleCopy} className="flex-shrink-0 text-muted-foreground hover:text-foreground transition-colors cursor-pointer" title="Copy">
          {copied ? <CheckCircle size={14} className="text-emerald-400" /> : <Copy size={14} />}
        </button>
      </div>
    </div>
  )
}

// ── Main Page ────────────────────────────────────────────────────────────────

export default function DeceptionPage() {
  const [tab, setTab] = useState<TabName>("Decoy Agents")
  const [showGuide, setShowGuide] = useState(false)
  const qc = useQueryClient()

  // ── Data fetching ──────────────────────────────────────────────────────────

  const { data: stats, isLoading: statsLoading } = useQuery<DeceptionStats>({
    queryKey: ["deception", "stats"],
    queryFn: () => apiClient.get("/deception/stats").then((r: { data: DeceptionStats }) => r.data),
    refetchInterval: 30_000,
  })

  const { data: decoyData, isLoading: decoysLoading } = useQuery<{ decoys: DecoyAgent[] }>({
    queryKey: ["deception", "decoys"],
    queryFn: () => apiClient.get("/deception/decoys").then((r: { data: { decoys: DecoyAgent[] } }) => r.data),
  })

  const { data: mcpData, isLoading: mcpLoading } = useQuery<{ canary_mcp_servers: CanaryMCP[] }>({
    queryKey: ["deception", "canary-mcp"],
    queryFn: () => apiClient.get("/deception/canary-mcp").then((r: { data: { canary_mcp_servers: CanaryMCP[] } }) => r.data),
  })

  const { data: tokenData, isLoading: tokensLoading } = useQuery<{ canary_tokens: CanaryToken[] }>({
    queryKey: ["deception", "canary-tokens"],
    queryFn: () => apiClient.get("/deception/canary-tokens").then((r: { data: { canary_tokens: CanaryToken[] } }) => r.data),
  })

  const [eventsPage, setEventsPage] = useState(0)
  const eventsLimit = 25
  const { data: eventsData, isLoading: eventsLoading } = useQuery<{ events: HoneypotEvent[]; total: number }>({
    queryKey: ["deception", "events", eventsPage],
    queryFn: () =>
      apiClient
        .get("/deception/events", { params: { limit: eventsLimit, offset: eventsPage * eventsLimit } })
        .then((r: { data: { events: HoneypotEvent[]; total: number } }) => r.data),
  })

  const decoys = decoyData?.decoys ?? []
  const mcpServers = mcpData?.canary_mcp_servers ?? []
  const tokens = tokenData?.canary_tokens ?? []
  const events = eventsData?.events ?? []
  const eventsTotal = eventsData?.total ?? 0

  // ── Mutations ──────────────────────────────────────────────────────────────

  const invalidateAll = useCallback(() => {
    qc.invalidateQueries({ queryKey: ["deception"] })
  }, [qc])

  const deleteMut = useMutation({
    mutationFn: (args: { path: string }) => apiClient.delete(args.path),
    onSuccess: invalidateAll,
  })

  const toggleMut = useMutation({
    mutationFn: (args: { path: string; enabled: boolean }) => apiClient.patch(args.path, { enabled: args.enabled }),
    onSuccess: invalidateAll,
  })

  // ── Stats row ──────────────────────────────────────────────────────────────

  const statsRow = useMemo(() => {
    if (statsLoading || !stats) return null
    return (
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-6">
        <StatCard label="Decoy Agents" value={stats.total_decoy_agents} icon={<Ghost size={20} />} />
        <StatCard label="Canary MCP Servers" value={stats.total_canary_mcp} icon={<Server size={20} />} />
        <StatCard label="Canary Tokens" value={stats.total_canary_tokens} icon={<Key size={20} />} />
        <StatCard
          label="Honeypot Events"
          value={stats.total_honeypot_events}
          sub={`${stats.events_last_24h} last 24h · ${stats.events_last_7d} last 7d`}
          icon={<AlertTriangle size={20} />}
        />
      </div>
    )
  }, [stats, statsLoading])

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
            <Ghost size={24} className="text-primary" />
            Deception Technology
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Deploy deceptive assets to detect unauthorized AI agent interaction
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowGuide(!showGuide)}
            className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"
          >
            <HelpCircle size={14} />
            {showGuide ? "Hide Guide" : "How does this work?"}
          </button>
          <button
            onClick={invalidateAll}
            className="flex items-center gap-1.5 rounded-lg border border-border/40 bg-card/60 px-3 py-1.5 text-xs font-medium text-muted-foreground hover:text-foreground hover:border-border/60 transition-colors cursor-pointer"
          >
            <RefreshCw size={14} />
            Refresh
          </button>
        </div>
      </div>

      {/* How It Works Guide */}
      {showGuide && <DeceptionGuide />}

      {/* Stats row */}
      {statsRow}

      {/* Tab bar */}
      <div className="flex gap-1 border-b border-border/30 mb-4">
        {TABS.map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors cursor-pointer ${tab === t ? "border-primary text-foreground" : "border-transparent text-muted-foreground hover:text-foreground hover:border-border/50"}`}
          >
            {t}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === "Decoy Agents" && (
        <DecoyAgentsTab
          decoys={decoys}
          loading={decoysLoading}
          onDelete={(id: string) => deleteMut.mutate({ path: `/deception/decoys/${id}` })}
          onToggle={(id: string, enabled: boolean) => toggleMut.mutate({ path: `/deception/decoys/${id}`, enabled })}
          onCreated={invalidateAll}
        />
      )}
      {tab === "Canary MCP" && (
        <CanaryMCPTab
          servers={mcpServers}
          loading={mcpLoading}
          onDelete={(id: string) => deleteMut.mutate({ path: `/deception/canary-mcp/${id}` })}
          onToggle={(id: string, enabled: boolean) => toggleMut.mutate({ path: `/deception/canary-mcp/${id}`, enabled })}
          onCreated={invalidateAll}
        />
      )}
      {tab === "Canary Tokens" && (
        <CanaryTokensTab
          tokens={tokens}
          loading={tokensLoading}
          onDelete={(id: string) => deleteMut.mutate({ path: `/deception/canary-tokens/${id}` })}
          onToggle={(id: string, enabled: boolean) => toggleMut.mutate({ path: `/deception/canary-tokens/${id}`, enabled })}
          onCreated={invalidateAll}
        />
      )}
      {tab === "Honeypot Events" && (
        <HoneypotEventsTab
          events={events}
          total={eventsTotal}
          loading={eventsLoading}
          page={eventsPage}
          pageSize={eventsLimit}
          onPageChange={setEventsPage}
        />
      )}
    </div>
  )
}

// ── Decoy Agents Tab ─────────────────────────────────────────────────────────

interface DecoyTabProps {
  decoys: DecoyAgent[]
  loading: boolean
  onDelete: (id: string) => void
  onToggle: (id: string, enabled: boolean) => void
  onCreated: () => void
}

function DecoyAgentsTab({ decoys, loading, onDelete, onToggle, onCreated }: DecoyTabProps) {
  const [showForm, setShowForm] = useState(false)

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          Decoy agents impersonate real AI agents with cryptographic identity. Any interaction is a guaranteed compromise indicator.
        </p>
        <button
          onClick={() => setShowForm(!showForm)}
          className="flex items-center gap-1.5 rounded-lg bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 transition-colors cursor-pointer"
        >
          <Plus size={14} />
          Deploy Decoy
        </button>
      </div>

      {showForm && <DecoyCreateForm onCreated={() => { onCreated(); setShowForm(false) }} onCancel={() => setShowForm(false)} />}

      {loading ? (
        <LoadingRows />
      ) : decoys.length === 0 ? (
        <EmptyState icon={<Ghost size={40} />} message="No decoy agents deployed" />
      ) : (
        <div className="space-y-3">
          {decoys.map((d: DecoyAgent) => (
            <div key={d.id} className="rounded-xl border border-border/40 bg-card/60 p-4 hover:border-border/60 transition-colors">
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <h3 className="font-semibold text-sm truncate">{d.name}</h3>
                    <StatusBadge enabled={d.enabled} />
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-purple-500/15 text-purple-400 border border-purple-500/30 font-medium">
                      {d.framework}
                    </span>
                  </div>
                  {d.description && <p className="text-xs text-muted-foreground mb-2">{d.description}</p>}
                  <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
                    <span>PAID: <code className="text-foreground/80">{truncate(d.paid, 24)}</code></span>
                    <span>Interactions: <strong className="text-foreground/80">{d.interaction_count}</strong></span>
                    <span>Last triggered: {fmtDate(d.last_triggered)}</span>
                    <span>Created: {fmtDate(d.created_at)}</span>
                  </div>
                  {d.public_key && (
                    <details className="mt-2">
                      <summary className="text-[10px] text-primary/70 cursor-pointer hover:text-primary">Show public key</summary>
                      <pre className="mt-1 rounded bg-black/20 border border-border/30 p-2 text-[10px] font-mono text-muted-foreground break-all whitespace-pre-wrap">{d.public_key}</pre>
                    </details>
                  )}
                </div>
                <div className="flex items-center gap-1.5 flex-shrink-0">
                  <button
                    onClick={() => onToggle(d.id, !d.enabled)}
                    className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-white/[0.06] transition-colors cursor-pointer"
                    title={d.enabled ? "Disable" : "Enable"}
                  >
                    {d.enabled ? <ToggleRight size={18} className="text-emerald-400" /> : <ToggleLeft size={18} />}
                  </button>
                  <button
                    onClick={() => { if (confirm(`Delete decoy "${d.name}"?`)) onDelete(d.id) }}
                    className="p-1.5 rounded-lg text-muted-foreground hover:text-red-400 hover:bg-red-500/10 transition-colors cursor-pointer"
                    title="Delete"
                  >
                    <Trash2 size={16} />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function DecoyCreateForm({ onCreated, onCancel }: { onCreated: () => void; onCancel: () => void }) {
  const [name, setName] = useState("")
  const [description, setDescription] = useState("")
  const [framework, setFramework] = useState("langchain")
  const [frameworkVer, setFrameworkVer] = useState("0.1.0")
  const [error, setError] = useState<string | null>(null)

  const mut = useMutation({
    mutationFn: (body: Record<string, unknown>) => apiClient.post("/deception/decoys", body),
    onSuccess: () => onCreated(),
    onError: (e: unknown) => setError(e instanceof Error ? e.message : "Failed to create decoy"),
  })

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    mut.mutate({ name: name.trim(), description: description.trim() || null, framework, framework_ver: frameworkVer })
  }

  return (
    <form onSubmit={submit} className="rounded-xl border border-primary/30 bg-primary/[0.03] p-4 space-y-3">
      <h4 className="text-sm font-semibold flex items-center gap-1.5"><Ghost size={16} className="text-primary" /> Deploy New Decoy Agent</h4>
      {error && <p className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-1.5">{error}</p>}
      <div className="grid grid-cols-2 gap-3">
        <label className="space-y-1">
          <span className="text-[11px] font-medium text-muted-foreground">Name *</span>
          <input value={name} onChange={(e) => setName(e.target.value)} required maxLength={200} placeholder="suspicious-gpt-assistant" className="w-full rounded-lg border border-border/40 bg-black/20 px-3 py-1.5 text-sm text-foreground placeholder:text-muted-foreground/40 focus:border-primary/50 focus:outline-none" />
        </label>
        <label className="space-y-1">
          <span className="text-[11px] font-medium text-muted-foreground">Framework</span>
          <select value={framework} onChange={(e) => setFramework(e.target.value)} className="w-full rounded-lg border border-border/40 bg-black/20 px-3 py-1.5 text-sm text-foreground focus:border-primary/50 focus:outline-none">
            {FRAMEWORKS.map((f) => <option key={f.value} value={f.value}>{f.label}</option>)}
          </select>
        </label>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <label className="space-y-1">
          <span className="text-[11px] font-medium text-muted-foreground">Framework Version</span>
          <input value={frameworkVer} onChange={(e) => setFrameworkVer(e.target.value)} maxLength={32} placeholder="0.1.0" className="w-full rounded-lg border border-border/40 bg-black/20 px-3 py-1.5 text-sm text-foreground placeholder:text-muted-foreground/40 focus:border-primary/50 focus:outline-none" />
        </label>
        <label className="space-y-1">
          <span className="text-[11px] font-medium text-muted-foreground">Description</span>
          <input value={description} onChange={(e) => setDescription(e.target.value)} maxLength={1000} placeholder="Optional description" className="w-full rounded-lg border border-border/40 bg-black/20 px-3 py-1.5 text-sm text-foreground placeholder:text-muted-foreground/40 focus:border-primary/50 focus:outline-none" />
        </label>
      </div>
      <div className="flex items-center gap-2 pt-1">
        <button type="submit" disabled={mut.isPending || !name.trim()} className="flex items-center gap-1.5 rounded-lg bg-primary px-4 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-40 transition-colors cursor-pointer">
          {mut.isPending ? <RefreshCw size={14} className="animate-spin" /> : <Plus size={14} />}
          Deploy
        </button>
        <button type="button" onClick={onCancel} className="rounded-lg border border-border/40 px-4 py-1.5 text-xs font-medium text-muted-foreground hover:text-foreground transition-colors cursor-pointer">Cancel</button>
      </div>
    </form>
  )
}

// ── Canary MCP Servers Tab ───────────────────────────────────────────────────

interface CanaryMCPTabProps {
  servers: CanaryMCP[]
  loading: boolean
  onDelete: (id: string) => void
  onToggle: (id: string, enabled: boolean) => void
  onCreated: () => void
}

function CanaryMCPTab({ servers, loading, onDelete, onToggle, onCreated }: CanaryMCPTabProps) {
  const [showForm, setShowForm] = useState(false)

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          Canary MCP servers advertise enticing tools. Any agent connecting is behaving outside its authorized scope.
        </p>
        <button
          onClick={() => setShowForm(!showForm)}
          className="flex items-center gap-1.5 rounded-lg bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 transition-colors cursor-pointer"
        >
          <Plus size={14} />
          Add Canary MCP
        </button>
      </div>

      {showForm && <CanaryMCPCreateForm onCreated={() => { onCreated(); setShowForm(false) }} onCancel={() => setShowForm(false)} />}

      {loading ? (
        <LoadingRows />
      ) : servers.length === 0 ? (
        <EmptyState icon={<Server size={40} />} message="No canary MCP servers deployed" />
      ) : (
        <div className="space-y-3">
          {servers.map((s: CanaryMCP) => (
            <div key={s.id} className="rounded-xl border border-border/40 bg-card/60 p-4 hover:border-border/60 transition-colors">
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <h3 className="font-semibold text-sm truncate">{s.name}</h3>
                    <StatusBadge enabled={s.enabled} />
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-500/15 text-cyan-400 border border-cyan-500/30 font-medium uppercase">
                      {s.protocol}
                    </span>
                    {s.tls_enabled && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 font-medium">
                        TLS
                      </span>
                    )}
                  </div>
                  {s.description && <p className="text-xs text-muted-foreground mb-2">{s.description}</p>}
                  <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
                    <span>URL: <code className="text-foreground/80">{truncate(s.server_url, 48)}</code></span>
                    <span>Tools: <strong className="text-foreground/80">{s.advertised_tools.length}</strong></span>
                    <span>Interactions: <strong className="text-foreground/80">{s.interaction_count}</strong></span>
                    <span>Last triggered: {fmtDate(s.last_triggered)}</span>
                  </div>
                  {s.advertised_tools.length > 0 && (
                    <details className="mt-2">
                      <summary className="text-[10px] text-primary/70 cursor-pointer hover:text-primary">
                        Show advertised tools ({s.advertised_tools.length})
                      </summary>
                      <div className="mt-1 flex flex-wrap gap-1">
                        {s.advertised_tools.map((tool: ToolDef, i: number) => (
                          <span key={i} className="text-[10px] px-1.5 py-0.5 rounded bg-white/5 border border-border/30 text-muted-foreground">
                            {tool.name}
                          </span>
                        ))}
                      </div>
                    </details>
                  )}
                  {s.rotate_identity && (
                    <p className="text-[10px] text-amber-400/70 mt-1 flex items-center gap-1">
                      <RefreshCw size={10} /> Identity rotates every {s.rotation_interval_hours}h
                    </p>
                  )}
                </div>
                <div className="flex items-center gap-1.5 flex-shrink-0">
                  <button
                    onClick={() => onToggle(s.id, !s.enabled)}
                    className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-white/[0.06] transition-colors cursor-pointer"
                    title={s.enabled ? "Disable" : "Enable"}
                  >
                    {s.enabled ? <ToggleRight size={18} className="text-emerald-400" /> : <ToggleLeft size={18} />}
                  </button>
                  <button
                    onClick={() => { if (confirm(`Delete canary MCP "${s.name}"?`)) onDelete(s.id) }}
                    className="p-1.5 rounded-lg text-muted-foreground hover:text-red-400 hover:bg-red-500/10 transition-colors cursor-pointer"
                    title="Delete"
                  >
                    <Trash2 size={16} />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function CanaryMCPCreateForm({ onCreated, onCancel }: { onCreated: () => void; onCancel: () => void }) {
  const [name, setName] = useState("")
  const [description, setDescription] = useState("")
  const [serverUrl, setServerUrl] = useState("https://")
  const [protocol, setProtocol] = useState("sse")
  const [tlsEnabled, setTlsEnabled] = useState(true)
  const [toolsText, setToolsText] = useState("")
  const [error, setError] = useState<string | null>(null)

  const mut = useMutation({
    mutationFn: (body: Record<string, unknown>) => apiClient.post("/deception/canary-mcp", body),
    onSuccess: () => onCreated(),
    onError: (e: unknown) => setError(e instanceof Error ? e.message : "Failed to create canary MCP"),
  })

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    // Parse tools from comma-separated list
    const tools = toolsText
      .split(",")
      .map((t: string) => t.trim())
      .filter(Boolean)
      .map((t: string) => ({ name: t, description: `Tool: ${t}` }))
    mut.mutate({
      name: name.trim(),
      description: description.trim() || null,
      server_url: serverUrl.trim(),
      protocol,
      tls_enabled: tlsEnabled,
      advertised_tools: tools,
    })
  }

  return (
    <form onSubmit={submit} className="rounded-xl border border-primary/30 bg-primary/[0.03] p-4 space-y-3">
      <h4 className="text-sm font-semibold flex items-center gap-1.5"><Server size={16} className="text-primary" /> Deploy Canary MCP Server</h4>
      {error && <p className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-1.5">{error}</p>}
      <div className="grid grid-cols-2 gap-3">
        <label className="space-y-1">
          <span className="text-[11px] font-medium text-muted-foreground">Name *</span>
          <input value={name} onChange={(e) => setName(e.target.value)} required maxLength={200} placeholder="secret-data-tools" className="w-full rounded-lg border border-border/40 bg-black/20 px-3 py-1.5 text-sm text-foreground placeholder:text-muted-foreground/40 focus:border-primary/50 focus:outline-none" />
        </label>
        <label className="space-y-1">
          <span className="text-[11px] font-medium text-muted-foreground">Server URL *</span>
          <input value={serverUrl} onChange={(e) => setServerUrl(e.target.value)} required maxLength={512} placeholder="https://canary.internal:9090" className="w-full rounded-lg border border-border/40 bg-black/20 px-3 py-1.5 text-sm text-foreground placeholder:text-muted-foreground/40 focus:border-primary/50 focus:outline-none" />
        </label>
      </div>
      <div className="grid grid-cols-3 gap-3">
        <label className="space-y-1">
          <span className="text-[11px] font-medium text-muted-foreground">Protocol</span>
          <select value={protocol} onChange={(e) => setProtocol(e.target.value)} className="w-full rounded-lg border border-border/40 bg-black/20 px-3 py-1.5 text-sm text-foreground focus:border-primary/50 focus:outline-none">
            <option value="sse">SSE</option>
            <option value="stdio">stdio</option>
            <option value="streamable-http">Streamable HTTP</option>
          </select>
        </label>
        <label className="space-y-1">
          <span className="text-[11px] font-medium text-muted-foreground">TLS</span>
          <button type="button" onClick={() => setTlsEnabled(!tlsEnabled)} className={`w-full flex items-center justify-center gap-1.5 rounded-lg border px-3 py-1.5 text-sm font-medium transition-colors cursor-pointer ${tlsEnabled ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400" : "border-border/40 bg-black/20 text-muted-foreground"}`}>
            {tlsEnabled ? <Shield size={14} /> : <XCircle size={14} />}
            {tlsEnabled ? "Enabled" : "Disabled"}
          </button>
        </label>
        <label className="space-y-1">
          <span className="text-[11px] font-medium text-muted-foreground">Description</span>
          <input value={description} onChange={(e) => setDescription(e.target.value)} maxLength={1000} placeholder="Optional" className="w-full rounded-lg border border-border/40 bg-black/20 px-3 py-1.5 text-sm text-foreground placeholder:text-muted-foreground/40 focus:border-primary/50 focus:outline-none" />
        </label>
      </div>
      <label className="block space-y-1">
        <span className="text-[11px] font-medium text-muted-foreground">Advertised Tools (comma-separated)</span>
        <input value={toolsText} onChange={(e) => setToolsText(e.target.value)} placeholder="get_credentials, read_secrets, export_database, admin_panel" className="w-full rounded-lg border border-border/40 bg-black/20 px-3 py-1.5 text-sm text-foreground placeholder:text-muted-foreground/40 focus:border-primary/50 focus:outline-none" />
        <p className="text-[10px] text-muted-foreground/50">Enticing tool names that malicious agents would attempt to call</p>
      </label>
      <div className="flex items-center gap-2 pt-1">
        <button type="submit" disabled={mut.isPending || !name.trim() || !serverUrl.trim()} className="flex items-center gap-1.5 rounded-lg bg-primary px-4 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-40 transition-colors cursor-pointer">
          {mut.isPending ? <RefreshCw size={14} className="animate-spin" /> : <Plus size={14} />}
          Deploy
        </button>
        <button type="button" onClick={onCancel} className="rounded-lg border border-border/40 px-4 py-1.5 text-xs font-medium text-muted-foreground hover:text-foreground transition-colors cursor-pointer">Cancel</button>
      </div>
    </form>
  )
}

// ── Canary Tokens Tab ────────────────────────────────────────────────────────

interface CanaryTokensTabProps {
  tokens: CanaryToken[]
  loading: boolean
  onDelete: (id: string) => void
  onToggle: (id: string, enabled: boolean) => void
  onCreated: () => void
}

function CanaryTokensTab({ tokens, loading, onDelete, onToggle, onCreated }: CanaryTokensTabProps) {
  const [showForm, setShowForm] = useState(false)
  const [newTokenValue, setNewTokenValue] = useState<string | null>(null)

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          Canary tokens are planted credentials and data that trigger high-confidence alerts when accessed or used.
        </p>
        <button
          onClick={() => setShowForm(!showForm)}
          className="flex items-center gap-1.5 rounded-lg bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 transition-colors cursor-pointer"
        >
          <Plus size={14} />
          Create Token
        </button>
      </div>

      {/* Show raw token value once after creation */}
      {newTokenValue && (
        <div className="rounded-xl border border-amber-500/40 bg-amber-500/[0.05] p-4">
          <div className="flex items-start gap-2">
            <AlertTriangle size={18} className="text-amber-400 mt-0.5 flex-shrink-0" />
            <div className="flex-1">
              <p className="text-sm font-semibold text-amber-400">Token Created — Copy Now!</p>
              <p className="text-xs text-muted-foreground mt-1">This value is shown once and stored as a SHA-256 hash. It cannot be retrieved later.</p>
              <CopyField value={newTokenValue} label="Raw Token Value" />
              <button
                onClick={() => setNewTokenValue(null)}
                className="mt-3 rounded-lg border border-border/40 px-3 py-1 text-xs font-medium text-muted-foreground hover:text-foreground transition-colors cursor-pointer"
              >
                I&apos;ve copied it — dismiss
              </button>
            </div>
          </div>
        </div>
      )}

      {showForm && (
        <CanaryTokenCreateForm
          onCreated={(rawValue: string) => {
            setNewTokenValue(rawValue)
            onCreated()
            setShowForm(false)
          }}
          onCancel={() => setShowForm(false)}
        />
      )}

      {loading ? (
        <LoadingRows />
      ) : tokens.length === 0 ? (
        <EmptyState icon={<Key size={40} />} message="No canary tokens created" />
      ) : (
        <div className="space-y-3">
          {tokens.map((t: CanaryToken) => (
            <div key={t.id} className="rounded-xl border border-border/40 bg-card/60 p-4 hover:border-border/60 transition-colors">
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <h3 className="font-semibold text-sm truncate">{t.name}</h3>
                    <StatusBadge enabled={t.enabled} />
                    <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium border ${t.token_type === "api_key" ? "bg-blue-500/15 text-blue-400 border-blue-500/30" : t.token_type === "credential" ? "bg-red-500/15 text-red-400 border-red-500/30" : t.token_type === "pii" ? "bg-amber-500/15 text-amber-400 border-amber-500/30" : "bg-purple-500/15 text-purple-400 border-purple-500/30"}`}>
                      {TOKEN_TYPES.find((tt) => tt.value === t.token_type)?.label ?? t.token_type}
                    </span>
                  </div>
                  {t.description && <p className="text-xs text-muted-foreground mb-2">{t.description}</p>}
                  <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
                    <span>Hint: <code className="text-foreground/80">{t.token_hint}</code></span>
                    <span>Triggers: <strong className="text-foreground/80">{t.trigger_count}</strong></span>
                    <span>Last triggered: {fmtDate(t.last_triggered)}</span>
                    <span className="flex items-center gap-1">
                      {t.alert_on_read ? <Eye size={10} className="text-amber-400" /> : <EyeOff size={10} />}
                      Read: {t.alert_on_read ? "Alert" : "Silent"}
                    </span>
                    <span className="flex items-center gap-1">
                      {t.alert_on_use ? <AlertTriangle size={10} className="text-red-400" /> : <XCircle size={10} />}
                      Use: {t.alert_on_use ? "Alert" : "Silent"}
                    </span>
                  </div>
                </div>
                <div className="flex items-center gap-1.5 flex-shrink-0">
                  <button
                    onClick={() => onToggle(t.id, !t.enabled)}
                    className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-white/[0.06] transition-colors cursor-pointer"
                    title={t.enabled ? "Disable" : "Enable"}
                  >
                    {t.enabled ? <ToggleRight size={18} className="text-emerald-400" /> : <ToggleLeft size={18} />}
                  </button>
                  <button
                    onClick={() => { if (confirm(`Delete token "${t.name}"?`)) onDelete(t.id) }}
                    className="p-1.5 rounded-lg text-muted-foreground hover:text-red-400 hover:bg-red-500/10 transition-colors cursor-pointer"
                    title="Delete"
                  >
                    <Trash2 size={16} />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function CanaryTokenCreateForm({ onCreated, onCancel }: { onCreated: (rawValue: string) => void; onCancel: () => void }) {
  const [name, setName] = useState("")
  const [description, setDescription] = useState("")
  const [tokenType, setTokenType] = useState("api_key")
  const [alertOnRead, setAlertOnRead] = useState(false)
  const [alertOnUse, setAlertOnUse] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const mut = useMutation({
    mutationFn: (body: Record<string, unknown>) => apiClient.post<{ raw_value: string }>("/deception/canary-tokens", body),
    onSuccess: (res: { data: { raw_value: string } }) => {
      onCreated(res.data.raw_value)
    },
    onError: (e: unknown) => setError(e instanceof Error ? e.message : "Failed to create token"),
  })

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    mut.mutate({
      name: name.trim(),
      description: description.trim() || null,
      token_type: tokenType,
      alert_on_read: alertOnRead,
      alert_on_use: alertOnUse,
    })
  }

  return (
    <form onSubmit={submit} className="rounded-xl border border-primary/30 bg-primary/[0.03] p-4 space-y-3">
      <h4 className="text-sm font-semibold flex items-center gap-1.5"><Key size={16} className="text-primary" /> Create Canary Token</h4>
      {error && <p className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-1.5">{error}</p>}
      <div className="grid grid-cols-2 gap-3">
        <label className="space-y-1">
          <span className="text-[11px] font-medium text-muted-foreground">Name *</span>
          <input value={name} onChange={(e) => setName(e.target.value)} required maxLength={200} placeholder="prod-db-key" className="w-full rounded-lg border border-border/40 bg-black/20 px-3 py-1.5 text-sm text-foreground placeholder:text-muted-foreground/40 focus:border-primary/50 focus:outline-none" />
        </label>
        <label className="space-y-1">
          <span className="text-[11px] font-medium text-muted-foreground">Token Type *</span>
          <select value={tokenType} onChange={(e) => setTokenType(e.target.value)} className="w-full rounded-lg border border-border/40 bg-black/20 px-3 py-1.5 text-sm text-foreground focus:border-primary/50 focus:outline-none">
            {TOKEN_TYPES.map((tt) => <option key={tt.value} value={tt.value}>{tt.label} — {tt.desc}</option>)}
          </select>
        </label>
      </div>
      <label className="block space-y-1">
        <span className="text-[11px] font-medium text-muted-foreground">Description</span>
        <input value={description} onChange={(e) => setDescription(e.target.value)} maxLength={1000} placeholder="Planted in HR agent prompt template" className="w-full rounded-lg border border-border/40 bg-black/20 px-3 py-1.5 text-sm text-foreground placeholder:text-muted-foreground/40 focus:border-primary/50 focus:outline-none" />
      </label>
      <div className="flex items-center gap-6">
        <label className="flex items-center gap-2 cursor-pointer">
          <input type="checkbox" checked={alertOnRead} onChange={() => setAlertOnRead(!alertOnRead)} className="rounded" />
          <span className="text-xs text-muted-foreground">Alert on read</span>
        </label>
        <label className="flex items-center gap-2 cursor-pointer">
          <input type="checkbox" checked={alertOnUse} onChange={() => setAlertOnUse(!alertOnUse)} className="rounded" />
          <span className="text-xs text-muted-foreground">Alert on use</span>
        </label>
      </div>
      <div className="flex items-center gap-2 pt-1">
        <button type="submit" disabled={mut.isPending || !name.trim()} className="flex items-center gap-1.5 rounded-lg bg-primary px-4 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-40 transition-colors cursor-pointer">
          {mut.isPending ? <RefreshCw size={14} className="animate-spin" /> : <Plus size={14} />}
          Create
        </button>
        <button type="button" onClick={onCancel} className="rounded-lg border border-border/40 px-4 py-1.5 text-xs font-medium text-muted-foreground hover:text-foreground transition-colors cursor-pointer">Cancel</button>
      </div>
    </form>
  )
}

// ── Honeypot Events Tab ──────────────────────────────────────────────────────

interface HoneypotEventsTabProps {
  events: HoneypotEvent[]
  total: number
  loading: boolean
  page: number
  pageSize: number
  onPageChange: (p: number) => void
}

function HoneypotEventsTab({ events, total, loading, page, pageSize, onPageChange }: HoneypotEventsTabProps) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize))

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        Append-only log of all interactions with deception assets. Every event is a high-confidence compromise indicator.
      </p>

      {loading ? (
        <LoadingRows />
      ) : events.length === 0 ? (
        <EmptyState icon={<AlertTriangle size={40} />} message="No honeypot events recorded" />
      ) : (
        <>
          <div className="rounded-xl border border-border/40 overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-card/80 border-b border-border/30 text-left">
                  <th className="px-3 py-2 text-[11px] font-semibold text-muted-foreground uppercase">Time</th>
                  <th className="px-3 py-2 text-[11px] font-semibold text-muted-foreground uppercase">Severity</th>
                  <th className="px-3 py-2 text-[11px] font-semibold text-muted-foreground uppercase">Source</th>
                  <th className="px-3 py-2 text-[11px] font-semibold text-muted-foreground uppercase">Source Name</th>
                  <th className="px-3 py-2 text-[11px] font-semibold text-muted-foreground uppercase">Interaction</th>
                  <th className="px-3 py-2 text-[11px] font-semibold text-muted-foreground uppercase">Agent</th>
                  <th className="px-3 py-2 text-[11px] font-semibold text-muted-foreground uppercase">MITRE</th>
                </tr>
              </thead>
              <tbody>
                {events.map((ev: HoneypotEvent) => (
                  <EventRow key={ev.id} event={ev} />
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>{total} event{total !== 1 ? "s" : ""} total</span>
            <div className="flex items-center gap-2">
              <button
                onClick={() => onPageChange(Math.max(0, page - 1))}
                disabled={page === 0}
                className="flex items-center gap-1 rounded-lg border border-border/40 px-2 py-1 hover:text-foreground disabled:opacity-30 transition-colors cursor-pointer"
              >
                <ChevronLeft size={14} /> Prev
              </button>
              <span>Page {page + 1} of {totalPages}</span>
              <button
                onClick={() => onPageChange(Math.min(totalPages - 1, page + 1))}
                disabled={page >= totalPages - 1}
                className="flex items-center gap-1 rounded-lg border border-border/40 px-2 py-1 hover:text-foreground disabled:opacity-30 transition-colors cursor-pointer"
              >
                Next <ChevronRight size={14} />
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  )
}

function EventRow({ event }: { event: HoneypotEvent }) {
  const [expanded, setExpanded] = useState(false)
  const sevClass = SEVERITY_COLORS[event.severity] ?? SEVERITY_COLORS.info

  return (
    <>
      <tr
        onClick={() => setExpanded(!expanded)}
        className="border-b border-border/20 hover:bg-white/[0.02] cursor-pointer transition-colors"
      >
        <td className="px-3 py-2 text-xs whitespace-nowrap tabular-nums">{fmtDate(event.triggered_at)}</td>
        <td className="px-3 py-2">
          <span className={`inline-block rounded-full px-2 py-0.5 text-[10px] font-bold uppercase border ${sevClass}`}>
            {event.severity}
          </span>
        </td>
        <td className="px-3 py-2 text-xs">{SOURCE_TYPE_LABELS[event.source_type] ?? event.source_type}</td>
        <td className="px-3 py-2 text-xs font-medium truncate max-w-[160px]">{event.source_name}</td>
        <td className="px-3 py-2 text-xs">{event.interaction_type}</td>
        <td className="px-3 py-2 text-xs text-muted-foreground">{event.agent_id ? truncate(event.agent_id, 16) : "—"}</td>
        <td className="px-3 py-2 text-xs text-muted-foreground">
          {event.mitre_technique ? `${event.mitre_tactic ?? ""}/${event.mitre_technique}` : "—"}
        </td>
      </tr>
      {expanded && (
        <tr className="bg-white/[0.01]">
          <td colSpan={7} className="px-3 py-3">
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 text-xs mb-2">
              <div><span className="text-muted-foreground">Source IP:</span> <span className="text-foreground">{event.source_ip ?? "N/A"}</span></div>
              <div><span className="text-muted-foreground">Agent PAID:</span> <span className="text-foreground font-mono text-[10px]">{event.agent_paid ?? "N/A"}</span></div>
              <div><span className="text-muted-foreground">Attack Class:</span> <span className="text-foreground">{event.attack_class ?? "N/A"}</span></div>
              <div><span className="text-muted-foreground">Source ID:</span> <span className="text-foreground font-mono text-[10px]">{truncate(event.source_id, 32)}</span></div>
            </div>
            {Object.keys(event.interaction_data).length > 0 && (
              <details>
                <summary className="text-[10px] text-primary/70 cursor-pointer hover:text-primary mb-1">Interaction data</summary>
                <pre className="rounded bg-black/20 border border-border/30 p-2 text-[10px] font-mono text-muted-foreground whitespace-pre-wrap max-h-40 overflow-auto">
                  {JSON.stringify(event.interaction_data, null, 2)}
                </pre>
              </details>
            )}
          </td>
        </tr>
      )}
    </>
  )
}

// ── How It Works Guide ───────────────────────────────────────────────────────

function DeceptionGuide() {
  return (
    <div className="space-y-4">
      {/* Section 1: What is Deception Technology */}
      <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
          <ShieldAlert size={16} className="text-primary" />
          What is Deception Technology?
        </h3>
        <p className="mt-1.5 text-xs text-muted-foreground leading-relaxed">
          Deception technology plants fake assets — decoy agents, canary MCP servers, and canary tokens — across your
          environment. These assets serve no legitimate purpose, so <strong className="text-foreground">any interaction is a guaranteed
          compromise indicator</strong> with zero false positives. Think of it as honeypots, purpose-built for AI agent security.
        </p>
      </div>

      {/* Section 2: End-to-end detection pipeline */}
      <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
          <Workflow size={16} className="text-primary" />
          Detection Pipeline
        </h3>
        <p className="mt-1.5 text-xs text-muted-foreground">
          When an attacker (or compromised agent) interacts with a deception asset, here's what happens:
        </p>
        <div className="mt-3 flex flex-wrap items-center gap-1.5 text-xs font-medium">
          {[
            { label: "Attacker discovers asset", color: "bg-red-500/15 text-red-400 border border-red-500/20" },
            { label: "→" },
            { label: "Interacts with decoy", color: "bg-orange-500/15 text-orange-400 border border-orange-500/20" },
            { label: "→" },
            { label: "Honeypot event recorded", color: "bg-amber-500/15 text-amber-400 border border-amber-500/20" },
            { label: "→" },
            { label: "Critical alert fires", color: "bg-red-500/15 text-red-400 border border-red-500/20" },
            { label: "→" },
            { label: "Agent auto-isolated", color: "bg-purple-500/15 text-purple-400 border border-purple-500/20" },
            { label: "→" },
            { label: "Forensics preserved", color: "bg-emerald-500/15 text-emerald-400 border border-emerald-500/20" },
          ].map((step, i) =>
            step.color ? (
              <span key={i} className={`rounded-full px-2.5 py-1 ${step.color}`}>{step.label}</span>
            ) : (
              <span key={i} className="text-muted-foreground/40">{step.label}</span>
            )
          )}
        </div>
        <p className="mt-3 text-[11px] text-muted-foreground/70">
          All events are written to an append-only audit log (cannot be updated or deleted) and feed
          into the auto-response engine for immediate containment.
        </p>
      </div>

      {/* Section 3: Three asset types */}
      <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
          <Fingerprint size={16} className="text-primary" />
          Three Types of Deception Assets
        </h3>
        <div className="mt-3 grid gap-3 md:grid-cols-3">
          <div className="rounded-lg border border-border/30 bg-black/10 p-3">
            <div className="flex items-center gap-1.5 mb-2">
              <Ghost size={14} className="text-purple-400" />
              <span className="text-xs font-semibold text-foreground">Decoy Agents</span>
            </div>
            <p className="text-[11px] text-muted-foreground leading-relaxed">
              Fake AI agents with real cryptographic identity (Ed25519 keypairs) and realistic profiles.
              They appear in agent discovery and respond to inter-agent communication.
              If any real agent communicates with a decoy — it's compromised.
            </p>
            <div className="mt-2 flex flex-wrap gap-1">
              {["Ed25519 keys", "Unique PAID", "Framework fingerprint"].map((tag) => (
                <span key={tag} className="text-[9px] px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20">{tag}</span>
              ))}
            </div>
          </div>
          <div className="rounded-lg border border-border/30 bg-black/10 p-3">
            <div className="flex items-center gap-1.5 mb-2">
              <Server size={14} className="text-cyan-400" />
              <span className="text-xs font-semibold text-foreground">Canary MCP Servers</span>
            </div>
            <p className="text-[11px] text-muted-foreground leading-relaxed">
              Fake MCP servers advertising enticing tools like <code className="text-[10px] text-cyan-400/80">get_credentials</code> or <code className="text-[10px] text-cyan-400/80">export_database</code>.
              Any agent connecting to these is behaving outside its authorized scope —
              a strong indicator of compromise or misconfiguration.
            </p>
            <div className="mt-2 flex flex-wrap gap-1">
              {["SSE / stdio / HTTP", "TLS support", "Identity rotation"].map((tag) => (
                <span key={tag} className="text-[9px] px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">{tag}</span>
              ))}
            </div>
          </div>
          <div className="rounded-lg border border-border/30 bg-black/10 p-3">
            <div className="flex items-center gap-1.5 mb-2">
              <Key size={14} className="text-amber-400" />
              <span className="text-xs font-semibold text-foreground">Canary Tokens</span>
            </div>
            <p className="text-[11px] text-muted-foreground leading-relaxed">
              Planted fake credentials, API keys, PII records, DNS names, or URLs.
              Stored as SHA-256 hashes (value shown once on creation, never again).
              If any agent reads or uses a canary token — data exfiltration detected.
            </p>
            <div className="mt-2 flex flex-wrap gap-1">
              {["API keys", "Credentials", "PII", "DNS", "URLs"].map((tag) => (
                <span key={tag} className="text-[9px] px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">{tag}</span>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Section 4: Getting started */}
      <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
          <Radio size={16} className="text-primary" />
          Getting Started
        </h3>
        <div className="mt-3 grid gap-3 text-xs text-muted-foreground md:grid-cols-2">
          <div className="flex gap-2">
            <span className="mt-0.5 text-sm font-bold text-primary/70">1.</span>
            <div><strong className="text-foreground">Deploy Decoy Agents</strong> — Create decoys that mimic real agents
              in your environment. Choose frameworks matching your real agents (LangChain, AutoGen, etc.)
              for maximum realism. Each decoy gets a unique cryptographic identity.</div>
          </div>
          <div className="flex gap-2">
            <span className="mt-0.5 text-sm font-bold text-primary/70">2.</span>
            <div><strong className="text-foreground">Set Up Canary MCP Servers</strong> — Deploy fake MCP servers with
              enticing tool names. Place them alongside real MCP servers in discovery directories.
              Any connection is an immediate high-confidence alert.</div>
          </div>
          <div className="flex gap-2">
            <span className="mt-0.5 text-sm font-bold text-primary/70">3.</span>
            <div><strong className="text-foreground">Plant Canary Tokens</strong> — Create fake API keys, credentials, or
              PII records and plant them in config files, databases, or RAG sources where attackers would
              look. Copy the raw value during creation — it's shown only once.</div>
          </div>
          <div className="flex gap-2">
            <span className="mt-0.5 text-sm font-bold text-primary/70">4.</span>
            <div><strong className="text-foreground">Monitor Honeypot Events</strong> — Check the Events tab for any
              interactions. Every event is critical — there are zero false positives.
              Enable auto-response policies to automatically isolate offending agents.</div>
          </div>
        </div>
      </div>

      {/* Section 5: Why zero false positives */}
      <div className="rounded-xl border border-amber-500/20 bg-amber-500/[0.03] p-5">
        <h3 className="text-sm font-semibold text-amber-400 flex items-center gap-1.5">
          <AlertTriangle size={16} />
          Why Zero False Positives?
        </h3>
        <p className="mt-1.5 text-xs text-muted-foreground leading-relaxed">
          Deception assets have <strong className="text-foreground">no legitimate purpose</strong>. No real agent should ever communicate with a decoy agent,
          connect to a canary MCP server, or use a planted canary token. If it happens, it means either:
        </p>
        <div className="mt-2 grid gap-2 md:grid-cols-3 text-[11px]">
          <div className="flex items-start gap-2 rounded-lg border border-red-500/20 bg-red-500/5 p-2.5">
            <span className="text-red-400 font-bold mt-px">1</span>
            <span className="text-muted-foreground"><strong className="text-red-400">Active attack</strong> — an attacker discovered and tried to use the deceptive asset</span>
          </div>
          <div className="flex items-start gap-2 rounded-lg border border-orange-500/20 bg-orange-500/5 p-2.5">
            <span className="text-orange-400 font-bold mt-px">2</span>
            <span className="text-muted-foreground"><strong className="text-orange-400">Compromised agent</strong> — an agent is being controlled by an attacker and exploring the environment</span>
          </div>
          <div className="flex items-start gap-2 rounded-lg border border-amber-500/20 bg-amber-500/5 p-2.5">
            <span className="text-amber-400 font-bold mt-px">3</span>
            <span className="text-muted-foreground"><strong className="text-amber-400">Data exfiltration</strong> — planted credentials or data appeared outside the environment</span>
          </div>
        </div>
        <p className="mt-2.5 text-[11px] text-muted-foreground/70">
          This makes deception the fastest, cheapest, and highest-confidence detection layer you can deploy.
          Honeypot alerts should always be treated as critical incidents.
        </p>
      </div>
    </div>
  )
}

// ── Shared UI Atoms ──────────────────────────────────────────────────────────

function LoadingRows() {
  return (
    <div className="space-y-3">
      {[1, 2, 3].map((i) => (
        <div key={i} className="rounded-xl border border-border/30 bg-card/30 p-4 animate-pulse">
          <div className="h-4 w-48 rounded bg-white/5 mb-2" />
          <div className="h-3 w-80 rounded bg-white/5" />
        </div>
      ))}
    </div>
  )
}

function EmptyState({ icon, message }: { icon: React.ReactNode; message: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-muted-foreground/50">
      {icon}
      <p className="mt-3 text-sm">{message}</p>
    </div>
  )
}
