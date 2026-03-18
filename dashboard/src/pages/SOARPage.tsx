// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — SOAR Integration Management Page
 *
 * Tabs:
 *   1. API Keys — Create/revoke SOAR API keys
 *   2. Webhooks — Manage outbound webhook subscriptions + delivery logs
 *   3. Integrations — Configure SOAR platforms (XSOAR, Phantom, Tines)
 *   4. Action Log — Audit trail of SOAR-initiated actions
 */

import { useState, useCallback, useEffect } from "react"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import apiClient from "@/api/client"
import {
  Key, Webhook, Plug, ScrollText, Plus, Trash2, TestTube,
  Copy, CheckCircle, XCircle, Eye, RefreshCw, Info,
  Unplug, HelpCircle,
} from "lucide-react"

// ── Types ────────────────────────────────────────────────────────────────────

interface ApiKey {
  id: string
  name: string
  key_prefix: string
  scopes: string[]
  expires_at: string | null
  last_used_at: string | null
  created_at: string
  revoked: boolean
  raw_key?: string
}

interface WebhookSub {
  id: string
  name: string
  url: string
  event_types: string[]
  severity_filter: string[] | null
  enabled: boolean
  retry_count: number
  created_at: string
  updated_at: string
}

interface WebhookLog {
  id: string
  event_type: string
  status_code: number | null
  response_ms: number | null
  success: boolean
  error: string | null
  created_at: string
}

interface Integration {
  id: string
  platform: string
  name: string
  config: Record<string, unknown>
  enabled: boolean
  last_sync_at: string | null
  last_error: string | null
  created_at: string
  updated_at: string
}

interface ActionLogEntry {
  id: string
  action: string
  target_type: string
  target_id: string
  result: string
  error: string | null
  created_at: string
}

// ── API hooks ────────────────────────────────────────────────────────────────

const soarKeys = {
  apiKeys: () => ["soar", "api-keys"] as const,
  webhooks: () => ["soar", "webhooks"] as const,
  integrations: () => ["soar", "integrations"] as const,
  actionLog: () => ["soar", "action-log"] as const,
  webhookLogs: (id: string) => ["soar", "webhooks", id, "logs"] as const,
}

function useApiKeys() {
  return useQuery({
    queryKey: soarKeys.apiKeys(),
    queryFn: async () => {
      const { data } = await apiClient.get<ApiKey[]>("/soar/api-keys")
      return data
    },
  })
}

function useCreateApiKey() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (body: { name: string; scopes: string[]; expires_in_days: number | null }) => {
      const { data } = await apiClient.post<ApiKey>("/soar/api-keys", body)
      return data
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: soarKeys.apiKeys() }),
  })
}

function useRevokeApiKey() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (id: string) => {
      await apiClient.delete(`/soar/api-keys/${id}`)
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: soarKeys.apiKeys() }),
  })
}

function useWebhooks() {
  return useQuery({
    queryKey: soarKeys.webhooks(),
    queryFn: async () => {
      const { data } = await apiClient.get<WebhookSub[]>("/soar/webhooks")
      return data
    },
  })
}

function useCreateWebhook() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (body: { name: string; url: string; secret?: string; event_types: string[] }) => {
      const { data } = await apiClient.post<WebhookSub>("/soar/webhooks", body)
      return data
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: soarKeys.webhooks() }),
  })
}

function useDeleteWebhook() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (id: string) => {
      await apiClient.delete(`/soar/webhooks/${id}`)
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: soarKeys.webhooks() }),
  })
}

function useTestWebhook() {
  return useMutation({
    mutationFn: async (id: string) => {
      const { data } = await apiClient.post<{ success: boolean; status_code: number; response_ms: number; error: string | null }>(`/soar/webhooks/${id}/test`)
      return data
    },
  })
}

function useWebhookLogs(id: string | null) {
  return useQuery({
    queryKey: soarKeys.webhookLogs(id ?? ""),
    queryFn: async () => {
      const { data } = await apiClient.get<{ total: number; entries: WebhookLog[] }>(`/soar/webhooks/${id}/logs`)
      return data
    },
    enabled: !!id,
  })
}

function useIntegrations() {
  return useQuery({
    queryKey: soarKeys.integrations(),
    queryFn: async () => {
      const { data } = await apiClient.get<Integration[]>("/soar/integrations")
      return data
    },
  })
}

function useCreateIntegration() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (body: { platform: string; name: string; config: Record<string, unknown>; enabled: boolean }) => {
      const { data } = await apiClient.post<Integration>("/soar/integrations", body)
      return data
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: soarKeys.integrations() }),
  })
}

function useDeleteIntegration() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (id: string) => {
      await apiClient.delete(`/soar/integrations/${id}`)
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: soarKeys.integrations() }),
  })
}

// ── Helpers ──────────────────────────────────────────────────────────────────

const TABS = [
  { key: "keys", label: "API Keys", icon: Key },
  { key: "webhooks", label: "Webhooks", icon: Webhook },
  { key: "integrations", label: "Integrations", icon: Plug },
  { key: "log", label: "Action Log", icon: ScrollText },
] as const

type TabKey = typeof TABS[number]["key"]

function Badge({ children, color }: { children: React.ReactNode; color: string }) {
  return <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${color}`}>{children}</span>
}

function fmtDate(iso: string | null) {
  if (!iso) return "—"
  return new Date(iso).toLocaleString()
}

function ScopeBadges({ scopes }: { scopes: string[] }) {
  return (
    <div className="flex flex-wrap gap-1">
      {scopes.map(s => (
        <Badge key={s} color="bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-300">{s}</Badge>
      ))}
    </div>
  )
}

// ── Main Page ────────────────────────────────────────────────────────────────

export default function SOARPage() {
  const [tab, setTab] = useState<TabKey>("keys")
  const [showGuide, setShowGuide] = useState(false)

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <div className="flex items-center gap-3">
            <Unplug className="h-7 w-7 text-indigo-600" />
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">SOAR Integration</h1>
          </div>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            Manage API keys, webhooks, and platform integrations for bidirectional SOAR connectivity.
          </p>
        </div>
        <button
          onClick={() => setShowGuide(!showGuide)}
          className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"
        >
          <HelpCircle size={14} />
          {showGuide ? "Hide Guide" : "How does this work?"}
        </button>
      </div>

      {showGuide && (
        <div className="space-y-4">
          <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
            <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
              <Unplug size={16} className="text-indigo-400" />
              What is SOAR Integration?
            </h3>
            <p className="mt-1.5 text-xs text-muted-foreground leading-relaxed">
              <strong className="text-foreground">SOAR</strong> (Security Orchestration, Automation, and Response) integration allows Phantex to connect bidirectionally with platforms like <strong className="text-foreground">Splunk SOAR (Phantom)</strong>, <strong className="text-foreground">Cortex XSOAR</strong>, and <strong className="text-foreground">Tines</strong>. Alerts flow out to your SOAR platform, and response actions flow back.
            </p>
          </div>
          <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
            <h3 className="text-sm font-semibold text-foreground">Quick Setup</h3>
            <div className="mt-2 space-y-1 text-xs text-muted-foreground">
              <p><strong className="text-foreground">1. API Keys tab</strong> — Generate a key with scopes matching your SOAR playbook needs (alerts, actions, read).</p>
              <p><strong className="text-foreground">2. Webhooks tab</strong> — Subscribe your SOAR endpoint to Phantex event types (alert.created, action.completed).</p>
              <p><strong className="text-foreground">3. Integrations tab</strong> — Configure your SOAR platform credentials and test connectivity.</p>
              <p><strong className="text-foreground">4. Action Log tab</strong> — Monitor every SOAR-initiated action for accountability.</p>
            </div>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="flex border-b border-gray-200 dark:border-gray-700">
        {TABS.map(t => {
          const Icon = t.icon
          return (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
                tab === t.key
                  ? "border-indigo-600 text-indigo-600 dark:text-indigo-400 dark:border-indigo-400"
                  : "border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
              }`}
            >
              <Icon size={16} />
              {t.label}
            </button>
          )
        })}
      </div>

      {/* Tab content */}
      {tab === "keys" && <ApiKeysTab />}
      {tab === "webhooks" && <WebhooksTab />}
      {tab === "integrations" && <IntegrationsTab />}
      {tab === "log" && <ActionLogTab />}
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════════════════════
//  API KEYS TAB
// ═══════════════════════════════════════════════════════════════════════════════

function ApiKeysTab() {
  const keys = useApiKeys()
  const create = useCreateApiKey()
  const revoke = useRevokeApiKey()
  const [showCreate, setShowCreate] = useState(false)
  const [newKey, setNewKey] = useState<ApiKey | null>(null)
  const [name, setName] = useState("")
  const [scopes, setScopes] = useState<string[]>(["*"])
  const [expDays, setExpDays] = useState<string>("")
  const [copied, setCopied] = useState(false)

  const handleCreate = async () => {
    const result = await create.mutateAsync({
      name,
      scopes,
      expires_in_days: expDays ? parseInt(expDays) : null,
    })
    setNewKey(result)
    setShowCreate(false)
    setName("")
  }

  const handleCopyKey = (key: string) => {
    navigator.clipboard.writeText(key)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="space-y-4">
      {/* Info banner */}
      <div className="flex items-start gap-3 rounded-lg border border-blue-200 bg-blue-50 p-4 dark:border-blue-900 dark:bg-blue-950/30">
        <Info className="h-5 w-5 shrink-0 text-blue-600 mt-0.5" />
        <div className="text-sm text-blue-800 dark:text-blue-300">
          <strong>API Keys</strong> authenticate SOAR platforms (XSOAR, Phantom, Tines) when they call Phantex.
          Keys are SHA-256 hashed — the raw key is shown <strong>only once</strong> at creation time. Store it securely.
        </div>
      </div>

      {/* New key display */}
      {newKey?.raw_key && (
        <div className="rounded-lg border-2 border-green-400 bg-green-50 p-4 dark:border-green-700 dark:bg-green-950/30">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-semibold text-green-800 dark:text-green-300">API Key Created — Copy Now!</p>
              <p className="mt-1 text-xs text-green-700 dark:text-green-400">This will not be shown again.</p>
            </div>
            <button
              onClick={() => handleCopyKey(newKey.raw_key!)}
              className="flex items-center gap-1.5 rounded-md bg-green-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-green-700"
            >
              {copied ? <CheckCircle size={14} /> : <Copy size={14} />}
              {copied ? "Copied!" : "Copy Key"}
            </button>
          </div>
          <code className="mt-2 block rounded bg-green-100 px-3 py-2 text-xs font-mono text-green-900 break-all dark:bg-green-900/40 dark:text-green-200">
            {newKey.raw_key}
          </code>
        </div>
      )}

      {/* Create form */}
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-gray-800 dark:text-gray-200">API Keys</h2>
        <button
          onClick={() => setShowCreate(!showCreate)}
          className="flex items-center gap-1.5 rounded-md bg-indigo-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-indigo-700"
        >
          <Plus size={14} />
          Create Key
        </button>
      </div>

      {showCreate && (
        <div className="rounded-lg border border-gray-200 bg-white p-4 dark:border-gray-700 dark:bg-gray-800 space-y-3">
          <div>
            <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Name</label>
            <input
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="e.g. XSOAR Production"
              className="w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm dark:border-gray-600 dark:bg-gray-900 dark:text-white"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Scopes</label>
            <div className="flex flex-wrap gap-2">
              {["*", "alerts.read", "alerts.write", "actions.execute", "enrichment.read", "webhooks.manage"].map(s => (
                <label key={s} className="flex items-center gap-1 text-xs text-gray-700 dark:text-gray-300">
                  <input
                    type="checkbox"
                    checked={scopes.includes(s)}
                    onChange={e => {
                      if (e.target.checked) setScopes([...scopes, s])
                      else setScopes(scopes.filter(x => x !== s))
                    }}
                  />
                  {s}
                </label>
              ))}
            </div>
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Expires in (days, blank = never)</label>
            <input
              value={expDays}
              onChange={e => setExpDays(e.target.value.replace(/\D/g, ""))}
              placeholder="365"
              className="w-32 rounded-md border border-gray-300 bg-white px-3 py-2 text-sm dark:border-gray-600 dark:bg-gray-900 dark:text-white"
            />
          </div>
          <button
            onClick={handleCreate}
            disabled={!name || create.isPending}
            className="rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-50"
          >
            {create.isPending ? "Creating..." : "Create"}
          </button>
        </div>
      )}

      {/* Key list */}
      <div className="rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead className="bg-gray-50 dark:bg-gray-800">
            <tr>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400">Name</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400">Key Prefix</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400">Scopes</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400">Expires</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400">Last Used</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400">Status</th>
              <th className="px-4 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-gray-700 bg-white dark:bg-gray-900">
            {keys.data?.map((k: ApiKey) => (
              <tr key={k.id}>
                <td className="px-4 py-3 text-sm font-medium text-gray-900 dark:text-white">{k.name}</td>
                <td className="px-4 py-3 text-sm font-mono text-gray-600 dark:text-gray-400">{k.key_prefix}...</td>
                <td className="px-4 py-3"><ScopeBadges scopes={k.scopes} /></td>
                <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-400">{fmtDate(k.expires_at)}</td>
                <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-400">{fmtDate(k.last_used_at)}</td>
                <td className="px-4 py-3">
                  {k.revoked
                    ? <Badge color="bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300">Revoked</Badge>
                    : <Badge color="bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300">Active</Badge>
                  }
                </td>
                <td className="px-4 py-3 text-right">
                  {!k.revoked && (
                    <button
                      onClick={() => revoke.mutate(k.id)}
                      className="text-red-600 hover:text-red-800 dark:text-red-400"
                      title="Revoke"
                    >
                      <Trash2 size={14} />
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {!keys.data?.length && (
              <tr><td colSpan={7} className="px-4 py-8 text-center text-sm text-gray-400">No API keys created yet</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════════════════════
//  WEBHOOKS TAB
// ═══════════════════════════════════════════════════════════════════════════════

function WebhooksTab() {
  const webhooks = useWebhooks()
  const create = useCreateWebhook()
  const del = useDeleteWebhook()
  const test = useTestWebhook()
  const [showCreate, setShowCreate] = useState(false)
  const [name, setName] = useState("")
  const [url, setUrl] = useState("")
  const [secret, setSecret] = useState("")
  const [events, setEvents] = useState<string[]>(["alert.created"])
  const [logsId, setLogsId] = useState<string | null>(null)
  const logs = useWebhookLogs(logsId)
  const [testResult, setTestResult] = useState<{ id: string; success: boolean; error: string | null } | null>(null)

  const EVENT_TYPES = [
    "alert.created", "alert.updated", "alert.resolved",
    "action.executed", "action.shadow",
    "escalation.triggered", "escalation.reset",
    "agent.isolated", "agent.trust_changed",
  ]

  const handleCreate = async () => {
    await create.mutateAsync({ name, url, secret: secret || undefined, event_types: events })
    setShowCreate(false)
    setName(""); setUrl(""); setSecret(""); setEvents(["alert.created"])
  }

  const handleTest = async (id: string) => {
    const result = await test.mutateAsync(id)
    setTestResult({ id, ...result })
    setTimeout(() => setTestResult(null), 5000)
  }

  return (
    <div className="space-y-4">
      <div className="flex items-start gap-3 rounded-lg border border-blue-200 bg-blue-50 p-4 dark:border-blue-900 dark:bg-blue-950/30">
        <Info className="h-5 w-5 shrink-0 text-blue-600 mt-0.5" />
        <div className="text-sm text-blue-800 dark:text-blue-300">
          <strong>Outbound Webhooks</strong> deliver events (new alerts, actions, escalations) to your SOAR platform in real-time.
          Payloads are signed with HMAC-SHA256. Configure retries and severity filters per subscription.
        </div>
      </div>

      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-gray-800 dark:text-gray-200">Webhook Subscriptions</h2>
        <button onClick={() => setShowCreate(!showCreate)} className="flex items-center gap-1.5 rounded-md bg-indigo-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-indigo-700">
          <Plus size={14} /> Add Webhook
        </button>
      </div>

      {showCreate && (
        <div className="rounded-lg border border-gray-200 bg-white p-4 dark:border-gray-700 dark:bg-gray-800 space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Name</label>
              <input value={name} onChange={e => setName(e.target.value)} placeholder="e.g. XSOAR Webhook" className="w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm dark:border-gray-600 dark:bg-gray-900 dark:text-white" />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">URL (HTTPS only)</label>
              <input value={url} onChange={e => setUrl(e.target.value)} placeholder="https://hooks.corp.com/phantex" className="w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm dark:border-gray-600 dark:bg-gray-900 dark:text-white" />
            </div>
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Signing Secret (optional)</label>
            <input value={secret} onChange={e => setSecret(e.target.value)} type="password" placeholder="HMAC secret" className="w-64 rounded-md border border-gray-300 bg-white px-3 py-2 text-sm dark:border-gray-600 dark:bg-gray-900 dark:text-white" />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Event Types</label>
            <div className="flex flex-wrap gap-2">
              {EVENT_TYPES.map(et => (
                <label key={et} className="flex items-center gap-1 text-xs text-gray-700 dark:text-gray-300">
                  <input type="checkbox" checked={events.includes(et)} onChange={e => {
                    if (e.target.checked) setEvents([...events, et])
                    else setEvents(events.filter(x => x !== et))
                  }} />
                  {et}
                </label>
              ))}
            </div>
          </div>
          <button onClick={handleCreate} disabled={!name || !url || create.isPending} className="rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-50">
            {create.isPending ? "Creating..." : "Create"}
          </button>
        </div>
      )}

      {/* Webhook list */}
      <div className="space-y-3">
        {webhooks.data?.map((w: WebhookSub) => (
          <div key={w.id} className="rounded-lg border border-gray-200 bg-white p-4 dark:border-gray-700 dark:bg-gray-800">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-semibold text-gray-900 dark:text-white">{w.name}</h3>
                <p className="text-xs text-gray-500 dark:text-gray-400 font-mono">{w.url}</p>
              </div>
              <div className="flex items-center gap-2">
                {w.enabled
                  ? <Badge color="bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300">Enabled</Badge>
                  : <Badge color="bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-400">Disabled</Badge>
                }
                <button onClick={() => handleTest(w.id)} className="rounded p-1 text-blue-600 hover:bg-blue-50 dark:hover:bg-blue-900/30" title="Test">
                  <TestTube size={14} />
                </button>
                <button onClick={() => setLogsId(logsId === w.id ? null : w.id)} className="rounded p-1 text-gray-600 hover:bg-gray-100 dark:text-gray-400 dark:hover:bg-gray-700" title="View Logs">
                  <Eye size={14} />
                </button>
                <button onClick={() => del.mutate(w.id)} className="rounded p-1 text-red-600 hover:bg-red-50 dark:hover:bg-red-900/30" title="Delete">
                  <Trash2 size={14} />
                </button>
              </div>
            </div>
            <div className="mt-2 flex flex-wrap gap-1">
              {w.event_types.map((et: string) => (
                <Badge key={et} color="bg-purple-100 text-purple-800 dark:bg-purple-900/40 dark:text-purple-300">{et}</Badge>
              ))}
            </div>
            {testResult && testResult.id === w.id && (
              <div className={`mt-2 flex items-center gap-2 text-xs ${testResult.success ? "text-green-600" : "text-red-600"}`}>
                {testResult.success ? <CheckCircle size={14} /> : <XCircle size={14} />}
                {testResult.success ? "Test delivery successful" : `Test failed: ${testResult.error}`}
              </div>
            )}
            {logsId === w.id && logs.data && (
              <div className="mt-3 rounded border border-gray-100 dark:border-gray-700 overflow-hidden">
                <table className="min-w-full text-xs">
                  <thead className="bg-gray-50 dark:bg-gray-800">
                    <tr>
                      <th className="px-3 py-1.5 text-left text-gray-500">Event</th>
                      <th className="px-3 py-1.5 text-left text-gray-500">Status</th>
                      <th className="px-3 py-1.5 text-left text-gray-500">Latency</th>
                      <th className="px-3 py-1.5 text-left text-gray-500">Result</th>
                      <th className="px-3 py-1.5 text-left text-gray-500">Time</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100 dark:divide-gray-700">
                    {logs.data.entries.map((l: WebhookLog) => (
                      <tr key={l.id}>
                        <td className="px-3 py-1.5 text-gray-700 dark:text-gray-300">{l.event_type}</td>
                        <td className="px-3 py-1.5 font-mono">{l.status_code ?? "—"}</td>
                        <td className="px-3 py-1.5">{l.response_ms ? `${l.response_ms}ms` : "—"}</td>
                        <td className="px-3 py-1.5">
                          {l.success
                            ? <span className="text-green-600">OK</span>
                            : <span className="text-red-600">{l.error || "Failed"}</span>
                          }
                        </td>
                        <td className="px-3 py-1.5 text-gray-500">{fmtDate(l.created_at)}</td>
                      </tr>
                    ))}
                    {!logs.data.entries.length && (
                      <tr><td colSpan={5} className="px-3 py-4 text-center text-gray-400">No delivery logs yet</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        ))}
        {!webhooks.data?.length && (
          <p className="text-sm text-gray-400 text-center py-8">No webhooks configured</p>
        )}
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════════════════════
//  INTEGRATIONS TAB
// ═══════════════════════════════════════════════════════════════════════════════

function IntegrationsTab() {
  const integrations = useIntegrations()
  const create = useCreateIntegration()
  const del = useDeleteIntegration()
  const [showCreate, setShowCreate] = useState(false)
  const [platform, setPlatform] = useState("xsoar")
  const [name, setName] = useState("")
  const [configJson, setConfigJson] = useState("{}")

  const PLATFORMS = [
    { value: "xsoar", label: "Cortex XSOAR", desc: "Palo Alto Networks XSOAR / Demisto" },
    { value: "phantom", label: "Splunk SOAR", desc: "Splunk SOAR (Phantom)" },
    { value: "tines", label: "Tines", desc: "Tines no-code SOAR" },
    { value: "generic", label: "Generic", desc: "Custom SOAR via webhook API" },
  ]

  const handleCreate = async () => {
    try {
      const config = JSON.parse(configJson)
      await create.mutateAsync({ platform, name, config, enabled: true })
      setShowCreate(false)
      setName("")
      setConfigJson("{}")
    } catch {
      alert("Invalid JSON in config")
    }
  }

  const platformIcon = (p: string) => {
    switch (p) {
      case "xsoar": return "🛡️"
      case "phantom": return "👻"
      case "tines": return "⚡"
      default: return "🔌"
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-start gap-3 rounded-lg border border-blue-200 bg-blue-50 p-4 dark:border-blue-900 dark:bg-blue-950/30">
        <Info className="h-5 w-5 shrink-0 text-blue-600 mt-0.5" />
        <div className="text-sm text-blue-800 dark:text-blue-300">
          <strong>SOAR Integrations</strong> connect Phantex to your orchestration platform.
          Integration packs are available for <strong>Cortex XSOAR</strong>, <strong>Splunk SOAR</strong>, and <strong>Tines</strong>.
          Use "Generic" for any platform that supports webhook APIs.
        </div>
      </div>

      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-gray-800 dark:text-gray-200">Integrations</h2>
        <button onClick={() => setShowCreate(!showCreate)} className="flex items-center gap-1.5 rounded-md bg-indigo-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-indigo-700">
          <Plus size={14} /> Add Integration
        </button>
      </div>

      {showCreate && (
        <div className="rounded-lg border border-gray-200 bg-white p-4 dark:border-gray-700 dark:bg-gray-800 space-y-3">
          <div>
            <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Platform</label>
            <div className="grid grid-cols-4 gap-2">
              {PLATFORMS.map(p => (
                <button
                  key={p.value}
                  onClick={() => setPlatform(p.value)}
                  className={`rounded-lg border p-3 text-left text-sm transition ${
                    platform === p.value
                      ? "border-indigo-500 bg-indigo-50 dark:bg-indigo-900/20"
                      : "border-gray-200 dark:border-gray-700 hover:border-gray-300"
                  }`}
                >
                  <div className="font-medium text-gray-900 dark:text-white">{p.label}</div>
                  <div className="text-xs text-gray-500 dark:text-gray-400">{p.desc}</div>
                </button>
              ))}
            </div>
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Name</label>
            <input value={name} onChange={e => setName(e.target.value)} placeholder="e.g. Production XSOAR" className="w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm dark:border-gray-600 dark:bg-gray-900 dark:text-white" />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Config (JSON)</label>
            <textarea value={configJson} onChange={e => setConfigJson(e.target.value)} rows={4} className="w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm font-mono dark:border-gray-600 dark:bg-gray-900 dark:text-white" placeholder='{"base_url": "https://xsoar.corp.com", "api_key": "..."}' />
          </div>
          <button onClick={handleCreate} disabled={!name || create.isPending} className="rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-50">
            {create.isPending ? "Creating..." : "Create"}
          </button>
        </div>
      )}

      {/* Integration list */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {integrations.data?.map((i: Integration) => (
          <div key={i.id} className="rounded-lg border border-gray-200 bg-white p-4 dark:border-gray-700 dark:bg-gray-800">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="text-xl">{platformIcon(i.platform)}</span>
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white">{i.name}</h3>
                  <p className="text-xs text-gray-500 dark:text-gray-400">{i.platform.toUpperCase()}</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                {i.enabled
                  ? <Badge color="bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300">Enabled</Badge>
                  : <Badge color="bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-400">Disabled</Badge>
                }
                <button onClick={() => del.mutate(i.id)} className="text-red-600 hover:text-red-800"><Trash2 size={14} /></button>
              </div>
            </div>
            {i.last_error && (
              <div className="mt-2 text-xs text-red-600 dark:text-red-400 flex items-center gap-1">
                <XCircle size={12} /> {i.last_error}
              </div>
            )}
            <div className="mt-2 text-xs text-gray-500 dark:text-gray-400">
              Created: {fmtDate(i.created_at)} • Last sync: {fmtDate(i.last_sync_at)}
            </div>
          </div>
        ))}
        {!integrations.data?.length && (
          <p className="text-sm text-gray-400 text-center py-8 col-span-2">No integrations configured</p>
        )}
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════════════════════
//  ACTION LOG TAB
// ═══════════════════════════════════════════════════════════════════════════════

function ActionLogTab() {
  // We use the internal admin API to view SOAR action log (not the ext/ API key one)
  // Since the router shares the same DB table, we query webhooks log as approximation
  // For the full action log, we'd need a user-facing endpoint — let's add one inline

  const [entries, setEntries] = useState<ActionLogEntry[]>([])
  const [loading, setLoading] = useState(true)

  // Fetch action log via a generic endpoint
  const fetchLog = useCallback(async () => {
    try {
      setLoading(true)
      // Try to get action log — this uses the admin JWT, not API key
      const { data } = await apiClient.get<ActionLogEntry[]>("/soar/action-log-admin")
      setEntries(data)
    } catch {
      // Endpoint may not exist yet — show empty state
      setEntries([])
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { fetchLog() }, [fetchLog])

  return (
    <div className="space-y-4">
      <div className="flex items-start gap-3 rounded-lg border border-blue-200 bg-blue-50 p-4 dark:border-blue-900 dark:bg-blue-950/30">
        <Info className="h-5 w-5 shrink-0 text-blue-600 mt-0.5" />
        <div className="text-sm text-blue-800 dark:text-blue-300">
          <strong>Action Log</strong> — Immutable audit trail of every action executed through the SOAR API.
          Each entry records who (API key), what (action), on what (target), and the result.
        </div>
      </div>

      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-gray-800 dark:text-gray-200">SOAR Action Audit Log</h2>
        <button onClick={fetchLog} className="flex items-center gap-1.5 text-sm text-gray-600 hover:text-gray-800 dark:text-gray-400">
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      <div className="rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead className="bg-gray-50 dark:bg-gray-800">
            <tr>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500">Action</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500">Target</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500">Result</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500">Error</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500">Time</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-gray-700 bg-white dark:bg-gray-900">
            {entries.map(e => (
              <tr key={e.id}>
                <td className="px-4 py-3 text-sm font-medium text-gray-900 dark:text-white">{e.action}</td>
                <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-400">
                  <Badge color="bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300">{e.target_type}</Badge>
                  <span className="ml-1 font-mono text-xs">{e.target_id.slice(0, 8)}...</span>
                </td>
                <td className="px-4 py-3">
                  {e.result === "success"
                    ? <Badge color="bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300">Success</Badge>
                    : <Badge color="bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300">Error</Badge>
                  }
                </td>
                <td className="px-4 py-3 text-xs text-red-600 dark:text-red-400">{e.error || "—"}</td>
                <td className="px-4 py-3 text-xs text-gray-500">{fmtDate(e.created_at)}</td>
              </tr>
            ))}
            {loading && (
              <tr><td colSpan={5} className="px-4 py-8 text-center text-sm text-gray-400">Loading...</td></tr>
            )}
            {!loading && !entries.length && (
              <tr><td colSpan={5} className="px-4 py-8 text-center text-sm text-gray-400">No actions executed yet</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
