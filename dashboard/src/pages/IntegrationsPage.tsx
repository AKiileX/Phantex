// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Integrations Hub Page.
 *
 * Unified management for all outbound integration layers:
 *   1. SIEM Connectors — Splunk, Azure Sentinel, Elastic, CrowdStrike LogScale, Syslog/CEF
 *   2. Notification Channels — Slack, PagerDuty, Email, Webhook
 *   3. SOAR — Quick-link to dedicated SOAR management page
 *
 * Security:
 *   - Admin-only route (enforced by ProtectedRoute + sidebar gate)
 *   - Credentials never rendered — backend returns masked config (`***`)
 *   - All mutations invalidate cache to prevent stale state
 *   - Input validation + length caps on all user-supplied fields
 *   - XSS-safe: no dangerouslySetInnerHTML, all values rendered as text nodes
 *   - CSRF: apiClient attaches HttpOnly cookie auth automatically
 */

import { useState, useCallback } from "react"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { useNavigate } from "react-router-dom"
import apiClient from "@/api/client"
import {
  Server,
  Bell,
  Unplug,
  Plus,
  Trash2,
  TestTube,
  CheckCircle,
  XCircle,
  RefreshCw,
  Eye,
  EyeOff,
  Cable,
  ArrowRight,
  HelpCircle,
} from "lucide-react"

// ── Constants ────────────────────────────────────────────────────────────────

const TABS = ["SIEM Connectors", "Notification Channels", "SOAR"] as const
type TabName = (typeof TABS)[number]

/** Platform display metadata */
const SIEM_PLATFORMS: Record<string, { label: string; color: string; fields: ConfigField[] }> = {
  splunk_hec: {
    label: "Splunk HEC",
    color: "bg-green-500/20 text-green-400 border-green-500/30",
    fields: [
      { key: "endpoint", label: "HEC Endpoint URL", type: "url", required: true, placeholder: "https://splunk.example.com:8088" },
      { key: "hec_token", label: "HEC Token", type: "secret", required: true, placeholder: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" },
      { key: "index", label: "Index", type: "text", required: false, placeholder: "phantex" },
      { key: "sourcetype", label: "Source Type", type: "text", required: false, placeholder: "phantex:alert" },
      { key: "verify_ssl", label: "Verify TLS", type: "toggle", required: false },
    ],
  },
  azure_sentinel: {
    label: "Azure Sentinel",
    color: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    fields: [
      { key: "workspace_id", label: "Workspace ID", type: "text", required: true, placeholder: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" },
      { key: "shared_key", label: "Shared Key", type: "secret", required: true, placeholder: "Base64-encoded primary key" },
      { key: "log_type", label: "Log Type", type: "text", required: false, placeholder: "PhantexAlerts" },
      { key: "verify_ssl", label: "Verify TLS", type: "toggle", required: false },
    ],
  },
  elastic_siem: {
    label: "Elastic SIEM",
    color: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    fields: [
      { key: "endpoint", label: "Elasticsearch URL", type: "url", required: true, placeholder: "https://elastic.example.com:9200" },
      { key: "api_key_id", label: "API Key ID", type: "secret", required: true, placeholder: "API key ID" },
      { key: "api_key_secret", label: "API Key Secret", type: "secret", required: true, placeholder: "API key secret" },
      { key: "index", label: "Index", type: "text", required: false, placeholder: "phantex-alerts" },
      { key: "verify_ssl", label: "Verify TLS", type: "toggle", required: false },
    ],
  },
  crowdstrike_logscale: {
    label: "CrowdStrike LogScale",
    color: "bg-red-500/20 text-red-400 border-red-500/30",
    fields: [
      { key: "endpoint", label: "LogScale Endpoint", type: "url", required: true, placeholder: "https://cloud.humio.com" },
      { key: "ingest_token", label: "Ingest Token", type: "secret", required: true, placeholder: "Ingest token" },
      { key: "verify_ssl", label: "Verify TLS", type: "toggle", required: false },
    ],
  },
  syslog_cef: {
    label: "Syslog / CEF",
    color: "bg-purple-500/20 text-purple-400 border-purple-500/30",
    fields: [
      { key: "host", label: "Syslog Host", type: "text", required: true, placeholder: "syslog.example.com" },
      { key: "port", label: "Port", type: "number", required: false, placeholder: "514" },
      { key: "protocol", label: "Protocol", type: "select", required: true, options: ["tcp", "udp"] },
      { key: "tls_enabled", label: "TLS Enabled", type: "toggle", required: false },
      { key: "tls_verify", label: "Verify TLS Certificate", type: "toggle", required: false },
    ],
  },
}

const NOTIFICATION_TYPES: Record<string, { label: string; color: string; fields: ConfigField[] }> = {
  slack: {
    label: "Slack",
    color: "bg-purple-500/20 text-purple-400 border-purple-500/30",
    fields: [
      { key: "webhook_url", label: "Webhook URL", type: "secret", required: true, placeholder: "https://hooks.slack.com/services/..." },
      { key: "channel", label: "Channel (optional override)", type: "text", required: false, placeholder: "#security-alerts" },
      { key: "username", label: "Bot Username", type: "text", required: false, placeholder: "Phantex" },
    ],
  },
  pagerduty: {
    label: "PagerDuty",
    color: "bg-green-500/20 text-green-400 border-green-500/30",
    fields: [
      { key: "routing_key", label: "Routing Key", type: "secret", required: true, placeholder: "PagerDuty integration key" },
      { key: "severity_map", label: "Severity Mapping", type: "text", required: false, placeholder: "JSON: {\"critical\":\"critical\",...}" },
    ],
  },
  email: {
    label: "Email / SMTP",
    color: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    fields: [
      { key: "smtp_host", label: "SMTP Host", type: "text", required: true, placeholder: "smtp.example.com" },
      { key: "smtp_port", label: "SMTP Port", type: "number", required: false, placeholder: "587" },
      { key: "smtp_user", label: "SMTP Username", type: "text", required: false, placeholder: "user@example.com" },
      { key: "smtp_password", label: "SMTP Password", type: "secret", required: false, placeholder: "Password" },
      { key: "sendgrid_api_key", label: "SendGrid API Key (alt)", type: "secret", required: false, placeholder: "SG.xxxxx" },
      { key: "from_email", label: "From Address", type: "text", required: true, placeholder: "phantex@example.com" },
      { key: "to_emails", label: "To Addresses (comma-separated)", type: "text", required: true, placeholder: "soc@example.com, admin@example.com" },
    ],
  },
  webhook: {
    label: "Webhook",
    color: "bg-amber-500/20 text-amber-400 border-amber-500/30",
    fields: [
      { key: "url", label: "Endpoint URL", type: "url", required: true, placeholder: "https://example.com/webhook" },
      { key: "secret", label: "HMAC Secret (optional)", type: "secret", required: false, placeholder: "Signing secret" },
      { key: "custom_headers", label: "Custom Headers (JSON)", type: "text", required: false, placeholder: '{"X-Custom":"value"}' },
    ],
  },
}

interface ConfigField {
  key: string
  label: string
  type: "text" | "secret" | "url" | "number" | "toggle" | "select"
  required: boolean
  placeholder?: string
  options?: string[]
}

// ── Types ────────────────────────────────────────────────────────────────────

interface SiemIntegration {
  id: string
  tenant_id: string
  platform: string
  name: string
  enabled: boolean
  rate_limit_per_min: number
  config_masked: Record<string, unknown>
  created_at: string
  updated_at: string
}

interface PlatformInfo {
  platform: string
  max_batch_size: number
  default_rate_limit: number
}

interface NotifChannel {
  id: string
  tenant_id: string
  channel_type: string
  name: string
  enabled: boolean
  rate_limit_per_min: number
  config_masked: Record<string, unknown>
  created_at: string
  updated_at: string
}

// ── Query Keys ───────────────────────────────────────────────────────────────

const qk = {
  siemList: () => ["integrations", "siem"] as const,
  platforms: () => ["integrations", "platforms"] as const,
  channels: () => ["integrations", "channels"] as const,
  channelTypes: () => ["integrations", "channel-types"] as const,
}

// ── API Hooks — SIEM ─────────────────────────────────────────────────────────

function useSiemList() {
  return useQuery({
    queryKey: qk.siemList(),
    queryFn: async () => {
      const { data } = await apiClient.get<{ integrations: SiemIntegration[] }>("/integrations/")
      return data.integrations
    },
  })
}

function usePlatforms() {
  return useQuery({
    queryKey: qk.platforms(),
    queryFn: async () => {
      const { data } = await apiClient.get<{ platforms: PlatformInfo[] }>("/integrations/platforms")
      return data.platforms
    },
  })
}

function useCreateSiem() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (body: {
      platform: string
      name: string
      config: Record<string, unknown>
      enabled: boolean
      rate_limit_per_min: number
    }) => {
      const { data } = await apiClient.post<SiemIntegration>("/integrations/", body)
      return data
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.siemList() }),
  })
}

function useDeleteSiem() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (id: string) => {
      await apiClient.delete(`/integrations/${id}`)
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.siemList() }),
  })
}

function useTestSiem() {
  return useMutation({
    mutationFn: async (id: string) => {
      const { data } = await apiClient.post<{ success: boolean; message?: string }>(
        `/integrations/${id}/test`,
      )
      return data
    },
  })
}

// ── API Hooks — Notifications ────────────────────────────────────────────────

function useChannelsList() {
  return useQuery({
    queryKey: qk.channels(),
    queryFn: async () => {
      const { data } = await apiClient.get<{ channels: NotifChannel[] }>("/notifications/channels")
      return data.channels
    },
  })
}

function useCreateChannel() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (body: {
      channel_type: string
      name: string
      config: Record<string, unknown>
      enabled: boolean
      rate_limit_per_min: number
    }) => {
      const { data } = await apiClient.post<NotifChannel>("/notifications/channels", body)
      return data
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.channels() }),
  })
}

function useDeleteChannel() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (id: string) => {
      await apiClient.delete(`/notifications/channels/${id}`)
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.channels() }),
  })
}

function useTestChannel() {
  return useMutation({
    mutationFn: async (id: string) => {
      const { data } = await apiClient.post<{ success: boolean; message?: string }>(
        `/notifications/channels/${id}/test`,
      )
      return data
    },
  })
}

// ── Utility ──────────────────────────────────────────────────────────────────

/** Truncate ISO timestamp to human-friendly local string */
function fmtDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    })
  } catch {
    return iso
  }
}

/** Validate URL-like strings — basic sanity check, not a full RFC parser */
function isValidUrl(s: string): boolean {
  try {
    const u = new URL(s)
    return u.protocol === "https:" || u.protocol === "http:"
  } catch {
    return false
  }
}

/** Sanitize user input — strip control chars, cap length */
function sanitize(s: string, maxLen = 256): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, "").slice(0, maxLen)
}

// ── Sub-Components ───────────────────────────────────────────────────────────

/** Generic config form for creating a new SIEM integration or notification channel */
function ConfigForm({
  fields,
  onSubmit,
  onCancel,
  isPending,
  namePrefix,
}: {
  fields: ConfigField[]
  onSubmit: (name: string, config: Record<string, unknown>, rateLimit: number) => void
  onCancel: () => void
  isPending: boolean
  namePrefix: string
}) {
  const [name, setName] = useState("")
  const [rateLimit, setRateLimit] = useState(1000)
  const [values, setValues] = useState<Record<string, string | boolean>>(() => {
    const init: Record<string, string | boolean> = {}
    for (const f of fields) {
      init[f.key] = f.type === "toggle" ? true : ""
    }
    return init
  })
  const [showSecrets, setShowSecrets] = useState<Record<string, boolean>>({})
  const [error, setError] = useState("")

  const handleSubmit = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault()
      setError("")

      const trimmedName = sanitize(name.trim(), 128)
      if (!trimmedName) {
        setError("Display name is required")
        return
      }

      // Validate required fields
      for (const f of fields) {
        if (f.required && f.type !== "toggle") {
          const v = typeof values[f.key] === "string" ? (values[f.key] as string).trim() : ""
          if (!v) {
            setError(`${f.label} is required`)
            return
          }
          if ((f.type === "url") && !isValidUrl(v)) {
            setError(`${f.label} must be a valid URL (https://...)`)
            return
          }
        }
      }

      // Build config object
      const config: Record<string, unknown> = {}
      for (const f of fields) {
        if (f.type === "toggle") {
          config[f.key] = values[f.key] === true
        } else if (f.type === "number") {
          const num = parseInt(String(values[f.key]), 10)
          if (!isNaN(num)) config[f.key] = num
        } else {
          const v = typeof values[f.key] === "string" ? (values[f.key] as string).trim() : ""
          if (v) config[f.key] = sanitize(v, 1024)
        }
      }

      onSubmit(trimmedName, config, rateLimit)
    },
    [name, values, rateLimit, fields, onSubmit],
  )

  return (
    <form onSubmit={handleSubmit} className="space-y-3 rounded-lg border border-neutral-700 bg-neutral-800/60 p-4">
      {/* Display name */}
      <div>
        <label className="mb-1 block text-xs font-medium text-neutral-400">Display Name</label>
        <input
          type="text"
          maxLength={128}
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder={`${namePrefix} — production`}
          className="w-full rounded border border-neutral-600 bg-neutral-900 px-3 py-1.5 text-sm text-neutral-100 placeholder:text-neutral-500 focus:border-primary focus:outline-none"
        />
      </div>

      {/* Platform-specific fields */}
      {fields.map((f: ConfigField) => (
        <div key={f.key}>
          <label className="mb-1 block text-xs font-medium text-neutral-400">
            {f.label}
            {f.required && <span className="ml-1 text-red-400">*</span>}
          </label>
          {f.type === "toggle" ? (
            <button
              type="button"
              onClick={() => setValues((prev) => ({ ...prev, [f.key]: !prev[f.key] }))}
              className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                values[f.key] ? "bg-primary" : "bg-neutral-600"
              }`}
            >
              <span
                className={`inline-block h-4 w-4 rounded-full bg-white transition-transform ${
                  values[f.key] ? "translate-x-6" : "translate-x-1"
                }`}
              />
            </button>
          ) : f.type === "select" ? (
            <select
              value={String(values[f.key] ?? "")}
              onChange={(e) => setValues((prev) => ({ ...prev, [f.key]: e.target.value }))}
              className="w-full rounded border border-neutral-600 bg-neutral-900 px-3 py-1.5 text-sm text-neutral-100 focus:border-primary focus:outline-none"
            >
              <option value="">— select —</option>
              {f.options?.map((opt: string) => (
                <option key={opt} value={opt}>
                  {opt.toUpperCase()}
                </option>
              ))}
            </select>
          ) : (
            <div className="relative">
              <input
                type={
                  f.type === "secret" && !showSecrets[f.key]
                    ? "password"
                    : f.type === "number"
                      ? "number"
                      : "text"
                }
                value={String(values[f.key] ?? "")}
                onChange={(e) => setValues((prev) => ({ ...prev, [f.key]: e.target.value }))}
                placeholder={f.placeholder}
                maxLength={1024}
                className="w-full rounded border border-neutral-600 bg-neutral-900 px-3 py-1.5 text-sm text-neutral-100 placeholder:text-neutral-500 focus:border-primary focus:outline-none pr-8"
              />
              {f.type === "secret" && (
                <button
                  type="button"
                  onClick={() =>
                    setShowSecrets((prev) => ({ ...prev, [f.key]: !prev[f.key] }))
                  }
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-neutral-500 hover:text-neutral-300"
                  title={showSecrets[f.key] ? "Hide" : "Show"}
                >
                  {showSecrets[f.key] ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              )}
            </div>
          )}
        </div>
      ))}

      {/* Rate limit */}
      <div>
        <label className="mb-1 block text-xs font-medium text-neutral-400">
          Rate Limit (events/min)
        </label>
        <input
          type="number"
          min={1}
          max={10000}
          value={rateLimit}
          onChange={(e) => setRateLimit(Math.min(10000, Math.max(1, parseInt(e.target.value, 10) || 1)))}
          className="w-32 rounded border border-neutral-600 bg-neutral-900 px-3 py-1.5 text-sm text-neutral-100 focus:border-primary focus:outline-none"
        />
      </div>

      {error && (
        <p className="flex items-center gap-1 text-xs text-red-400">
          <XCircle size={12} /> {error}
        </p>
      )}

      <div className="flex gap-2 pt-1">
        <button
          type="submit"
          disabled={isPending}
          className="rounded bg-primary px-4 py-1.5 text-sm font-medium text-white hover:bg-primary/90 disabled:opacity-50"
        >
          {isPending ? "Creating…" : "Create"}
        </button>
        <button
          type="button"
          onClick={onCancel}
          className="rounded border border-neutral-600 px-4 py-1.5 text-sm text-neutral-300 hover:bg-neutral-700"
        >
          Cancel
        </button>
      </div>
    </form>
  )
}

/** Integration / channel card with actions */
function IntegrationCard({
  id,
  name,
  typeLabel,
  typeColor,
  enabled,
  rateLimitPerMin,
  configMasked,
  createdAt,
  updatedAt,
  onDelete,
  onTest,
  deleteLoading,
  testResult,
  testLoading,
}: {
  id: string
  name: string
  typeLabel: string
  typeColor: string
  enabled: boolean
  rateLimitPerMin: number
  configMasked: Record<string, unknown>
  createdAt: string
  updatedAt: string
  onDelete: (id: string) => void
  onTest: (id: string) => void
  deleteLoading: boolean
  testResult: { success: boolean; message?: string } | null
  testLoading: boolean
}) {
  const [confirmDelete, setConfirmDelete] = useState(false)

  return (
    <div className="rounded-lg border border-neutral-700 bg-neutral-800/40 p-4 transition-colors hover:border-neutral-600">
      {/* Header row */}
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${typeColor}`}>
              {typeLabel}
            </span>
            <span
              className={`inline-flex items-center rounded-full px-1.5 py-0.5 text-[10px] font-medium ${
                enabled
                  ? "bg-emerald-500/20 text-emerald-400"
                  : "bg-neutral-600/40 text-neutral-500"
              }`}
            >
              {enabled ? "Active" : "Disabled"}
            </span>
          </div>
          <h3 className="mt-1 truncate text-sm font-semibold text-neutral-100">{name}</h3>
        </div>

        {/* Actions */}
        <div className="flex shrink-0 items-center gap-1">
          <button
            onClick={() => onTest(id)}
            disabled={testLoading}
            className="rounded p-1.5 text-neutral-400 hover:bg-neutral-700 hover:text-neutral-200 disabled:opacity-50"
            title="Test connection"
          >
            {testLoading ? <RefreshCw size={14} className="animate-spin" /> : <TestTube size={14} />}
          </button>
          {!confirmDelete ? (
            <button
              onClick={() => setConfirmDelete(true)}
              className="rounded p-1.5 text-neutral-400 hover:bg-red-900/30 hover:text-red-400"
              title="Delete"
            >
              <Trash2 size={14} />
            </button>
          ) : (
            <div className="flex items-center gap-1">
              <button
                onClick={() => onDelete(id)}
                disabled={deleteLoading}
                className="rounded bg-red-600 px-2 py-0.5 text-[10px] font-medium text-white hover:bg-red-500 disabled:opacity-50"
              >
                Confirm
              </button>
              <button
                onClick={() => setConfirmDelete(false)}
                className="rounded bg-neutral-700 px-2 py-0.5 text-[10px] text-neutral-300 hover:bg-neutral-600"
              >
                No
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Config preview (masked) */}
      <div className="mt-2 space-y-0.5">
        {Object.entries(configMasked).map(([k, v]: [string, unknown]) => (
          <div key={k} className="flex gap-2 text-xs">
            <span className="shrink-0 text-neutral-500">{k}:</span>
            <span className="truncate text-neutral-300">{String(v)}</span>
          </div>
        ))}
      </div>

      {/* Meta row */}
      <div className="mt-2 flex flex-wrap items-center gap-3 text-[10px] text-neutral-500">
        <span>Rate: {rateLimitPerMin}/min</span>
        <span>Created: {fmtDate(createdAt)}</span>
        <span>Updated: {fmtDate(updatedAt)}</span>
      </div>

      {/* Test result */}
      {testResult && (
        <div
          className={`mt-2 flex items-center gap-1 rounded px-2 py-1 text-xs ${
            testResult.success
              ? "bg-emerald-500/10 text-emerald-400"
              : "bg-red-500/10 text-red-400"
          }`}
        >
          {testResult.success ? <CheckCircle size={12} /> : <XCircle size={12} />}
          {testResult.success ? "Connection OK" : testResult.message ?? "Test failed"}
        </div>
      )}
    </div>
  )
}

// ── SIEM Tab ─────────────────────────────────────────────────────────────────

function SiemTab() {
  const { data: integrations, isLoading, error } = useSiemList()
  const { data: platforms } = usePlatforms()
  const createMut = useCreateSiem()
  const deleteMut = useDeleteSiem()
  const testMut = useTestSiem()

  const [showForm, setShowForm] = useState<string | null>(null) // platform key or null
  const [testResults, setTestResults] = useState<Record<string, { success: boolean; message?: string }>>({})

  const handleCreate = useCallback(
    (platform: string) =>
      (name: string, config: Record<string, unknown>, rateLimit: number) => {
        createMut.mutate(
          { platform, name, config, enabled: true, rate_limit_per_min: rateLimit },
          { onSuccess: () => setShowForm(null) },
        )
      },
    [createMut],
  )

  const handleTest = useCallback(
    (id: string) => {
      setTestResults((prev) => ({ ...prev, [id]: { success: false, message: "Testing…" } }))
      testMut.mutate(id, {
        onSuccess: (result) => setTestResults((prev) => ({ ...prev, [id]: result })),
        onError: () =>
          setTestResults((prev) => ({ ...prev, [id]: { success: false, message: "Network error" } })),
      })
    },
    [testMut],
  )

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-16">
        <RefreshCw size={20} className="animate-spin text-neutral-500" />
      </div>
    )
  }
  if (error) {
    return (
      <div className="rounded border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-400">
        Failed to load SIEM integrations: {(error as Error).message}
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Description */}
      <p className="text-sm text-neutral-400">
        Forward Phantex alerts and events to your SIEM/XDR platforms in real time.
        Each connector validates credentials on creation and enforces TLS for all external endpoints.
      </p>

      {/* Available platforms */}
      <div>
        <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-neutral-500">
          Available Platforms
          {platforms && (
            <span className="ml-2 text-neutral-600">
              ({platforms.length})
            </span>
          )}
        </h3>
        <div className="flex flex-wrap gap-2">
          {Object.entries(SIEM_PLATFORMS).map(([key, meta]: [string, typeof SIEM_PLATFORMS[string]]) => (
            <button
              key={key}
              onClick={() => setShowForm(showForm === key ? null : key)}
              className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-2 text-sm font-medium transition-colors ${
                showForm === key
                  ? "border-primary bg-primary/10 text-primary"
                  : "border-neutral-700 bg-neutral-800 text-neutral-300 hover:border-neutral-500 hover:text-neutral-100"
              }`}
            >
              <Plus size={14} />
              {meta.label}
            </button>
          ))}
        </div>
      </div>

      {/* Create form (conditional) */}
      {showForm && SIEM_PLATFORMS[showForm] && (
        <div>
          <h3 className="mb-2 text-sm font-semibold text-neutral-200">
            New {SIEM_PLATFORMS[showForm].label} Integration
          </h3>
          <ConfigForm
            fields={SIEM_PLATFORMS[showForm].fields}
            onSubmit={handleCreate(showForm)}
            onCancel={() => setShowForm(null)}
            isPending={createMut.isPending}
            namePrefix={SIEM_PLATFORMS[showForm].label}
          />
          {createMut.error && (
            <p className="mt-2 flex items-center gap-1 text-xs text-red-400">
              <XCircle size={12} />
              {(createMut.error as Error).message || "Failed to create integration"}
            </p>
          )}
        </div>
      )}

      {/* Existing integrations */}
      <div>
        <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-neutral-500">
          Configured Integrations
          <span className="ml-2 text-neutral-600">
            ({integrations?.length ?? 0})
          </span>
        </h3>
        {integrations && integrations.length > 0 ? (
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {integrations.map((it: SiemIntegration) => {
              const meta = SIEM_PLATFORMS[it.platform]
              return (
                <IntegrationCard
                  key={it.id}
                  id={it.id}
                  name={it.name}
                  typeLabel={meta?.label ?? it.platform}
                  typeColor={meta?.color ?? "bg-neutral-600/20 text-neutral-400 border-neutral-500/30"}
                  enabled={it.enabled}
                  rateLimitPerMin={it.rate_limit_per_min}
                  configMasked={it.config_masked}
                  createdAt={it.created_at}
                  updatedAt={it.updated_at}
                  onDelete={(id: string) => deleteMut.mutate(id)}
                  onTest={handleTest}
                  deleteLoading={deleteMut.isPending}
                  testResult={testResults[it.id] ?? null}
                  testLoading={testMut.isPending && testMut.variables === it.id}
                />
              )
            })}
          </div>
        ) : (
          <p className="text-sm italic text-neutral-500">
            No SIEM integrations configured yet. Click a platform above to add one.
          </p>
        )}
      </div>
    </div>
  )
}

// ── Notifications Tab ────────────────────────────────────────────────────────

function NotificationsTab() {
  const { data: channels, isLoading, error } = useChannelsList()
  const createMut = useCreateChannel()
  const deleteMut = useDeleteChannel()
  const testMut = useTestChannel()

  const [showForm, setShowForm] = useState<string | null>(null)
  const [testResults, setTestResults] = useState<Record<string, { success: boolean; message?: string }>>({})

  const handleCreate = useCallback(
    (channelType: string) =>
      (name: string, config: Record<string, unknown>, rateLimit: number) => {
        createMut.mutate(
          { channel_type: channelType, name, config, enabled: true, rate_limit_per_min: rateLimit },
          { onSuccess: () => setShowForm(null) },
        )
      },
    [createMut],
  )

  const handleTest = useCallback(
    (id: string) => {
      setTestResults((prev) => ({ ...prev, [id]: { success: false, message: "Testing…" } }))
      testMut.mutate(id, {
        onSuccess: (result) => setTestResults((prev) => ({ ...prev, [id]: result })),
        onError: () =>
          setTestResults((prev) => ({ ...prev, [id]: { success: false, message: "Network error" } })),
      })
    },
    [testMut],
  )

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-16">
        <RefreshCw size={20} className="animate-spin text-neutral-500" />
      </div>
    )
  }
  if (error) {
    return (
      <div className="rounded border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-400">
        Failed to load channels: {(error as Error).message}
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <p className="text-sm text-neutral-400">
        Route alert notifications to Slack, PagerDuty, email, or custom webhooks.
        Configure routing rules on the{" "}
        <a href="/alert-routing" className="text-primary underline hover:text-primary/80">
          Alert Routing
        </a>{" "}
        page.
      </p>

      {/* Channel type buttons */}
      <div>
        <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-neutral-500">
          Channel Types
        </h3>
        <div className="flex flex-wrap gap-2">
          {Object.entries(NOTIFICATION_TYPES).map(([key, meta]: [string, typeof NOTIFICATION_TYPES[string]]) => (
            <button
              key={key}
              onClick={() => setShowForm(showForm === key ? null : key)}
              className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-2 text-sm font-medium transition-colors ${
                showForm === key
                  ? "border-primary bg-primary/10 text-primary"
                  : "border-neutral-700 bg-neutral-800 text-neutral-300 hover:border-neutral-500 hover:text-neutral-100"
              }`}
            >
              <Plus size={14} />
              {meta.label}
            </button>
          ))}
        </div>
      </div>

      {/* Create form */}
      {showForm && NOTIFICATION_TYPES[showForm] && (
        <div>
          <h3 className="mb-2 text-sm font-semibold text-neutral-200">
            New {NOTIFICATION_TYPES[showForm].label} Channel
          </h3>
          <ConfigForm
            fields={NOTIFICATION_TYPES[showForm].fields}
            onSubmit={handleCreate(showForm)}
            onCancel={() => setShowForm(null)}
            isPending={createMut.isPending}
            namePrefix={NOTIFICATION_TYPES[showForm].label}
          />
          {createMut.error && (
            <p className="mt-2 flex items-center gap-1 text-xs text-red-400">
              <XCircle size={12} />
              {(createMut.error as Error).message || "Failed to create channel"}
            </p>
          )}
        </div>
      )}

      {/* Existing channels */}
      <div>
        <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-neutral-500">
          Configured Channels
          <span className="ml-2 text-neutral-600">
            ({channels?.length ?? 0})
          </span>
        </h3>
        {channels && channels.length > 0 ? (
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {channels.map((ch: NotifChannel) => {
              const meta = NOTIFICATION_TYPES[ch.channel_type]
              return (
                <IntegrationCard
                  key={ch.id}
                  id={ch.id}
                  name={ch.name}
                  typeLabel={meta?.label ?? ch.channel_type}
                  typeColor={meta?.color ?? "bg-neutral-600/20 text-neutral-400 border-neutral-500/30"}
                  enabled={ch.enabled}
                  rateLimitPerMin={ch.rate_limit_per_min}
                  configMasked={ch.config_masked}
                  createdAt={ch.created_at}
                  updatedAt={ch.updated_at}
                  onDelete={(id: string) => deleteMut.mutate(id)}
                  onTest={handleTest}
                  deleteLoading={deleteMut.isPending}
                  testResult={testResults[ch.id] ?? null}
                  testLoading={testMut.isPending && testMut.variables === ch.id}
                />
              )
            })}
          </div>
        ) : (
          <p className="text-sm italic text-neutral-500">
            No notification channels yet. Click a channel type above to add one.
          </p>
        )}
      </div>
    </div>
  )
}

// ── SOAR Redirect Tab ────────────────────────────────────────────────────────

function SoarTab() {
  const nav = useNavigate()

  return (
    <div className="space-y-4">
      <p className="text-sm text-neutral-400">
        SOAR (Security Orchestration, Automation &amp; Response) integrations manage API keys,
        webhook subscriptions, and platform connectors for Palo Alto XSOAR, Splunk Phantom, and Tines.
      </p>
      <button
        onClick={() => nav("/settings/soar")}
        className="inline-flex items-center gap-2 rounded-lg border border-primary bg-primary/10 px-4 py-2.5 text-sm font-medium text-primary transition-colors hover:bg-primary/20"
      >
        <Unplug size={16} />
        Open SOAR Management
        <ArrowRight size={14} />
      </button>
    </div>
  )
}

// ── Main Page ────────────────────────────────────────────────────────────────

export default function IntegrationsPage() {
  const [activeTab, setActiveTab] = useState<TabName>("SIEM Connectors")
  const [showGuide, setShowGuide] = useState(false)

  const tabIcons: Record<TabName, React.ReactNode> = {
    "SIEM Connectors": <Server size={16} />,
    "Notification Channels": <Bell size={16} />,
    SOAR: <Unplug size={16} />,
  }

  return (
    <div className="mx-auto max-w-7xl space-y-6 p-6">
      {/* Page header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Cable size={22} className="text-primary" />
            <h1 className="text-xl font-bold text-neutral-100">Integrations Hub</h1>
          </div>
          <p className="mt-1 text-sm text-neutral-400">
            Manage SIEM connectors, notification channels, and SOAR platform integrations from a single pane.
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
              <Cable size={16} className="text-primary" />
              What is the Integrations Hub?
            </h3>
            <p className="mt-1.5 text-xs text-muted-foreground leading-relaxed">
              The <strong className="text-foreground">Integrations Hub</strong> lets you connect Phantex with your existing security stack. Forward alerts and events to your <strong className="text-foreground">SIEM</strong> (Splunk, Elastic, Sentinel, etc.), route notifications to <strong className="text-foreground">Slack, PagerDuty, or email</strong>, and link SOAR platforms for automated response.
            </p>
          </div>
          <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
            <h3 className="text-sm font-semibold text-foreground">Quick Setup</h3>
            <div className="mt-2 space-y-1 text-xs text-muted-foreground">
              <p><strong className="text-foreground">SIEM Connectors</strong> — Add your SIEM endpoint (HEC URL, API key, etc.) and click &quot;Test&quot; to verify connectivity.</p>
              <p><strong className="text-foreground">Notification Channels</strong> — Configure Slack webhooks, PagerDuty routing keys, or email SMTP to receive alert notifications.</p>
              <p><strong className="text-foreground">SOAR</strong> — Quick-link to the dedicated SOAR management page for deeper playbook integration.</p>
            </div>
          </div>
        </div>
      )}

      {/* Tab bar */}
      <div className="flex gap-1 rounded-lg border border-neutral-700 bg-neutral-800/50 p-1">
        {TABS.map((tab: TabName) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`inline-flex items-center gap-1.5 rounded-md px-4 py-2 text-sm font-medium transition-colors ${
              activeTab === tab
                ? "bg-neutral-700 text-neutral-100 shadow-sm"
                : "text-neutral-400 hover:text-neutral-200"
            }`}
          >
            {tabIcons[tab]}
            {tab}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="min-h-[400px]">
        {activeTab === "SIEM Connectors" && <SiemTab />}
        {activeTab === "Notification Channels" && <NotificationsTab />}
        {activeTab === "SOAR" && <SoarTab />}
      </div>
    </div>
  )
}
