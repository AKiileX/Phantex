// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Telemetry Admin Page (O10).
 *
 * Admin-only page for controlling anonymized telemetry export:
 *   - Opt-in/opt-out toggle (default OFF, very clear)
 *   - Differential-privacy epsilon slider
 *   - Runtime status: buffer, batches, export health
 *   - Viewer: table of recently exported feature vectors
 *
 * @module pages/TelemetryPage
 */

import { useState, useCallback } from "react"
import {
  Radio,
  BarChart3,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
  Activity,
  HelpCircle,
  Lock,
  Server,
  Eye,
} from "lucide-react"
import {
  useTelemetryConfig,
  useUpdateTelemetryConfig,
  useTelemetryStatus,
  useTelemetryViewer,
} from "@/api/telemetry"
import { useAuditLog } from "@/hooks/useAuditLog"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { AnimatedNumber } from "@/components/ui/animated-number"
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table"

/* ── Epsilon validation ────────────────────────────────────────────────────── */

function clampEpsilon(val: number): number {
  return Math.max(0.1, Math.min(10.0, val))
}

/* ── Status Card ───────────────────────────────────────────────────────────── */

interface MetricCardProps {
  label: string
  value: number
  icon: React.ElementType
  variant?: "default" | "success" | "error"
}

function MetricCard({ label, value, icon: Icon, variant = "default" }: MetricCardProps) {
  const colorClass =
    variant === "success"
      ? "text-emerald-400"
      : variant === "error"
        ? "text-destructive"
        : "text-muted-foreground/40"

  return (
    <Card className="relative overflow-hidden">
      <CardContent className="p-4">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-[10px] uppercase tracking-widest text-muted-foreground">
              {label}
            </p>
            <span className="text-2xl font-bold mt-1 block">
              <AnimatedNumber value={value} />
            </span>
          </div>
          <Icon className={`h-5 w-5 ${colorClass}`} />
        </div>
      </CardContent>
    </Card>
  )
}

/* ── Page ───────────────────────────────────────────────────────────────────── */

export default function TelemetryPage() {
  const { data: config, isLoading: configLoading } = useTelemetryConfig()
  const { data: status } = useTelemetryStatus()
  const { data: viewer, isLoading: viewerLoading } = useTelemetryViewer(50)
  const updateConfig = useUpdateTelemetryConfig()
  const logAction = useAuditLog()

  const [epsilon, setEpsilon] = useState<string>("")
  const [showGuide, setShowGuide] = useState(false)

  /* ── Handlers ────────────────────────────────────────────────────────────── */

  const handleToggle = useCallback(() => {
    if (!config) return
    const newEnabled = !config.enabled
    updateConfig.mutate({
      enabled: newEnabled,
      dp_epsilon: config.dp_epsilon,
    })
    logAction({ action: "telemetry.config.toggle", details: { enabled: newEnabled } })
  }, [config, updateConfig, logAction])

  const handleEpsilonUpdate = useCallback(() => {
    if (!config) return
    const parsed = parseFloat(epsilon)
    if (isNaN(parsed)) return
    const clamped = clampEpsilon(parsed)
    updateConfig.mutate({
      enabled: config.enabled,
      dp_epsilon: clamped,
    })
    logAction({ action: "telemetry.config.epsilon", details: { dp_epsilon: clamped } })
    setEpsilon("")
  }, [config, epsilon, updateConfig, logAction])

  /* ── Loading ─────────────────────────────────────────────────────────────── */

  if (configLoading) {
    return (
      <div className="flex items-center justify-center py-24">
        <div className="h-6 w-6 animate-spin rounded-full border-2 border-primary/20 border-t-primary" />
      </div>
    )
  }

  /* ── Render ──────────────────────────────────────────────────────────────── */

  return (
    <div className="flex flex-col gap-6 p-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div className="flex items-center gap-3">
          <Radio className="h-5 w-5 text-primary/70" />
          <div>
            <h1 className="text-lg font-semibold">Telemetry Export</h1>
            <p className="text-xs text-muted-foreground">
              Control anonymized telemetry sharing for global threat intelligence
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
      {showGuide && <TelemetryGuide />}

      {/* ── Config Section ─────────────────────────────────────────────────── */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm">Configuration</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Opt-in toggle */}
          <div className="flex items-center justify-between rounded-lg border border-border/40 p-4">
            <div>
              <p className="text-sm font-medium">Telemetry Export</p>
              <p className="text-xs text-muted-foreground mt-0.5">
                Share anonymized feature vectors to improve global threat detection.
                All data is irreversibly anonymized with differential privacy.
              </p>
            </div>
            <div className="flex items-center gap-3">
              <Badge variant={config?.enabled ? "active" : "terminated"}>
                {config?.enabled ? "Enabled" : "Disabled"}
              </Badge>
              <Button
                variant={config?.enabled ? "outline" : "default"}
                size="sm"
                onClick={handleToggle}
                disabled={updateConfig.isPending}
              >
                {config?.enabled ? "Opt Out" : "Opt In"}
              </Button>
            </div>
          </div>

          {/* Kill switch + endpoint warnings */}
          {config?.global_kill_switch_active && (
            <div className="flex items-center gap-2 rounded-md border border-amber-500/30 bg-amber-500/5 px-3 py-2">
              <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0" />
              <p className="text-xs text-amber-400">
                Global kill switch is active — telemetry export disabled at system level.
              </p>
            </div>
          )}

          {config && !config.cloud_endpoint_configured && (
            <div className="flex items-center gap-2 rounded-md border border-amber-500/30 bg-amber-500/5 px-3 py-2">
              <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0" />
              <p className="text-xs text-amber-400">
                No cloud endpoint configured — data will be buffered but not exported.
              </p>
            </div>
          )}

          {/* Epsilon control */}
          <div className="flex items-end gap-3">
            <div className="flex-1">
              <label
                htmlFor="dp-epsilon"
                className="text-[10px] uppercase tracking-widest text-muted-foreground"
              >
                Differential Privacy Epsilon
              </label>
              <p className="text-[10px] text-muted-foreground mb-1">
                Current: {config?.dp_epsilon ?? 2.0} — Lower = more privacy, higher = more utility (0.1–10.0)
              </p>
              <input
                id="dp-epsilon"
                type="number"
                step="0.1"
                min="0.1"
                max="10.0"
                maxLength={6}
                value={epsilon}
                onChange={(e) => setEpsilon(e.target.value.slice(0, 6))}
                placeholder={String(config?.dp_epsilon ?? 2.0)}
                className="w-32 rounded-md border border-border/50 bg-background px-3 py-1.5 text-sm"
              />
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={handleEpsilonUpdate}
              disabled={!epsilon || updateConfig.isPending}
            >
              Update
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* ── Status Section ─────────────────────────────────────────────────── */}
      {status && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <MetricCard
            label="Batches Sent"
            value={status.metrics.batches_sent}
            icon={CheckCircle2}
            variant="success"
          />
          <MetricCard
            label="Batches Failed"
            value={status.metrics.batches_failed}
            icon={XCircle}
            variant={status.metrics.batches_failed > 0 ? "error" : "default"}
          />
          <MetricCard
            label="Records Exported"
            value={status.metrics.records_exported}
            icon={BarChart3}
          />
          <MetricCard
            label="Buffer Size"
            value={status.buffer_size}
            icon={Activity}
          />
        </div>
      )}

      {/* Last export + error */}
      {status && (
        <div className="flex flex-wrap gap-4 text-xs text-muted-foreground">
          {status.metrics.last_export_at && (
            <span className="flex items-center gap-1.5">
              <Clock className="h-3 w-3" />
              Last export: {new Date(status.metrics.last_export_at).toLocaleString()}
            </span>
          )}
          {status.metrics.last_error && (
            <span className="flex items-center gap-1.5 text-destructive">
              <XCircle className="h-3 w-3" />
              Last error: {status.metrics.last_error}
            </span>
          )}
          {status.metrics.records_dropped > 0 && (
            <span className="flex items-center gap-1.5 text-amber-400">
              <AlertTriangle className="h-3 w-3" />
              {status.metrics.records_dropped} records dropped
            </span>
          )}
        </div>
      )}

      {/* ── Viewer Section ─────────────────────────────────────────────────── */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm">
              Export Viewer ({viewer?.total_entries ?? 0} batches)
            </CardTitle>
            {viewer && viewer.pending_records > 0 && (
              <Badge variant="info">
                {viewer.pending_records} pending
              </Badge>
            )}
          </div>
        </CardHeader>
        <CardContent>
          {viewerLoading ? (
            <div className="flex items-center justify-center py-8">
              <div className="h-5 w-5 animate-spin rounded-full border-2 border-primary/20 border-t-primary" />
            </div>
          ) : !viewer || viewer.entries.length === 0 ? (
            <p className="text-sm text-muted-foreground py-8 text-center">
              No exported batches to display.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Time</TableHead>
                  <TableHead>Records</TableHead>
                  <TableHead>Destination</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Error</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {viewer.entries.map((entry, idx) => (
                  <TableRow key={`${entry.exported_at}-${idx}`}>
                    <TableCell className="text-xs">
                      {new Date(entry.exported_at * 1000).toLocaleString()}
                    </TableCell>
                    <TableCell className="tabular-nums">
                      {entry.record_count}
                    </TableCell>
                    <TableCell className="font-mono text-[11px] text-muted-foreground max-w-[200px] truncate">
                      {entry.destination}
                    </TableCell>
                    <TableCell>
                      {entry.success ? (
                        <Badge variant="active">OK</Badge>
                      ) : (
                        <Badge variant="critical">Failed</Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-xs text-destructive max-w-[200px] truncate">
                      {entry.error ?? "—"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

/* ── How It Works Guide ────────────────────────────────────────────────────── */

function TelemetryGuide() {
  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
          <Radio size={16} className="text-primary" />
          What is Telemetry Export?
        </h3>
        <p className="mt-1.5 text-xs text-muted-foreground leading-relaxed">
          Telemetry Export lets you <strong className="text-foreground">optionally share anonymized threat detection
          data</strong> to improve global threat intelligence. It strips all personally identifiable information
          using <strong className="text-foreground">differential privacy</strong> — a mathematical guarantee
          that individual records cannot be reverse-engineered — then exports only statistical feature vectors,
          never raw events. Telemetry is <strong className="text-foreground">disabled by default</strong> and
          requires explicit opt-in.
        </p>
      </div>

      <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
          <Lock size={16} className="text-primary" />
          Privacy Guarantees
        </h3>
        <p className="mt-1.5 text-xs text-muted-foreground">How your data is protected:</p>
        <div className="mt-3 flex flex-wrap items-center gap-1.5 text-xs font-medium">
          {[
            { label: "Raw events collected", color: "bg-blue-500/15 text-blue-400 border border-blue-500/20" },
            { label: "→" },
            { label: "HMAC-SHA256 tenant hashing", color: "bg-cyan-500/15 text-cyan-400 border border-cyan-500/20" },
            { label: "→" },
            { label: "Laplacian ε-DP noise added", color: "bg-amber-500/15 text-amber-400 border border-amber-500/20" },
            { label: "→" },
            { label: "Feature vectors only (no raw data)", color: "bg-orange-500/15 text-orange-400 border border-orange-500/20" },
            { label: "→" },
            { label: "Buffered locally", color: "bg-purple-500/15 text-purple-400 border border-purple-500/20" },
            { label: "→" },
            { label: "Exported in batches", color: "bg-emerald-500/15 text-emerald-400 border border-emerald-500/20" },
          ].map((step, i) =>
            step.color ? (
              <span key={i} className={`rounded-full px-2.5 py-1 ${step.color}`}>{step.label}</span>
            ) : (
              <span key={i} className="text-muted-foreground/40">{step.label}</span>
            )
          )}
        </div>
      </div>

      <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
          <Server size={16} className="text-primary" />
          On-Prem &amp; Air-Gapped Deployments
        </h3>
        <p className="mt-1.5 text-xs text-muted-foreground leading-relaxed">
          PhanTeX is <strong className="text-foreground">on-prem first</strong> — the telemetry exporter runs
          entirely inside your deployment. When no cloud endpoint is configured, data is buffered locally
          and <strong className="text-foreground">never leaves your network</strong>. For fully air-gapped
          environments, set the environment variable <code className="rounded bg-muted/50 px-1.5 py-0.5 text-[11px] font-mono text-foreground">PHANTEX_TELEMETRY_EXPORT=false</code> to
          disable the export pipeline entirely. The dashboard still shows buffer metrics so you can
          monitor telemetry health even when export is off.
        </p>
      </div>

      <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
          <Activity size={16} className="text-primary" />
          Understanding the Controls
        </h3>
        <div className="mt-3 grid gap-3 md:grid-cols-2">
          <div className="rounded-lg border border-blue-500/20 bg-blue-500/5 p-3">
            <span className="text-xs font-semibold text-blue-400">Opt In / Opt Out</span>
            <p className="mt-1 text-[11px] text-muted-foreground leading-relaxed">
              Toggle telemetry sharing on or off. When disabled, all data stays local.
              Changes are logged in the audit trail.
            </p>
          </div>
          <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3">
            <span className="text-xs font-semibold text-amber-400">Epsilon (ε)</span>
            <p className="mt-1 text-[11px] text-muted-foreground leading-relaxed">
              Controls the privacy-utility trade-off. Lower ε = more noise = more privacy.
              Higher ε = less noise = better data quality. Default is 2.0.
              Range: 0.1 (maximum privacy) to 10.0 (maximum utility).
            </p>
          </div>
          <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-3">
            <span className="text-xs font-semibold text-emerald-400">Batches Sent / Failed</span>
            <p className="mt-1 text-[11px] text-muted-foreground leading-relaxed">
              Tracks how many export batches succeeded vs failed. A high failure rate
              may indicate network issues or an unreachable endpoint.
            </p>
          </div>
          <div className="rounded-lg border border-purple-500/20 bg-purple-500/5 p-3">
            <span className="text-xs font-semibold text-purple-400">Export Viewer</span>
            <p className="mt-1 text-[11px] text-muted-foreground leading-relaxed">
              Browse the most recent exported batches for admin review. Shows timestamp,
              record count, destination, and any errors. All exports are immutable logs.
            </p>
          </div>
        </div>
      </div>

      <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
          <Eye size={16} className="text-primary" />
          &quot;No cloud endpoint configured&quot;
        </h3>
        <p className="mt-1.5 text-xs text-muted-foreground leading-relaxed">
          This warning means no external telemetry receiver is set up. In on-prem deployments, this is
          <strong className="text-foreground"> expected and normal</strong>. Data is safely buffered
          locally. To configure a cloud endpoint, set the <code className="rounded bg-muted/50 px-1.5 py-0.5 text-[11px] font-mono text-foreground">PHANTEX_CLOUD_ENDPOINT</code> environment
          variable on the backend container. For most self-hosted installations, leaving this unconfigured
          is the correct setting — your data stays entirely within your infrastructure.
        </p>
      </div>
    </div>
  )
}
