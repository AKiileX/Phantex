// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Sensor detail page.
 *
 * Full sensor info with:
 *   - Identity card (sensor ID, host, kernel, arch, version)
 *   - Health card (probes, events, drops, errors, buffer)
 *   - Resource card (CPU, memory, uptime)
 *   - Status timeline placeholder
 */

import { useState } from "react"
import { useParams, Link } from "react-router-dom"
import {
  ArrowLeft,
  Wifi,
  WifiOff,
  Cpu,
  HardDrive,
  Clock,
  Activity,
  AlertTriangle,
  Trash2,
  HelpCircle,
} from "lucide-react"
import { useSensor, useDecommissionSensor } from "@/api/sensors"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { timeAgo } from "@/lib/utils"
import { useAuthStore, selectIsAdmin } from "@/stores/authStore"

/** SVG OS icons — inline to avoid external dependency */
function LinuxIcon({ size = 16, className = "" }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" className={className}>
      <path d="M12.5 2C10 2 8.2 4.1 8.2 7c0 1.3.4 2.5 1 3.5-.6.4-1 .8-1.5 1.3C6.5 13 6 14.2 6 15.5c0 .3 0 .6.1.9C4.8 17 4 17.8 4 19c0 1.7 2.2 3 5 3 1.5 0 2.8-.3 3.8-.9 1 .6 2.3.9 3.8.9 2.8 0 5-1.3 5-3 0-1.2-.8-2-2.1-2.6.1-.3.1-.6.1-.9 0-1.3-.5-2.5-1.7-3.7-.5-.5-.9-.9-1.5-1.3.6-1 1-2.2 1-3.5C17.4 4.1 15.6 2 13.1 2h-.6z" />
    </svg>
  )
}

function WindowsIcon({ size = 16, className = "" }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" className={className}>
      <path d="M3 5.5l7.5-1V11H3V5.5zm0 7H10.5v6.5L3 17.5V12.5zm8.5-8.2L21 3v8H11.5V4.3zm0 8.2H21v8l-9.5-1.3V12.5z" />
    </svg>
  )
}

function AppleIcon({ size = 16, className = "" }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" className={className}>
      <path d="M18.7 19.5c-.9 1.2-1.8 2.4-3.3 2.4-1.4 0-1.9-.9-3.5-.9-1.6 0-2.2.9-3.5.9-1.4 0-2.5-1.3-3.4-2.5C3.2 16.8 2 13.3 3.9 11c.9-1.2 2.4-2 3.9-2 1.4 0 2.3.9 3.5.9 1.1 0 1.8-.9 3.5-.9 1.3 0 2.6.7 3.5 1.8-3.1 1.7-2.6 6 .5 7.1-.5 1-1 1.7-1.5 2.2l1.4.4zM15 4c.1-1.6-.4-3.1-1.2-4.2-.9 1-2 1.8-2 3.3 0 1.5 1.2 2.4 1.7 2.4.6 0 1.4-.8 1.5-1.5z" />
    </svg>
  )
}

function OsIcon({ osType, size = 16 }: { osType: string | null; size?: number }) {
  const os = (osType ?? "").toLowerCase()
  if (os.includes("linux") || os.includes("ubuntu") || os.includes("debian") || os.includes("rhel") || os.includes("centos"))
    return <LinuxIcon size={size} className="text-[#FCC624]" />
  if (os.includes("windows") || os.includes("win"))
    return <WindowsIcon size={size} className="text-[#00A4EF]" />
  if (os.includes("darwin") || os.includes("macos") || os.includes("mac"))
    return <AppleIcon size={size} className="text-muted-foreground" />
  return <HardDrive size={size} className="text-muted-foreground" />
}

function DetailRow({
  label,
  children,
  mono,
}: {
  label: string
  children: React.ReactNode
  mono?: boolean
}) {
  return (
    <div className="flex items-start justify-between gap-4 py-2 border-b border-border/50 last:border-0">
      <span className="text-sm text-muted-foreground shrink-0">{label}</span>
      <div className={`text-sm text-foreground text-right ${mono ? "font-mono" : ""}`}>
        {children}
      </div>
    </div>
  )
}

function formatBytes(bytes: number | null): string {
  if (bytes == null) return "—"
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`
}

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`
  return `${Math.floor(seconds / 86400)}d ${Math.floor((seconds % 86400) / 3600)}h`
}

function statusVariant(s: string): "default" | "medium" | "critical" {
  if (s === "online") return "default"
  if (s === "degraded" || s === "decommissioned") return "medium"
  return "critical"
}

export function SensorDetailPage() {
  const { id } = useParams<{ id: string }>()
  const { data: sensor, isLoading } = useSensor(id ?? "")
  const isAdmin = useAuthStore(selectIsAdmin)
  const decommission = useDecommissionSensor()
  const [showDecommission, setShowDecommission] = useState(false)
  const [decommissionReason, setDecommissionReason] = useState("")
  const [showGuide, setShowGuide] = useState(false)

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-24">
        <div className="h-6 w-6 animate-spin rounded-full border-2 border-primary/20 border-t-primary" />
      </div>
    )
  }

  if (!sensor) {
    return (
      <div className="space-y-4 animate-fade-in">
        <Link to="/sensors" className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors">
          <ArrowLeft size={14} /> Back to Sensors
        </Link>
        <div className="text-center py-12">
          <p className="text-muted-foreground">Sensor not found</p>
        </div>
      </div>
    )
  }

  const dropRate = sensor.events_sent > 0
    ? ((sensor.events_dropped / (sensor.events_sent + sensor.events_dropped)) * 100).toFixed(2)
    : "0.00"

  // Fallback: if probes_total is 0 (old sensor binary), use probes_loaded as total
  const probesTotal = sensor.probes_total > 0 ? sensor.probes_total : sensor.probes_loaded

  return (
    <div className="space-y-6 animate-fade-in">
      {/* ── Back + Title ──────────────────────────── */}
      <div className="space-y-2">
        <Link to="/sensors" className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors">
          <ArrowLeft size={14} /> Back to Sensors
        </Link>
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-white/[0.04] border border-border/50">
            <OsIcon osType={sensor.os_type} size={20} />
          </div>
          <div className="flex-1">
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-semibold text-foreground tracking-tight font-mono">
                {sensor.sensor_id}
              </h1>
              {sensor.status === "online" ? (
                <Wifi size={14} className="text-primary" />
              ) : (
                <WifiOff size={14} className="text-severity-critical" />
              )}
            </div>
            <div className="flex items-center gap-2 mt-0.5">
              <Badge variant={statusVariant(sensor.status)}>{sensor.status}</Badge>
              <span className="text-xs text-muted-foreground">
                Last heartbeat {timeAgo(sensor.last_heartbeat)}
              </span>
              {sensor.os_type && (
                <span className="text-xs text-muted-foreground capitalize">
                  · {sensor.os_type}
                </span>
              )}
            </div>
          </div>
          {/* Decommission button — admin only, not already decommissioned */}
          {isAdmin && sensor.status !== "decommissioned" && (
            <button
              onClick={() => setShowDecommission(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-severity-critical/30 text-severity-critical text-xs font-medium hover:bg-severity-critical/10 transition-colors"
            >
              <Trash2 size={13} /> Decommission
            </button>
          )}
          <button onClick={() => setShowGuide(!showGuide)} className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"><HelpCircle size={14} />{showGuide ? "Hide Guide" : "How does this work?"}</button>
        </div>

        {/* Decommission confirmation */}
        {showDecommission && (
          <div className="rounded-lg border border-severity-critical/30 bg-severity-critical/5 p-4 space-y-3">
            <p className="text-sm font-medium text-severity-critical">Confirm Sensor Decommission</p>
            <p className="text-xs text-muted-foreground">
              This will permanently mark the sensor as decommissioned. It will no longer appear in active views
              but is retained for audit trail. This action cannot be undone.
            </p>
            <textarea
              value={decommissionReason}
              onChange={(e) => setDecommissionReason(e.target.value)}
              placeholder="Reason for decommission (min 5 characters)..."
              className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-1 focus:ring-primary resize-none"
              rows={2}
            />
            <div className="flex gap-2">
              <button
                onClick={() => {
                  if (id && decommissionReason.length >= 5) {
                    decommission.mutate({ id, reason: decommissionReason })
                    setShowDecommission(false)
                    setDecommissionReason("")
                  }
                }}
                disabled={decommissionReason.length < 5 || decommission.isPending}
                className="px-3 py-1.5 rounded-md bg-severity-critical text-white text-xs font-medium hover:bg-severity-critical/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {decommission.isPending ? "Decommissioning..." : "Confirm Decommission"}
              </button>
              <button
                onClick={() => { setShowDecommission(false); setDecommissionReason("") }}
                className="px-3 py-1.5 rounded-md border border-border text-xs font-medium text-muted-foreground hover:text-foreground transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {/* Decommission info banner */}
        {sensor.status === "decommissioned" && (
          <div className="rounded-lg border border-severity-medium/30 bg-severity-medium/5 p-4">
            <p className="text-sm font-medium text-severity-medium">Sensor Decommissioned</p>
            <div className="text-xs text-muted-foreground mt-1 space-y-0.5">
              {sensor.decommissioned_by && <p>By: {sensor.decommissioned_by}</p>}
              {sensor.decommissioned_at && <p>At: {timeAgo(sensor.decommissioned_at)}</p>}
              {sensor.decommission_reason && <p>Reason: {sensor.decommission_reason}</p>}
            </div>
          </div>
        )}
      </div>

      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5 space-y-3 text-sm text-muted-foreground">
          <h3 className="text-base font-semibold text-foreground">How does Sensor Detail work?</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Sensor Identity</p>
              <p>Fetches via <code className="text-xs bg-white/5 px-1 rounded">GET /api/v1/sensors/{'{id}'}</code>. Shows sensor ID, hostname, OS, version, and the IP address it reports from. Heartbeat timing shows how recently the sensor checked in.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Discovered Agents</p>
              <p>Lists all AI agents this sensor has discovered on its host. Each agent link goes to the full agent detail page. This is how agents enter the system — sensors detect AI framework processes and report them.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Telemetry Stats</p>
              <p>Shows events ingested, events dropped, and drop rate for this sensor. High drop rates indicate the sensor is overwhelmed or the gateway connection is degraded. Metrics update with each heartbeat cycle.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Decommission</p>
              <p>Admin-only action that permanently marks the sensor as decommissioned. Requires a reason (min 5 chars) for the audit trail. Decommissioned sensors are retained for compliance but hidden from active views.</p>
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* ── Identity Card ───────────────────────── */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <HardDrive size={14} className="text-muted-foreground" />
              Identity
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-0">
            <DetailRow label="Sensor ID" mono>{sensor.sensor_id}</DetailRow>
            <DetailRow label="Hostname">{sensor.hostname ?? "—"}</DetailRow>
            <DetailRow label="IP Address">{sensor.ip_address ?? "—"}</DetailRow>
            <DetailRow label="OS / Kernel">
              <span className="flex items-center gap-1.5 justify-end">
                <OsIcon osType={sensor.os_type} size={14} />
                {sensor.os_type ? `${sensor.os_type} — ` : ""}{sensor.kernel ?? "—"}
              </span>
            </DetailRow>
            <DetailRow label="Architecture">{sensor.arch ?? "—"}</DetailRow>
            <DetailRow label="Version" mono>{sensor.version ?? "—"}</DetailRow>
            <DetailRow label="First Seen">{sensor.first_seen ? timeAgo(sensor.first_seen) : "—"}</DetailRow>
          </CardContent>
        </Card>

        {/* ── Health Metrics Card ─────────────────── */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Activity size={14} className="text-muted-foreground" />
              Health Metrics
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-0">
            <DetailRow label="Probes Loaded" mono>
              <span className={sensor.probes_loaded < probesTotal ? "text-severity-medium" : ""}>
                {sensor.probes_loaded} / {probesTotal}
              </span>
            </DetailRow>
            <DetailRow label="Events Read" mono>{sensor.events_read?.toLocaleString()}</DetailRow>
            <DetailRow label="Events Sent" mono>{sensor.events_sent?.toLocaleString()}</DetailRow>
            <DetailRow label="Events Dropped" mono>
              <span className={sensor.events_dropped > 0 ? "text-severity-high" : ""}>
                {sensor.events_dropped?.toLocaleString()} ({dropRate}%)
              </span>
            </DetailRow>
            <DetailRow label="Parse Errors" mono>
              <span className={sensor.parse_errors > 0 ? "text-severity-medium" : ""}>
                {sensor.parse_errors?.toLocaleString()}
              </span>
            </DetailRow>
            <DetailRow label="Agents Tracked" mono>{sensor.agents_tracked}</DetailRow>
            <DetailRow label="Buffer Used" mono>{formatBytes(sensor.buffer_used)}</DetailRow>
          </CardContent>
        </Card>

        {/* ── Resources Card ──────────────────────── */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Cpu size={14} className="text-muted-foreground" />
              Resources
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-0">
            <DetailRow label="CPU Usage">
              <span className={sensor.cpu_percent != null && sensor.cpu_percent > 80 ? "text-severity-high" : ""}>
                {sensor.cpu_percent != null ? `${sensor.cpu_percent.toFixed(1)}%` : "—"}
              </span>
            </DetailRow>
            <DetailRow label="Memory (RSS)">{formatBytes(sensor.memory_bytes)}</DetailRow>
            <DetailRow label="Uptime">
              <span className="flex items-center gap-1">
                <Clock size={12} className="text-muted-foreground" />
                {formatUptime(sensor.uptime_seconds ?? 0)}
              </span>
            </DetailRow>
          </CardContent>
        </Card>

        {/* ── Diagnostics Card ────────────────────── */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <AlertTriangle size={14} className="text-muted-foreground" />
              Diagnostics
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {sensor.events_dropped > 0 && (
                <div className="rounded-md bg-severity-high/10 border border-severity-high/20 p-3">
                  <p className="text-xs text-severity-high font-medium">Event Drops Detected</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    {sensor.events_dropped.toLocaleString()} events dropped ({dropRate}% rate).
                    This indicates ring buffer saturation or gateway backpressure.
                    Increasing <code className="font-mono text-[10px]">ebpf.ringbuf_chan_size</code> or
                    reducing <code className="font-mono text-[10px]">batch_timeout</code> may help.
                  </p>
                </div>
              )}

              {sensor.probes_loaded < probesTotal && (
                <div className="rounded-md bg-severity-medium/10 border border-severity-medium/20 p-3">
                  <p className="text-xs text-severity-medium font-medium">
                    {probesTotal - sensor.probes_loaded} Probe{probesTotal - sensor.probes_loaded > 1 ? "s" : ""} Failed to Load
                  </p>
                  <p className="text-xs text-muted-foreground mt-1">
                    {sensor.probes_loaded}/{probesTotal} probes active. The sensor has 6 eBPF probes:
                    execve, openat, tcp_connect, write_read, mmap, and dns.
                    The DNS kprobe (udp_sendmsg) requires kernel &ge; 5.8
                    and may exceed the BPF verifier instruction limit on some kernels.
                    The sensor continues operating with reduced visibility.
                  </p>
                </div>
              )}

              {sensor.parse_errors > 0 && (
                <div className="rounded-md bg-severity-low/10 border border-severity-low/20 p-3">
                  <p className="text-xs text-severity-low font-medium">Parse Errors</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    {sensor.parse_errors.toLocaleString()} events failed to parse. Usually non-critical.
                  </p>
                </div>
              )}

              {sensor.events_dropped === 0 && sensor.probes_loaded >= probesTotal && sensor.parse_errors === 0 && (
                <div className="rounded-md bg-primary/10 border border-primary/20 p-3">
                  <p className="text-xs text-primary font-medium">All Systems Normal</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    All probes loaded, no drops, no errors.
                  </p>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
