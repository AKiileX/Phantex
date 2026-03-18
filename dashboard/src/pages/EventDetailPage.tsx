// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Event detail page (enriched CrowdStrike Falcon-style).
 *
 * Full event payload with:
 *   - Event metadata card (type, severity, timestamps)
 *   - Source card (agent, sensor, tenant links)
 *   - Enrichment card (extracted fields from raw_data)
 *   - Raw JSON viewer with copy-to-clipboard
 *   - Timeline context placeholder
 */

import { useParams, Link } from "react-router-dom"
import {
  ArrowLeft,
  Activity,
  Copy,
  Check,
  ExternalLink,
  FileJson,
  Clock,
  Layers,
  Tag,
  HelpCircle,
} from "lucide-react"
import { useState, useMemo } from "react"
import { useEvent } from "@/api/events"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { formatDate, timeAgo } from "@/lib/utils"

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
      <div
        className={`text-sm text-foreground text-right break-all ${mono ? "font-mono text-xs" : ""}`}
      >
        {children}
      </div>
    </div>
  )
}

export function EventDetailPage() {
  const { id } = useParams<{ id: string }>()
  const { data: event, isLoading } = useEvent(id ?? "")
  const [copied, setCopied] = useState(false)
  const [showGuide, setShowGuide] = useState(false)

  function copyRawData() {
    if (!event) return
    navigator.clipboard.writeText(JSON.stringify(event.raw_data, null, 2))
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  // Extract enrichment fields from raw_data
  const rawData = event?.raw_data
  const enrichment = useMemo(() => {
    if (!rawData) return []
    const fields: { key: string; value: string }[] = []
    const raw = rawData as Record<string, unknown>

    const walk = (obj: Record<string, unknown>, prefix = "") => {
      for (const [k, v] of Object.entries(obj)) {
        const fullKey = prefix ? `${prefix}.${k}` : k
        if (v && typeof v === "object" && !Array.isArray(v)) {
          walk(v as Record<string, unknown>, fullKey)
        } else if (v !== null && v !== undefined) {
          fields.push({
            key: fullKey,
            value: Array.isArray(v) ? v.join(", ") : String(v),
          })
        }
      }
    }

    walk(raw)
    return fields
  }, [rawData])

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20 text-sm text-muted-foreground">
        Loading event details…
      </div>
    )
  }

  if (!event) {
    return (
      <div className="flex flex-col items-center justify-center py-20 gap-2">
        <Activity size={28} className="text-surface-3" />
        <p className="text-sm text-muted-foreground">Event not found</p>
      </div>
    )
  }

  const rawStr = JSON.stringify(event.raw_data, null, 2)

  return (
    <div className="space-y-4 animate-fade-in">
      {/* Back + title */}
      <div className="flex items-center gap-3">
        <Link to="/events">
          <Button variant="ghost" size="sm" className="gap-1">
            <ArrowLeft size={14} /> Events
          </Button>
        </Link>
        <div className="h-4 w-px bg-border" />
        <h1 className="text-lg font-semibold text-foreground font-mono">
          {event.event_type}
        </h1>
        <Badge
          variant={event.severity as "critical" | "high" | "medium" | "low" | "info"}
        >
          {event.severity}
        </Badge>
        <span className="text-xs text-muted-foreground ml-auto flex items-center gap-1">
          <Clock size={12} />
          {timeAgo(event.timestamp)}
        </span>
        <button onClick={() => setShowGuide(!showGuide)} className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"><HelpCircle size={14} />{showGuide ? "Hide Guide" : "How does this work?"}</button>
      </div>

      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5 space-y-3 text-sm text-muted-foreground">
          <h3 className="text-base font-semibold text-foreground">How does Event Detail work?</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Event Lookup</p>
              <p>Fetches via <code className="text-xs bg-white/5 px-1 rounded">GET /api/v1/events/{'{id}'}</code>. Each event is stored in ClickHouse with high-throughput columnar storage. The raw_data JSON contains the full original payload from the sensor/gateway pipeline.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Structured Fields</p>
              <p>The metadata grid extracts key fields: event type, severity, agent PAID, source IP, timestamp, and any classification tags. Extracted fields are walked recursively from the raw JSON for convenient viewing.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Data Classification</p>
              <p>Events may carry classification labels (PII, PHI, FINANCIAL, CREDENTIAL) assigned by the data classification pipeline. These map to compliance frameworks (GDPR, HIPAA, PCI-DSS, SOX, CCPA) for regulatory tracking.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Raw JSON</p>
              <p>The full raw JSON payload is displayed with syntax formatting. Use the Copy button to grab the complete payload for external analysis or SOAR playbook integration.</p>
            </div>
          </div>
        </div>
      )}

      {/* Metadata grid */}
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader className="pb-1">
            <CardTitle className="text-xs text-muted-foreground flex items-center gap-1.5">
              <Layers size={12} /> Event Info
            </CardTitle>
          </CardHeader>
          <CardContent>
            <DetailRow label="Event ID" mono>
              {event.id}
            </DetailRow>
            <DetailRow label="Type" mono>
              {event.event_type}
            </DetailRow>
            <DetailRow label="Severity">
              <Badge
                variant={
                  event.severity as "critical" | "high" | "medium" | "low" | "info"
                }
              >
                {event.severity}
              </Badge>
            </DetailRow>
            <DetailRow label="Timestamp">
              {formatDate(event.timestamp)}
            </DetailRow>
            <DetailRow label="Created">
              {formatDate(event.created_at)}
            </DetailRow>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-1">
            <CardTitle className="text-xs text-muted-foreground flex items-center gap-1.5">
              <ExternalLink size={12} /> Source
            </CardTitle>
          </CardHeader>
          <CardContent>
            <DetailRow label="Agent">
              {event.agent_id ? (
                <Link
                  to={`/agents/${event.agent_id}`}
                  className="font-mono text-xs text-primary hover:underline inline-flex items-center gap-1"
                >
                  {event.agent_id}
                  <ExternalLink size={10} />
                </Link>
              ) : (
                <span className="text-muted-foreground">—</span>
              )}
            </DetailRow>
            <DetailRow label="Sensor" mono>
              {event.sensor_id ?? "—"}
            </DetailRow>
            <DetailRow label="Tenant" mono>
              {event.tenant_id}
            </DetailRow>
          </CardContent>
        </Card>
      </div>

      {/* Enrichment — auto-extracted fields from raw_data */}
      {enrichment.length > 0 && (
        <Card>
          <CardHeader className="pb-1 flex flex-row items-center justify-between">
            <CardTitle className="text-xs text-muted-foreground flex items-center gap-1.5">
              <Tag size={12} /> Enrichment Fields
            </CardTitle>
            <span className="text-[11px] text-muted-foreground tabular-nums">
              {enrichment.length} field{enrichment.length !== 1 ? "s" : ""} extracted
            </span>
          </CardHeader>
          <CardContent>
            <div className="grid md:grid-cols-2 gap-x-8">
              {enrichment.map(({ key, value }) => (
                <div
                  key={key}
                  className="flex items-start justify-between gap-4 py-2 border-b border-border/30 last:border-0"
                >
                  <span className="text-xs font-mono text-primary/70 shrink-0">
                    {key}
                  </span>
                  <span className="text-xs text-foreground/80 text-right break-all font-mono">
                    {value}
                  </span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Raw data */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="flex items-center gap-1.5">
            <FileJson size={14} className="text-muted-foreground" />
            Raw Data
          </CardTitle>
          <Button
            variant="ghost"
            size="sm"
            onClick={copyRawData}
            className="gap-1 text-xs"
          >
            {copied ? <Check size={12} /> : <Copy size={12} />}
            {copied ? "Copied" : "Copy"}
          </Button>
        </CardHeader>
        <CardContent>
          <pre className="bg-surface-2 border border-border rounded-md p-4 text-xs font-mono text-foreground overflow-x-auto max-h-[28rem] overflow-y-auto leading-relaxed">
            {rawStr}
          </pre>
        </CardContent>
      </Card>
    </div>
  )
}
