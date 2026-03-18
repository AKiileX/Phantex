// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — EventDetailPanel: side panel showing full event detail.
 *
 * Displays the complete event payload, ATLAS technique mappings,
 * trust score, raw JSON, and source metadata.
 * Security: all text output is rendered via React (auto-escaped).
 *
 * @module components/investigation/EventDetailPanel
 */

import {
  X,
  FileJson,
  Shield,
  Clock,
  Database,
  ExternalLink,
} from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { formatDate } from "@/lib/utils"
import type { TimelineEvent as TEvent, Severity } from "@/types"

/* ── Props ─────────────────────────────────────────────────────────────────── */

interface EventDetailPanelProps {
  event: TEvent
  onClose: () => void
}

/* ── Component ─────────────────────────────────────────────────────────────── */

export function EventDetailPanel({ event, onClose }: EventDetailPanelProps) {
  const severity = event.severity as Severity

  return (
    <div className="flex flex-col h-full bg-card border-l border-border/50">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-border/40">
        <div className="flex items-center gap-2 min-w-0">
          <FileJson size={14} className="text-primary flex-shrink-0" />
          <span className="text-sm font-semibold text-foreground truncate">
            Event Detail
          </span>
        </div>
        <button
          onClick={onClose}
          className="p-1 rounded-md hover:bg-surface-2 text-muted-foreground hover:text-foreground transition-colors cursor-pointer"
          aria-label="Close event detail"
        >
          <X size={14} />
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto px-4 py-3 space-y-4">
        {/* ── Summary ─────────────────────────────────── */}
        <section>
          <SectionLabel>Summary</SectionLabel>
          <div className="space-y-2">
            <DetailRow label="Event ID">
              <span className="font-mono text-[11px]">{event.id}</span>
            </DetailRow>
            <DetailRow label="Type">
              <span className="font-mono text-xs">{event.event_type}</span>
            </DetailRow>
            <DetailRow label="Severity">
              <Badge variant={severity} className="text-[9px] px-1.5 py-0">
                {severity}
              </Badge>
            </DetailRow>
            <DetailRow label="Timestamp">
              <div className="flex items-center gap-1">
                <Clock size={10} className="text-muted-foreground" />
                <span className="text-xs">{formatDate(event.timestamp)}</span>
              </div>
            </DetailRow>
            <DetailRow label="Source">
              <div className="flex items-center gap-1">
                <Database size={10} className="text-muted-foreground" />
                <span className="text-xs capitalize">{event.source}</span>
              </div>
            </DetailRow>
            {event.agent_id && (
              <DetailRow label="Agent">
                <span className="font-mono text-[11px]">
                  {event.agent_id}
                </span>
              </DetailRow>
            )}
            {event.session_id && (
              <DetailRow label="Session">
                <span className="font-mono text-[11px] text-muted-foreground">
                  {event.session_id}
                </span>
              </DetailRow>
            )}
          </div>
        </section>

        {/* ── Description ─────────────────────────────── */}
        {event.description && (
          <section>
            <SectionLabel>Description</SectionLabel>
            <p className="text-sm text-foreground/90 leading-relaxed">
              {event.description}
            </p>
          </section>
        )}

        {/* ── Trust Score ─────────────────────────────── */}
        {event.trust_score != null && (
          <section>
            <SectionLabel>Trust Score</SectionLabel>
            <div className="flex items-center gap-3">
              <Shield
                size={16}
                className={
                  event.trust_score < 0.3
                    ? "text-severity-critical"
                    : event.trust_score < 0.6
                      ? "text-severity-medium"
                      : "text-status-active"
                }
              />
              <div className="flex-1">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-bold tabular-nums">
                    {event.trust_score.toFixed(3)}
                  </span>
                  <span className="text-[10px] text-muted-foreground">
                    {event.trust_score < 0.3
                      ? "Untrusted"
                      : event.trust_score < 0.6
                        ? "Moderate"
                        : "Trusted"}
                  </span>
                </div>
                {/* Trust bar */}
                <div className="h-1.5 bg-surface-2 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all ${
                      event.trust_score < 0.3
                        ? "bg-severity-critical"
                        : event.trust_score < 0.6
                          ? "bg-severity-medium"
                          : "bg-status-active"
                    }`}
                    style={{ width: `${Math.max(0, Math.min(100, event.trust_score * 100))}%` }}
                  />
                </div>
              </div>
            </div>
          </section>
        )}

        {/* ── ATLAS Techniques ────────────────────────── */}
        {event.atlas_techniques.length > 0 && (
          <section>
            <SectionLabel>MITRE ATLAS Mapping</SectionLabel>
            <div className="space-y-1.5">
              {event.atlas_techniques.map((tech, i) => (
                <div
                  key={i}
                  className="flex items-start gap-2 p-2 rounded-md bg-surface-2/30 border border-border/30"
                >
                  <span className="text-[10px] font-mono font-bold text-primary bg-primary/10 px-1.5 py-0.5 rounded flex-shrink-0">
                    {String(tech.technique_id ?? tech.id ?? `T${i}`)}
                  </span>
                  <div className="flex-1 min-w-0">
                    <span className="text-xs text-foreground">
                      {String(tech.name ?? tech.technique_name ?? "Unknown")}
                    </span>
                    {tech.description ? (
                      <p className="text-[10px] text-muted-foreground mt-0.5">
                        {String(tech.description)}
                      </p>
                    ) : null}
                  </div>
                  <ExternalLink
                    size={10}
                    className="text-muted-foreground/40 flex-shrink-0 mt-0.5"
                  />
                </div>
              ))}
            </div>
          </section>
        )}

        {/* ── Raw Data (JSON) ─────────────────────────── */}
        <section>
          <SectionLabel>Raw Payload</SectionLabel>
          <pre className="text-[10px] font-mono text-foreground/70 bg-surface-2/30 border border-border/30 rounded-md p-3 overflow-x-auto max-h-64 whitespace-pre-wrap break-all">
            {JSON.stringify(event.raw_data, null, 2)}
          </pre>
        </section>
      </div>
    </div>
  )
}

/* ── Helpers ───────────────────────────────────────────────────────────────── */

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <h3 className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium mb-2">
      {children}
    </h3>
  )
}

function DetailRow({
  label,
  children,
}: {
  label: string
  children: React.ReactNode
}) {
  return (
    <div className="flex items-center justify-between py-0.5">
      <span className="text-[11px] text-muted-foreground">{label}</span>
      <div>{children}</div>
    </div>
  )
}
