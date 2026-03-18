// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Threat Replay Timeline.
 *
 * DVR-style scrubber that replays an incident second-by-second with
 * animated data flows. Drag the playhead, see exactly what happened.
 *
 * Data source: GET /api/v1/events, GET /api/v1/alerts
 *
 * @module pages/ThreatReplayPage
 */

import { useState, useMemo, useCallback, useRef, useEffect } from "react"
import {
  Play,
  Pause,
  SkipBack,
  SkipForward,
  Rewind,
  FastForward,
  Clock,
  AlertTriangle,
  Activity,
  Shield,
  HelpCircle,
} from "lucide-react"
import { useEvents } from "@/api/events"
import { useAlerts } from "@/api/alerts"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"
import type { EventSummary, AlertSummary, Severity } from "@/types"

/* ── Unified timeline entry ────────────────────────────────── */

interface TimelineEntry {
  id: string
  timestamp: number
  type: "event" | "alert"
  severity: Severity
  title: string
  agentId: string | null
  eventType?: string
}

/* ── Severity colors ───────────────────────────────────────── */

const SEV_COLOR: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
  info: "#71717a",
}

const SEV_BG: Record<string, string> = {
  critical: "bg-severity-critical/10 border-severity-critical/20 text-severity-critical",
  high: "bg-severity-high/10 border-severity-high/20 text-severity-high",
  medium: "bg-severity-medium/10 border-severity-medium/20 text-severity-medium",
  low: "bg-severity-low/10 border-severity-low/20 text-severity-low",
  info: "bg-surface-1 border-border/30 text-muted-foreground",
}

/* ── Time range options ────────────────────────────────────── */

type ReplayRange = "1h" | "6h" | "24h" | "48h"
const RANGE_MS: Record<ReplayRange, number> = {
  "1h": 3600_000,
  "6h": 21600_000,
  "24h": 86400_000,
  "48h": 172800_000,
}

/* ── Speed options ─────────────────────────────────────────── */

const SPEEDS = [0.5, 1, 2, 5, 10] as const

/* ── Component ─────────────────────────────────────────────── */

export default function ThreatReplayPage() {
  const [range, setRange] = useState<ReplayRange>("24h")
  const [playing, setPlaying] = useState(false)
  const [speed, setSpeed] = useState<number>(1)
  const [playhead, setPlayhead] = useState(0) // 0-1 normalized
  const [severityFilter, setSeverityFilter] = useState<Severity | null>(null)
  const [selectedEntry, setSelectedEntry] = useState<TimelineEntry | null>(null)
  const [showGuide, setShowGuide] = useState(false)
  const scrubberRef = useRef<HTMLDivElement>(null)
  const playIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const [mountTime] = useState(Date.now)

  const since = useMemo(() => new Date(mountTime - RANGE_MS[range]).toISOString(), [range, mountTime])
  const { data: eventsData } = useEvents({ since, limit: 100 }, 15_000)
  const { data: alertsData } = useAlerts({ since, limit: 100 }, 15_000)

  /* ── Build unified timeline ──────────────────────────── */
  const entries = useMemo(() => {
    const items: TimelineEntry[] = []
    const rangeStart = mountTime - RANGE_MS[range]

    ;(eventsData?.items ?? []).forEach((e: EventSummary) => {
      items.push({
        id: e.id,
        timestamp: new Date(e.timestamp).getTime(),
        type: "event",
        severity: e.severity,
        title: e.event_type.replace(/_/g, " "),
        agentId: e.agent_id,
        eventType: e.event_type,
      })
    })

    ;(alertsData?.items ?? []).forEach((a: AlertSummary) => {
      items.push({
        id: a.id,
        timestamp: new Date(a.created_at).getTime(),
        type: "alert",
        severity: a.severity,
        title: a.title,
        agentId: a.agent_id,
      })
    })

    return items
      .filter((e) => e.timestamp >= rangeStart)
      .filter((e) => !severityFilter || e.severity === severityFilter)
      .sort((a, b) => a.timestamp - b.timestamp)
  }, [eventsData, alertsData, range, severityFilter, mountTime])

  /* ── Time window based on playhead ───────────────────── */
  const rangeStart = mountTime - RANGE_MS[range]
  const rangeEnd = mountTime
  const currentTime = rangeStart + playhead * RANGE_MS[range]

  const visibleEntries = useMemo(
    () => entries.filter((e) => e.timestamp <= currentTime),
    [entries, currentTime],
  )

  /* ── Playback ────────────────────────────────────────── */
  useEffect(() => {
    if (playing) {
      playIntervalRef.current = setInterval(() => {
        setPlayhead((p) => {
          const next = p + (speed * 0.002)
          if (next >= 1) {
            setPlaying(false)
            return 1
          }
          return next
        })
      }, 50)
    } else {
      if (playIntervalRef.current) clearInterval(playIntervalRef.current)
    }
    return () => { if (playIntervalRef.current) clearInterval(playIntervalRef.current) }
  }, [playing, speed])

  /* ── Scrubber interaction ────────────────────────────── */
  const scrub = useCallback((e: React.MouseEvent) => {
    const rect = scrubberRef.current?.getBoundingClientRect()
    if (!rect) return
    const x = Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width))
    setPlayhead(x)
  }, [])

  const [dragging, setDragging] = useState(false)

  const onScrubStart = useCallback((e: React.MouseEvent) => {
    setDragging(true)
    scrub(e)
  }, [scrub])

  const onScrubMove = useCallback((e: React.MouseEvent) => {
    if (dragging) scrub(e)
  }, [dragging, scrub])

  const onScrubEnd = useCallback(() => setDragging(false), [])

  /* ── Format time ─────────────────────────────────────── */
  const formatTime = useCallback((ts: number) => {
    const d = new Date(ts)
    return d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" })
  }, [])

  /* ── Severity distribution on scrubber ───────────────── */
  const dots = useMemo(() => {
    return entries.map((e) => ({
      position: (e.timestamp - rangeStart) / (rangeEnd - rangeStart),
      color: SEV_COLOR[e.severity] ?? SEV_COLOR.info,
      entry: e,
    }))
  }, [entries, rangeStart, rangeEnd])

  /* ── Stats ───────────────────────────────────────────── */
  const stats = useMemo(() => {
    const byType = { events: 0, alerts: 0 }
    const bySev: Record<string, number> = {}
    visibleEntries.forEach((e) => {
      byType[e.type === "event" ? "events" : "alerts"]++
      bySev[e.severity] = (bySev[e.severity] ?? 0) + 1
    })
    return { ...byType, bySev, total: visibleEntries.length }
  }, [visibleEntries])

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center h-9 w-9 rounded-lg bg-amber-500/10 border border-amber-500/20">
            <Rewind size={18} className="text-amber-400" />
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-tight">Threat Replay</h1>
            <p className="text-xs text-muted-foreground">DVR-style incident playback — scrub through time</p>
          </div>
          <button onClick={() => setShowGuide(!showGuide)} className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"><HelpCircle size={14} />{showGuide ? "Hide Guide" : "How does this work?"}</button>
        </div>
        <div className="flex items-center gap-2">
          {/* Range selector */}
          <div className="flex items-center gap-1 bg-surface-1 border border-border/50 rounded-lg p-0.5">
            {(Object.keys(RANGE_MS) as ReplayRange[]).map((r) => (
              <button
                key={r}
                onClick={() => { setRange(r); setPlayhead(0); setPlaying(false) }}
                className={cn(
                  "px-2.5 py-1 rounded-md text-xs font-medium transition-all cursor-pointer",
                  range === r
                    ? "bg-primary/15 text-primary border border-primary/20"
                    : "text-muted-foreground hover:text-foreground",
                )}
              >
                {r}
              </button>
            ))}
          </div>
          {/* Severity filter */}
          <div className="flex items-center gap-1 bg-surface-1 border border-border/50 rounded-lg p-0.5">
            <button
              onClick={() => setSeverityFilter(null)}
              className={cn(
                "px-2 py-1 rounded-md text-xs font-medium cursor-pointer",
                !severityFilter ? "bg-primary/15 text-primary" : "text-muted-foreground",
              )}
            >
              All
            </button>
            {(["critical", "high", "medium", "low"] as Severity[]).map((s) => (
              <button
                key={s}
                onClick={() => setSeverityFilter(severityFilter === s ? null : s)}
                className={cn(
                  "px-2 py-1 rounded-md text-xs font-medium capitalize cursor-pointer",
                  severityFilter === s ? "bg-primary/15 text-primary" : "text-muted-foreground",
                )}
              >
                {s}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* How it works banner — appears when nothing is playing */}
      {!playing && playhead === 0 && entries.length > 0 && (
        <div className="flex items-center gap-4 px-5 py-3.5 rounded-xl border border-primary/15 bg-primary/[0.03] backdrop-blur-sm">
          <div className="flex items-center justify-center h-9 w-9 rounded-lg bg-primary/10 border border-primary/20 flex-shrink-0">
            <Play size={16} className="text-primary ml-0.5" />
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-xs font-semibold text-foreground">How Threat Replay works</p>
            <p className="text-[11px] text-muted-foreground mt-0.5">
              Press <span className="font-semibold text-primary">Play</span> or drag the scrubber to travel through time. Events and alerts appear as they happened — use speed controls to fast-forward. Click any event for details.
            </p>
          </div>
          <Button variant="default" size="sm" onClick={() => setPlaying(true)} className="flex-shrink-0 gap-1.5">
            <Play size={13} /> Start Replay
          </Button>
        </div>
      )}

      {/* Playback controls + scrubber */}
      <Card className="!p-0 overflow-hidden">
        {/* Top accent gradient */}
        <div className="h-[2px] bg-gradient-to-r from-transparent via-primary/30 to-transparent" />
        <div className="p-4 space-y-3">
          {/* Transport controls */}
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1">
              <Button variant="ghost" size="icon" onClick={() => { setPlayhead(0); setPlaying(false) }}>
                <SkipBack size={16} />
              </Button>
              <Button
                variant={playing ? "outline" : "default"}
                size="icon"
                onClick={() => setPlaying(!playing)}
                className="h-9 w-9"
              >
                {playing ? <Pause size={16} /> : <Play size={16} />}
              </Button>
              <Button variant="ghost" size="icon" onClick={() => setPlayhead(1)}>
                <SkipForward size={16} />
              </Button>
            </div>

            {/* Current time */}
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-surface-1 border border-border/30">
              <Clock size={13} className="text-muted-foreground" />
              <span className="text-xs font-mono text-foreground">{formatTime(currentTime)}</span>
            </div>

            {/* Speed selector */}
            <div className="flex items-center gap-1 ml-auto">
              <FastForward size={13} className="text-muted-foreground" />
              {SPEEDS.map((s) => (
                <button
                  key={s}
                  onClick={() => setSpeed(s)}
                  className={cn(
                    "px-2 py-0.5 rounded text-[10px] font-mono font-bold cursor-pointer transition-all",
                    speed === s
                      ? "bg-primary/15 text-primary border border-primary/20"
                      : "text-muted-foreground hover:text-foreground",
                  )}
                >
                  {s}x
                </button>
              ))}
            </div>

            {/* Event counter */}
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <span className="tabular-nums font-bold text-foreground">{stats.total}</span>
              <span>events shown</span>
            </div>
          </div>

          {/* Scrubber track (v2 — with density waveform) */}
          <div
            ref={scrubberRef}
            className="relative h-16 bg-surface-0/80 rounded-xl border border-border/30 cursor-crosshair overflow-hidden select-none backdrop-blur-sm"
            onMouseDown={onScrubStart}
            onMouseMove={onScrubMove}
            onMouseUp={onScrubEnd}
            onMouseLeave={onScrubEnd}
          >
            {/* Density waveform background */}
            <svg className="absolute inset-0 w-full h-full" preserveAspectRatio="none">
              {(() => {
                // Build density bars
                const buckets = 80
                const counts = new Array(buckets).fill(0)
                entries.forEach((e) => {
                  const pos = (e.timestamp - rangeStart) / (rangeEnd - rangeStart)
                  const idx = Math.min(buckets - 1, Math.max(0, Math.floor(pos * buckets)))
                  counts[idx]++
                })
                const maxCount = Math.max(1, ...counts)
                return counts.map((c, i) => {
                  const h = (c / maxCount) * 50
                  const x = (i / buckets) * 100
                  const w = 100 / buckets
                  const isBeforePlayhead = (i / buckets) <= playhead
                  return (
                    <rect
                      key={i}
                      x={`${x}%`} y={`${64 - h}%`}
                      width={`${w}%`} height={`${h}%`}
                      fill={isBeforePlayhead ? "rgba(16,185,129,0.15)" : "rgba(63,63,70,0.08)"}
                      rx={1}
                    />
                  )
                })
              })()}
            </svg>

            {/* Filled area */}
            <div
              className="absolute inset-y-0 left-0 bg-gradient-to-r from-primary/[0.04] to-primary/[0.08] border-r border-primary/30 transition-[width] duration-75"
              style={{ width: `${playhead * 100}%` }}
            />

            {/* Event dots on scrubber */}
            {dots.map((d, i) => (
              <div
                key={i}
                className="absolute bottom-0 transition-opacity"
                style={{
                  left: `${d.position * 100}%`,
                  height: d.entry.type === "alert" ? "100%" : "35%",
                  width: d.entry.type === "alert" ? "2px" : "1px",
                  backgroundColor: d.color,
                  opacity: d.position <= playhead ? 0.7 : 0.15,
                  boxShadow: d.entry.type === "alert" && d.position <= playhead ? `0 0 4px ${d.color}` : undefined,
                }}
              />
            ))}

            {/* Playhead with glow */}
            <div
              className="absolute top-0 h-full w-0.5 bg-primary z-10"
              style={{
                left: `${playhead * 100}%`,
                boxShadow: "0 0 8px rgba(16,185,129,0.4), 0 0 16px rgba(16,185,129,0.15)",
              }}
            >
              <div className="absolute -top-0.5 left-1/2 -translate-x-1/2 w-3.5 h-3.5 rounded-full bg-primary border-2 border-background shadow-lg shadow-primary/30" />
              <div className="absolute -bottom-0.5 left-1/2 -translate-x-1/2 w-2 h-2 rounded-full bg-primary/60" />
            </div>

            {/* Time labels */}
            <div className="absolute bottom-1.5 left-3 text-[9px] font-mono text-muted-foreground/40">
              {formatTime(rangeStart)}
            </div>
            <div className="absolute bottom-1.5 right-3 text-[9px] font-mono text-muted-foreground/40">
              {formatTime(rangeEnd)}
            </div>
            {/* Current time label following playhead */}
            <div
              className="absolute top-1.5 text-[8px] font-mono font-bold text-primary/70 transition-[left] duration-75 pointer-events-none"
              style={{ left: `${Math.min(92, Math.max(2, playhead * 100))}%` }}
            >
              {formatTime(currentTime)}
            </div>
          </div>
        </div>
      </Card>

      {/* Content area */}
      <div className="grid grid-cols-12 gap-4">
        {/* Event feed */}
        <div className="col-span-8 space-y-2">
          <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wider px-1">
            Event Feed — {formatTime(rangeStart)} → {formatTime(currentTime)}
          </div>
          <div className="space-y-1.5 max-h-[500px] overflow-y-auto pr-1">
            {visibleEntries.slice(-50).reverse().map((entry) => (
              <button
                key={entry.id}
                onClick={() => setSelectedEntry(entry)}
                className={cn(
                  "w-full flex items-center gap-3 px-3 py-2 rounded-lg border text-left transition-all cursor-pointer hover:bg-white/[0.02]",
                  selectedEntry?.id === entry.id
                    ? "bg-primary/5 border-primary/20"
                    : "border-border/20 bg-surface-0/50",
                )}
              >
                {/* Severity dot */}
                <span
                  className="flex-shrink-0 w-2 h-2 rounded-full"
                  style={{ backgroundColor: SEV_COLOR[entry.severity] }}
                />

                {/* Type icon */}
                {entry.type === "alert" ? (
                  <AlertTriangle size={14} className="flex-shrink-0 text-severity-high" />
                ) : (
                  <Activity size={14} className="flex-shrink-0 text-muted-foreground" />
                )}

                {/* Content */}
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-medium text-foreground truncate">{entry.title}</div>
                  <div className="text-[10px] text-muted-foreground">
                    {entry.agentId ? `Agent ${entry.agentId.slice(0, 8)}` : "System"}
                    {entry.eventType && ` · ${entry.eventType}`}
                  </div>
                </div>

                {/* Time */}
                <span className="text-[10px] font-mono text-muted-foreground flex-shrink-0">
                  {formatTime(entry.timestamp)}
                </span>

                <Badge variant={entry.severity} className="flex-shrink-0">
                  {entry.severity}
                </Badge>
              </button>
            ))}
            {visibleEntries.length === 0 && (
              <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
                <div className="relative mb-4">
                  <div className="absolute inset-0 bg-primary/5 rounded-full blur-2xl scale-150" />
                  <Clock size={36} className="opacity-20 relative" />
                </div>
                <span className="text-sm font-medium">No events at this point in time</span>
                <span className="text-xs mt-1 opacity-60">
                  {entries.length === 0
                    ? "No events found in this time range — try expanding the range"
                    : "Press play or drag the scrubber forward to see events"}
                </span>
              </div>
            )}
          </div>
        </div>

        {/* Stats panel */}
        <div className="col-span-4 space-y-3">
          {/* Live counters */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-xs">
                <Activity size={14} />
                Replay Stats
              </CardTitle>
            </CardHeader>
            <CardContent className="grid grid-cols-2 gap-3">
              <div className="text-center">
                <div className="text-2xl font-bold tabular-nums text-foreground">{stats.events}</div>
                <div className="text-[10px] text-muted-foreground uppercase">Events</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold tabular-nums text-severity-high">{stats.alerts}</div>
                <div className="text-[10px] text-muted-foreground uppercase">Alerts</div>
              </div>
            </CardContent>
          </Card>

          {/* Severity breakdown */}
          <Card>
            <CardHeader>
              <CardTitle className="text-xs flex items-center gap-2">
                <Shield size={14} />
                Severity Distribution
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {(["critical", "high", "medium", "low", "info"] as Severity[]).map((sev) => {
                const count = stats.bySev[sev] ?? 0
                const pct = stats.total > 0 ? (count / stats.total) * 100 : 0
                return (
                  <div key={sev} className="space-y-1">
                    <div className="flex items-center justify-between text-[10px]">
                      <span className="uppercase font-medium" style={{ color: SEV_COLOR[sev] }}>{sev}</span>
                      <span className="text-muted-foreground tabular-nums">{count}</span>
                    </div>
                    <div className="h-1.5 rounded-full bg-surface-2 overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all duration-500"
                        style={{ width: `${pct}%`, backgroundColor: SEV_COLOR[sev] }}
                      />
                    </div>
                  </div>
                )
              })}
            </CardContent>
          </Card>

          {/* Selected entry detail */}
          {selectedEntry && (
            <Card>
              <CardHeader>
                <CardTitle className="text-xs">Selected Entry</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-xs">
                <div className={cn("px-2.5 py-2 rounded-lg border", SEV_BG[selectedEntry.severity])}>
                  <div className="font-bold">{selectedEntry.title}</div>
                </div>
                <div className="grid grid-cols-2 gap-y-1.5 text-[10px]">
                  <span className="text-muted-foreground">Type</span>
                  <span className="font-medium capitalize">{selectedEntry.type}</span>
                  <span className="text-muted-foreground">Time</span>
                  <span className="font-mono">{formatTime(selectedEntry.timestamp)}</span>
                  <span className="text-muted-foreground">Agent</span>
                  <span className="font-mono">{selectedEntry.agentId?.slice(0, 12) ?? "—"}</span>
                </div>
                {selectedEntry.type === "alert" && (
                  <a href={`/alerts/${selectedEntry.id}`} className="text-primary text-[11px] hover:underline">
                    View alert details →
                  </a>
                )}
                {selectedEntry.type === "event" && (
                  <a href={`/events/${selectedEntry.id}`} className="text-primary text-[11px] hover:underline">
                    View event details →
                  </a>
                )}
              </CardContent>
            </Card>
          )}
        </div>
      </div>

      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5 space-y-3 text-sm text-muted-foreground">
          <h3 className="text-base font-semibold text-foreground">How does Threat Replay work?</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">DVR-Style Playback</p>
              <p>Combines events from <code className="text-xs bg-white/5 px-1 rounded">useEvents</code> and alerts from <code className="text-xs bg-white/5 px-1 rounded">useAlerts</code> into a unified timeline. The scrubber bar lets you move through time with play/pause, speed controls (0.5x–4x), and skip forward/back buttons.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Time Ranges</p>
              <p>Choose from 1h, 6h, 24h, 7d, or 30d windows. Events and alerts within the window are plotted chronologically. Severity-colored dots on the scrubber show event density and threat concentration at each point in time.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Severity Filter</p>
              <p>Filter the replay by severity level to focus on critical/high events during incident review. The event feed below the scrubber shows entries visible at the current playhead position, updating in real time as you scrub.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Incident Review</p>
              <p>Click any entry in the feed to see full details in a side panel. This is designed for post-incident review — reconstruct exactly what happened, when, and in what order. Great for SOC debriefs and root cause analysis.</p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
