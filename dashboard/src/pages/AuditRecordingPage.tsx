// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Agent Audit & DVR Recording Dashboard.
 *
 * Tabs:
 *   1. Recording Config  — Set/view Level 1/2/3 per agent
 *   2. Event Browser     — Query recorded events
 *   3. DVR Replay        — Build and replay agent sessions
 *   4. Audit Chain       — View tamper-proof chain, verify integrity
 *   5. Legal Holds       — Set/release/view legal holds
 *   6. Compliance Export — Generate ISO/SOC2/HIPAA/FedRAMP packages
 *
 * @module pages/AuditRecordingPage
 */

import { useState } from "react"
import {
  Video,
  Shield,
  Lock,
  FileCheck,
  Play,
  Link2,
  Settings,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  ChevronRight,
  HelpCircle,
} from "lucide-react"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"
import {
  useRecordingConfigs,
  useSetRecordingConfig,
  useRecordingEvents,
  useRecordingStats,
  useReplaySessions,
  useBuildReplay,
  useChainEntries,
  useVerifyChain,
  useLegalHolds,
  useSetLegalHold,
  useReleaseLegalHold,
  useComplianceExports,
  useGenerateExport,
} from "@/api/auditRecording"
import type {
  RecordingConfig,
  RecordingEvent,
  ReplaySession,
  ChainEntry,
  LegalHold,
  ComplianceExport,
  ChainVerification,
} from "@/api/auditRecording"

/* ── Tab definitions ──────────────────────────────────────────── */

const TABS = [
  { key: "config", label: "Recording Config", icon: <Settings size={16} /> },
  { key: "events", label: "Event Browser", icon: <Video size={16} /> },
  { key: "replay", label: "DVR Replay", icon: <Play size={16} /> },
  { key: "chain", label: "Audit Chain", icon: <Link2 size={16} /> },
  { key: "holds", label: "Legal Holds", icon: <Lock size={16} /> },
  { key: "export", label: "Compliance Export", icon: <FileCheck size={16} /> },
] as const

type TabKey = (typeof TABS)[number]["key"]

/* ── Level badges ─────────────────────────────────────────────── */

const LEVEL_LABELS: Record<number, string> = {
  1: "Audit (L1)",
  2: "Extended (L2)",
  3: "Full DVR (L3)",
}
const LEVEL_COLOR: Record<number, string> = {
  1: "bg-blue-500/10 text-blue-400 border-blue-500/20",
  2: "bg-amber-500/10 text-amber-400 border-amber-500/20",
  3: "bg-red-500/10 text-red-400 border-red-500/20",
}

/* ── Step type colors ─────────────────────────────────────────── */

const STEP_COLOR: Record<string, string> = {
  input: "bg-blue-500/10 text-blue-400",
  decision: "bg-purple-500/10 text-purple-400",
  action: "bg-emerald-500/10 text-emerald-400",
  result: "bg-zinc-500/10 text-zinc-400",
  blocked: "bg-red-500/10 text-red-400",
}

/* ── Main page component ──────────────────────────────────────── */

export function AuditRecordingPage() {
  const [tab, setTab] = useState<TabKey>("config")
  const [showGuide, setShowGuide] = useState(false)

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Shield className="h-7 w-7 text-primary" />
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Agent Audit & DVR Recording</h1>
          <p className="text-sm text-muted-foreground">
            Three-tier recording · Tamper-proof chain · DVR replay · Compliance exports
          </p>
        </div>
        <button onClick={() => setShowGuide(!showGuide)} className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"><HelpCircle size={14} />{showGuide ? "Hide Guide" : "How does this work?"}</button>
      </div>

      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5 space-y-3 text-sm text-muted-foreground">
          <h3 className="text-base font-semibold text-foreground">How does Agent Audit &amp; DVR Recording work?</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Three-Tier Recording</p>
              <p>Configure recording levels per agent via <code className="text-xs bg-white/5 px-1 rounded">/api/audit-recording/config</code>. Level 1: metadata only. Level 2: metadata + payloads. Level 3: full session capture with tool I/O. Higher levels increase storage but provide richer forensic evidence.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">DVR Replay</p>
              <p>Build replay sessions from <code className="text-xs bg-white/5 px-1 rounded">/api/audit-recording/replay/build</code> for any agent and time range. Sessions reconstruct exact agent behavior — tool calls, decisions, and outputs — like a DVR recording for security review.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Tamper-Proof Chain</p>
              <p>All audit entries are chained via <code className="text-xs bg-white/5 px-1 rounded">/api/audit-recording/chain</code> with cryptographic hashes. Verify chain integrity with a single click. Any tampering breaks the hash chain and raises an alert immediately.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Legal Holds &amp; Exports</p>
              <p>Set legal holds on agents to prevent audit data deletion. Generate compliance packages (ISO 27001, SOC 2, HIPAA, FedRAMP) via <code className="text-xs bg-white/5 px-1 rounded">/api/audit-recording/compliance/generate</code> with all evidence included.</p>
            </div>
          </div>
        </div>
      )}

      {/* Tab bar */}
      <div className="flex gap-1 rounded-lg border bg-card p-1">
        {TABS.map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={cn(
              "flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition-colors",
              tab === t.key
                ? "bg-primary text-primary-foreground"
                : "text-muted-foreground hover:bg-muted",
            )}
          >
            {t.icon} {t.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === "config" && <ConfigTab />}
      {tab === "events" && <EventsTab />}
      {tab === "replay" && <ReplayTab />}
      {tab === "chain" && <ChainTab />}
      {tab === "holds" && <HoldsTab />}
      {tab === "export" && <ExportTab />}
    </div>
  )
}

/* ── Config Tab ───────────────────────────────────────────────── */

function ConfigTab() {
  const { data: configs, isLoading } = useRecordingConfigs()
  const { data: stats } = useRecordingStats()
  const setConfig = useSetRecordingConfig()
  const [agentId, setAgentId] = useState("")
  const [level, setLevel] = useState(1)

  return (
    <div className="grid gap-4 md:grid-cols-2">
      {/* Stats card */}
      <Card>
        <CardHeader><CardTitle className="text-sm">Recording Stats</CardTitle></CardHeader>
        <CardContent>
          {stats ? (
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div>
                <span className="text-muted-foreground">Total Events</span>
                <p className="text-lg font-bold">{stats.recording?.total_events ?? 0}</p>
              </div>
              <div>
                <span className="text-muted-foreground">Chain Length</span>
                <p className="text-lg font-bold">{stats.chain?.chain_length ?? 0}</p>
              </div>
              <div>
                <span className="text-muted-foreground">Active Holds</span>
                <p className="text-lg font-bold">{stats.chain?.active_holds ?? 0}</p>
              </div>
              <div>
                <span className="text-muted-foreground">Configs</span>
                <p className="text-lg font-bold">{stats.recording?.configs ?? 0}</p>
              </div>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">Loading…</p>
          )}
        </CardContent>
      </Card>

      {/* Set config card */}
      <Card>
        <CardHeader><CardTitle className="text-sm">Set Recording Level</CardTitle></CardHeader>
        <CardContent className="space-y-3">
          <input
            className="w-full rounded border bg-background px-3 py-1.5 text-sm"
            placeholder="Agent ID (blank = tenant default)"
            value={agentId}
            onChange={(e) => setAgentId(e.target.value)}
          />
          <select
            className="w-full rounded border bg-background px-3 py-1.5 text-sm"
            value={level}
            onChange={(e) => setLevel(Number(e.target.value))}
          >
            <option value={1}>Level 1 — Audit Log (always on)</option>
            <option value={2}>Level 2 — Extended Recording</option>
            <option value={3}>Level 3 — Full DVR</option>
          </select>
          <Button
            size="sm"
            onClick={() => setConfig.mutate({ agent_id: agentId || undefined, level })}
            disabled={setConfig.isPending}
          >
            {setConfig.isPending ? "Saving…" : "Save Config"}
          </Button>
        </CardContent>
      </Card>

      {/* Configs list */}
      <Card className="md:col-span-2">
        <CardHeader><CardTitle className="text-sm">Active Configurations</CardTitle></CardHeader>
        <CardContent>
          {isLoading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : configs && configs.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead><tr className="border-b text-left text-muted-foreground">
                  <th className="pb-2">Scope</th>
                  <th className="pb-2">Level</th>
                  <th className="pb-2">Enabled</th>
                </tr></thead>
                <tbody>
                  {configs.map((c: RecordingConfig, i: number) => (
                    <tr key={i} className="border-b border-border/50">
                      <td className="py-2 font-mono text-xs">{c.agent_id ?? "Tenant Default"}</td>
                      <td className="py-2">
                        <Badge className={LEVEL_COLOR[c.level]}>{LEVEL_LABELS[c.level]}</Badge>
                      </td>
                      <td className="py-2">{c.enabled ? <CheckCircle2 size={14} className="text-green-400" /> : <XCircle size={14} className="text-red-400" />}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No configurations set. Level 1 is active by default.</p>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

/* ── Events Tab ───────────────────────────────────────────────── */

function EventsTab() {
  const [agentFilter, setAgentFilter] = useState("")
  const { data, isLoading } = useRecordingEvents(agentFilter ? { agent_id: agentFilter } : undefined)

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        <input
          className="rounded border bg-background px-3 py-1.5 text-sm"
          placeholder="Filter by Agent ID"
          value={agentFilter}
          onChange={(e) => setAgentFilter(e.target.value)}
        />
      </div>

      <Card>
        <CardHeader><CardTitle className="text-sm">Recorded Events ({data?.count ?? 0})</CardTitle></CardHeader>
        <CardContent>
          {isLoading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : data?.events && data.events.length > 0 ? (
            <div className="max-h-[600px] overflow-y-auto space-y-2">
              {data.events.map((evt: RecordingEvent) => (
                <div key={evt.id} className="rounded border p-3 text-xs">
                  <div className="flex items-center gap-2">
                    <Badge className={LEVEL_COLOR[evt.level]}>{LEVEL_LABELS[evt.level]}</Badge>
                    <span className="font-mono">{evt.audit?.agent_id}</span>
                    <span className="text-muted-foreground">{evt.audit?.event_type}</span>
                    <Badge variant={evt.audit?.result === "blocked" ? "critical" : "secondary"}>
                      {evt.audit?.result}
                    </Badge>
                    <span className="ml-auto text-muted-foreground">{evt.audit?.timestamp}</span>
                  </div>
                  {evt.audit?.tool_name && (
                    <p className="mt-1 text-muted-foreground">Tool: {evt.audit.tool_name}</p>
                  )}
                  {evt.audit?.data_classification !== "clean" && (
                    <Badge className="mt-1 bg-amber-500/10 text-amber-400">{evt.audit?.data_classification}</Badge>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No recorded events yet.</p>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

/* ── Replay Tab ───────────────────────────────────────────────── */

function ReplayTab() {
  const { data: sessionsData } = useReplaySessions()
  const buildReplay = useBuildReplay()
  const [replayAgentId, setReplayAgentId] = useState("")
  const [selectedSession, setSelectedSession] = useState<ReplaySession | null>(null)

  return (
    <div className="grid gap-4 md:grid-cols-3">
      {/* Build replay */}
      <Card>
        <CardHeader><CardTitle className="text-sm">Build DVR Replay</CardTitle></CardHeader>
        <CardContent className="space-y-3">
          <input
            className="w-full rounded border bg-background px-3 py-1.5 text-sm"
            placeholder="Agent ID"
            value={replayAgentId}
            onChange={(e) => setReplayAgentId(e.target.value)}
          />
          <Button
            size="sm"
            onClick={() =>
              buildReplay.mutate(
                { agent_id: replayAgentId },
                { onSuccess: (s) => setSelectedSession(s as ReplaySession) },
              )
            }
            disabled={!replayAgentId || buildReplay.isPending}
          >
            <Play size={14} className="mr-1" />
            {buildReplay.isPending ? "Building…" : "Build Replay"}
          </Button>
        </CardContent>
      </Card>

      {/* Sessions list */}
      <Card>
        <CardHeader><CardTitle className="text-sm">Replay Sessions</CardTitle></CardHeader>
        <CardContent>
          {sessionsData?.sessions && sessionsData.sessions.length > 0 ? (
            <div className="max-h-[400px] overflow-y-auto space-y-1">
              {sessionsData.sessions.map((s: ReplaySession) => (
                <button
                  key={s.session_id}
                  onClick={() => setSelectedSession(s)}
                  className={cn(
                    "w-full rounded p-2 text-left text-xs transition-colors hover:bg-muted",
                    selectedSession?.session_id === s.session_id && "bg-muted",
                  )}
                >
                  <div className="flex items-center gap-1">
                    <span className="font-mono">{s.agent_id}</span>
                    <ChevronRight size={12} />
                    <span>{s.step_count} steps</span>
                    {s.blocked_count > 0 && (
                      <Badge variant="critical" className="ml-auto text-[10px]">
                        {s.blocked_count} blocked
                      </Badge>
                    )}
                  </div>
                </button>
              ))}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No replay sessions yet.</p>
          )}
        </CardContent>
      </Card>

      {/* Timeline viewer */}
      <Card>
        <CardHeader><CardTitle className="text-sm">
          {selectedSession ? `Timeline: ${selectedSession.agent_id}` : "Select a session"}
        </CardTitle></CardHeader>
        <CardContent>
          {selectedSession?.steps && selectedSession.steps.length > 0 ? (
            <div className="max-h-[500px] overflow-y-auto space-y-1.5">
              {selectedSession.steps.map((step) => (
                <div
                  key={step.index}
                  className={cn("rounded p-2 text-xs border", STEP_COLOR[step.step_type])}
                >
                  <div className="flex items-center gap-1.5">
                    <span className="font-mono opacity-50">#{step.index}</span>
                    <Badge className={STEP_COLOR[step.step_type]}>{step.step_type}</Badge>
                    {step.rule_matched && (
                      <AlertTriangle size={12} className="text-amber-400" />
                    )}
                  </div>
                  <p className="mt-1">{step.summary}</p>
                  <p className="mt-0.5 text-[10px] text-muted-foreground">{step.timestamp}</p>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">
              {selectedSession ? "No steps in this session." : "Build or select a replay session."}
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

/* ── Chain Tab ────────────────────────────────────────────────── */

function ChainTab() {
  const { data: chainData } = useChainEntries()
  const verifyChain = useVerifyChain()
  const [verification, setVerification] = useState<ChainVerification | null>(null)

  return (
    <div className="grid gap-4 md:grid-cols-2">
      {/* Verify chain */}
      <Card>
        <CardHeader><CardTitle className="text-sm">Chain Integrity</CardTitle></CardHeader>
        <CardContent className="space-y-3">
          <Button
            size="sm"
            onClick={() =>
              verifyChain.mutate(undefined, { onSuccess: (v) => setVerification(v as ChainVerification) })
            }
            disabled={verifyChain.isPending}
          >
            <Shield size={14} className="mr-1" />
            {verifyChain.isPending ? "Verifying…" : "Verify Chain"}
          </Button>
          {verification && (
            <div className={cn("rounded border p-3 text-sm", verification.valid ? "border-green-500/30 bg-green-500/5" : "border-red-500/30 bg-red-500/5")}>
              {verification.valid ? (
                <div className="flex items-center gap-2 text-green-400">
                  <CheckCircle2 size={16} /> {verification.message}
                </div>
              ) : (
                <div className="flex items-center gap-2 text-red-400">
                  <XCircle size={16} /> {verification.message}
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Chain entries */}
      <Card className="md:col-span-2">
        <CardHeader><CardTitle className="text-sm">Audit Chain Entries ({chainData?.count ?? 0})</CardTitle></CardHeader>
        <CardContent>
          {chainData?.entries && chainData.entries.length > 0 ? (
            <div className="max-h-[500px] overflow-y-auto">
              <table className="w-full text-xs">
                <thead><tr className="border-b text-left text-muted-foreground">
                  <th className="pb-2">Timestamp</th>
                  <th className="pb-2">Action</th>
                  <th className="pb-2">Actor</th>
                  <th className="pb-2">Agent</th>
                  <th className="pb-2">Hash</th>
                </tr></thead>
                <tbody>
                  {chainData.entries.map((e: ChainEntry) => (
                    <tr key={e.id} className="border-b border-border/50">
                      <td className="py-1.5 font-mono">{e.timestamp}</td>
                      <td className="py-1.5"><Badge variant="outline">{e.action}</Badge></td>
                      <td className="py-1.5 font-mono">{e.actor.slice(0, 8)}…</td>
                      <td className="py-1.5">{e.agent_id ?? "—"}</td>
                      <td className="py-1.5 font-mono text-muted-foreground">{e.entry_hash.slice(0, 12)}…</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No chain entries yet.</p>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

/* ── Holds Tab ────────────────────────────────────────────────── */

function HoldsTab() {
  const { data: holdsData } = useLegalHolds()
  const setHold = useSetLegalHold()
  const releaseHold = useReleaseLegalHold()
  const [holdAgentId, setHoldAgentId] = useState("")
  const [holdReason, setHoldReason] = useState("")

  return (
    <div className="grid gap-4 md:grid-cols-2">
      {/* Set hold */}
      <Card>
        <CardHeader><CardTitle className="text-sm">Set Legal Hold</CardTitle></CardHeader>
        <CardContent className="space-y-3">
          <input
            className="w-full rounded border bg-background px-3 py-1.5 text-sm"
            placeholder="Agent ID"
            value={holdAgentId}
            onChange={(e) => setHoldAgentId(e.target.value)}
          />
          <input
            className="w-full rounded border bg-background px-3 py-1.5 text-sm"
            placeholder="Reason for legal hold"
            value={holdReason}
            onChange={(e) => setHoldReason(e.target.value)}
          />
          <Button
            size="sm"
            onClick={() => setHold.mutate({ agent_id: holdAgentId, reason: holdReason })}
            disabled={!holdAgentId || !holdReason || setHold.isPending}
          >
            <Lock size={14} className="mr-1" />
            {setHold.isPending ? "Setting…" : "Set Legal Hold"}
          </Button>
        </CardContent>
      </Card>

      {/* Holds list */}
      <Card className="md:col-span-2">
        <CardHeader><CardTitle className="text-sm">Active Legal Holds ({holdsData?.count ?? 0})</CardTitle></CardHeader>
        <CardContent>
          {holdsData?.holds && holdsData.holds.length > 0 ? (
            <div className="space-y-2">
              {holdsData.holds.map((h: LegalHold, i: number) => (
                <div key={i} className="flex items-center justify-between rounded border p-3 text-sm">
                  <div>
                    <span className="font-mono">{h.agent_id}</span>
                    <p className="text-xs text-muted-foreground mt-0.5">{h.reason}</p>
                    <p className="text-[10px] text-muted-foreground">Held by {h.held_by} at {h.held_at}</p>
                  </div>
                  {h.active && (
                    <Button
                      size="sm"
                      variant="destructive"
                      onClick={() => releaseHold.mutate({ agent_id: h.agent_id })}
                      disabled={releaseHold.isPending}
                    >
                      Release
                    </Button>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No active legal holds.</p>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

/* ── Export Tab ────────────────────────────────────────────────── */

function ExportTab() {
  const { data: exportsData } = useComplianceExports()
  const generateExport = useGenerateExport()
  const [framework, setFramework] = useState("iso_27001")

  return (
    <div className="grid gap-4 md:grid-cols-2">
      {/* Generate export */}
      <Card>
        <CardHeader><CardTitle className="text-sm">Generate Compliance Export</CardTitle></CardHeader>
        <CardContent className="space-y-3">
          <select
            className="w-full rounded border bg-background px-3 py-1.5 text-sm"
            value={framework}
            onChange={(e) => setFramework(e.target.value)}
          >
            <option value="iso_27001">ISO 27001</option>
            <option value="soc2">SOC 2</option>
            <option value="hipaa">HIPAA</option>
            <option value="fedramp">FedRAMP</option>
          </select>
          <Button
            size="sm"
            onClick={() => generateExport.mutate({ framework })}
            disabled={generateExport.isPending}
          >
            <FileCheck size={14} className="mr-1" />
            {generateExport.isPending ? "Generating…" : "Generate Export"}
          </Button>
        </CardContent>
      </Card>

      {/* Exports list */}
      <Card className="md:col-span-2">
        <CardHeader><CardTitle className="text-sm">Generated Exports ({exportsData?.count ?? 0})</CardTitle></CardHeader>
        <CardContent>
          {exportsData?.exports && exportsData.exports.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead><tr className="border-b text-left text-muted-foreground">
                  <th className="pb-2">Framework</th>
                  <th className="pb-2">Generated</th>
                  <th className="pb-2">Chain Valid</th>
                  <th className="pb-2">Entries</th>
                  <th className="pb-2">Holds</th>
                </tr></thead>
                <tbody>
                  {exportsData.exports.map((ex: ComplianceExport) => (
                    <tr key={ex.export_id} className="border-b border-border/50">
                      <td className="py-1.5"><Badge variant="outline">{ex.framework}</Badge></td>
                      <td className="py-1.5 font-mono">{ex.generated_at}</td>
                      <td className="py-1.5">
                        {ex.chain_verification?.valid ? (
                          <CheckCircle2 size={14} className="text-green-400" />
                        ) : (
                          <XCircle size={14} className="text-red-400" />
                        )}
                      </td>
                      <td className="py-1.5">{ex.audit_entry_count}</td>
                      <td className="py-1.5">{ex.legal_holds?.length ?? 0}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No exports generated yet.</p>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
