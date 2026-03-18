// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Alert detail page (F4 — enterprise incident view).
 *
 * Horizontal property-sheet layout:
 *   Section 1: Header bar (title, severity badge, status badge, triage actions)
 *   Section 2: Two-column detail grid (metadata left, related resources right)
 *   Section 3: Response Actions (isolate, block, quarantine, etc.)
 *   Section 4: Description (if any)
 *   Section 5: ML Feedback (analyst verdict)
 *   Section 6: Context / Raw JSON (full width)
 *
 * Data source: GET /api/v1/alerts/{id} → Alert
 * Triage actions (Acknowledge / Resolve / False Positive) are role-gated:
 *   - admin & analyst can act; viewer sees read-only.
 *   - Only actionable for open or acknowledged statuses.
 */

import { useState, useCallback } from "react"
import { useParams, Link, useNavigate } from "react-router-dom"
import {
  ArrowLeft,
  Bell,
  Copy,
  Check,
  ExternalLink,
  ShieldAlert,
  Clock,
  User,
  Shield,
  Ban,
  FileWarning,
  Skull,
  UserX,
  HardDrive,
  ThumbsUp,
  ThumbsDown,
  HelpCircle,
  Wrench,
  Loader2,
  CheckCircle2,
} from "lucide-react"
import { useAlert, useUpdateAlertStatus, useExecuteResponseAction, useRecordFeedback } from "@/api/alerts"
import type { ResponseAction, AnalystVerdict } from "@/api/alerts"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { usePermissionStore } from "@/stores/permissionStore"
import { formatDate } from "@/lib/utils"
import type { AlertStatus } from "@/types"

/* ── Severity → accent color ─────────────────────────────── */
const SEVERITY_BORDER: Record<string, string> = {
  critical: "border-l-severity-critical",
  high: "border-l-severity-high",
  medium: "border-l-severity-medium",
  low: "border-l-severity-low",
}

/* ── Property row (compact horizontal key:value) ──────────── */
function Prop({
  label,
  children,
  mono,
}: {
  label: string
  children: React.ReactNode
  mono?: boolean
}) {
  return (
    <div className="grid grid-cols-[120px_1fr] gap-3 py-1.5 border-b border-border/30 last:border-0 items-start">
      <span className="text-xs font-medium text-muted-foreground tracking-wide uppercase shrink-0">
        {label}
      </span>
      <span
        className={`text-sm text-foreground break-all ${mono ? "font-mono text-xs" : ""}`}
      >
        {children}
      </span>
    </div>
  )
}

export function AlertDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { data: alert, isLoading } = useAlert(id ?? "")
  const updateStatus = useUpdateAlertStatus()
  const executeAction = useExecuteResponseAction()
  const recordFeedback = useRecordFeedback()
  const permissions = usePermissionStore((s) => s.permissions)
  const canAction = permissions.has("alerts.acknowledge")

  /* Copy-to-clipboard for context JSON */
  const [copied, setCopied] = useState(false)
  const [showGuide, setShowGuide] = useState(false)
  const copyContext = () => {
    if (!alert?.context) return
    navigator.clipboard.writeText(JSON.stringify(alert.context, null, 2))
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  /* Response action state */
  const [activeAction, setActiveAction] = useState<ResponseAction | null>(null)
  const [actionResult, setActionResult] = useState<{ action: string; message: string } | null>(null)

  /* ML Feedback state */
  const [feedbackSent, setFeedbackSent] = useState<AnalystVerdict | null>(null)

  const handleResponseAction = useCallback(async (action: ResponseAction) => {
    if (!alert) return
    setActiveAction(action)
    setActionResult(null)
    try {
      const result = await executeAction.mutateAsync({
        alertId: alert.id,
        action,
        parameters: {
          agent_id: alert.agent_id,
          // Extract IP from context if available
          ...(alert.context?.source_ip ? { ip: alert.context.source_ip } : {}),
          ...(alert.context?.dest_ip ? { ip: alert.context.dest_ip } : {}),
        },
        reason: "",
      })
      setActionResult({ action: result.action, message: result.message })
    } catch {
      setActionResult({ action, message: "Action failed — check backend logs." })
    } finally {
      setActiveAction(null)
    }
  }, [alert, executeAction])

  const handleFeedback = useCallback(async (verdict: AnalystVerdict) => {
    if (!alert) return
    try {
      await recordFeedback.mutateAsync({ alertId: alert.id, verdict })
      setFeedbackSent(verdict)
    } catch {
      // Silently fail — non-critical
    }
  }, [alert, recordFeedback])

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20 text-sm text-muted-foreground">
        Loading alert…
      </div>
    )
  }

  if (!alert) {
    return (
      <div className="flex flex-col items-center justify-center py-20 gap-2">
        <Bell size={28} className="text-surface-3" />
        <p className="text-sm text-muted-foreground">Alert not found</p>
      </div>
    )
  }

  const handleStatusChange = (newStatus: AlertStatus) => {
    updateStatus.mutate({ id: alert.id, status: newStatus })
  }

  const isActionable =
    alert.status === "open" || alert.status === "acknowledged"

  return (
    <div className="space-y-4 animate-fade-in">
      {/* ── Header bar ────────────────────────────────────── */}
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div className="flex items-center gap-3 min-w-0">
          <Link to="/alerts">
            <Button variant="ghost" size="sm" className="gap-1">
              <ArrowLeft size={14} /> Alerts
            </Button>
          </Link>
          <div className="h-4 w-px bg-border" />
          <h1 className="text-lg font-semibold text-foreground truncate">
            {alert.title}
          </h1>
          <Badge
            variant={alert.severity as "critical" | "high" | "medium" | "low"}
          >
            {alert.severity}
          </Badge>
          <Badge variant="outline" className="capitalize">
            {alert.status.replace("_", " ")}
          </Badge>
          <button onClick={() => setShowGuide(!showGuide)} className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"><HelpCircle size={14} />{showGuide ? "Hide Guide" : "How does this work?"}</button>
        </div>

        {/* Triage actions (inline in header for quick access) */}
        {canAction && isActionable && (
          <div className="flex items-center gap-2">
            {alert.status === "open" && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => handleStatusChange("acknowledged")}
                disabled={updateStatus.isPending}
              >
                Acknowledge
              </Button>
            )}
            <Button
              size="sm"
              onClick={() => handleStatusChange("resolved")}
              disabled={updateStatus.isPending}
            >
              Resolve
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => handleStatusChange("false_positive")}
              disabled={updateStatus.isPending}
            >
              False Positive
            </Button>
          </div>
        )}
        {!canAction && isActionable && (
          <span className="text-xs text-muted-foreground">
            Actions require <span className="font-medium">analyst</span> or{" "}
            <span className="font-medium">admin</span> role
          </span>
        )}
      </div>
      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5 space-y-3 text-sm text-muted-foreground">
          <h3 className="text-base font-semibold text-foreground">How does Alert Detail work?</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Alert Lookup</p>
              <p>Fetches via <code className="text-xs bg-white/5 px-1 rounded">GET /api/v1/alerts/{'{id}'}</code>. Each alert is generated when an event matches a PRL detection rule. Contains full context: triggering event, matched rule, agent info, and severity assessment.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Triage Actions</p>
              <p>Status transitions: <strong>open → acknowledged → resolved/false_positive</strong>. Uses <code className="text-xs bg-white/5 px-1 rounded">PATCH /api/v1/alerts/{'{id}'}/status</code>. Requires analyst or admin role. Each transition is audit-logged for compliance.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Response Actions</p>
              <p>Automated response actions (isolate agent, block IP, etc.) can be triggered from the detail view. Actions execute via the response engine and are recorded for the audit trail. Feedback (thumbs up/down) trains the ML model.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Context JSON</p>
              <p>The raw alert context contains the full event payload that triggered the detection, PRL rule metadata, and any enrichment data. Copy it for SOAR integration or incident response documentation.</p>
            </div>
          </div>
        </div>
      )}
      {/* ── Two-column detail grid ────────────────────────── */}
      <div className="grid gap-4 lg:grid-cols-2 items-start">
        {/* Left: Alert metadata */}
        <Card
          className={`border-l-[3px] ${SEVERITY_BORDER[alert.severity] ?? "border-l-border"}`}
        >
          <CardHeader className="pb-1">
            <CardTitle className="text-xs text-muted-foreground flex items-center gap-1.5">
              <ShieldAlert size={12} /> Alert Details
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-2">
            <Prop label="Alert ID" mono>
              <span className="select-all">{alert.id}</span>
            </Prop>
            <Prop label="Title">{alert.title}</Prop>
            <Prop label="Severity">
              <Badge
                variant={
                  alert.severity as "critical" | "high" | "medium" | "low"
                }
              >
                {alert.severity}
              </Badge>
            </Prop>
            <Prop label="Status">
              <Badge variant="outline" className="capitalize">
                {alert.status.replace("_", " ")}
              </Badge>
            </Prop>
            <Prop label="Created">
              <span className="flex items-center gap-1.5">
                <Clock size={11} className="text-muted-foreground" />
                {formatDate(alert.created_at)}
              </span>
            </Prop>
            <Prop label="Updated">{formatDate(alert.updated_at)}</Prop>
            {alert.resolved_at && (
              <Prop label="Resolved">{formatDate(alert.resolved_at)}</Prop>
            )}
            {alert.resolved_by && (
              <Prop label="Resolved By" mono>
                <span className="flex items-center gap-1.5 select-all">
                  <User size={11} className="text-muted-foreground" />
                  {alert.resolved_by}
                </span>
              </Prop>
            )}
          </CardContent>
        </Card>

        {/* Right: Related resources + tenant */}
        <Card>
          <CardHeader className="pb-1">
            <CardTitle className="text-xs text-muted-foreground flex items-center gap-1.5">
              <ExternalLink size={12} /> Related Resources
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-2">
            <Prop label="Agent" mono>
              {alert.agent_id ? (
                <button
                  onClick={() => navigate(`/agents/${alert.agent_id}`)}
                  className="text-primary hover:underline cursor-pointer select-all"
                >
                  {alert.agent_id}
                </button>
              ) : (
                <span className="text-muted-foreground">—</span>
              )}
            </Prop>
            <Prop label="Event" mono>
              {alert.event_id ? (
                <button
                  onClick={() => navigate(`/events/${alert.event_id}`)}
                  className="text-primary hover:underline cursor-pointer select-all"
                >
                  {alert.event_id}
                </button>
              ) : (
                <span className="text-muted-foreground">—</span>
              )}
            </Prop>
            <Prop label="Rule" mono>
              {alert.rule_id ? (
                <span className="select-all">{alert.rule_id}</span>
              ) : (
                <span className="text-muted-foreground">—</span>
              )}
            </Prop>
            <Prop label="Tenant" mono>
              <span className="select-all">{alert.tenant_id}</span>
            </Prop>
          </CardContent>
        </Card>
      </div>

      {/* ── Response Actions ──────────────────────────────── */}
      {canAction && isActionable && (
        <Card>
          <CardHeader className="pb-1">
            <CardTitle className="text-xs text-muted-foreground flex items-center gap-1.5">
              <Shield size={12} /> Response Actions
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-2">
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
              {([
                { action: "isolate_agent" as ResponseAction, icon: Shield, label: "Isolate Agent", desc: "Network isolation via EDR" },
                { action: "block_ip" as ResponseAction, icon: Ban, label: "Block IP", desc: "Firewall block rule" },
                { action: "quarantine_file" as ResponseAction, icon: FileWarning, label: "Quarantine File", desc: "Isolate suspicious file" },
                { action: "kill_process" as ResponseAction, icon: Skull, label: "Kill Process", desc: "Terminate process" },
                { action: "disable_user" as ResponseAction, icon: UserX, label: "Disable User", desc: "Lock user account" },
                { action: "collect_forensics" as ResponseAction, icon: HardDrive, label: "Collect Forensics", desc: "Trigger data collection" },
              ]).map(({ action, icon: Icon, label, desc }) => (
                <button
                  key={action}
                  onClick={() => handleResponseAction(action)}
                  disabled={activeAction !== null}
                  className="flex flex-col items-center gap-1.5 p-3 rounded-lg border border-border bg-surface-2 hover:bg-surface-3 hover:border-primary/40 transition-all text-center cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed group"
                >
                  {activeAction === action ? (
                    <Loader2 size={18} className="text-primary animate-spin" />
                  ) : (
                    <Icon size={18} className="text-muted-foreground group-hover:text-primary transition-colors" />
                  )}
                  <span className="text-xs font-medium text-foreground">{label}</span>
                  <span className="text-[10px] text-muted-foreground leading-tight">{desc}</span>
                </button>
              ))}
            </div>
            {actionResult && (
              <div className="mt-3 flex items-start gap-2 p-2.5 rounded-md border border-primary/30 bg-primary/5 text-xs text-foreground/80">
                <CheckCircle2 size={14} className="text-primary shrink-0 mt-0.5" />
                <div>
                  <span className="font-medium capitalize">{actionResult.action.replace("_", " ")}</span>
                  <span className="text-muted-foreground"> — {actionResult.message}</span>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* ── Description ───────────────────────────────────── */}
      {alert.description && (
        <Card>
          <CardHeader className="pb-1">
            <CardTitle className="text-xs text-muted-foreground">
              Description
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm leading-relaxed text-foreground/90 whitespace-pre-wrap">
              {alert.description}
            </p>
          </CardContent>
        </Card>
      )}

      {/* ── ML Feedback (Analyst Verdict) ─────────────────── */}
      {canAction && (
        <Card>
          <CardHeader className="pb-1">
            <CardTitle className="text-xs text-muted-foreground flex items-center gap-1.5">
              <ThumbsUp size={12} /> Analyst Verdict — ML Feedback
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-2">
            <p className="text-xs text-muted-foreground mb-3">
              Your verdict trains the ML pipeline. True positives reinforce detections; false positives tune thresholds.
            </p>
            {feedbackSent ? (
              <div className="flex items-center gap-2 p-2.5 rounded-md border border-status-active/30 bg-status-active/5 text-xs">
                <CheckCircle2 size={14} className="text-status-active" />
                <span className="text-foreground">
                  Verdict recorded: <span className="font-medium capitalize">{feedbackSent.replace("_", " ")}</span> — ML pipeline will incorporate this in the next training cycle.
                </span>
              </div>
            ) : (
              <div className="flex flex-wrap gap-2">
                {([
                  { verdict: "true_positive" as AnalystVerdict, icon: ThumbsUp, label: "True Positive", cls: "hover:border-severity-high/50 hover:bg-severity-high/5" },
                  { verdict: "false_positive" as AnalystVerdict, icon: ThumbsDown, label: "False Positive", cls: "hover:border-status-active/50 hover:bg-status-active/5" },
                  { verdict: "benign" as AnalystVerdict, icon: HelpCircle, label: "Benign", cls: "hover:border-primary/50 hover:bg-primary/5" },
                  { verdict: "needs_tuning" as AnalystVerdict, icon: Wrench, label: "Needs Tuning", cls: "hover:border-severity-medium/50 hover:bg-severity-medium/5" },
                ]).map(({ verdict, icon: Icon, label, cls }) => (
                  <Button
                    key={verdict}
                    variant="outline"
                    size="sm"
                    className={`gap-1.5 ${cls}`}
                    disabled={recordFeedback.isPending}
                    onClick={() => handleFeedback(verdict)}
                  >
                    <Icon size={13} />
                    {label}
                  </Button>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* ── Context / Raw JSON ────────────────────────────── */}
      <Card>
        <CardHeader className="pb-1 flex flex-row items-center justify-between">
          <CardTitle className="text-xs text-muted-foreground">
            Context
          </CardTitle>
          <button
            onClick={copyContext}
            className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors cursor-pointer"
          >
            {copied ? (
              <>
                <Check size={12} className="text-status-active" /> Copied
              </>
            ) : (
              <>
                <Copy size={12} /> Copy JSON
              </>
            )}
          </button>
        </CardHeader>
        <CardContent>
          <pre className="overflow-auto rounded-md border border-border bg-surface-2 p-3 text-xs font-mono text-foreground max-h-72">
            {JSON.stringify(alert.context, null, 2)}
          </pre>
        </CardContent>
      </Card>
    </div>
  )
}
