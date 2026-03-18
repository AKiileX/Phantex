// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Rules page (enterprise detection management).
 *
 * Full CRUD rule management:
 *   - Create new rules with PRL expression editor
 *   - Inline editing of name, description, severity, PRL source
 *   - Enable/disable toggle per rule
 *   - Delete with confirmation (soft-delete on backend)
 *   - Severity left-stripe and status indicators
 *   - Global rules marked as read-only (cannot modify)
 *   - Summary stats in toolbar
 */

import { useState, useMemo } from "react"
import {
  ShieldAlert,
  Plus,
  X,
  Code2,
  Clock,
  ToggleLeft,
  ToggleRight,
  Pencil,
  Trash2,
  Save,
  Ban,
  Lock,
  AlertTriangle,
  Check,
  Search,
  HelpCircle,
} from "lucide-react"
import { useRules, useCreateRule, useToggleRule, useUpdateRule, useDeleteRule } from "@/api/rules"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { usePermissionStore } from "@/stores/permissionStore"
import { useToast } from "@/components/ui/toast"
import { formatDate } from "@/lib/utils"

/* ── Severity → card left-border color ───────────────────── */
const SEVERITY_BORDER: Record<string, string> = {
  critical: "border-l-severity-critical",
  high: "border-l-severity-high",
  medium: "border-l-severity-medium",
  low: "border-l-severity-low",
}

const SEVERITY_OPTIONS = ["critical", "high", "medium", "low", "info"] as const

export function RulesPage() {
  const { data, isLoading } = useRules()
  const createRule = useCreateRule()
  const toggleRule = useToggleRule()
  const updateRule = useUpdateRule()
  const deleteRule = useDeleteRule()
  const permissions = usePermissionStore((s) => s.permissions)
  const canEdit = permissions.has("rules.write")
  const { toast } = useToast()

  /* ── Create form state ─────────────────────────────────── */
  const [showCreate, setShowCreate] = useState(false)
  const [name, setName] = useState("")
  const [prlSource, setPrlSource] = useState("")
  const [severity, setSeverity] = useState("medium")
  const [description, setDescription] = useState("")

  /* ── Edit state ────────────────────────────────────────── */
  const [editingId, setEditingId] = useState<string | null>(null)
  const [editName, setEditName] = useState("")
  const [editDescription, setEditDescription] = useState("")
  const [editSeverity, setEditSeverity] = useState("")
  const [editPrl, setEditPrl] = useState("")

  /* ── Delete confirmation state ─────────────────────────── */
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null)

  /* ── Search ────────────────────────────────────────────── */
  const [searchQuery, setSearchQuery] = useState("")
  const [showGuide, setShowGuide] = useState(false)

  const rules = useMemo(() => data?.items ?? [], [data?.items])

  const filteredRules = useMemo(() => {
    if (!searchQuery) return rules
    const q = searchQuery.toLowerCase()
    return rules.filter(
      (r) =>
        r.name.toLowerCase().includes(q) ||
        r.severity.toLowerCase().includes(q) ||
        (r.description ?? "").toLowerCase().includes(q) ||
        (r.prl_source ?? "").toLowerCase().includes(q)
    )
  }, [rules, searchQuery])

  /* Summary stats */
  const stats = useMemo(() => {
    const enabled = rules.filter((r) => r.enabled).length
    const disabled = rules.length - enabled
    const bySeverity: Record<string, number> = {}
    for (const r of rules) {
      bySeverity[r.severity] = (bySeverity[r.severity] ?? 0) + 1
    }
    return { enabled, disabled, bySeverity }
  }, [rules])

  const handleCreate = () => {
    if (!name || !prlSource) return
    createRule.mutate(
      {
        name,
        prl_source: prlSource,
        severity,
        description: description || undefined,
      },
      {
        onSuccess: () => {
          toast({ title: "Rule created", variant: "success" })
          setShowCreate(false)
          setName("")
          setPrlSource("")
          setSeverity("medium")
          setDescription("")
        },
        onError: (err: Error & { response?: { data?: { detail?: string } } }) =>
          toast({
            title: "Failed to create rule",
            description: err?.response?.data?.detail || err.message,
            variant: "error",
          }),
      },
    )
  }

  const startEditing = (rule: (typeof rules)[0]) => {
    setEditingId(rule.id)
    setEditName(rule.name)
    setEditDescription(rule.description ?? "")
    setEditSeverity(rule.severity)
    setEditPrl(rule.prl_source ?? "")
    setDeleteConfirmId(null)
  }

  const cancelEditing = () => {
    setEditingId(null)
    setEditName("")
    setEditDescription("")
    setEditSeverity("")
    setEditPrl("")
  }

  const handleSaveEdit = () => {
    if (!editingId || !editName) return
    updateRule.mutate(
      {
        id: editingId,
        name: editName,
        description: editDescription || undefined,
        severity: editSeverity,
        prl_source: editPrl || undefined,
      },
      {
        onSuccess: () => {
          toast({ title: "Rule updated", variant: "success" })
          cancelEditing()
        },
        onError: (err: Error & { response?: { data?: { detail?: string } } }) =>
          toast({
            title: "Failed to update rule",
            description: err?.response?.data?.detail || err.message,
            variant: "error",
          }),
      },
    )
  }

  const handleDelete = (id: string) => {
    deleteRule.mutate(id, {
      onSuccess: () => {
        toast({ title: "Rule deleted", variant: "success" })
        setDeleteConfirmId(null)
        if (editingId === id) cancelEditing()
      },
      onError: (err: Error & { response?: { data?: { detail?: string } } }) =>
        toast({
          title: "Failed to delete rule",
          description: err?.response?.data?.detail || err.message,
          variant: "error",
        }),
    })
  }

  const isGlobalRule = (rule: (typeof rules)[0]) => !rule.tenant_id

  return (
    <div className="space-y-4 animate-fade-in">
      {/* Toolbar */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div>
            <h1 className="text-xl font-semibold text-foreground">Detection Rules</h1>
            <div className="flex items-center gap-3 mt-0.5">
              <p className="text-sm text-muted-foreground">
                {rules.length} PRL rules configured
              </p>
            {rules.length > 0 && (
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <span className="h-3 w-px bg-border" />
                <span className="flex items-center gap-1">
                  <span className="status-dot status-dot-active" />
                  {stats.enabled} active
                </span>
                {stats.disabled > 0 && (
                  <span className="flex items-center gap-1">
                    <span className="status-dot status-dot-terminated" />
                    {stats.disabled} disabled
                  </span>
                )}
              </div>
            )}
          </div>
        </div>
          <button onClick={() => setShowGuide(!showGuide)} className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"><HelpCircle size={14} />{showGuide ? "Hide Guide" : "How does this work?"}</button>
        </div>

        <div className="flex items-center gap-2">
          {/* Search */}
          <div className="relative">
            <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search rules…"
              className="pl-8 h-9 w-48 text-sm"
            />
          </div>

          {canEdit && (
            <Button
              variant={showCreate ? "outline" : "default"}
              size="sm"
              onClick={() => setShowCreate(!showCreate)}
              className="gap-1.5"
            >
              {showCreate ? (
                <><X size={14} /> Cancel</>
              ) : (
                <><Plus size={14} /> New Rule</>
              )}
            </Button>
          )}
        </div>
      </div>

      {/* Create form */}
      {showCreate && (
        <Card className="border-primary/20">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm">
              <Plus size={14} className="text-primary" />
              New Detection Rule
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid gap-3 md:grid-cols-2">
              <div className="space-y-1.5">
                <label className="text-sm font-medium text-muted-foreground uppercase tracking-wider">Name</label>
                <Input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g., High Tool Call Rate"
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-sm font-medium text-muted-foreground uppercase tracking-wider">Severity</label>
                <select
                  value={severity}
                  onChange={(e) => setSeverity(e.target.value)}
                  className="flex h-9 w-full rounded-md border border-border bg-surface-2 px-3 py-1.5 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-ring cursor-pointer"
                >
                  {SEVERITY_OPTIONS.map((s) => (
                    <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
                  ))}
                </select>
              </div>
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-muted-foreground uppercase tracking-wider">Description</label>
              <Input
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Optional description"
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
                <Code2 size={14} />
                PRL Expression
              </label>
              <textarea
                value={prlSource}
                onChange={(e) => setPrlSource(e.target.value)}
                placeholder='event.type == "tool_call" and count("tool_call", 300) > 50'
                rows={3}
                className="flex w-full rounded-md border border-border bg-surface-0 px-3 py-2 text-sm font-mono text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring"
              />
            </div>
            <div className="flex items-center gap-2 pt-1">
              <Button
                size="sm"
                onClick={handleCreate}
                disabled={createRule.isPending || !name || !prlSource}
              >
                {createRule.isPending ? "Creating…" : "Create Rule"}
              </Button>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setShowCreate(false)}
              >
                Cancel
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Rules list */}
      <div className="space-y-2">
        {isLoading ? (
          <div className="flex items-center justify-center py-16">
            <p className="text-sm text-muted-foreground">Loading rules…</p>
          </div>
        ) : filteredRules.length === 0 && searchQuery ? (
          <Card>
            <CardContent className="py-12 text-center">
              <div className="flex flex-col items-center gap-3">
                <Search size={22} className="text-muted-foreground" />
                <p className="text-sm text-muted-foreground">
                  No rules matching "{searchQuery}"
                </p>
              </div>
            </CardContent>
          </Card>
        ) : rules.length === 0 ? (
          <Card>
            <CardContent className="py-16 text-center">
              <div className="flex flex-col items-center gap-3">
                <div className="flex h-12 w-12 items-center justify-center rounded-full bg-surface-2">
                  <ShieldAlert size={22} className="text-muted-foreground" />
                </div>
                <div>
                  <p className="text-sm font-medium text-foreground">No detection rules defined</p>
                  <p className="text-sm text-muted-foreground mt-1">
                    Create a PRL rule to start generating alerts.
                  </p>
                </div>
                {canEdit && (
                  <Button size="sm" className="mt-2 gap-1.5" onClick={() => setShowCreate(true)}>
                    <Plus size={14} /> Create First Rule
                  </Button>
                )}
              </div>
            </CardContent>
          </Card>
        ) : (
          filteredRules.map((rule) => {
            const isEditing = editingId === rule.id
            const isGlobal = isGlobalRule(rule)
            const isDeleting = deleteConfirmId === rule.id

            return (
              <Card
                key={rule.id}
                className={`border-l-[3px] transition-all duration-150 ${
                  SEVERITY_BORDER[rule.severity] ?? "border-l-border"
                } ${
                  isEditing
                    ? "ring-1 ring-primary/40 bg-surface-1/50"
                    : rule.enabled
                      ? "hover:bg-surface-1 hover:border-border/80"
                      : "opacity-60 hover:opacity-80"
                }`}
              >
                <CardContent className="py-3 px-4">
                  {isEditing ? (
                    /* ── EDIT MODE ───────────────────────────────── */
                    <div className="space-y-3">
                      <div className="flex items-center gap-2 text-sm font-medium text-primary">
                        <Pencil size={14} />
                        Editing Rule
                      </div>

                      <div className="grid gap-3 md:grid-cols-2">
                        <div className="space-y-1.5">
                          <label className="text-sm font-medium text-muted-foreground">Name</label>
                          <Input
                            value={editName}
                            onChange={(e) => setEditName(e.target.value)}
                          />
                        </div>
                        <div className="space-y-1.5">
                          <label className="text-sm font-medium text-muted-foreground">Severity</label>
                          <select
                            value={editSeverity}
                            onChange={(e) => setEditSeverity(e.target.value)}
                            className="flex h-9 w-full rounded-md border border-border bg-surface-2 px-3 py-1.5 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-ring cursor-pointer"
                          >
                            {SEVERITY_OPTIONS.map((s) => (
                              <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
                            ))}
                          </select>
                        </div>
                      </div>

                      <div className="space-y-1.5">
                        <label className="text-sm font-medium text-muted-foreground">Description</label>
                        <Input
                          value={editDescription}
                          onChange={(e) => setEditDescription(e.target.value)}
                          placeholder="Rule description"
                        />
                      </div>

                      <div className="space-y-1.5">
                        <label className="text-sm font-medium text-muted-foreground flex items-center gap-1.5">
                          <Code2 size={14} />
                          PRL Expression
                        </label>
                        <textarea
                          value={editPrl}
                          onChange={(e) => setEditPrl(e.target.value)}
                          rows={3}
                          className="flex w-full rounded-md border border-border bg-surface-0 px-3 py-2 text-sm font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-ring"
                        />
                      </div>

                      <div className="flex items-center gap-2 pt-1">
                        <Button
                          size="sm"
                          onClick={handleSaveEdit}
                          disabled={updateRule.isPending || !editName}
                          className="gap-1.5"
                        >
                          <Save size={14} />
                          {updateRule.isPending ? "Saving…" : "Save Changes"}
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={cancelEditing}
                          className="gap-1.5"
                        >
                          <Ban size={14} />
                          Cancel
                        </Button>
                      </div>
                    </div>
                  ) : (
                    /* ── VIEW MODE ───────────────────────────────── */
                    <div className="flex items-start justify-between">
                      <div className="space-y-2 min-w-0 flex-1">
                        {/* Row 1: status dot + name + badges */}
                        <div className="flex items-center gap-2.5 flex-wrap">
                          <span
                            className={`status-dot ${rule.enabled ? "status-dot-active" : "status-dot-terminated"}`}
                            title={rule.enabled ? "Enabled" : "Disabled"}
                          />
                          <span className="text-sm font-semibold text-foreground">{rule.name}</span>
                          <Badge variant={rule.severity as "critical" | "high" | "medium" | "low"}>
                            {rule.severity}
                          </Badge>
                          {!rule.enabled && (
                            <Badge variant="secondary">Disabled</Badge>
                          )}
                          {isGlobal && (
                            <Badge variant="secondary" className="gap-1 text-xs">
                              <Lock size={10} />
                              Global
                            </Badge>
                          )}
                          {rule.version > 1 && (
                            <span className="text-xs text-muted-foreground font-mono">v{rule.version}</span>
                          )}
                        </div>

                        {/* Row 2: description */}
                        {rule.description && (
                          <p className="text-sm text-muted-foreground pl-[18px]">{rule.description}</p>
                        )}

                        {/* Row 3: PRL expression in code block */}
                        {rule.prl_source && (
                          <div className="ml-[18px] rounded border border-border bg-surface-0 px-3 py-2 font-mono text-sm text-muted-foreground overflow-x-auto">
                            <code>{rule.prl_source}</code>
                          </div>
                        )}

                        {/* Row 4: metadata */}
                        <div className="flex items-center gap-3 pl-[18px] text-sm text-muted-foreground flex-wrap">
                          <span className="flex items-center gap-1">
                            <Clock size={12} />
                            Updated {formatDate(rule.updated_at)}
                          </span>
                          {rule.author && (
                            <span className="text-xs text-muted-foreground/60">
                              by {rule.author}
                            </span>
                          )}
                        </div>
                      </div>

                      {/* Action buttons */}
                      {canEdit && (
                        <div className="flex items-center gap-1 ml-4 shrink-0">
                          {/* Edit button — disabled for global rules */}
                          <Button
                            variant="ghost"
                            size="sm"
                            className="gap-1.5 text-muted-foreground hover:text-foreground"
                            onClick={() => startEditing(rule)}
                            disabled={isGlobal}
                            title={isGlobal ? "Global rules are read-only" : "Edit rule"}
                          >
                            <Pencil size={14} />
                          </Button>

                          {/* Toggle */}
                          <Button
                            variant="ghost"
                            size="sm"
                            className="gap-1.5 text-muted-foreground hover:text-foreground"
                            onClick={() =>
                              toggleRule.mutate(
                                {
                                  id: rule.id,
                                  enabled: !rule.enabled,
                                },
                                {
                                  onSuccess: () =>
                                    toast({
                                      title: rule.enabled ? "Rule disabled" : "Rule enabled",
                                      variant: "success",
                                    }),
                                  onError: (err: Error & { response?: { data?: { detail?: string } } }) =>
                                    toast({
                                      title: "Failed to toggle rule",
                                      description: err?.response?.data?.detail || err.message,
                                      variant: "error",
                                    }),
                                },
                              )
                            }
                            disabled={toggleRule.isPending}
                          >
                            {rule.enabled ? (
                              <ToggleRight size={16} className="text-status-active" />
                            ) : (
                              <ToggleLeft size={16} />
                            )}
                          </Button>

                          {/* Delete — disabled for global rules */}
                          {isDeleting ? (
                            <div className="flex items-center gap-1 ml-1">
                              <span className="text-xs text-destructive font-medium">Delete?</span>
                              <Button
                                variant="ghost"
                                size="sm"
                                className="h-7 w-7 p-0 text-destructive hover:bg-destructive/10"
                                onClick={() => handleDelete(rule.id)}
                                disabled={deleteRule.isPending}
                              >
                                <Check size={14} />
                              </Button>
                              <Button
                                variant="ghost"
                                size="sm"
                                className="h-7 w-7 p-0 text-muted-foreground"
                                onClick={() => setDeleteConfirmId(null)}
                              >
                                <X size={14} />
                              </Button>
                            </div>
                          ) : (
                            <Button
                              variant="ghost"
                              size="sm"
                              className="gap-1.5 text-muted-foreground hover:text-destructive"
                              onClick={() => setDeleteConfirmId(rule.id)}
                              disabled={isGlobal}
                              title={isGlobal ? "Cannot delete global rules" : "Delete rule"}
                            >
                              <Trash2 size={14} />
                            </Button>
                          )}
                        </div>
                      )}
                    </div>
                  )}
                </CardContent>
              </Card>
            )
          })
        )}
      </div>

      {/* Info about global rules */}
      {rules.some(isGlobalRule) && canEdit && (
        <div className="flex items-start gap-2 rounded-lg border border-border/40 bg-surface-1/30 px-4 py-3">
          <AlertTriangle size={14} className="text-amber-400 mt-0.5 flex-shrink-0" />
          <p className="text-sm text-muted-foreground">
            Rules marked <Badge variant="secondary" className="gap-1 text-xs mx-1"><Lock size={9} /> Global</Badge>
            are shipped with Phantex and cannot be edited or deleted. You can only toggle them on/off.
            Create your own rules to customize detection for your environment.
          </p>
        </div>
      )}

      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5 space-y-3 text-sm text-muted-foreground">
          <h3 className="text-base font-semibold text-foreground">How do Detection Rules work?</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">PRL Language</p>
              <p>Rules are written in <strong>PRL (Phantex Rule Language)</strong> — a domain-specific language for matching event patterns. PRL expressions evaluate against each incoming event in the ClickHouse pipeline. When matched, an alert is generated with the rule's configured severity.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Backend API</p>
              <p>Full CRUD via <code className="text-xs bg-white/5 px-1 rounded">rules.py</code>: create, update, toggle enable/disable, and delete (soft). Rules are stored in PostgreSQL with RLS tenant isolation. Global rules ship with Phantex and are read-only — you can only toggle them.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Evaluation Pipeline</p>
              <p>Events from Kafka consumers are evaluated against all enabled rules. The rule engine checks PRL expressions in priority order. Matching events produce alerts stored in PostgreSQL and surfaced in the Alerts panel with enriched metadata.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Severity &amp; Status</p>
              <p>Each rule defines a severity (critical/high/medium/low). Active rules are continuously evaluated. Disabled rules are skipped. The toolbar shows a summary of enabled vs. disabled rules with live counts updated on each fetch.</p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
