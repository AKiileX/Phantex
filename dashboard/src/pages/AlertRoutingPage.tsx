// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Alert Routing management page.
 *
 * CRUD table for alert routing rules with:
 *   - Filterable list with enable/disable toggles
 *   - Inline create form for tag/severity matching + channels
 *   - Priority ordering display
 *   - Routing simulation panel
 *   - Delete confirmation
 *
 * @module pages/AlertRoutingPage
 */

import { useState, useCallback } from "react"
import {
  Route,
  Plus,
  Trash2,
  ToggleLeft,
  ToggleRight,
  Zap,
  ChevronUp,
  HelpCircle,
} from "lucide-react"
import {
  useRoutingRules,
  useCreateRoutingRule,
  useUpdateRoutingRule,
  useDeleteRoutingRule,
  useSimulateRouting,
} from "@/api/routing"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table"
import type {
  RoutingRuleCreate,
  RoutingSeverity,
  RoutingSimulationResult,
} from "@/types"

/* ── Helpers ───────────────────────────────────────────────────────────────── */

const SEVERITIES: RoutingSeverity[] = [
  "info",
  "low",
  "medium",
  "high",
  "critical",
]

function parseTagInput(raw: string): Record<string, string> {
  const tags: Record<string, string> = {}
  raw.split(",").forEach((pair) => {
    const [k, v] = pair.split("=").map((s) => s.trim())
    if (k && v) tags[k] = v
  })
  return tags
}

/* ── Component ─────────────────────────────────────────────────────────────── */

export function AlertRoutingPage() {
  const { data: rules, isLoading } = useRoutingRules()
  const createRule = useCreateRoutingRule()
  const updateRule = useUpdateRoutingRule()
  const deleteRule = useDeleteRoutingRule()
  const simulate = useSimulateRouting()

  // Create form
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({
    name: "",
    description: "",
    match_tags: "",
    severity_min: "medium" as RoutingSeverity,
    channels: "",
    priority: "100",
  })
  const [formError, setFormError] = useState<string | null>(null)

  // Simulate panel
  const [showSim, setShowSim] = useState(false)
  const [simForm, setSimForm] = useState({
    severity: "high" as RoutingSeverity,
    agent_tags: "",
    rule_name: "",
  })
  const [simResult, setSimResult] = useState<RoutingSimulationResult | null>(
    null,
  )

  const [deleteTarget, setDeleteTarget] = useState<string | null>(null)
  const [search, setSearch] = useState("")
  const [showGuide, setShowGuide] = useState(false)

  const handleCreate = useCallback(() => {
    setFormError(null)
    const name = form.name.trim()
    const tags = parseTagInput(form.match_tags)
    const channels = form.channels
      .split(",")
      .map((c) => c.trim())
      .filter(Boolean)
    const priority = parseInt(form.priority, 10)

    if (!name || name.length > 256) {
      setFormError("Name required (max 256 chars)")
      return
    }
    if (Object.keys(tags).length > 20) {
      setFormError("Max 20 match tags")
      return
    }
    if (channels.length === 0 || channels.length > 20) {
      setFormError("1-20 channels required (comma-separated)")
      return
    }
    if (isNaN(priority) || priority < 0 || priority > 1000) {
      setFormError("Priority must be 0-1000")
      return
    }

    const body: RoutingRuleCreate = {
      name,
      match_tags: tags,
      severity_min: form.severity_min,
      channels,
      priority,
    }
    if (form.description.trim()) {
      body.description = form.description.trim()
    }

    createRule.mutate(body, {
      onSuccess: () => {
        setShowForm(false)
        setForm({
          name: "",
          description: "",
          match_tags: "",
          severity_min: "medium",
          channels: "",
          priority: "100",
        })
      },
      onError: (err) => setFormError(err.message),
    })
  }, [form, createRule])

  const handleToggle = useCallback(
    (id: string, enabled: boolean) => {
      updateRule.mutate({ id, body: { enabled: !enabled } })
    },
    [updateRule],
  )

  const handleDelete = useCallback(
    (id: string) => {
      deleteRule.mutate(id, {
        onSuccess: () => setDeleteTarget(null),
      })
    },
    [deleteRule],
  )

  const handleSimulate = useCallback(() => {
    const tags = parseTagInput(simForm.agent_tags)
    simulate.mutate(
      {
        severity: simForm.severity,
        agent_tags: tags,
        rule_name: simForm.rule_name.trim() || undefined,
      },
      {
        onSuccess: (data) => setSimResult(data),
      },
    )
  }, [simForm, simulate])

  const sorted = [...(rules ?? [])]
    .filter(
      (r) =>
        !search ||
        r.name.toLowerCase().includes(search.toLowerCase()) ||
        r.channels.some((c) => c.toLowerCase().includes(search.toLowerCase())),
    )
    .sort((a, b) => b.priority - a.priority)

  return (
    <div className="space-y-4 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Route size={18} className="text-muted-foreground" />
          <h1 className="text-xl font-semibold text-foreground">
            Alert Routing
          </h1>
          <Badge variant="secondary">{rules?.length ?? 0}</Badge>
        </div>
        <div className="flex gap-2">
          <button onClick={() => setShowGuide(!showGuide)} className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"><HelpCircle size={14} />{showGuide ? "Hide Guide" : "How does this work?"}</button>
          <Button
            variant="outline"
            size="sm"
            className="gap-1"
            onClick={() => setShowSim((v) => !v)}
          >
            <Zap size={14} /> Simulate
          </Button>
          <Button
            size="sm"
            className="gap-1"
            onClick={() => setShowForm((v) => !v)}
          >
            <Plus size={14} /> New Rule
          </Button>
        </div>
      </div>

      {/* Search */}
      <Input
        placeholder="Search by name or channel…"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        className="max-w-sm"
      />

      {/* Simulate panel */}
      {showSim && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Zap size={14} /> Routing Simulation
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="grid gap-2 sm:grid-cols-3">
              <div>
                <label className="text-xs text-muted-foreground block mb-1">
                  Severity
                </label>
                <select
                  value={simForm.severity}
                  onChange={(e) =>
                    setSimForm((f) => ({
                      ...f,
                      severity: e.target.value as RoutingSeverity,
                    }))
                  }
                  className="flex h-9 w-full rounded-md border border-border bg-surface-2 px-3 py-1.5 text-sm text-foreground"
                  aria-label="Simulation severity"
                >
                  {SEVERITIES.map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </select>
              </div>
              <Input
                placeholder="Agent tags (env=prod, team=ml)"
                value={simForm.agent_tags}
                onChange={(e) =>
                  setSimForm((f) => ({ ...f, agent_tags: e.target.value }))
                }
                aria-label="Simulation agent tags"
              />
              <Input
                placeholder="Rule name (optional)"
                value={simForm.rule_name}
                onChange={(e) =>
                  setSimForm((f) => ({ ...f, rule_name: e.target.value }))
                }
                aria-label="Simulation rule name"
              />
            </div>
            <Button
              size="sm"
              onClick={handleSimulate}
              disabled={simulate.isPending}
            >
              {simulate.isPending ? "Simulating…" : "Run Simulation"}
            </Button>

            {simResult && (
              <div className="mt-2 rounded border border-border bg-surface-2 p-3 space-y-2">
                <div className="flex items-center gap-2">
                  <span className="text-xs text-muted-foreground">
                    Matched Rules:
                  </span>
                  <span className="text-sm font-medium">
                    {simResult.matched_rules.length}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-muted-foreground">
                    Channels:
                  </span>
                  <div className="flex gap-1">
                    {simResult.channels.map((ch) => (
                      <Badge key={ch} variant="default" className="text-[10px]">
                        {ch}
                      </Badge>
                    ))}
                    {simResult.channels.length === 0 && (
                      <span className="text-xs text-muted-foreground">
                        None
                      </span>
                    )}
                  </div>
                </div>
                {simResult.would_be_exempted && (
                  <div className="flex items-center gap-2 text-amber-400">
                    <span className="text-xs font-medium">
                      Would be exempted
                    </span>
                    {simResult.exemption_reason && (
                      <span className="text-xs text-muted-foreground">
                        — {simResult.exemption_reason}
                      </span>
                    )}
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Create form */}
      {showForm && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Create Routing Rule</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="grid gap-2 sm:grid-cols-2">
              <Input
                placeholder="Rule name"
                value={form.name}
                onChange={(e) =>
                  setForm((f) => ({ ...f, name: e.target.value }))
                }
                maxLength={256}
                aria-label="Routing rule name"
              />
              <Input
                placeholder="Description (optional)"
                value={form.description}
                onChange={(e) =>
                  setForm((f) => ({ ...f, description: e.target.value }))
                }
                maxLength={2048}
                aria-label="Description"
              />
            </div>
            <div className="grid gap-2 sm:grid-cols-3">
              <Input
                placeholder="Match tags (key=value, …)"
                value={form.match_tags}
                onChange={(e) =>
                  setForm((f) => ({ ...f, match_tags: e.target.value }))
                }
                maxLength={2048}
                aria-label="Match tags"
              />
              <div>
                <select
                  value={form.severity_min}
                  onChange={(e) =>
                    setForm((f) => ({
                      ...f,
                      severity_min: e.target.value as RoutingSeverity,
                    }))
                  }
                  className="flex h-9 w-full rounded-md border border-border bg-surface-2 px-3 py-1.5 text-sm text-foreground"
                  aria-label="Minimum severity"
                >
                  {SEVERITIES.map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </select>
              </div>
              <Input
                placeholder="Channels (slack, email, …)"
                value={form.channels}
                onChange={(e) =>
                  setForm((f) => ({ ...f, channels: e.target.value }))
                }
                maxLength={2048}
                aria-label="Channels"
              />
            </div>
            <div className="flex items-center gap-2">
              <Input
                type="number"
                placeholder="Priority (0-1000)"
                value={form.priority}
                onChange={(e) =>
                  setForm((f) => ({ ...f, priority: e.target.value }))
                }
                className="max-w-32"
                min={0}
                max={1000}
                aria-label="Priority"
              />
              <span className="text-xs text-muted-foreground">
                Higher = evaluated first
              </span>
            </div>
            {formError && (
              <p className="text-xs text-destructive" role="alert">
                {formError}
              </p>
            )}
            <div className="flex gap-2">
              <Button
                size="sm"
                onClick={handleCreate}
                disabled={createRule.isPending}
              >
                {createRule.isPending ? "Creating…" : "Create"}
              </Button>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setShowForm(false)}
              >
                Cancel
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Table */}
      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="flex items-center justify-center py-12 text-sm text-muted-foreground">
              Loading routing rules…
            </div>
          ) : sorted.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 gap-2">
              <Route size={24} className="text-surface-3" />
              <p className="text-sm text-muted-foreground">
                {search
                  ? "No matching routing rules"
                  : "No routing rules configured"}
              </p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-12 text-center">
                    <span title="Priority">
                      <ChevronUp size={12} className="inline" />
                    </span>
                  </TableHead>
                  <TableHead>Name</TableHead>
                  <TableHead>Match Tags</TableHead>
                  <TableHead>Min Severity</TableHead>
                  <TableHead>Channels</TableHead>
                  <TableHead className="text-center">Status</TableHead>
                  <TableHead className="w-20" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {sorted.map((rule) => (
                  <TableRow key={rule.id}>
                    <TableCell className="text-center">
                      <span className="tabular-nums text-xs font-mono text-muted-foreground">
                        {rule.priority}
                      </span>
                    </TableCell>
                    <TableCell>
                      <div>
                        <span className="text-sm font-medium">
                          {rule.name}
                        </span>
                        {rule.description && (
                          <span className="block text-[10px] text-muted-foreground truncate max-w-48">
                            {rule.description}
                          </span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {Object.entries(rule.match_tags).map(([k, v]) => (
                          <Badge
                            key={k}
                            variant="secondary"
                            className="text-[10px] font-mono"
                          >
                            {k}={v}
                          </Badge>
                        ))}
                        {Object.keys(rule.match_tags).length === 0 && (
                          <span className="text-xs text-muted-foreground">
                            Any
                          </span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={
                          rule.severity_min as
                            | "critical"
                            | "high"
                            | "medium"
                            | "low"
                            | "info"
                        }
                      >
                        {rule.severity_min}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {rule.channels.map((ch) => (
                          <Badge
                            key={ch}
                            variant="outline"
                            className="text-[10px]"
                          >
                            {ch}
                          </Badge>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell className="text-center">
                      <button
                        type="button"
                        onClick={() => handleToggle(rule.id, rule.enabled)}
                        className="text-muted-foreground hover:text-foreground transition-colors"
                        aria-label={
                          rule.enabled
                            ? `Disable rule ${rule.name}`
                            : `Enable rule ${rule.name}`
                        }
                      >
                        {rule.enabled ? (
                          <ToggleRight
                            size={20}
                            className="text-status-active"
                          />
                        ) : (
                          <ToggleLeft size={20} />
                        )}
                      </button>
                    </TableCell>
                    <TableCell>
                      {deleteTarget === rule.id ? (
                        <div className="flex gap-1">
                          <Button
                            variant="destructive"
                            size="sm"
                            onClick={() => handleDelete(rule.id)}
                            disabled={deleteRule.isPending}
                            className="h-6 text-[10px] px-2"
                          >
                            Confirm
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setDeleteTarget(null)}
                            className="h-6 text-[10px] px-2"
                          >
                            Cancel
                          </Button>
                        </div>
                      ) : (
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => setDeleteTarget(rule.id)}
                          aria-label={`Delete rule ${rule.name}`}
                        >
                          <Trash2 size={14} />
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5 space-y-3 text-sm text-muted-foreground">
          <h3 className="text-base font-semibold text-foreground">How does Alert Routing work?</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Routing Rules</p>
              <p>Managed via <code className="text-xs bg-white/5 px-1 rounded">/api/alert-routing/rules</code>. Each rule matches alerts by severity threshold, agent tags, and rule names, then routes to configured channels (Slack, email, webhook, PagerDuty). Priority determines evaluation order.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Simulation</p>
              <p>Test routing without generating real alerts using <code className="text-xs bg-white/5 px-1 rounded">/api/alert-routing/simulate</code>. Enter severity, agent tags, and rule name to see which routing rules would match and which channels would receive the alert.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Channel Configuration</p>
              <p>Channels are comma-separated in each rule (e.g., "slack-soc,pagerduty-oncall"). Multiple rules can fire for the same alert if their conditions overlap. Use priority ordering to control notification escalation.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Lifecycle</p>
              <p>Toggle rules on/off for quick suppression. Delete removes the rule permanently. All routing changes are audit-logged. Rules with severity_min filter ensure only high-priority alerts wake up on-call teams.</p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
