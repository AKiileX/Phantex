// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Maintenance Windows management page.
 *
 * CRUD table for maintenance windows with:
 *   - Filterable list with enable/disable toggles
 *   - Inline create form (cron, duration, rules, tags)
 *   - Active-window indicator with next-start display
 *   - Force-end button (admin only)
 *   - Delete confirmation
 *
 * @module pages/MaintenancePage
 */

import { useState, useCallback } from "react"
import {
  Calendar,
  Plus,
  Trash2,
  ToggleLeft,
  ToggleRight,
  StopCircle,
  Clock,
  HelpCircle,
} from "lucide-react"
import {
  useMaintenanceWindows,
  useCreateMaintenanceWindow,
  useUpdateMaintenanceWindow,
  useDeleteMaintenanceWindow,
  useForceEndMaintenanceWindow,
} from "@/api/maintenance"
import { usePermissionStore } from "@/stores/permissionStore"
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
import { formatDate, timeAgo } from "@/lib/utils"
import type { MaintenanceWindowCreate } from "@/types"

/* ── Helpers ───────────────────────────────────────────────────────────────── */

/** Validate a 5-field cron expression by splitting (avoids ReDoS). */
const CRON_FIELD_RE = /^[0-9*,/-]+$/
function isValidCron(cron: string): boolean {
  const fields = cron.trim().split(/\s+/)
  return fields.length === 5 && fields.every((f) => CRON_FIELD_RE.test(f))
}

function parseTagInput(raw: string): Record<string, string> {
  const tags: Record<string, string> = {}
  raw.split(",").forEach((pair) => {
    const [k, v] = pair.split("=").map((s) => s.trim())
    if (k && v) tags[k] = v
  })
  return tags
}

function isWindowActive(w: {
  last_started_at: string | null
  last_ended_at: string | null
  force_ended_by: string | null
}): boolean {
  if (!w.last_started_at) return false
  if (w.force_ended_by) return false
  if (w.last_ended_at && new Date(w.last_ended_at) > new Date(w.last_started_at))
    return false
  return true
}

/* ── Component ─────────────────────────────────────────────────────────────── */

export function MaintenancePage() {
  const permissions = usePermissionStore((s) => s.permissions)
  const isAdmin = permissions.has("auth.manage")

  const { data: windows, isLoading } = useMaintenanceWindows()
  const createWindow = useCreateMaintenanceWindow()
  const updateWindow = useUpdateMaintenanceWindow()
  const deleteWindow = useDeleteMaintenanceWindow()
  const forceEnd = useForceEndMaintenanceWindow()

  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({
    name: "",
    description: "",
    cron_schedule: "",
    duration_minutes: "60",
    rules: "",
    match_tags: "",
  })
  const [formError, setFormError] = useState<string | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null)
  const [search, setSearch] = useState("")
  const [showGuide, setShowGuide] = useState(false)

  const handleCreate = useCallback(() => {
    setFormError(null)
    const name = form.name.trim()
    const cron = form.cron_schedule.trim()
    const duration = parseInt(form.duration_minutes, 10)
    const rules = form.rules
      .split(",")
      .map((r) => r.trim())
      .filter(Boolean)
    const tags = form.match_tags.trim()
      ? parseTagInput(form.match_tags)
      : undefined

    if (!name || name.length > 256) {
      setFormError("Name required (max 256 chars)")
      return
    }
    if (cron.length > 128 || !isValidCron(cron)) {
      setFormError("Valid 5-field cron schedule required (max 128 chars)")
      return
    }
    if (isNaN(duration) || duration < 1 || duration > 1440) {
      setFormError("Duration must be 1-1440 minutes")
      return
    }
    if (rules.length === 0 || rules.length > 50) {
      setFormError("1-50 rule patterns required (comma-separated, * for all)")
      return
    }
    if (tags && Object.keys(tags).length > 20) {
      setFormError("Max 20 match tags")
      return
    }

    const body: MaintenanceWindowCreate = {
      name,
      cron_schedule: cron,
      duration_minutes: duration,
      rules,
    }
    if (form.description.trim()) {
      body.description = form.description.trim()
    }
    if (tags && Object.keys(tags).length > 0) {
      body.match_tags = tags
    }

    createWindow.mutate(body, {
      onSuccess: () => {
        setShowForm(false)
        setForm({
          name: "",
          description: "",
          cron_schedule: "",
          duration_minutes: "60",
          rules: "",
          match_tags: "",
        })
      },
      onError: (err) => setFormError(err.message),
    })
  }, [form, createWindow])

  const handleToggle = useCallback(
    (id: string, enabled: boolean) => {
      updateWindow.mutate({ id, body: { enabled: !enabled } })
    },
    [updateWindow],
  )

  const handleForceEnd = useCallback(
    (id: string) => {
      forceEnd.mutate(id)
    },
    [forceEnd],
  )

  const handleDelete = useCallback(
    (id: string) => {
      deleteWindow.mutate(id, {
        onSuccess: () => setDeleteTarget(null),
      })
    },
    [deleteWindow],
  )

  const filtered = (windows ?? []).filter(
    (w) =>
      !search ||
      w.name.toLowerCase().includes(search.toLowerCase()) ||
      w.cron_schedule.includes(search),
  )

  return (
    <div className="space-y-4 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Calendar size={18} className="text-muted-foreground" />
          <h1 className="text-xl font-semibold text-foreground">
            Maintenance Windows
          </h1>
          <Badge variant="secondary">{windows?.length ?? 0}</Badge>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => setShowGuide(!showGuide)} className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"><HelpCircle size={14} />{showGuide ? "Hide Guide" : "How does this work?"}</button>
          <Button
            size="sm"
            className="gap-1"
            onClick={() => setShowForm((v) => !v)}
          >
            <Plus size={14} /> New Window
          </Button>
        </div>
      </div>

      {/* Search */}
      <Input
        placeholder="Search by name or schedule…"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        className="max-w-sm"
      />

      {/* Create form */}
      {showForm && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Create Maintenance Window</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="grid gap-2 sm:grid-cols-2">
              <Input
                placeholder="Window name"
                value={form.name}
                onChange={(e) =>
                  setForm((f) => ({ ...f, name: e.target.value }))
                }
                maxLength={256}
                aria-label="Window name"
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
              <div>
                <Input
                  placeholder="Cron schedule (e.g. 0 2 * * 0)"
                  value={form.cron_schedule}
                  onChange={(e) =>
                    setForm((f) => ({ ...f, cron_schedule: e.target.value }))
                  }
                  maxLength={128}
                  aria-label="Cron schedule"
                />
                <span className="text-[10px] text-muted-foreground mt-0.5 block">
                  5-field cron: min hour day month weekday
                </span>
              </div>
              <div>
                <Input
                  type="number"
                  placeholder="Duration (minutes)"
                  value={form.duration_minutes}
                  onChange={(e) =>
                    setForm((f) => ({
                      ...f,
                      duration_minutes: e.target.value,
                    }))
                  }
                  min={1}
                  max={1440}
                  aria-label="Duration minutes"
                />
                <span className="text-[10px] text-muted-foreground mt-0.5 block">
                  1-1440 minutes
                </span>
              </div>
              <Input
                placeholder="Rules (rule1, rule2, or * for all)"
                value={form.rules}
                onChange={(e) =>
                  setForm((f) => ({ ...f, rules: e.target.value }))
                }
                maxLength={2048}
                aria-label="Rules"
              />
            </div>
            <Input
              placeholder="Match tags (optional — key=value, key2=value2)"
              value={form.match_tags}
              onChange={(e) =>
                setForm((f) => ({ ...f, match_tags: e.target.value }))
              }
              maxLength={2048}
              aria-label="Match tags"
            />
            {formError && (
              <p className="text-xs text-destructive" role="alert">
                {formError}
              </p>
            )}
            <div className="flex gap-2">
              <Button
                size="sm"
                onClick={handleCreate}
                disabled={createWindow.isPending}
              >
                {createWindow.isPending ? "Creating…" : "Create"}
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
              Loading maintenance windows…
            </div>
          ) : filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 gap-2">
              <Calendar size={24} className="text-surface-3" />
              <p className="text-sm text-muted-foreground">
                {search
                  ? "No matching maintenance windows"
                  : "No maintenance windows configured"}
              </p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Schedule</TableHead>
                  <TableHead>Duration</TableHead>
                  <TableHead>Rules</TableHead>
                  <TableHead>Next Start</TableHead>
                  <TableHead className="text-center">Active</TableHead>
                  <TableHead className="text-center">Status</TableHead>
                  <TableHead className="w-28" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map((w) => {
                  const active = isWindowActive(w)
                  return (
                    <TableRow key={w.id}>
                      <TableCell>
                        <div>
                          <span className="text-sm font-medium">
                            {w.name}
                          </span>
                          {w.description && (
                            <span className="block text-[10px] text-muted-foreground truncate max-w-48">
                              {w.description}
                            </span>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <span className="font-mono text-xs">
                          {w.cron_schedule}
                        </span>
                      </TableCell>
                      <TableCell>
                        <span className="tabular-nums text-xs">
                          {w.duration_minutes}m
                        </span>
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          {w.rules.slice(0, 3).map((r) => (
                            <Badge
                              key={r}
                              variant="secondary"
                              className="text-[10px] font-mono"
                            >
                              {r}
                            </Badge>
                          ))}
                          {w.rules.length > 3 && (
                            <Badge
                              variant="outline"
                              className="text-[10px]"
                            >
                              +{w.rules.length - 3}
                            </Badge>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        {w.next_start ? (
                          <div>
                            <span className="text-xs">
                              {formatDate(w.next_start)}
                            </span>
                            <span className="block text-[10px] text-muted-foreground">
                              {timeAgo(w.next_start)}
                            </span>
                          </div>
                        ) : (
                          <span className="text-xs text-muted-foreground">
                            —
                          </span>
                        )}
                      </TableCell>
                      <TableCell className="text-center">
                        {active ? (
                          <div className="flex items-center justify-center gap-1">
                            <Clock
                              size={14}
                              className="text-amber-400 animate-pulse"
                            />
                            <span className="text-xs text-amber-400 font-medium">
                              Active
                            </span>
                          </div>
                        ) : (
                          <span className="text-xs text-muted-foreground">
                            Idle
                          </span>
                        )}
                      </TableCell>
                      <TableCell className="text-center">
                        <button
                          type="button"
                          onClick={() => handleToggle(w.id, w.enabled)}
                          className="text-muted-foreground hover:text-foreground transition-colors"
                          aria-label={
                            w.enabled
                              ? `Disable window ${w.name}`
                              : `Enable window ${w.name}`
                          }
                        >
                          {w.enabled ? (
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
                        <div className="flex items-center gap-1">
                          {active && isAdmin && (
                            <Button
                              variant="destructive"
                              size="sm"
                              onClick={() => handleForceEnd(w.id)}
                              disabled={forceEnd.isPending}
                              className="h-6 text-[10px] px-2 gap-1"
                              aria-label={`Force end ${w.name}`}
                            >
                              <StopCircle size={10} /> End
                            </Button>
                          )}
                          {deleteTarget === w.id ? (
                            <div className="flex gap-1">
                              <Button
                                variant="destructive"
                                size="sm"
                                onClick={() => handleDelete(w.id)}
                                disabled={deleteWindow.isPending}
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
                              onClick={() => setDeleteTarget(w.id)}
                              aria-label={`Delete window ${w.name}`}
                            >
                              <Trash2 size={14} />
                            </Button>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5 space-y-3 text-sm text-muted-foreground">
          <h3 className="text-base font-semibold text-foreground">How do Maintenance Windows work?</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Window Scheduling</p>
              <p>Create windows via <code className="text-xs bg-white/5 px-1 rounded">/api/maintenance/windows</code>. Each window defines a cron schedule, duration in minutes, and scope (rules and agent tags). During active windows, matching alerts are suppressed to reduce false positives.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Cron Expressions</p>
              <p>Schedules use standard cron syntax (minute hour day month weekday). Example: "0 2 * * 0" = every Sunday at 2 AM. Duration controls how long the window stays active from its start time. Supports recurring and one-time windows.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Force End</p>
              <p>Active windows can be force-ended early if maintenance completes ahead of schedule. This immediately re-enables alert processing for the scoped rules and agents. Useful for cutting short planned outages.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Scoping</p>
              <p>Scope by rule names to suppress specific detections, or by agent tags to suppress all alerts for a group of agents. Combine both for precise maintenance coverage without global alert suppression.</p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
