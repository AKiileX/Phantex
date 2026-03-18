// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — PDR Export Schedule Manager (O9).
 *
 * Manages scheduled exports — list, create, toggle, run-now, delete.
 * Each schedule ties a cron expression to an export channel.
 *
 * @module components/exports/ScheduleManager
 */

import { useState, useCallback } from "react"
import {
  Plus,
  Trash2,
  ToggleLeft,
  ToggleRight,
  Play,
  Loader2,
  CheckCircle2,
  XCircle,
  Clock,
} from "lucide-react"
import {
  useExportSchedules,
  useCreateExportSchedule,
  useUpdateExportSchedule,
  useDeleteExportSchedule,
  useRunExportSchedule,
} from "@/api/schedules"
import { useExportChannels } from "@/api/exports"
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
import { formatDate } from "@/lib/utils"
import type { PDRScheduleCreate, PDRChannelResponse } from "@/types"

/* ── Create form ───────────────────────────────────────────────────────────── */

function ScheduleForm({
  channels,
  onSubmit,
  onCancel,
  isPending,
}: {
  channels: PDRChannelResponse[]
  onSubmit: (data: PDRScheduleCreate) => void
  onCancel: () => void
  isPending: boolean
}) {
  const [name, setName] = useState("")
  const [channelId, setChannelId] = useState(channels[0]?.id ?? "")
  const [cron, setCron] = useState("0 */6 * * *")
  const [lookback, setLookback] = useState("360")
  const [maxEvents, setMaxEvents] = useState("1000")

  const handleSubmit = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault()
      if (!name.trim() || !channelId || !cron.trim()) return
      onSubmit({
        name: name.trim(),
        channel_id: channelId,
        cron_schedule: cron.trim(),
        lookback_minutes: parseInt(lookback, 10) || 360,
        max_events: parseInt(maxEvents, 10) || 1000,
      })
    },
    [name, channelId, cron, lookback, maxEvents, onSubmit],
  )

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm">New Scheduled Export</CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          <div>
            <label htmlFor="sched-name" className="text-xs font-medium text-muted-foreground">
              Name
            </label>
            <Input
              id="sched-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Nightly S3 export"
              required
            />
          </div>

          <div>
            <label htmlFor="sched-channel" className="text-xs font-medium text-muted-foreground">
              Channel
            </label>
            <select
              id="sched-channel"
              value={channelId}
              onChange={(e) => setChannelId(e.target.value)}
              className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
              required
            >
              {channels.map((ch) => (
                <option key={ch.id} value={ch.id}>
                  {ch.name} ({ch.channel_type})
                </option>
              ))}
            </select>
          </div>

          <div>
            <label htmlFor="sched-cron" className="text-xs font-medium text-muted-foreground">
              Cron Schedule
            </label>
            <Input
              id="sched-cron"
              value={cron}
              onChange={(e) => setCron(e.target.value)}
              placeholder="0 */6 * * *"
              required
            />
            <p className="mt-0.5 text-[10px] text-muted-foreground">5-field cron expression</p>
          </div>

          <div>
            <label htmlFor="sched-lookback" className="text-xs font-medium text-muted-foreground">
              Lookback (minutes)
            </label>
            <Input
              id="sched-lookback"
              type="number"
              min={1}
              max={10080}
              value={lookback}
              onChange={(e) => setLookback(e.target.value)}
            />
          </div>

          <div>
            <label htmlFor="sched-max" className="text-xs font-medium text-muted-foreground">
              Max Events
            </label>
            <Input
              id="sched-max"
              type="number"
              min={1}
              max={10000}
              value={maxEvents}
              onChange={(e) => setMaxEvents(e.target.value)}
            />
          </div>

          <div className="flex items-end gap-2">
            <Button type="submit" size="sm" disabled={isPending}>
              {isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin mr-1" /> : null}
              Create
            </Button>
            <Button type="button" variant="ghost" size="sm" onClick={onCancel}>
              Cancel
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  )
}

/* ── Last-run status badge ─────────────────────────────────────────────────── */

function RunStatusBadge({ status }: { status: string | null }) {
  if (!status) return <span className="text-xs text-muted-foreground">—</span>
  const variant = status === "ok" ? "active" : status === "error" ? "critical" : "secondary"
  return <Badge variant={variant}>{status}</Badge>
}

/* ── Main component ────────────────────────────────────────────────────────── */

export function ScheduleManager() {
  const { data, isLoading, error } = useExportSchedules()
  const { data: channelData } = useExportChannels()
  const createMutation = useCreateExportSchedule()
  const updateMutation = useUpdateExportSchedule()
  const deleteMutation = useDeleteExportSchedule()
  const runMutation = useRunExportSchedule()

  const [showForm, setShowForm] = useState(false)
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null)
  const [runResults, setRunResults] = useState<
    Record<string, { success: boolean; message?: string }>
  >({})

  const schedules = data?.schedules ?? []
  const channels = channelData?.channels ?? []
  const channelMap = Object.fromEntries(channels.map((c) => [c.id, c]))

  /* ── Handlers ──────────────────────────────────────────────────────────── */

  const handleCreate = useCallback(
    (payload: PDRScheduleCreate) => {
      createMutation.mutate(payload, {
        onSuccess: () => setShowForm(false),
      })
    },
    [createMutation],
  )

  const handleToggle = useCallback(
    (id: string, currentEnabled: boolean) => {
      updateMutation.mutate({ id, body: { enabled: !currentEnabled } })
    },
    [updateMutation],
  )

  const handleDelete = useCallback(
    (id: string) => {
      if (deleteConfirm === id) {
        deleteMutation.mutate(id, {
          onSuccess: () => setDeleteConfirm(null),
        })
      } else {
        setDeleteConfirm(id)
      }
    },
    [deleteConfirm, deleteMutation],
  )

  const handleRunNow = useCallback(
    (id: string) => {
      setRunResults((prev) => ({ ...prev, [id]: { success: true, message: "Running…" } }))
      runMutation.mutate(id, {
        onSuccess: (result) => {
          setRunResults((prev) => ({
            ...prev,
            [id]: {
              success: true,
              message: `Exported ${result.events_exported} events`,
            },
          }))
        },
        onError: (err) => {
          setRunResults((prev) => ({
            ...prev,
            [id]: { success: false, message: err.message || "Run failed" },
          }))
        },
      })
    },
    [runMutation],
  )

  /* ── Loading / Error ───────────────────────────────────────────────────── */

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="h-5 w-5 animate-spin rounded-full border-2 border-primary/20 border-t-primary" />
      </div>
    )
  }

  if (error) {
    return (
      <p className="text-sm text-destructive" role="alert">
        Failed to load export schedules.
      </p>
    )
  }

  /* ── Render ────────────────────────────────────────────────────────────── */

  return (
    <div className="flex flex-col gap-4">
      {/* Header bar */}
      <div className="flex items-center justify-between">
        <p className="text-xs text-muted-foreground">
          Cron-based scheduled exports through configured channels
        </p>
        {!showForm && channels.length > 0 && (
          <Button size="sm" onClick={() => setShowForm(true)} className="gap-1.5">
            <Plus className="h-3.5 w-3.5" />
            Add Schedule
          </Button>
        )}
      </div>

      {channels.length === 0 && (
        <p className="text-sm text-muted-foreground text-center py-6">
          Create an export channel first before adding schedules.
        </p>
      )}

      {/* Create form */}
      {showForm && (
        <ScheduleForm
          channels={channels}
          onSubmit={handleCreate}
          onCancel={() => setShowForm(false)}
          isPending={createMutation.isPending}
        />
      )}

      {/* Schedules table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm">
            Schedules ({schedules.length})
          </CardTitle>
        </CardHeader>
        <CardContent>
          {schedules.length === 0 ? (
            <p className="text-sm text-muted-foreground py-8 text-center">
              No scheduled exports configured.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Channel</TableHead>
                  <TableHead>Cron</TableHead>
                  <TableHead>Lookback</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Next Run</TableHead>
                  <TableHead>Last Run</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {schedules.map((s) => {
                  const ch = channelMap[s.channel_id]
                  const runResult = runResults[s.id]
                  return (
                    <TableRow key={s.id}>
                      <TableCell className="font-medium">{s.name}</TableCell>
                      <TableCell>
                        <span className="text-xs">
                          {ch?.name ?? s.channel_id.slice(0, 8)}
                        </span>
                      </TableCell>
                      <TableCell>
                        <code className="rounded bg-muted px-1.5 py-0.5 text-[11px]">
                          {s.cron_schedule}
                        </code>
                      </TableCell>
                      <TableCell className="text-xs">
                        {s.lookback_minutes}m
                      </TableCell>
                      <TableCell>
                        {s.enabled ? (
                          <Badge variant="active">Active</Badge>
                        ) : (
                          <Badge variant="terminated">Disabled</Badge>
                        )}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {s.next_run_at ? (
                          <span className="flex items-center gap-1">
                            <Clock className="h-3 w-3" />
                            {formatDate(s.next_run_at)}
                          </span>
                        ) : (
                          "—"
                        )}
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-col gap-0.5">
                          <RunStatusBadge status={s.last_run_status} />
                          {s.last_run_at && (
                            <span className="text-[10px] text-muted-foreground">
                              {formatDate(s.last_run_at)}
                            </span>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center justify-end gap-1">
                          {/* Run now */}
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => handleRunNow(s.id)}
                            disabled={runMutation.isPending}
                            aria-label={`Run ${s.name} now`}
                            title="Run now"
                          >
                            {runResult?.message === "Running…" ? (
                              <Loader2 className="h-3.5 w-3.5 animate-spin" />
                            ) : runResult?.success === true && runResult.message !== "Running…" ? (
                              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                            ) : runResult?.success === false ? (
                              <XCircle className="h-3.5 w-3.5 text-destructive" />
                            ) : (
                              <Play className="h-3.5 w-3.5" />
                            )}
                          </Button>

                          {/* Toggle */}
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => handleToggle(s.id, s.enabled)}
                            aria-label={s.enabled ? `Disable ${s.name}` : `Enable ${s.name}`}
                            title={s.enabled ? "Disable" : "Enable"}
                          >
                            {s.enabled ? (
                              <ToggleRight className="h-3.5 w-3.5 text-emerald-400" />
                            ) : (
                              <ToggleLeft className="h-3.5 w-3.5 text-muted-foreground" />
                            )}
                          </Button>

                          {/* Delete */}
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => handleDelete(s.id)}
                            aria-label={
                              deleteConfirm === s.id
                                ? `Confirm delete ${s.name}`
                                : `Delete ${s.name}`
                            }
                            title={deleteConfirm === s.id ? "Click again to confirm" : "Delete"}
                            className={
                              deleteConfirm === s.id
                                ? "text-destructive hover:text-destructive"
                                : ""
                            }
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </div>

                        {/* Run result message */}
                        {runResult && runResult.message !== "Running…" && (
                          <p
                            className={`text-[10px] mt-1 text-right ${
                              runResult.success
                                ? "text-emerald-400"
                                : "text-destructive"
                            }`}
                          >
                            {runResult.message}
                          </p>
                        )}
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
