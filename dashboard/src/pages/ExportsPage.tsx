// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — OCSF/PDR Export Channels & Schedules Page (O9).
 *
 * Admin-only page with two tabs:
 *   - Channels: CRUD for export destinations (S3, Webhook, Kafka)
 *   - Schedules: cron-based scheduled exports through channels
 *
 * @module pages/ExportsPage
 */

import { useState, useCallback } from "react"
import {
  Upload,
  Plus,
  Trash2,
  ToggleLeft,
  ToggleRight,
  Zap,
  CheckCircle2,
  XCircle,
  Loader2,
  Calendar,
  HelpCircle,
} from "lucide-react"
import {
  useExportChannels,
  useCreateExportChannel,
  useUpdateExportChannel,
  useDeleteExportChannel,
  useTestExportChannel,
} from "@/api/exports"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table"
import { ChannelForm } from "@/components/exports/ChannelForm"
import { ChannelStatus } from "@/components/exports/ChannelStatus"
import { ScheduleManager } from "@/components/exports/ScheduleManager"
import { cn, formatDate } from "@/lib/utils"
import type { PDRChannelCreate, PDRChannelType } from "@/types"

/* ── Type labels + badges ──────────────────────────────────────────────────── */

const typeLabel: Record<PDRChannelType, string> = {
  s3: "S3",
  webhook: "Webhook",
  kafka_mirror: "Kafka",
}

const typeBadgeVariant: Record<PDRChannelType, "default" | "info" | "medium"> = {
  s3: "default",
  webhook: "info",
  kafka_mirror: "medium",
}

/* ── Masked config display ─────────────────────────────────────────────────── */

function ConfigSummary({ config, type }: { config: Record<string, unknown>; type: PDRChannelType }) {
  // Show only the primary identifier field
  const primaryKeys: Record<PDRChannelType, string> = {
    s3: "s3_bucket",
    webhook: "webhook_url",
    kafka_mirror: "kafka_bootstrap",
  }
  const primaryKey = primaryKeys[type]
  const primaryValue = config[primaryKey]

  if (!primaryValue || primaryValue === "***") {
    return <span className="text-muted-foreground italic">Configured</span>
  }

  return (
    <span className="font-mono text-[11px] text-foreground/70 truncate max-w-[200px] inline-block">
      {String(primaryValue)}
    </span>
  )
}

/* ── Page ───────────────────────────────────────────────────────────────────── */

const TABS = [
  { key: "channels", label: "Channels", icon: <Upload className="h-3.5 w-3.5" /> },
  { key: "schedules", label: "Schedules", icon: <Calendar className="h-3.5 w-3.5" /> },
] as const

type TabKey = (typeof TABS)[number]["key"]

export default function ExportsPage() {
  const [tab, setTab] = useState<TabKey>("channels")
  const [showGuide, setShowGuide] = useState(false)

  return (
    <div className="flex flex-col gap-6 p-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div className="flex items-center gap-3">
          <Upload className="h-5 w-5 text-primary/70" />
          <div>
            <h1 className="text-lg font-semibold">Export Channels & Schedules</h1>
            <p className="text-xs text-muted-foreground">
              Configure OCSF/PDR data export destinations and automated schedules
            </p>
          </div>
        </div>
        <button
          onClick={() => setShowGuide(!showGuide)}
          className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"
        >
          <HelpCircle size={14} />
          {showGuide ? "Hide Guide" : "How does this work?"}
        </button>
      </div>

      {showGuide && (
        <div className="space-y-4">
          <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
            <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
              <Upload size={16} className="text-primary" />
              What are Export Channels?
            </h3>
            <p className="mt-1.5 text-xs text-muted-foreground leading-relaxed">
              <strong className="text-foreground">Export Channels</strong> let you automatically send Phantex security events in <strong className="text-foreground">OCSF/PDR format</strong> to external destinations — S3 buckets, Kafka topics, or webhook endpoints. Combined with <strong className="text-foreground">Schedules</strong>, you can set up cron-based automated exports for compliance, archival, or downstream analytics.
            </p>
          </div>
          <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
            <h3 className="text-sm font-semibold text-foreground">Quick Setup</h3>
            <div className="mt-2 space-y-1 text-xs text-muted-foreground">
              <p><strong className="text-foreground">1. Channels tab</strong> — Create a channel (S3, Webhook, or Kafka) with connection details, then test it.</p>
              <p><strong className="text-foreground">2. Schedules tab</strong> — Attach a cron schedule to a channel to export data automatically at set intervals.</p>
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
      {tab === "channels" && <ChannelsTab />}
      {tab === "schedules" && <ScheduleManager />}
    </div>
  )
}

/* ── Channels Tab ──────────────────────────────────────────────────────────── */

function ChannelsTab() {
  const { data, isLoading, error } = useExportChannels()
  const createMutation = useCreateExportChannel()
  const updateMutation = useUpdateExportChannel()
  const deleteMutation = useDeleteExportChannel()
  const testMutation = useTestExportChannel()

  const [showForm, setShowForm] = useState(false)
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null)
  const [testResults, setTestResults] = useState<Record<string, { success: boolean; message?: string }>>({})

  const channels = data?.channels ?? []

  /* ── Handlers ────────────────────────────────────────────────────────────── */

  const handleCreate = useCallback(
    (payload: PDRChannelCreate) => {
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

  const handleTest = useCallback(
    (id: string) => {
      setTestResults((prev) => ({ ...prev, [id]: { success: true, message: "Testing…" } }))
      testMutation.mutate(id, {
        onSuccess: (result) => {
          setTestResults((prev) => ({
            ...prev,
            [id]: { success: result.success, message: result.success ? "Connected" : result.message },
          }))
        },
        onError: (err) => {
          setTestResults((prev) => ({
            ...prev,
            [id]: { success: false, message: err.message || "Test failed" },
          }))
        },
      })
    },
    [testMutation],
  )

  /* ── Loading / Error ─────────────────────────────────────────────────────── */

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-24">
        <div className="h-6 w-6 animate-spin rounded-full border-2 border-primary/20 border-t-primary" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="p-6">
        <p className="text-sm text-destructive" role="alert">
          Failed to load export channels.
        </p>
      </div>
    )
  }

  /* ── Render ──────────────────────────────────────────────────────────────── */

  return (
    <div className="flex flex-col gap-4">
      {/* Add channel button */}
      <div className="flex items-center justify-between">
        <p className="text-xs text-muted-foreground">
          S3, Webhook, and Kafka export destinations
        </p>
        {!showForm && (
          <Button size="sm" onClick={() => setShowForm(true)} className="gap-1.5">
            <Plus className="h-3.5 w-3.5" />
            Add Channel
          </Button>
        )}
      </div>

      {/* Create form */}
      {showForm && (
        <ChannelForm
          onSubmit={handleCreate}
          onCancel={() => setShowForm(false)}
          isPending={createMutation.isPending}
        />
      )}

      {/* Channels table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm">
            Channels ({channels.length})
          </CardTitle>
        </CardHeader>
        <CardContent>
          {channels.length === 0 ? (
            <p className="text-sm text-muted-foreground py-8 text-center">
              No export channels configured.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Destination</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Updated</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {channels.map((ch) => {
                  const testResult = testResults[ch.id]
                  return (
                    <TableRow key={ch.id}>
                      <TableCell className="font-medium">{ch.name}</TableCell>
                      <TableCell>
                        <Badge variant={typeBadgeVariant[ch.channel_type]}>
                          {typeLabel[ch.channel_type]}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <ConfigSummary config={ch.config_masked} type={ch.channel_type} />
                      </TableCell>
                      <TableCell>
                        <ChannelStatus enabled={ch.enabled} />
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {formatDate(ch.updated_at)}
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center justify-end gap-1">
                          {/* Test connection */}
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => handleTest(ch.id)}
                            disabled={testMutation.isPending}
                            aria-label={`Test ${ch.name}`}
                            title="Test connection"
                          >
                            {testResult?.message === "Testing…" ? (
                              <Loader2 className="h-3.5 w-3.5 animate-spin" />
                            ) : testResult?.success === true ? (
                              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                            ) : testResult?.success === false ? (
                              <XCircle className="h-3.5 w-3.5 text-destructive" />
                            ) : (
                              <Zap className="h-3.5 w-3.5" />
                            )}
                          </Button>

                          {/* Toggle enable/disable */}
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => handleToggle(ch.id, ch.enabled)}
                            aria-label={ch.enabled ? `Disable ${ch.name}` : `Enable ${ch.name}`}
                            title={ch.enabled ? "Disable" : "Enable"}
                          >
                            {ch.enabled ? (
                              <ToggleRight className="h-3.5 w-3.5 text-emerald-400" />
                            ) : (
                              <ToggleLeft className="h-3.5 w-3.5 text-muted-foreground" />
                            )}
                          </Button>

                          {/* Delete */}
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => handleDelete(ch.id)}
                            aria-label={
                              deleteConfirm === ch.id
                                ? `Confirm delete ${ch.name}`
                                : `Delete ${ch.name}`
                            }
                            title={deleteConfirm === ch.id ? "Click again to confirm" : "Delete"}
                            className={
                              deleteConfirm === ch.id
                                ? "text-destructive hover:text-destructive"
                                : ""
                            }
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </div>

                        {/* Test result message */}
                        {testResult && testResult.message !== "Testing…" && (
                          <p
                            className={`text-[10px] mt-1 text-right ${
                              testResult.success
                                ? "text-emerald-400"
                                : "text-destructive"
                            }`}
                          >
                            {testResult.message}
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
