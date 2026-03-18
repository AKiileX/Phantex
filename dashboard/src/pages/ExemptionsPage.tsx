// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Exemptions management page.
 *
 * CRUD table for policy exemptions with:
 *   - Filterable list with enable/disable toggles
 *   - Inline create form
 *   - Hit counter + last-hit display
 *   - Expiration status indicators
 *   - Delete confirmation
 *
 * @module pages/ExemptionsPage
 */

import { useState, useCallback } from "react"
import { ShieldOff, Plus, Trash2, ToggleLeft, ToggleRight, HelpCircle } from "lucide-react"
import {
  useExemptions,
  useCreateExemption,
  useUpdateExemption,
  useDeleteExemption,
} from "@/api/exemptions"
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
import type { ExemptionCreate } from "@/types"

/* ── Tag Input Helper ──────────────────────────────────────────────────────── */

function parseTagInput(raw: string): Record<string, string> {
  const tags: Record<string, string> = {}
  raw.split(",").forEach((pair) => {
    const [k, v] = pair.split("=").map((s) => s.trim())
    if (k && v) tags[k] = v
  })
  return tags
}

/* ── Component ─────────────────────────────────────────────────────────────── */

export function ExemptionsPage() {
  const { data: exemptions, isLoading } = useExemptions()
  const createExemption = useCreateExemption()
  const updateExemption = useUpdateExemption()
  const deleteExemption = useDeleteExemption()

  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState<{
    rule_name: string
    match_tags: string
    reason: string
    expires_at: string
  }>({ rule_name: "", match_tags: "", reason: "", expires_at: "" })
  const [formError, setFormError] = useState<string | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null)
  const [search, setSearch] = useState("")
  const [showGuide, setShowGuide] = useState(false)

  const handleCreate = useCallback(() => {
    setFormError(null)
    const ruleName = form.rule_name.trim()
    const tags = parseTagInput(form.match_tags)
    const reason = form.reason.trim()

    if (!ruleName || ruleName.length > 128) {
      setFormError("Rule name required (max 128 chars)")
      return
    }
    if (Object.keys(tags).length === 0 || Object.keys(tags).length > 20) {
      setFormError("1-20 match tags required (format: key=value, key2=value2)")
      return
    }
    if (!reason || reason.length > 1024) {
      setFormError("Reason required (max 1024 chars)")
      return
    }

    const body: ExemptionCreate = {
      rule_name: ruleName,
      match_tags: tags,
      reason,
    }
    if (form.expires_at) {
      body.expires_at = new Date(form.expires_at).toISOString()
    }

    createExemption.mutate(body, {
      onSuccess: () => {
        setShowForm(false)
        setForm({ rule_name: "", match_tags: "", reason: "", expires_at: "" })
      },
      onError: (err) => setFormError(err.message),
    })
  }, [form, createExemption])

  const handleToggle = useCallback(
    (id: string, enabled: boolean) => {
      updateExemption.mutate({ id, body: { enabled: !enabled } })
    },
    [updateExemption],
  )

  const handleDelete = useCallback(
    (id: string) => {
      deleteExemption.mutate(id, {
        onSuccess: () => setDeleteTarget(null),
      })
    },
    [deleteExemption],
  )

  const filtered = (exemptions ?? []).filter(
    (e) =>
      !search ||
      e.rule_name.toLowerCase().includes(search.toLowerCase()) ||
      e.reason.toLowerCase().includes(search.toLowerCase()),
  )

  function isExpired(expiresAt: string | null): boolean {
    if (!expiresAt) return false
    return new Date(expiresAt) < new Date()
  }

  return (
    <div className="space-y-4 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldOff size={18} className="text-muted-foreground" />
          <h1 className="text-xl font-semibold text-foreground">Exemptions</h1>
          <Badge variant="secondary">{exemptions?.length ?? 0}</Badge>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => setShowGuide(!showGuide)} className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"><HelpCircle size={14} />{showGuide ? "Hide Guide" : "How does this work?"}</button>
          <Button
            size="sm"
            className="gap-1"
            onClick={() => setShowForm((v) => !v)}
          >
            <Plus size={14} /> New Exemption
          </Button>
        </div>
      </div>

      {/* Search */}
      <Input
        placeholder="Search by rule name or reason…"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        className="max-w-sm"
      />

      {/* Create form */}
      {showForm && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Create Exemption</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="grid gap-2 sm:grid-cols-2">
              <Input
                placeholder="Rule name pattern (e.g. excessive_api_calls)"
                value={form.rule_name}
                onChange={(e) =>
                  setForm((f) => ({ ...f, rule_name: e.target.value }))
                }
                maxLength={128}
                aria-label="Rule name"
              />
              <Input
                placeholder="Match tags (key=value, key2=value2)"
                value={form.match_tags}
                onChange={(e) =>
                  setForm((f) => ({ ...f, match_tags: e.target.value }))
                }
                maxLength={2048}
                aria-label="Match tags"
              />
            </div>
            <Input
              placeholder="Reason for exemption"
              value={form.reason}
              onChange={(e) =>
                setForm((f) => ({ ...f, reason: e.target.value }))
              }
              maxLength={1024}
              aria-label="Reason"
            />
            <div className="flex items-center gap-2">
              <Input
                type="datetime-local"
                value={form.expires_at}
                onChange={(e) =>
                  setForm((f) => ({ ...f, expires_at: e.target.value }))
                }
                className="max-w-xs"
                aria-label="Expires at"
              />
              <span className="text-xs text-muted-foreground">
                Optional expiration
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
                disabled={createExemption.isPending}
              >
                {createExemption.isPending ? "Creating…" : "Create"}
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
              Loading exemptions…
            </div>
          ) : filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 gap-2">
              <ShieldOff size={24} className="text-surface-3" />
              <p className="text-sm text-muted-foreground">
                {search ? "No matching exemptions" : "No exemptions configured"}
              </p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Rule</TableHead>
                  <TableHead>Match Tags</TableHead>
                  <TableHead>Reason</TableHead>
                  <TableHead className="text-center">Hits</TableHead>
                  <TableHead>Expires</TableHead>
                  <TableHead className="text-center">Status</TableHead>
                  <TableHead className="w-20" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map((ex) => (
                  <TableRow key={ex.id}>
                    <TableCell>
                      <span className="font-mono text-xs">{ex.rule_name}</span>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {Object.entries(ex.match_tags).map(([k, v]) => (
                          <Badge
                            key={k}
                            variant="secondary"
                            className="text-[10px] font-mono"
                          >
                            {k}={v}
                          </Badge>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell>
                      <span className="text-xs max-w-48 truncate block">
                        {ex.reason}
                      </span>
                    </TableCell>
                    <TableCell className="text-center">
                      <span className="tabular-nums text-xs">
                        {ex.hit_count}
                      </span>
                      {ex.last_hit_at && (
                        <span className="block text-[10px] text-muted-foreground">
                          {timeAgo(ex.last_hit_at)}
                        </span>
                      )}
                    </TableCell>
                    <TableCell>
                      {ex.expires_at ? (
                        <span
                          className={`text-xs ${isExpired(ex.expires_at) ? "text-destructive" : "text-muted-foreground"}`}
                        >
                          {isExpired(ex.expires_at)
                            ? "Expired"
                            : formatDate(ex.expires_at)}
                        </span>
                      ) : (
                        <span className="text-xs text-muted-foreground">
                          Never
                        </span>
                      )}
                    </TableCell>
                    <TableCell className="text-center">
                      <button
                        type="button"
                        onClick={() => handleToggle(ex.id, ex.enabled)}
                        className="text-muted-foreground hover:text-foreground transition-colors"
                        aria-label={
                          ex.enabled
                            ? `Disable exemption ${ex.rule_name}`
                            : `Enable exemption ${ex.rule_name}`
                        }
                      >
                        {ex.enabled ? (
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
                      {deleteTarget === ex.id ? (
                        <div className="flex gap-1">
                          <Button
                            variant="destructive"
                            size="sm"
                            onClick={() => handleDelete(ex.id)}
                            disabled={deleteExemption.isPending}
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
                          onClick={() => setDeleteTarget(ex.id)}
                          aria-label={`Delete exemption ${ex.rule_name}`}
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
          <h3 className="text-base font-semibold text-foreground">How do Exemptions work?</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Exemption Rules</p>
              <p>Managed via <code className="text-xs bg-white/5 px-1 rounded">/api/exemptions</code>. Each exemption suppresses alerts from a specific rule for agents matching given tags. Useful for known-good behaviors or planned maintenance that would otherwise trigger false positives.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Expiration</p>
              <p>Exemptions can be permanent or time-limited with an expiration date. Expired exemptions are automatically disabled. This prevents "exemption drift" where temporary suppressions become permanent security gaps.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Tag Matching</p>
              <p>Match tags scope exemptions to specific agent groups (e.g., "dev", "staging"). Only agents with matching tags benefit from the exemption. Production agents continue to receive full detection coverage.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Toggle &amp; Delete</p>
              <p>Toggle exemptions on/off without deleting via <code className="text-xs bg-white/5 px-1 rounded">/api/exemptions/:id</code> PATCH. Delete permanently removes the exemption. All changes are audit-logged for compliance review.</p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
