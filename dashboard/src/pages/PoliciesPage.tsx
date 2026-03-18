// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — PoliciesPage: list of detection policies (O5).
 *
 * Features:
 *   - Filterable list with enable/disable toggles
 *   - Create / edit navigation
 *   - Scope + rule count summary per card
 *   - Admin/analyst role gating for editing
 *
 * @module pages/PoliciesPage
 */

import { useState, useMemo } from "react"
import { useNavigate } from "react-router-dom"
import {
  Shield,
  Plus,
  Search,
  ToggleLeft,
  ToggleRight,
  FileEdit,
  Trash2,
  ChevronRight,
  Loader2,
  HelpCircle,
} from "lucide-react"
import { usePolicies, useDeletePolicy, useUpdatePolicy } from "@/api/policies"
import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { usePermissionStore } from "@/stores/permissionStore"
import { formatDate } from "@/lib/utils"
import type { Policy } from "@/types"

/* ── Component ─────────────────────────────────────────────────────────────── */

export function PoliciesPage() {
  const navigate = useNavigate()
  const permissions = usePermissionStore((s) => s.permissions)
  const canEdit = permissions.has("policies.write")

  const [page, setPage] = useState(1)
  const [search, setSearch] = useState("")
  const [showGuide, setShowGuide] = useState(false)

  const { data, isLoading } = usePolicies({ page, pageSize: 50 })
  const deleteMutation = useDeletePolicy()
  const updateMutation = useUpdatePolicy()

  const policies = useMemo(() => {
    const items: Policy[] = data?.items ?? []
    if (!search.trim()) return items
    const q = search.toLowerCase()
    return items.filter(
      (p) =>
        p.name.toLowerCase().includes(q) ||
        (p.description ?? "").toLowerCase().includes(q),
    )
  }, [data?.items, search])

  const stats = useMemo(() => {
    const all = data?.items ?? []
    const enabled = all.filter((p: Policy) => p.enabled).length
    return { total: all.length, enabled, disabled: all.length - enabled }
  }, [data?.items])

  const toggleEnabled = (policy: Policy) => {
    updateMutation.mutate({
      id: policy.id,
      enabled: !policy.enabled,
      change_summary: policy.enabled ? "Disabled policy" : "Enabled policy",
    })
  }

  const handleDelete = (id: string) => {
    if (window.confirm("Delete this policy? This cannot be undone.")) {
      deleteMutation.mutate(id)
    }
  }

  return (
    <div className="space-y-4 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-foreground flex items-center gap-2">
            <Shield className="size-5" /> Detection Policies
          </h1>
          <div className="flex items-center gap-3 mt-0.5">
            <p className="text-sm text-muted-foreground">
              {stats.total} policies configured
            </p>
            {stats.total > 0 && (
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
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
        <div className="flex items-center gap-2">
          <button onClick={() => setShowGuide(!showGuide)} className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"><HelpCircle size={14} />{showGuide ? "Hide Guide" : "How does this work?"}</button>
          {canEdit && (
            <Button
              size="sm"
              className="gap-1.5"
              onClick={() => navigate("/policies/new")}
            >
              <Plus size={14} /> New Policy
            </Button>
          )}
        </div>
      </div>

      {/* Search */}
      <div className="relative max-w-sm">
        <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 size-3.5 text-muted-foreground" />
        <Input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Filter policies…"
          className="pl-8 h-8 text-xs"
        />
      </div>

      {/* List */}
      {isLoading ? (
        <div className="flex items-center justify-center py-16 text-muted-foreground">
          <Loader2 className="size-5 animate-spin" />
        </div>
      ) : policies.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-muted-foreground gap-2">
          <Shield className="size-8 opacity-40" />
          <p className="text-sm">{search ? "No policies match your filter" : "No policies configured yet"}</p>
          {canEdit && !search && (
            <Button variant="outline" size="sm" className="mt-2 gap-1" onClick={() => navigate("/policies/new")}>
              <Plus size={12} /> Create your first policy
            </Button>
          )}
        </div>
      ) : (
        <div className="space-y-2">
          {policies.map((policy) => (
            <Card
              key={policy.id}
              className={`p-0 ${!policy.enabled ? "opacity-60" : ""} hover:border-border/80 transition-all cursor-pointer`}
              onClick={() => navigate(`/policies/${policy.id}/edit`)}
            >
              <div className="flex items-center gap-3 px-4 py-3">
                {/* Toggle */}
                {canEdit && (
                  <button
                    onClick={(e) => { e.stopPropagation(); toggleEnabled(policy) }}
                    className="cursor-pointer"
                    title={policy.enabled ? "Disable" : "Enable"}
                  >
                    {policy.enabled ? (
                      <ToggleRight className="size-5 text-emerald-400" />
                    ) : (
                      <ToggleLeft className="size-5 text-muted-foreground" />
                    )}
                  </button>
                )}

                {/* Info */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-foreground truncate">
                      {policy.name}
                    </span>
                    <Badge variant="outline" className="text-[9px] px-1.5 shrink-0">
                      v{policy.version}
                    </Badge>
                  </div>
                  {policy.description && (
                    <p className="text-xs text-muted-foreground mt-0.5 truncate">
                      {policy.description}
                    </p>
                  )}
                </div>

                {/* Scope badges */}
                <div className="flex items-center gap-1 shrink-0">
                  {(policy.scope_agent_tags ?? []).length > 0 && (
                    <Badge variant="outline" className="text-[9px] bg-blue-500/10 text-blue-400 border-blue-500/30">
                      {(policy.scope_agent_tags ?? []).length} tag{(policy.scope_agent_tags ?? []).length > 1 ? "s" : ""}
                    </Badge>
                  )}
                  {(policy.scope_frameworks ?? []).length > 0 && (
                    <Badge variant="outline" className="text-[9px] bg-violet-500/10 text-violet-400 border-violet-500/30">
                      {(policy.scope_frameworks ?? []).length} fw
                    </Badge>
                  )}
                </div>

                {/* Date */}
                <span className="text-[10px] text-muted-foreground/60 shrink-0">
                  {formatDate(policy.updated_at)}
                </span>

                {/* Actions */}
                <div className="flex items-center gap-1 shrink-0">
                  {canEdit && (
                    <>
                      <button
                        onClick={(e) => { e.stopPropagation(); navigate(`/policies/${policy.id}/edit`) }}
                        className="p-1 hover:text-foreground text-muted-foreground cursor-pointer"
                        title="Edit"
                      >
                        <FileEdit className="size-3.5" />
                      </button>
                      <button
                        onClick={(e) => { e.stopPropagation(); handleDelete(policy.id) }}
                        className="p-1 hover:text-red-400 text-muted-foreground cursor-pointer"
                        title="Delete"
                      >
                        <Trash2 className="size-3.5" />
                      </button>
                    </>
                  )}
                  <ChevronRight className="size-3.5 text-muted-foreground/40" />
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}

      {/* Pagination */}
      {(data?.total ?? 0) > 50 && (
        <div className="flex justify-center gap-2 pt-2">
          <Button
            variant="outline"
            size="sm"
            disabled={page <= 1}
            onClick={() => setPage((p) => p - 1)}
          >
            Previous
          </Button>
          <span className="flex items-center text-xs text-muted-foreground">
            Page {page}
          </span>
          <Button
            variant="outline"
            size="sm"
            disabled={policies.length < 50}
            onClick={() => setPage((p) => p + 1)}
          >
            Next
          </Button>
        </div>
      )}

      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5 space-y-3 text-sm text-muted-foreground">
          <h3 className="text-base font-semibold text-foreground">How do Detection Policies work?</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Policy CRUD</p>
              <p>Policies are managed via <code className="text-xs bg-white/5 px-1 rounded">/api/policies</code> with pagination (50 per page). Each policy defines detection rules, severity thresholds, and scoping by agent tags or compliance frameworks.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Visual + YAML Editor</p>
              <p>Create or edit policies using the visual builder or raw YAML. The editor validates policy syntax in real time via <code className="text-xs bg-white/5 px-1 rounded">/api/policies/validate</code>. Changes are versioned with full edit history.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Scoping</p>
              <p>Policies scope to specific agent tags and compliance frameworks. Only matching agents are evaluated against the policy. Toggle policies on/off without deleting for quick incident response or maintenance.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Apply &amp; Deploy</p>
              <p>Apply policies to push them to the evaluation engine via <code className="text-xs bg-white/5 px-1 rounded">/api/policies/:id/apply</code>. Active policies are continuously evaluated against incoming events. Policy changes take effect within one evaluation cycle.</p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
