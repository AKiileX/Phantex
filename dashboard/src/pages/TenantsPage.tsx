// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Tenant Management Page (platform-admin only).
 *
 * CRUD for tenants, suspend/activate, usage metrics, delete.
 * Route: /settings/tenants
 */

import { useState, Fragment } from "react"
import {
  Building2,
  Plus,
  Trash2,
  Pause,
  Play,
  BarChart3,
  ChevronDown,
  ChevronRight,
  X,
  Check,
  AlertTriangle,
  HelpCircle,
} from "lucide-react"
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table"
import { useToast } from "@/components/ui/toast"
import {
  useTenants,
  useTenantUsage,
  useCreateTenant,
  useUpdateTenant,
  useSuspendTenant,
  useActivateTenant,
  useDeleteTenant,
  type TenantCreate,
  type Tenant,
} from "@/api/tenants"

/* ── Usage Panel ──────────────────────────────────────── */

function UsagePanel({ tenantId }: { tenantId: string }) {
  const { data: usage, isLoading } = useTenantUsage(tenantId)

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 py-3 px-4">
        <div className="h-4 w-4 animate-spin rounded-full border-2 border-primary/20 border-t-primary" />
        <span className="text-xs text-muted-foreground">Loading usage data…</span>
      </div>
    )
  }

  if (!usage) {
    return (
      <div className="py-3 px-4 text-xs text-muted-foreground">No usage data available</div>
    )
  }

  const metrics = [
    { label: "Users", value: usage.user_count },
    { label: "Events (24h)", value: usage.events_today?.toLocaleString() ?? "—" },
    { label: "Storage", value: usage.storage_bytes ? `${(usage.storage_bytes / 1e9).toFixed(2)} GB` : "—" },
    { label: "Open Alerts", value: usage.alerts_open?.toLocaleString() ?? "—" },
  ]

  return (
    <div className="grid grid-cols-4 gap-4 py-3 px-4">
      {metrics.map((m) => (
        <div key={m.label} className="text-center">
          <p className="text-lg font-semibold text-foreground">{m.value ?? 0}</p>
          <p className="text-[10px] text-muted-foreground">{m.label}</p>
        </div>
      ))}
    </div>
  )
}

/* ── Create/Edit Form ─────────────────────────────────── */

function TenantForm({
  editing,
  onSubmit,
  onCancel,
  isPending,
}: {
  editing?: Tenant
  onSubmit: (data: TenantCreate & { id?: string }) => void
  onCancel: () => void
  isPending: boolean
}) {
  const [name, setName] = useState(editing?.name ?? "")
  const [slug, setSlug] = useState(editing?.slug ?? "")
  const [plan, setPlan] = useState(editing?.plan ?? "community")
  const [maxUsers, setMaxUsers] = useState(editing?.max_users?.toString() ?? "25")
  const [adminEmail, setAdminEmail] = useState("")
  const [adminPassword, setAdminPassword] = useState("")

  const autoSlug = (val: string) =>
    val
      .toLowerCase()
      .replace(/[^a-z0-9-]/g, "-")
      .replace(/-+/g, "-")

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">
          {editing ? `Edit Tenant: ${editing.name}` : "New Tenant"}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="text-xs text-muted-foreground mb-1 block">Tenant Name</label>
            <Input
              value={name}
              onChange={(e) => {
                setName(e.target.value)
                if (!editing) setSlug(autoSlug(e.target.value))
              }}
              placeholder="Acme Corporation"
            />
          </div>
          <div>
            <label className="text-xs text-muted-foreground mb-1 block">Slug</label>
            <Input
              value={slug}
              onChange={(e) => setSlug(autoSlug(e.target.value))}
              placeholder="acme-corp"
              disabled={!!editing}
            />
          </div>
        </div>

        <div className="grid grid-cols-3 gap-4">
          <div>
            <label className="text-xs text-muted-foreground mb-1 block">Plan</label>
            <select
              className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm text-foreground focus:border-primary focus:outline-none"
              value={plan}
              onChange={(e) => setPlan(e.target.value as typeof plan)}
            >
              <option value="community">Community</option>
              <option value="starter">Starter</option>
              <option value="business">Business</option>
              <option value="enterprise">Enterprise</option>
            </select>
          </div>
          <div>
            <label className="text-xs text-muted-foreground mb-1 block">Max Users</label>
            <Input
              type="number"
              min={1}
              value={maxUsers}
              onChange={(e) => setMaxUsers(e.target.value)}
              placeholder="25"
            />
          </div>
          {!editing && (
            <>
              <div>
                <label className="text-xs text-muted-foreground mb-1 block">Admin Email</label>
                <Input
                  type="email"
                  value={adminEmail}
                  onChange={(e) => setAdminEmail(e.target.value)}
                  placeholder="admin@acme.com"
                />
              </div>
              <div>
                <label className="text-xs text-muted-foreground mb-1 block">Admin Password</label>
                <Input
                  type="password"
                  value={adminPassword}
                  onChange={(e) => setAdminPassword(e.target.value)}
                  placeholder="••••••••"
                />
              </div>
            </>
          )}
        </div>

        <div className="flex justify-end gap-2 pt-2 border-t border-border">
          <Button variant="outline" onClick={onCancel} disabled={isPending}>
            Cancel
          </Button>
          <Button
            onClick={() => {
              const payload: TenantCreate & { id?: string } = editing
                ? { id: editing.id, name, slug, plan, max_users: parseInt(maxUsers) || 25, admin_email: "", admin_password: "" }
                : { name, slug, plan, max_users: parseInt(maxUsers) || 25, admin_email: adminEmail, admin_password: adminPassword }
              onSubmit(payload)
            }}
            disabled={isPending || !name || !slug || (!editing && (!adminEmail || !adminPassword))}
          >
            {isPending ? "Saving…" : editing ? "Update Tenant" : "Create Tenant"}
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}

/* ── Status Badge ─────────────────────────────────────── */

function StatusBadge({ tenant }: { tenant: Tenant }) {
  if (tenant.suspended_at) {
    return <Badge variant="high">Suspended</Badge>
  }
  if (tenant.is_active) {
    return <Badge variant="active">Active</Badge>
  }
  return <Badge variant="secondary">Inactive</Badge>
}

/* ── Main Page ────────────────────────────────────────── */

export function TenantsPage() {
  const { data: tenants, isLoading } = useTenants()
  const createMut = useCreateTenant()
  const updateMut = useUpdateTenant()
  const suspendMut = useSuspendTenant()
  const activateMut = useActivateTenant()
  const deleteMut = useDeleteTenant()
  const { toast } = useToast()
  const [showForm, setShowForm] = useState(false)
  const [showGuide, setShowGuide] = useState(false)
  const [editingTenant, setEditingTenant] = useState<Tenant | null>(null)
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null)
  const [expandedTenant, setExpandedTenant] = useState<string | null>(null)

  const PLATFORM_TENANT = "a0000000-0000-0000-0000-000000000000"

  const handleSave = (data: TenantCreate & { id?: string }) => {
    const { id, admin_email, admin_password, admin_name, ...rest } = data
    if (id) {
      // Strip admin credentials from update payload — they're only for create
      updateMut.mutate(
        { id, ...rest },
        {
          onSuccess: () => {
            toast({ title: "Tenant updated", variant: "success" })
            setShowForm(false)
            setEditingTenant(null)
          },
          onError: (err: Error & { response?: { data?: { detail?: string } } }) =>
            toast({
              title: "Failed to update tenant",
              description: err?.response?.data?.detail || err.message,
              variant: "error",
            }),
        },
      )
    } else {
      createMut.mutate({ admin_email, admin_password, admin_name, ...rest }, {
        onSuccess: () => {
          toast({ title: "Tenant created", variant: "success" })
          setShowForm(false)
        },
        onError: (err: Error & { response?: { data?: { detail?: string } } }) =>
          toast({
            title: "Failed to create tenant",
            description: err?.response?.data?.detail || err.message,
            variant: "error",
          }),
      })
    }
  }

  const handleSuspend = (id: string) => {
    suspendMut.mutate(id, {
      onSuccess: () => toast({ title: "Tenant suspended", variant: "warning" }),
      onError: (err: Error & { response?: { data?: { detail?: string } } }) =>
        toast({ title: "Suspend failed", description: err?.response?.data?.detail, variant: "error" }),
    })
  }

  const handleActivate = (id: string) => {
    activateMut.mutate(id, {
      onSuccess: () => toast({ title: "Tenant activated", variant: "success" }),
      onError: (err: Error & { response?: { data?: { detail?: string } } }) =>
        toast({ title: "Activate failed", description: err?.response?.data?.detail, variant: "error" }),
    })
  }

  const handleDelete = (id: string) => {
    deleteMut.mutate(id, {
      onSuccess: () => {
        toast({ title: "Tenant deleted", variant: "success" })
        setConfirmDelete(null)
      },
      onError: (err: Error & { response?: { data?: { detail?: string } } }) =>
        toast({
          title: "Cannot delete tenant",
          description: err?.response?.data?.detail || err.message,
          variant: "error",
        }),
    })
  }

  return (
    <div className="space-y-4 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-foreground flex items-center gap-2">
            <Building2 size={20} /> Tenant Management
          </h1>
          <p className="text-sm text-muted-foreground">
            Create and manage platform tenants, quotas, and billing plans
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowGuide(!showGuide)}
            className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"
          >
            <HelpCircle size={14} />
            {showGuide ? "Hide Guide" : "How does this work?"}
          </button>
          {!showForm && (
            <Button
              onClick={() => {
                setEditingTenant(null)
                setShowForm(true)
              }}
            >
              <Plus size={16} className="mr-1" /> New Tenant
            </Button>
          )}
        </div>
      </div>

      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
          <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
            <Building2 size={16} className="text-primary" />
            What is Tenant Management?
          </h3>
          <p className="mt-1.5 text-xs text-muted-foreground leading-relaxed">
            PhanTeX is a <strong className="text-foreground">multi-tenant platform</strong> — each organization gets its own isolated environment with separate data, users, agents, and configurations. Tenants cannot see each other&apos;s data (enforced by Row-Level Security in the database). Use this page to create new tenants, manage quotas, assign billing plans, or suspend/activate tenants.
          </p>
          <div className="mt-2 space-y-1.5 text-xs text-muted-foreground">
            <p><strong className="text-foreground">Create:</strong> Click New Tenant, set name, plan, and quotas</p>
            <p><strong className="text-foreground">Suspend:</strong> Temporarily disable a tenant without deleting data</p>
            <p><strong className="text-foreground">Usage:</strong> Expand a tenant row to see event counts, agent counts, and storage usage</p>
          </div>
        </div>
      )}

      {/* Platform admin warning */}
      <Card className="border-yellow-500/20 bg-yellow-500/5">
        <CardContent className="py-3">
          <div className="flex items-start gap-2 text-sm">
            <AlertTriangle size={16} className="text-yellow-500 mt-0.5 flex-shrink-0" />
            <div>
              <p className="font-medium text-foreground">Platform Admin Access</p>
              <p className="text-muted-foreground text-xs mt-0.5">
                Tenant management is restricted to platform administrators. All operations
                are audit-logged. The platform tenant cannot be deleted or suspended.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {showForm && (
        <TenantForm
          editing={editingTenant ?? undefined}
          onSubmit={handleSave}
          onCancel={() => {
            setShowForm(false)
            setEditingTenant(null)
          }}
          isPending={createMut.isPending || updateMut.isPending}
        />
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">All Tenants</CardTitle>
          <CardDescription>
            {tenants?.length ?? 0} tenant{(tenants?.length ?? 0) !== 1 && "s"} on the platform
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex justify-center py-8">
              <div className="h-5 w-5 animate-spin rounded-full border-2 border-primary/20 border-t-primary" />
            </div>
          ) : !tenants?.length ? (
            <div className="flex flex-col items-center py-8 text-center">
              <Building2 size={32} className="text-muted-foreground/30 mb-2" />
              <p className="text-sm text-muted-foreground">No tenants found</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead />
                  <TableHead>Name</TableHead>
                  <TableHead>Slug</TableHead>
                  <TableHead>Plan</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Max Users</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {tenants.map((t) => {
                  const isPlatform = t.id === PLATFORM_TENANT
                  return (
                    <Fragment key={t.id}>
                      <TableRow>
                        <TableCell className="w-8">
                          <button
                            onClick={() =>
                              setExpandedTenant(expandedTenant === t.id ? null : t.id)
                            }
                            className="text-muted-foreground hover:text-foreground"
                          >
                            {expandedTenant === t.id ? (
                              <ChevronDown size={14} />
                            ) : (
                              <ChevronRight size={14} />
                            )}
                          </button>
                        </TableCell>
                        <TableCell className="font-medium">
                          {t.name}
                          {isPlatform && (
                            <Badge variant="default" className="ml-2 text-[9px]">
                              PLATFORM
                            </Badge>
                          )}
                        </TableCell>
                        <TableCell className="text-xs font-mono text-muted-foreground">
                          {t.slug}
                        </TableCell>
                        <TableCell>
                          <Badge variant="secondary" className="capitalize text-[10px]">
                            {t.plan}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <StatusBadge tenant={t} />
                        </TableCell>
                        <TableCell>{t.max_users ?? "—"}</TableCell>
                        <TableCell className="text-right">
                          <div className="flex items-center justify-end gap-1">
                            {/* Usage toggle = expand */}
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() =>
                                setExpandedTenant(expandedTenant === t.id ? null : t.id)
                              }
                              title="Usage"
                            >
                              <BarChart3 size={14} />
                            </Button>

                            {/* Suspend / Activate */}
                            {!isPlatform &&
                              (!t.suspended_at && t.is_active ? (
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  onClick={() => handleSuspend(t.id)}
                                  title="Suspend"
                                >
                                  <Pause size={14} className="text-yellow-500" />
                                </Button>
                              ) : t.suspended_at ? (
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  onClick={() => handleActivate(t.id)}
                                  title="Activate"
                                >
                                  <Play size={14} className="text-green-500" />
                                </Button>
                              ) : null)}

                            {/* Edit */}
                            {!isPlatform && (
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => {
                                  setEditingTenant(t)
                                  setShowForm(true)
                                }}
                                title="Edit"
                              >
                                <span className="text-xs">Edit</span>
                              </Button>
                            )}

                            {/* Delete */}
                            {isPlatform ? (
                              <Button variant="ghost" size="sm" disabled title="Cannot delete platform">
                                <Trash2 size={14} className="text-muted-foreground/30" />
                              </Button>
                            ) : confirmDelete === t.id ? (
                              <div className="flex items-center gap-1">
                                <Button
                                  variant="destructive"
                                  size="sm"
                                  onClick={() => handleDelete(t.id)}
                                  disabled={deleteMut.isPending}
                                >
                                  <Check size={14} />
                                </Button>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  onClick={() => setConfirmDelete(null)}
                                >
                                  <X size={14} />
                                </Button>
                              </div>
                            ) : (
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => setConfirmDelete(t.id)}
                                title="Delete"
                              >
                                <Trash2 size={14} className="text-destructive" />
                              </Button>
                            )}
                          </div>
                        </TableCell>
                      </TableRow>
                      {expandedTenant === t.id && (
                        <TableRow key={`${t.id}-usage`}>
                          <TableCell colSpan={7} className="bg-accent/5 p-0">
                            <UsagePanel tenantId={t.id} />
                          </TableCell>
                        </TableRow>
                      )}
                    </Fragment>
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
