// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Roles & Permissions Management Page (admin only).
 *
 * CRUD for custom roles, permission picker, user role assignments.
 * Route: /settings/roles
 */

import { useState, useMemo, Fragment } from "react"
import {
  Users,
  ShieldCheck,
  Plus,
  Trash2,
  Pencil,
  ChevronDown,
  ChevronRight,
  X,
  Check,
  HelpCircle,
  Lock,
} from "lucide-react"
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table"
import { useToast } from "@/components/ui/toast"
import {
  useRoles,
  useCreateRole,
  useUpdateRole,
  useDeleteRole,
  usePermissions,
  type Role,
  type RoleCreate,
  type Permission,
} from "@/api/roles"

/* ── Permission Picker ────────────────────────────────── */

/** Build a display name for a permission: "resource.action" */
function permDisplayName(p: Permission): string {
  return `${p.resource}.${p.action}`
}

function groupPermissions(perms: Permission[]): Record<string, Permission[]> {
  const groups: Record<string, Permission[]> = {}
  for (const p of perms) {
    const category = p.resource
    if (!groups[category]) groups[category] = []
    groups[category].push(p)
  }
  return groups
}

function PermissionPicker({
  allPermissions,
  selected,
  onToggle,
}: {
  allPermissions: Permission[]
  selected: Set<string>
  onToggle: (name: string) => void
}) {
  const groups = useMemo(() => groupPermissions(allPermissions), [allPermissions])
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({})

  return (
    <div className="space-y-2 max-h-[360px] overflow-y-auto pr-1">
      {Object.entries(groups).map(([cat, perms]) => (
        <div key={cat} className="border border-border rounded-md">
          <button
            onClick={() => setCollapsed((p) => ({ ...p, [cat]: !p[cat] }))}
            className="flex items-center gap-2 w-full px-3 py-2 text-xs font-semibold text-foreground hover:bg-accent/5 transition-colors"
          >
            {collapsed[cat] ? <ChevronRight size={14} /> : <ChevronDown size={14} />}
            <span className="uppercase tracking-wide">{cat}</span>
            <Badge variant="secondary" className="ml-auto text-[10px]">
              {perms.filter((p) => selected.has(p.id)).length}/{perms.length}
            </Badge>
          </button>
          {!collapsed[cat] && (
            <div className="border-t border-border px-3 pb-2 space-y-1 pt-1">
              {perms.map((perm) => (
                <label
                  key={perm.id}
                  className="flex items-center gap-2 py-1 px-1 rounded hover:bg-accent/5 cursor-pointer"
                >
                  <input
                    type="checkbox"
                    checked={selected.has(perm.id)}
                    onChange={() => onToggle(perm.id)}
                    className="rounded border-border text-primary focus:ring-primary"
                  />
                  <span className="text-sm text-foreground">{permDisplayName(perm)}</span>
                  {perm.description && (
                    <span className="text-xs text-muted-foreground ml-auto">
                      {perm.description}
                    </span>
                  )}
                </label>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  )
}

/* ── Create/Edit Form ─────────────────────────────────── */

function RoleForm({
  editing,
  allPermissions,
  onSubmit,
  onCancel,
  isPending,
}: {
  editing?: Role
  allPermissions: Permission[]
  onSubmit: (data: RoleCreate & { id?: string; permission_ids: string[] }) => void
  onCancel: () => void
  isPending: boolean
}) {
  const [name, setName] = useState(editing?.name ?? "")
  const [description, setDescription] = useState(editing?.description ?? "")
  const [selected, setSelected] = useState<Set<string>>(
    new Set(editing?.role_permissions?.map((rp) => rp.permission_id) ?? []),
  )

  const toggle = (permName: string) => {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(permName)) next.delete(permName)
      else next.add(permName)
      return next
    })
  }

  const handleSubmit = () => {
    onSubmit({
      id: editing?.id,
      name,
      description,
      permission_ids: Array.from(selected),
    })
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">
          {editing ? `Edit Role: ${editing.name}` : "New Custom Role"}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="text-xs text-muted-foreground mb-1 block">Role Name</label>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. security-analyst"
              disabled={!!editing?.is_builtin}
            />
          </div>
          <div>
            <label className="text-xs text-muted-foreground mb-1 block">Description</label>
            <Input
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Describe what this role is for"
            />
          </div>
        </div>

        <div>
          <label className="text-xs text-muted-foreground mb-1 block">
            Permissions ({selected.size} selected)
          </label>
          <PermissionPicker allPermissions={allPermissions} selected={selected} onToggle={toggle} />
        </div>

        <div className="flex justify-end gap-2 pt-2 border-t border-border">
          <Button variant="outline" onClick={onCancel} disabled={isPending}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={isPending || !name}>
            {isPending ? "Saving…" : editing ? "Update Role" : "Create Role"}
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}

/* ── Main Page ────────────────────────────────────────── */

export function RolesPage() {
  const { data: roles, isLoading } = useRoles()
  const { data: permissions = [] } = usePermissions()
  const createMut = useCreateRole()
  const updateMut = useUpdateRole()
  const deleteMut = useDeleteRole()
  const { toast } = useToast()
  const [showForm, setShowForm] = useState(false)
  const [showGuide, setShowGuide] = useState(false)
  const [editingRole, setEditingRole] = useState<Role | null>(null)
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null)
  const [expandedRole, setExpandedRole] = useState<string | null>(null)

  const handleSave = (data: RoleCreate & { id?: string; permission_ids: string[] }) => {
    if (data.id) {
      updateMut.mutate(
        { id: data.id, name: data.name, description: data.description, permission_ids: data.permission_ids },
        {
          onSuccess: () => {
            toast({ title: "Role updated", variant: "success" })
            setEditingRole(null)
            setShowForm(false)
          },
          onError: (err: Error & { response?: { data?: { detail?: string } } }) =>
            toast({
              title: "Failed to update role",
              description: err?.response?.data?.detail || err.message,
              variant: "error",
            }),
        },
      )
    } else {
      createMut.mutate(
        { name: data.name, description: data.description, permission_ids: data.permission_ids },
        {
          onSuccess: () => {
            toast({ title: "Role created", variant: "success" })
            setShowForm(false)
          },
          onError: (err: Error & { response?: { data?: { detail?: string } } }) =>
            toast({
              title: "Failed to create role",
              description: err?.response?.data?.detail || err.message,
              variant: "error",
            }),
        },
      )
    }
  }

  const handleDelete = (id: string) => {
    deleteMut.mutate(id, {
      onSuccess: () => {
        toast({ title: "Role deleted", variant: "success" })
        setConfirmDelete(null)
      },
      onError: (err: Error & { response?: { data?: { detail?: string } } }) =>
        toast({
          title: "Cannot delete role",
          description: err?.response?.data?.detail || err.message,
          variant: "error",
        }),
    })
  }

  const startEdit = (role: Role) => {
    setEditingRole(role)
    setShowForm(true)
  }

  return (
    <div className="space-y-4 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-foreground flex items-center gap-2">
            <ShieldCheck size={20} /> Roles & Permissions
          </h1>
          <p className="text-sm text-muted-foreground">
            Manage access control roles and their permission sets
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
                setEditingRole(null)
                setShowForm(true)
              }}
            >
              <Plus size={16} className="mr-1" /> New Role
            </Button>
          )}
        </div>
      </div>

      {showGuide && (
        <div className="space-y-4">
          <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
            <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
              <ShieldCheck size={16} className="text-primary" />
              What are Roles &amp; Permissions?
            </h3>
            <p className="mt-1.5 text-xs text-muted-foreground leading-relaxed">
              <strong className="text-foreground">Role-Based Access Control (RBAC)</strong> determines who can do what in PhanTeX. Each user is assigned one or more roles, and each role grants a specific set of permissions. This ensures analysts can view alerts but not change settings, while admins have full control.
            </p>
          </div>
          <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
            <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
              <Lock size={16} className="text-primary" />
              Quick Setup
            </h3>
            <div className="mt-2 space-y-1.5 text-xs text-muted-foreground">
              <p><strong className="text-foreground">1.</strong> Click <strong className="text-foreground">New Role</strong> to create a custom role</p>
              <p><strong className="text-foreground">2.</strong> Give it a name and description (e.g., &quot;SOC Analyst&quot;)</p>
              <p><strong className="text-foreground">3.</strong> Select permissions — each permission controls access to a specific feature (alerts.view, rules.manage, ml.manage, etc.)</p>
              <p><strong className="text-foreground">4.</strong> Assign the role to users from the Users page</p>
              <p><strong className="text-foreground">5.</strong> Built-in roles (admin, analyst, viewer) cannot be deleted but can be used as templates</p>
            </div>
          </div>
        </div>
      )}

      {showForm && (
        <RoleForm
          editing={editingRole ?? undefined}
          allPermissions={permissions}
          onSubmit={handleSave}
          onCancel={() => {
            setShowForm(false)
            setEditingRole(null)
          }}
          isPending={createMut.isPending || updateMut.isPending}
        />
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Defined Roles</CardTitle>
          <CardDescription>
            {roles?.length ?? 0} role{(roles?.length ?? 0) !== 1 && "s"} —
            Built-in roles cannot be renamed or deleted
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex justify-center py-8">
              <div className="h-5 w-5 animate-spin rounded-full border-2 border-primary/20 border-t-primary" />
            </div>
          ) : !roles?.length ? (
            <div className="flex flex-col items-center py-8 text-center">
              <Users size={32} className="text-muted-foreground/30 mb-2" />
              <p className="text-sm text-muted-foreground">No roles defined yet</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead />
                  <TableHead>Name</TableHead>
                  <TableHead>Description</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Permissions</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {roles.map((role) => (
                  <Fragment key={role.id}>
                    <TableRow>
                      <TableCell className="w-8">
                        <button
                          onClick={() =>
                            setExpandedRole(expandedRole === role.id ? null : role.id)
                          }
                          className="text-muted-foreground hover:text-foreground"
                        >
                          {expandedRole === role.id ? (
                            <ChevronDown size={14} />
                          ) : (
                            <ChevronRight size={14} />
                          )}
                        </button>
                      </TableCell>
                      <TableCell className="font-medium">{role.name}</TableCell>
                      <TableCell className="text-sm text-muted-foreground max-w-[240px] truncate">
                        {role.description || "—"}
                      </TableCell>
                      <TableCell>
                        <Badge variant={role.is_builtin ? "default" : "secondary"}>
                          {role.is_builtin ? "Built-in" : "Custom"}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <span className="text-sm">{role.role_permissions?.length ?? 0}</span>
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-1">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => startEdit(role)}
                            title="Edit"
                          >
                            <Pencil size={14} />
                          </Button>
                          {role.is_builtin ? (
                            <Button variant="ghost" size="sm" disabled title="Cannot delete built-in">
                              <Trash2 size={14} className="text-muted-foreground/30" />
                            </Button>
                          ) : confirmDelete === role.id ? (
                            <div className="flex items-center gap-1">
                              <Button
                                variant="destructive"
                                size="sm"
                                onClick={() => handleDelete(role.id)}
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
                              onClick={() => setConfirmDelete(role.id)}
                              title="Delete"
                            >
                              <Trash2 size={14} className="text-destructive" />
                            </Button>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                    {expandedRole === role.id && (
                      <TableRow key={`${role.id}-perms`}>
                        <TableCell colSpan={6} className="bg-accent/5">
                          <div className="flex flex-wrap gap-1 py-1">
                            {role.role_permissions?.length ? (
                              role.role_permissions.map((rp) => (
                                <Badge key={rp.permission_id} variant="secondary" className="text-[10px]">
                                  {rp.permission ? permDisplayName(rp.permission) : rp.permission_id}
                                </Badge>
                              ))
                            ) : (
                              <span className="text-xs text-muted-foreground">
                                No permissions assigned
                              </span>
                            )}
                          </div>
                        </TableCell>
                      </TableRow>
                    )}
                  </Fragment>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
