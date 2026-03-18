// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Roles & Permissions API hooks (TanStack Query).
 *
 * CRUD for custom roles, permission listing, user role assignments.
 * Backend: /api/v1/roles, /api/v1/permissions, /api/v1/users/{id}/roles
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import apiClient from "./client"

/* ── Types ──────────────────────────────────────────────────────────── */

export interface Permission {
  id: string
  resource: string
  action: string
  description: string
}

export interface RolePermission {
  permission_id: string
  conditions: Record<string, unknown> | null
  permission: Permission
}

export interface Role {
  id: string
  tenant_id: string
  name: string
  description: string | null
  is_builtin: boolean
  policy: Record<string, unknown> | null
  role_permissions: RolePermission[]
  created_at: string
  updated_at: string
}

export interface RoleSummary {
  id: string
  name: string
  description: string | null
  is_builtin: boolean
}

export interface UserRoles {
  user_id: string
  roles: RoleSummary[]
  effective_permissions: string[]
}

export interface RoleCreate {
  name: string
  description?: string
  permission_ids: string[]
  policy?: Record<string, unknown>
}

export interface RoleUpdate {
  name?: string
  description?: string
  permission_ids?: string[]
  policy?: Record<string, unknown>
}

/* ── Query Keys ─────────────────────────────────────────────────────── */

const ROLE_KEYS = {
  all: ["roles"] as const,
  list: () => [...ROLE_KEYS.all, "list"] as const,
  detail: (id: string) => [...ROLE_KEYS.all, "detail", id] as const,
  permissions: () => ["permissions"] as const,
  userRoles: (userId: string) => ["userRoles", userId] as const,
}

/* ── Roles ──────────────────────────────────────────────────────────── */

export function useRoles() {
  return useQuery({
    queryKey: ROLE_KEYS.list(),
    queryFn: async () => {
      const { data } = await apiClient.get<Role[]>("/roles")
      return data
    },
  })
}

export function useRole(id: string) {
  return useQuery({
    queryKey: ROLE_KEYS.detail(id),
    queryFn: async () => {
      const { data } = await apiClient.get<Role>(`/roles/${id}`)
      return data
    },
    enabled: !!id,
  })
}

export function useCreateRole() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (input: RoleCreate) => {
      const { data } = await apiClient.post<Role>("/roles", input)
      return data
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ROLE_KEYS.all }),
  })
}

export function useUpdateRole() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ id, ...input }: RoleUpdate & { id: string }) => {
      const { data } = await apiClient.put<Role>(`/roles/${id}`, input)
      return data
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ROLE_KEYS.all }),
  })
}

export function useDeleteRole() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (id: string) => {
      await apiClient.delete(`/roles/${id}`)
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ROLE_KEYS.all }),
  })
}

/* ── Permissions ────────────────────────────────────────────────────── */

export function usePermissions() {
  return useQuery({
    queryKey: ROLE_KEYS.permissions(),
    queryFn: async () => {
      const { data } = await apiClient.get<Permission[]>("/permissions")
      return data
    },
    staleTime: 60_000, // permissions rarely change
  })
}

/* ── User Role Assignments ──────────────────────────────────────────── */

export function useUserRoles(userId: string) {
  return useQuery({
    queryKey: ROLE_KEYS.userRoles(userId),
    queryFn: async () => {
      const { data } = await apiClient.get<UserRoles>(`/users/${userId}/roles`)
      return data
    },
    enabled: !!userId,
  })
}

export function useAssignRole() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ userId, roleId }: { userId: string; roleId: string }) => {
      await apiClient.post(`/users/${userId}/roles`, { role_id: roleId })
    },
    onSuccess: (_d, vars) => {
      qc.invalidateQueries({ queryKey: ROLE_KEYS.userRoles(vars.userId) })
    },
  })
}

export function useRemoveRole() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ userId, roleId }: { userId: string; roleId: string }) => {
      await apiClient.delete(`/users/${userId}/roles/${roleId}`)
    },
    onSuccess: (_d, vars) => {
      qc.invalidateQueries({ queryKey: ROLE_KEYS.userRoles(vars.userId) })
    },
  })
}
