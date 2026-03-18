// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — SSO Configuration Page (admin only).
 *
 * Manage SAML 2.0 and OIDC identity provider configurations.
 * Routes: /settings/sso
 */

import { useState } from "react"
import {
  KeyRound,
  Plus,
  Trash2,
  ToggleLeft,
  ToggleRight,
  Shield,
  Globe,
  Copy,
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
  useSSOConfigs,
  useCreateSSOConfig,
  useUpdateSSOConfig,
  useDeleteSSOConfig,
  type SSOConfigCreate,
} from "@/api/sso"

/* ── Helpers ────────────────────────────────────────────── */

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      onClick={() => {
        navigator.clipboard.writeText(value)
        setCopied(true)
        setTimeout(() => setCopied(false), 2000)
      }}
      className="ml-1 text-muted-foreground hover:text-foreground"
      title="Copy"
    >
      {copied ? <Check size={14} /> : <Copy size={14} />}
    </button>
  )
}

function FieldRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[140px_1fr] items-start gap-2 py-1.5">
      <span className="text-xs text-muted-foreground pt-1.5">{label}</span>
      <div>{children}</div>
    </div>
  )
}

/* ── Create/Edit Form ─────────────────────────────────── */

const EMPTY_CREATE: SSOConfigCreate = {
  provider_type: "oidc",
  name: "",
  is_enabled: true,
  oidc_issuer: "",
  oidc_client_id: "",
  oidc_client_secret: "",
  oidc_scopes: "openid email profile",
  oidc_redirect_uri: "",
  sp_entity_id: "",
  idp_entity_id: "",
  idp_sso_url: "",
  idp_slo_url: "",
  idp_certificate: "",
  default_role: "viewer",
  jit_provisioning: true,
}

function SSOConfigForm({
  onSubmit,
  onCancel,
  isPending,
}: {
  onSubmit: (data: SSOConfigCreate) => void
  onCancel: () => void
  isPending: boolean
}) {
  const [form, setForm] = useState<SSOConfigCreate>({ ...EMPTY_CREATE })
  const set = (field: string, value: string | boolean) =>
    setForm((prev) => ({ ...prev, [field]: value }))

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">New SSO Configuration</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Provider type selector */}
        <div className="flex gap-2">
          <button
            onClick={() => set("provider_type", "oidc")}
            className={`flex items-center gap-2 rounded-md border px-3 py-2 text-sm transition-colors ${
              form.provider_type === "oidc"
                ? "border-primary bg-primary/10 text-primary"
                : "border-border text-muted-foreground hover:border-primary/50"
            }`}
          >
            <Globe size={16} /> OIDC
          </button>
          <button
            onClick={() => set("provider_type", "saml")}
            className={`flex items-center gap-2 rounded-md border px-3 py-2 text-sm transition-colors ${
              form.provider_type === "saml"
                ? "border-primary bg-primary/10 text-primary"
                : "border-border text-muted-foreground hover:border-primary/50"
            }`}
          >
            <Shield size={16} /> SAML 2.0
          </button>
        </div>

        <FieldRow label="Name">
          <Input
            value={form.name}
            onChange={(e) => set("name", e.target.value)}
            placeholder="e.g. Okta Production"
          />
        </FieldRow>

        {form.provider_type === "oidc" ? (
          <>
            <FieldRow label="Issuer URL">
              <Input
                value={form.oidc_issuer ?? ""}
                onChange={(e) => set("oidc_issuer", e.target.value)}
                placeholder="https://accounts.google.com"
              />
            </FieldRow>
            <FieldRow label="Client ID">
              <Input
                value={form.oidc_client_id ?? ""}
                onChange={(e) => set("oidc_client_id", e.target.value)}
                placeholder="your-client-id"
              />
            </FieldRow>
            <FieldRow label="Client Secret">
              <Input
                type="password"
                autoComplete="off"
                value={form.oidc_client_secret ?? ""}
                onChange={(e) => set("oidc_client_secret", e.target.value)}
                placeholder="••••••••"
              />
            </FieldRow>
            <FieldRow label="Scopes">
              <Input
                value={form.oidc_scopes ?? ""}
                onChange={(e) => set("oidc_scopes", e.target.value)}
                placeholder="openid email profile"
              />
            </FieldRow>
            <FieldRow label="Redirect URI">
              <Input
                value={form.oidc_redirect_uri ?? ""}
                onChange={(e) => set("oidc_redirect_uri", e.target.value)}
                placeholder="https://phantex.example.com/api/v1/sso/oidc/callback"
              />
            </FieldRow>
          </>
        ) : (
          <>
            <FieldRow label="SP Entity ID">
              <Input
                value={form.sp_entity_id ?? ""}
                onChange={(e) => set("sp_entity_id", e.target.value)}
                placeholder="https://phantex.example.com/saml/metadata"
              />
            </FieldRow>
            <FieldRow label="IdP Entity ID">
              <Input
                value={form.idp_entity_id ?? ""}
                onChange={(e) => set("idp_entity_id", e.target.value)}
                placeholder="https://idp.example.com/entity"
              />
            </FieldRow>
            <FieldRow label="IdP SSO URL">
              <Input
                value={form.idp_sso_url ?? ""}
                onChange={(e) => set("idp_sso_url", e.target.value)}
                placeholder="https://idp.example.com/sso/saml"
              />
            </FieldRow>
            <FieldRow label="IdP SLO URL">
              <Input
                value={form.idp_slo_url ?? ""}
                onChange={(e) => set("idp_slo_url", e.target.value)}
                placeholder="https://idp.example.com/slo/saml"
              />
            </FieldRow>
            <FieldRow label="IdP Certificate">
              <textarea
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
                rows={4}
                value={form.idp_certificate ?? ""}
                onChange={(e) => set("idp_certificate", e.target.value)}
                placeholder="-----BEGIN CERTIFICATE-----&#10;MIIDpTCCA...&#10;-----END CERTIFICATE-----"
              />
            </FieldRow>
          </>
        )}

        <FieldRow label="Default Role">
          <select
            className="rounded-md border border-border bg-background px-3 py-1.5 text-sm text-foreground focus:border-primary focus:outline-none"
            value={form.default_role ?? "viewer"}
            onChange={(e) => set("default_role", e.target.value)}
          >
            <option value="viewer">Viewer</option>
            <option value="analyst">Analyst</option>
            <option value="admin">Admin</option>
          </select>
        </FieldRow>

        <FieldRow label="JIT Provisioning">
          <button
            onClick={() => set("jit_provisioning", !form.jit_provisioning)}
            className="text-foreground"
          >
            {form.jit_provisioning ? (
              <ToggleRight size={24} className="text-primary" />
            ) : (
              <ToggleLeft size={24} className="text-muted-foreground" />
            )}
          </button>
        </FieldRow>

        <div className="flex justify-end gap-2 pt-2 border-t border-border">
          <Button variant="outline" onClick={onCancel} disabled={isPending}>
            Cancel
          </Button>
          <Button
            onClick={() => onSubmit(form)}
            disabled={
              isPending ||
              !form.name ||
              (form.provider_type === "oidc" && (!form.oidc_issuer || !form.oidc_client_id || !form.oidc_client_secret)) ||
              (form.provider_type === "saml" && (!form.idp_entity_id || !form.idp_sso_url || !form.idp_certificate))
            }
          >
            {isPending ? "Creating…" : "Create Configuration"}
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}

/* ── Main Page ────────────────────────────────────────── */

export function SSOConfigPage() {
  const { data: configs, isLoading } = useSSOConfigs()
  const createMut = useCreateSSOConfig()
  const updateMut = useUpdateSSOConfig()
  const deleteMut = useDeleteSSOConfig()
  const { toast } = useToast()
  const [showCreate, setShowCreate] = useState(false)
  const [showGuide, setShowGuide] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null)

  const handleCreate = (data: SSOConfigCreate) => {
    createMut.mutate(data, {
      onSuccess: () => {
        toast({ title: "SSO configuration created", variant: "success" })
        setShowCreate(false)
      },
      onError: (err: Error & { response?: { data?: { detail?: string } } }) => {
        toast({
          title: "Failed to create SSO config",
          description: err?.response?.data?.detail || err.message,
          variant: "error",
        })
      },
    })
  }

  const handleToggle = (id: string, currentEnabled: boolean) => {
    updateMut.mutate(
      { id, is_enabled: !currentEnabled },
      {
        onSuccess: () =>
          toast({
            title: `SSO config ${currentEnabled ? "disabled" : "enabled"}`,
            variant: "success",
          }),
      },
    )
  }

  const handleDelete = (id: string) => {
    deleteMut.mutate(id, {
      onSuccess: () => {
        toast({ title: "SSO configuration deleted", variant: "success" })
        setConfirmDelete(null)
      },
    })
  }

  return (
    <div className="space-y-4 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-foreground flex items-center gap-2">
            <KeyRound size={20} /> SSO Configuration
          </h1>
          <p className="text-sm text-muted-foreground">
            Manage SAML 2.0 and OIDC identity providers for single sign-on
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
          {!showCreate && (
            <Button onClick={() => setShowCreate(true)}>
              <Plus size={16} className="mr-1" /> Add Provider
            </Button>
          )}
        </div>
      </div>

      {showGuide && <SSOGuide />}

      {/* Info banner */}
      <Card className="border-primary/20 bg-primary/5">
        <CardContent className="py-3">
          <div className="flex items-start gap-2 text-sm">
            <Shield size={16} className="text-primary mt-0.5 flex-shrink-0" />
            <div>
              <p className="font-medium text-foreground">Security Hardened</p>
              <p className="text-muted-foreground text-xs mt-0.5">
                OIDC client secrets are encrypted at rest via Vault Transit (or Fernet fallback).
                SAML responses are validated with XML-DSig signature verification.
                All SSO endpoints are rate-limited to 10 req/min.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {showCreate && (
        <SSOConfigForm
          onSubmit={handleCreate}
          onCancel={() => setShowCreate(false)}
          isPending={createMut.isPending}
        />
      )}

      {/* Config list */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Identity Providers</CardTitle>
          <CardDescription>
            {configs?.length ?? 0} configured provider{(configs?.length ?? 0) !== 1 && "s"}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex justify-center py-8">
              <div className="h-5 w-5 animate-spin rounded-full border-2 border-primary/20 border-t-primary" />
            </div>
          ) : !configs?.length ? (
            <div className="flex flex-col items-center py-8 text-center">
              <KeyRound size={32} className="text-muted-foreground/30 mb-2" />
              <p className="text-sm text-muted-foreground">No SSO providers configured</p>
              <p className="text-xs text-muted-foreground mt-1">
                Click "Add Provider" to set up SAML or OIDC authentication
              </p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Issuer / IdP</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>JIT</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {configs.map((cfg) => (
                  <TableRow key={cfg.id}>
                    <TableCell className="font-medium">{cfg.name}</TableCell>
                    <TableCell>
                      <Badge variant="secondary" className="uppercase text-[10px]">
                        {cfg.provider_type}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs font-mono text-muted-foreground max-w-[200px] truncate">
                      {cfg.provider_type === "oidc"
                        ? cfg.oidc_issuer
                        : cfg.idp_entity_id}
                      {(cfg.oidc_issuer || cfg.idp_entity_id) && (
                        <CopyButton
                          value={cfg.provider_type === "oidc" ? cfg.oidc_issuer! : cfg.idp_entity_id!}
                        />
                      )}
                    </TableCell>
                    <TableCell>
                      <Badge variant={cfg.is_enabled ? "default" : "secondary"}>
                        {cfg.is_enabled ? "Active" : "Disabled"}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      {cfg.jit_provisioning ? (
                        <span className="text-xs text-green-500">Enabled</span>
                      ) : (
                        <span className="text-xs text-muted-foreground">Off</span>
                      )}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleToggle(cfg.id, cfg.is_enabled)}
                          title={cfg.is_enabled ? "Disable" : "Enable"}
                        >
                          {cfg.is_enabled ? (
                            <ToggleRight size={16} className="text-primary" />
                          ) : (
                            <ToggleLeft size={16} />
                          )}
                        </Button>
                        {confirmDelete === cfg.id ? (
                          <div className="flex items-center gap-1">
                            <Button
                              variant="destructive"
                              size="sm"
                              onClick={() => handleDelete(cfg.id)}
                              disabled={deleteMut.isPending}
                            >
                              Confirm
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => setConfirmDelete(null)}
                            >
                              Cancel
                            </Button>
                          </div>
                        ) : (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setConfirmDelete(cfg.id)}
                            title="Delete"
                          >
                            <Trash2 size={16} className="text-destructive" />
                          </Button>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* ACS / Callback URLs reference */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Service Provider URLs</CardTitle>
          <CardDescription>
            Configure these in your identity provider
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          <div className="flex items-center justify-between py-1.5 border-b border-border">
            <span className="text-xs text-muted-foreground">SAML ACS URL</span>
            <span className="text-xs font-mono text-foreground">
              {window.location.origin}/api/v1/sso/saml/acs
              <CopyButton value={`${window.location.origin}/api/v1/sso/saml/acs`} />
            </span>
          </div>
          <div className="flex items-center justify-between py-1.5 border-b border-border">
            <span className="text-xs text-muted-foreground">OIDC Callback URL</span>
            <span className="text-xs font-mono text-foreground">
              {window.location.origin}/api/v1/sso/oidc/callback
              <CopyButton value={`${window.location.origin}/api/v1/sso/oidc/callback`} />
            </span>
          </div>
          <div className="flex items-center justify-between py-1.5">
            <span className="text-xs text-muted-foreground">SAML Login URL</span>
            <span className="text-xs font-mono text-foreground">
              {window.location.origin}/api/v1/sso/saml/login
              <CopyButton value={`${window.location.origin}/api/v1/sso/saml/login`} />
            </span>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

function SSOGuide() {
  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
          <KeyRound size={16} className="text-primary" />
          What is SSO?
        </h3>
        <p className="mt-1.5 text-xs text-muted-foreground leading-relaxed">
          <strong className="text-foreground">Single Sign-On (SSO)</strong> lets your team log into PhanTeX
          using their existing corporate identity provider (like Okta, Azure AD, or Google Workspace) instead
          of separate passwords. This improves security by centralizing authentication and enables automatic
          account provisioning/deprovisioning when employees join or leave.
        </p>
      </div>
      <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
          <Shield size={16} className="text-primary" />
          Supported Protocols
        </h3>
        <div className="mt-3 grid gap-2 sm:grid-cols-2">
          <div className="rounded-lg border border-blue-500/20 bg-blue-500/5 p-3">
            <span className="text-xs font-semibold text-blue-400">SAML 2.0</span>
            <p className="mt-1 text-[11px] text-muted-foreground">Enterprise standard. Works with Okta, Azure AD, OneLogin, PingIdentity. Uses XML assertions and redirect-based login flow.</p>
          </div>
          <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-3">
            <span className="text-xs font-semibold text-emerald-400">OIDC (OpenID Connect)</span>
            <p className="mt-1 text-[11px] text-muted-foreground">Modern OAuth2-based protocol. Works with Google, Auth0, Keycloak. Uses JSON tokens and is simpler to configure.</p>
          </div>
        </div>
      </div>
      <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
          <Lock size={16} className="text-primary" />
          Quick Setup
        </h3>
        <div className="mt-2 space-y-1.5 text-xs text-muted-foreground">
          <p><strong className="text-foreground">1.</strong> Click <strong className="text-foreground">Add Provider</strong> and choose SAML or OIDC</p>
          <p><strong className="text-foreground">2.</strong> Enter your Identity Provider&apos;s metadata URL or upload the XML certificate</p>
          <p><strong className="text-foreground">3.</strong> Copy the ACS URL and Entity ID shown below to your IdP configuration</p>
          <p><strong className="text-foreground">4.</strong> Toggle the provider to <strong className="text-emerald-400">Enabled</strong></p>
          <p><strong className="text-foreground">5.</strong> Users can now log in with their corporate credentials via the SSO button on the login page</p>
        </div>
      </div>
    </div>
  )
}
