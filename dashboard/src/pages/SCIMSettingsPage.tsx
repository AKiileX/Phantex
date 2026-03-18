// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — SCIM Provisioning Settings Page (admin only).
 *
 * Manage SCIM bearer tokens for identity provider directory sync.
 * Route: /settings/scim
 */

import { useState } from "react"
import {
  RefreshCw,
  Plus,
  Trash2,
  Copy,
  Check,
  EyeOff,
  AlertTriangle,
  Key,
  HelpCircle,
} from "lucide-react"
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table"
import { useToast } from "@/components/ui/toast"
import { useSCIMTokens, useCreateSCIMToken, useRevokeSCIMToken } from "@/api/scim"

/* ── Copy button ──────────────────────────────────────── */

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
      {copied ? <Check size={14} className="text-green-500" /> : <Copy size={14} />}
    </button>
  )
}

/* ── Newly created token display ──────────────────────── */

function NewTokenBanner({
  token,
  onDismiss,
}: {
  token: string
  onDismiss: () => void
}) {
  return (
    <Card className="border-green-500/30 bg-green-500/5">
      <CardContent className="py-4">
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <Key size={16} className="text-green-500" />
            <p className="text-sm font-medium text-foreground">New SCIM Token Created</p>
          </div>
          <div className="flex items-center gap-2">
            <code className="flex-1 rounded bg-background border border-border px-3 py-2 text-xs font-mono text-foreground break-all select-all">
              {token}
            </code>
            <CopyButton value={token} />
          </div>
          <div className="flex items-start gap-2">
            <AlertTriangle size={14} className="text-yellow-500 mt-0.5 flex-shrink-0" />
            <p className="text-xs text-muted-foreground">
              Copy this token now. It will <strong>not</strong> be shown again.
            </p>
          </div>
          <Button variant="outline" size="sm" onClick={onDismiss}>
            I've saved the token
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}

/* ── Main Page ────────────────────────────────────────── */

export function SCIMSettingsPage() {
  const { data: tokens, isLoading } = useSCIMTokens()
  const createMut = useCreateSCIMToken()
  const revokeMut = useRevokeSCIMToken()
  const { toast } = useToast()

  const [newTokenDesc, setNewTokenDesc] = useState("")
  const [expiryDays, setExpiryDays] = useState("90")
  const [showCreate, setShowCreate] = useState(false)
  const [showGuide, setShowGuide] = useState(false)
  const [newlyCreatedToken, setNewlyCreatedToken] = useState<string | null>(null)
  const [confirmRevoke, setConfirmRevoke] = useState<string | null>(null)

  const handleCreate = () => {
    if (!newTokenDesc.trim()) return
    createMut.mutate(
      { description: newTokenDesc.trim(), expires_in_days: parseInt(expiryDays) || 90 },
      {
        onSuccess: (data) => {
          // The response includes the full token only once
          setNewlyCreatedToken(data.token ?? "")
          toast({ title: "SCIM token created", variant: "success" })
          setShowCreate(false)
          setNewTokenDesc("")
        },
        onError: (err: Error & { response?: { data?: { detail?: string } } }) =>
          toast({
            title: "Failed to create SCIM token",
            description: err?.response?.data?.detail || err.message,
            variant: "error",
          }),
      },
    )
  }

  const handleRevoke = (id: string) => {
    revokeMut.mutate(id, {
      onSuccess: () => {
        toast({ title: "Token revoked", variant: "success" })
        setConfirmRevoke(null)
      },
      onError: (err: Error & { response?: { data?: { detail?: string } } }) =>
        toast({
          title: "Failed to revoke token",
          description: err?.response?.data?.detail || err.message,
          variant: "error",
        }),
    })
  }

  const activeTokens = tokens?.filter((t) => t.is_active) ?? []
  const revokedTokens = tokens?.filter((t) => !t.is_active) ?? []

  return (
    <div className="space-y-4 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-foreground flex items-center gap-2">
            <RefreshCw size={20} /> SCIM Provisioning
          </h1>
          <p className="text-sm text-muted-foreground">
            Manage SCIM 2.0 bearer tokens for identity provider directory sync
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
              <Plus size={16} className="mr-1" /> New Token
            </Button>
          )}
        </div>
      </div>

      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
          <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
            <RefreshCw size={16} className="text-primary" />
            What is SCIM?
          </h3>
          <p className="mt-1.5 text-xs text-muted-foreground leading-relaxed">
            <strong className="text-foreground">SCIM (System for Cross-domain Identity Management)</strong> automatically
            syncs user accounts between your identity provider (Okta, Azure AD, etc.) and PhanTeX. When someone joins or leaves your company, SCIM automatically creates or deactivates their PhanTeX account — no manual setup needed.
          </p>
          <div className="mt-2 space-y-1.5 text-xs text-muted-foreground">
            <p><strong className="text-foreground">1.</strong> Click <strong className="text-foreground">New Token</strong> to generate a SCIM bearer token</p>
            <p><strong className="text-foreground">2.</strong> Copy the SCIM endpoint URL and token to your identity provider&apos;s provisioning settings</p>
            <p><strong className="text-foreground">3.</strong> Your IdP will call PhanTeX&apos;s SCIM API to create, update, and deactivate users automatically</p>
          </div>
        </div>
      )}

      {/* Info card */}
      <Card className="border-primary/20 bg-primary/5">
        <CardContent className="py-3">
          <div className="text-sm space-y-1">
            <p className="font-medium text-foreground">SCIM 2.0 Endpoint</p>
            <div className="flex items-center gap-2">
              <code className="text-xs font-mono text-foreground bg-background rounded border border-border px-2 py-1">
                {window.location.origin}/api/v1/scim/v2
              </code>
              <CopyButton value={`${window.location.origin}/api/v1/scim/v2`} />
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              Configure this URL and a bearer token in your identity provider's SCIM settings
              (e.g. Okta, Azure AD, OneLogin).
            </p>
          </div>
        </CardContent>
      </Card>

      {/* New token just created */}
      {newlyCreatedToken && (
        <NewTokenBanner
          token={newlyCreatedToken}
          onDismiss={() => setNewlyCreatedToken(null)}
        />
      )}

      {/* Create form */}
      {showCreate && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Create SCIM Token</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Description</label>
              <Input
                value={newTokenDesc}
                onChange={(e) => setNewTokenDesc(e.target.value)}
                placeholder="e.g. Okta SCIM provisioning"
                onKeyDown={(e) => e.key === "Enter" && handleCreate()}
              />
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Expires in (days)</label>
              <Input
                type="number"
                min={1}
                max={365}
                value={expiryDays}
                onChange={(e) => setExpiryDays(e.target.value)}
                placeholder="90"
              />
            </div>
            <div className="flex justify-end gap-2">
              <Button
                variant="outline"
                onClick={() => {
                  setShowCreate(false)
                  setNewTokenDesc("")
                }}
              >
                Cancel
              </Button>
              <Button onClick={handleCreate} disabled={createMut.isPending || !newTokenDesc.trim()}>
                {createMut.isPending ? "Creating…" : "Generate Token"}
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Active tokens */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Active Tokens</CardTitle>
          <CardDescription>
            {activeTokens.length} active token{activeTokens.length !== 1 && "s"}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex justify-center py-8">
              <div className="h-5 w-5 animate-spin rounded-full border-2 border-primary/20 border-t-primary" />
            </div>
          ) : !activeTokens.length ? (
            <div className="flex flex-col items-center py-8 text-center">
              <EyeOff size={32} className="text-muted-foreground/30 mb-2" />
              <p className="text-sm text-muted-foreground">No active SCIM tokens</p>
              <p className="text-xs text-muted-foreground mt-1">
                Create a token to enable directory sync with your identity provider
              </p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Description</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead>Expires</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {activeTokens.map((t) => (
                  <TableRow key={t.id}>
                    <TableCell className="font-medium">{t.description}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {t.created_at ? new Date(t.created_at).toLocaleDateString() : "—"}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {t.expires_at
                        ? new Date(t.expires_at).toLocaleDateString()
                        : "Never"}
                    </TableCell>
                    <TableCell className="text-right">
                      {confirmRevoke === t.id ? (
                        <div className="flex items-center justify-end gap-1">
                          <Button
                            variant="destructive"
                            size="sm"
                            onClick={() => handleRevoke(t.id)}
                            disabled={revokeMut.isPending}
                          >
                            Revoke
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setConfirmRevoke(null)}
                          >
                            Cancel
                          </Button>
                        </div>
                      ) : (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setConfirmRevoke(t.id)}
                          title="Revoke token"
                        >
                          <Trash2 size={14} className="text-destructive" />
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

      {/* Revoked tokens (collapsed) */}
      {revokedTokens.length > 0 && (
        <Card className="opacity-60">
          <CardHeader>
            <CardTitle className="text-base text-muted-foreground">
              Revoked Tokens ({revokedTokens.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                  <TableRow>
                  <TableHead>Description</TableHead>
                  <TableHead>Expired</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {revokedTokens.map((t) => (
                  <TableRow key={t.id}>
                    <TableCell className="text-muted-foreground line-through">
                      {t.description}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {t.expires_at ? new Date(t.expires_at).toLocaleDateString() : "—"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
