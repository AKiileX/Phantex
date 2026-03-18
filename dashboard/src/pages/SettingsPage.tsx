// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Settings hub page (admin only).
 *
 * Shows account info + quick-links to SSO, Roles, Tenants, SCIM sub-pages.
 */

import { Link } from "react-router-dom"
import {
  Settings,
  KeyRound,
  ShieldCheck,
  Building2,
  RefreshCw,
  ChevronRight,
} from "lucide-react"
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { useAuthStore } from "@/stores/authStore"

function SettingsRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between py-2 border-b border-border last:border-0">
      <span className="text-sm text-muted-foreground">{label}</span>
      <div className="text-sm text-foreground">{children}</div>
    </div>
  )
}

const adminLinks = [
  {
    to: "/settings/sso",
    label: "SSO Configuration",
    description: "SAML 2.0 & OIDC identity providers",
    icon: <KeyRound size={20} />,
  },
  {
    to: "/settings/roles",
    label: "Roles & Permissions",
    description: "Manage access-control roles and permission sets",
    icon: <ShieldCheck size={20} />,
  },
  {
    to: "/settings/tenants",
    label: "Tenant Management",
    description: "Create, suspend, and manage platform tenants",
    icon: <Building2 size={20} />,
  },
  {
    to: "/settings/scim",
    label: "SCIM Provisioning",
    description: "Directory sync tokens for identity providers",
    icon: <RefreshCw size={20} />,
  },
]

export function SettingsPage() {
  const user = useAuthStore((s) => s.user)

  return (
    <div className="space-y-4 animate-fade-in">
      <div>
        <h1 className="text-xl font-semibold text-foreground flex items-center gap-2">
          <Settings size={20} /> Settings
        </h1>
        <p className="text-sm text-muted-foreground">
          Account info and platform administration
        </p>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        {/* Current user info */}
        <Card>
          <CardHeader>
            <CardTitle>Your Account</CardTitle>
            <CardDescription>Signed in as {user?.email}</CardDescription>
          </CardHeader>
          <CardContent>
            <SettingsRow label="Role">
              <Badge variant="secondary" className="capitalize">{user?.role}</Badge>
            </SettingsRow>
            <SettingsRow label="Tenant ID">
              <span className="font-mono text-xs">{user?.tenant_id}</span>
            </SettingsRow>
            <SettingsRow label="User ID">
              <span className="font-mono text-xs">{user?.id}</span>
            </SettingsRow>
          </CardContent>
        </Card>

        {/* Admin quick-links */}
        <Card>
          <CardHeader>
            <CardTitle>Administration</CardTitle>
            <CardDescription>Enterprise auth & tenant management</CardDescription>
          </CardHeader>
          <CardContent className="space-y-1">
            {adminLinks.map((link) => (
              <Link
                key={link.to}
                to={link.to}
                className="flex items-center gap-3 rounded-md px-3 py-2.5 transition-colors hover:bg-accent/10 group"
              >
                <span className="text-muted-foreground group-hover:text-primary transition-colors">
                  {link.icon}
                </span>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-foreground">{link.label}</p>
                  <p className="text-xs text-muted-foreground truncate">{link.description}</p>
                </div>
                <ChevronRight size={16} className="text-muted-foreground/40 group-hover:text-foreground transition-colors" />
              </Link>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
