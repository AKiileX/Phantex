// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Top header bar (enterprise toolbar).
 *
 * Features:
 *   - System health banner (critical alert warning)
 *   - Clickable breadcrumbs with entity name resolution
 *   - Cmd+K search trigger
 *   - Notification dropdown panel
 *   - User avatar with initials + role badge
 *   - Dark/Light/System theme toggle
 *   - Responsive sidebar awareness
 */

import { useCallback, useState, useRef, useEffect } from "react"
import {
  LogOut,
  Search,
  ChevronRight,
  Moon,
  Sun,
  Monitor,
  AlertTriangle,
  Zap,
  Shield,
  Building2,
  Key,
  X,
} from "lucide-react"
import { useLocation, Link } from "react-router-dom"
import { useAuth } from "@/hooks/useAuth"
import { useAlerts } from "@/api/alerts"
import { NotificationDropdown } from "@/components/NotificationDropdown"
import { useThemeStore, type ThemeMode } from "@/stores/themeStore"
import { ChangePasswordDialog } from "@/components/ChangePasswordDialog"

/* ── Theme icon map ────────────────────────────────────── */
const THEME_ICONS: Record<ThemeMode, React.ReactNode> = {
  dark: <Moon size={14} />,
  light: <Sun size={14} />,
  system: <Monitor size={14} />,
}
const THEME_CYCLE: ThemeMode[] = ["dark", "light", "system"]

/* ── Breadcrumb label map (friendly names for routes) ──── */
const ROUTE_LABELS: Record<string, string> = {
  agents: "Agents",
  topology: "Topology",
  trust: "Trust Graph",
  events: "Events",
  alerts: "Alerts",
  rules: "Rules",
  atlas: "ATLAS",
  policies: "Policies",
  exemptions: "Exemptions",
  "alert-routing": "Alert Routing",
  maintenance: "Maintenance",
  exports: "Exports",
  telemetry: "Telemetry",
  ml: "ML Models",
  settings: "Settings",
  investigate: "Investigation",
  new: "New",
  edit: "Edit",
}

/** Derive breadcrumb segments from current URL path with linking. */
function useBreadcrumbs() {
  const { pathname } = useLocation()
  if (pathname === "/") return [{ label: "Dashboard", path: "/", isId: false }]

  const segments = pathname.split("/").filter(Boolean)
  return segments.map((seg, i) => {
    const path = "/" + segments.slice(0, i + 1).join("/")
    const isId = /^[0-9a-f-]{8,}$/i.test(seg)
    const label = isId
      ? seg.slice(0, 8) + "…"
      : ROUTE_LABELS[seg] ?? seg.charAt(0).toUpperCase() + seg.slice(1)
    return { label, path, isId }
  })
}

/* ── User Avatar (initials + online dot) ────────────────── */
function UserAvatar({ email, role }: { email?: string; role?: string }) {
  const initials = email
    ? email.split("@")[0].slice(0, 2).toUpperCase()
    : "??"

  const bgColors: Record<string, string> = {
    admin: "bg-primary/20 text-primary ring-primary/30",
    analyst: "bg-blue-500/20 text-blue-400 ring-blue-500/30",
    viewer: "bg-zinc-500/20 text-zinc-400 ring-zinc-500/30",
  }
  const bg = bgColors[role ?? ""] ?? "bg-surface-3 text-muted-foreground ring-border/30"

  return (
    <div
      className={`relative flex h-8 w-8 items-center justify-center rounded-full text-[11px] font-bold ring-2 ${bg}`}
      title={email}
    >
      {initials}
      {/* Online status dot */}
      <span className="absolute -bottom-0.5 -right-0.5 flex h-2.5 w-2.5">
        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-status-active opacity-40" />
        <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-status-active border-2 border-sidebar" />
      </span>
    </div>
  )
}

/* ── User popover card (glassmorphism) ──────────────────── */
function UserCard({
  email,
  name,
  role,
  onClose,
  onLogout,
  onChangePassword,
}: {
  email?: string
  name?: string
  role?: string
  onClose: () => void
  onLogout: () => void
  onChangePassword: () => void
}) {
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose()
    }
    document.addEventListener("mousedown", handler)
    return () => document.removeEventListener("mousedown", handler)
  }, [onClose])

  const displayName = name ?? email?.split("@")[0] ?? "User"
  const org = email?.split("@")[1]?.replace(/\.\w+$/, "") ?? "Phantex"

  const roleColors: Record<string, string> = {
    admin: "bg-primary/15 text-primary border-primary/20",
    analyst: "bg-blue-500/15 text-blue-400 border-blue-500/20",
    viewer: "bg-zinc-500/15 text-zinc-400 border-zinc-500/20",
  }
  const rolePill = roleColors[role ?? ""] ?? "bg-surface-2 text-muted-foreground border-border/30"

  return (
    <div
      ref={ref}
      className="absolute right-0 top-full mt-2 w-[260px] rounded-xl glass-user-card shadow-2xl shadow-black/40 z-50 animate-slide-up overflow-hidden"
    >
      {/* Gradient accent top */}
      <div className="h-1 w-full bg-gradient-to-r from-primary/60 via-primary to-primary/60" />

      <div className="p-4 space-y-3">
        {/* Name + role */}
        <div className="flex items-start gap-3">
          <UserAvatar email={email} role={role} />
          <div className="flex-1 min-w-0">
            <p className="text-sm font-semibold text-foreground truncate">{displayName}</p>
            <p className="text-[11px] text-muted-foreground truncate">{email}</p>
          </div>
        </div>

        {/* Org + role badges */}
        <div className="flex items-center gap-2">
          <span className="flex items-center gap-1 px-2 py-0.5 rounded-md bg-white/[0.04] border border-border/30 text-[10px] font-medium text-muted-foreground">
            <Building2 size={10} />
            {org.charAt(0).toUpperCase() + org.slice(1)}
          </span>
          <span className={`flex items-center gap-1 px-2 py-0.5 rounded-md border text-[10px] font-semibold uppercase tracking-wider ${rolePill}`}>
            <Shield size={10} />
            {role}
          </span>
        </div>

        {/* Divider */}
        <div className="h-px bg-border/30" />

        {/* Quick stats */}
        <div className="flex items-center justify-between text-[11px]">
          <span className="text-muted-foreground">Session</span>
          <span className="flex items-center gap-1 text-primary font-medium">
            <Zap size={10} />
            Active
          </span>
        </div>

        {/* Change password */}
        <button
          onClick={onChangePassword}
          className="flex items-center justify-center gap-2 w-full py-2 rounded-lg text-xs font-medium text-muted-foreground hover:text-foreground bg-white/[0.02] hover:bg-white/[0.06] border border-border/30 hover:border-primary/20 transition-all cursor-pointer"
        >
          <Key size={13} />
          Change Password
        </button>

        {/* Sign out */}
        <button
          onClick={onLogout}
          className="flex items-center justify-center gap-2 w-full py-2 rounded-lg text-xs font-medium text-muted-foreground hover:text-severity-critical bg-white/[0.02] hover:bg-severity-critical/8 border border-border/30 hover:border-severity-critical/20 transition-all cursor-pointer logout-btn"
        >
          <LogOut size={13} />
          Sign out
        </button>
      </div>
    </div>
  )
}

export function Header() {
  const { user, logout } = useAuth()
  const breadcrumbs = useBreadcrumbs()
  const { mode, setMode } = useThemeStore()
  const [userCardOpen, setUserCardOpen] = useState(false)
  const [changePwOpen, setChangePwOpen] = useState(false)
  const [bannerDismissed, setBannerDismissed] = useState(false)

  // Critical alert banner
  const { data: critAlerts } = useAlerts({ status: "open", severity: "critical" })
  const critCount = critAlerts?.items?.length ?? 0

  const cycleTheme = useCallback(() => {
    const idx = THEME_CYCLE.indexOf(mode)
    const next = THEME_CYCLE[(idx + 1) % THEME_CYCLE.length]
    setMode(next)
  }, [mode, setMode])

  const openCommandPalette = useCallback(() => {
    window.dispatchEvent(
      new KeyboardEvent("keydown", { key: "k", ctrlKey: true, bubbles: true }),
    )
  }, [])

  return (
    <div className="sticky top-0 z-30">
      {/* ── Critical alert health banner (with glow + pulse) ── */}
      {critCount > 0 && !bannerDismissed && (
        <div className="flex items-center gap-2 h-9 px-4 critical-banner border-b border-severity-critical/20 relative overflow-hidden">
          {/* Animated glow sweep */}
          <div className="absolute inset-0 bg-gradient-to-r from-transparent via-severity-critical/[0.06] to-transparent animate-[shimmer_3s_ease-in-out_infinite] pointer-events-none" style={{ backgroundSize: '200% 100%' }} />

          <span className="relative flex h-2 w-2 flex-shrink-0">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-severity-critical opacity-60" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-severity-critical" />
          </span>
          <AlertTriangle size={13} className="text-severity-critical flex-shrink-0 relative" />
          <span className="text-xs font-semibold text-severity-critical relative">
            {critCount} critical alert{critCount !== 1 ? "s" : ""} require immediate attention
          </span>
          <Link
            to="/alerts?severity=critical&status=open"
            className="ml-auto relative flex items-center gap-1.5 px-3 py-1 rounded-md text-[11px] font-semibold text-severity-critical bg-severity-critical/10 hover:bg-severity-critical/20 border border-severity-critical/20 transition-all"
          >
            View alerts
            <ChevronRight size={11} />
          </Link>
          <button
            onClick={() => setBannerDismissed(true)}
            className="relative flex h-6 w-6 items-center justify-center rounded-md text-severity-critical/60 hover:text-severity-critical hover:bg-severity-critical/10 transition-all cursor-pointer"
            title="Dismiss banner"
          >
            <X size={14} />
          </button>
        </div>
      )}

      {/* ── Main header bar ───────────────────────────────── */}
      <header className="flex h-12 items-center justify-between border-b border-border/30 bg-background/80 backdrop-blur-xl px-4">
        {/* Left: breadcrumbs */}
        <div className="flex items-center gap-1 text-[13px]">
          {breadcrumbs.map((crumb, i) => (
            <span key={i} className="flex items-center gap-1">
              {i > 0 && <ChevronRight size={11} className="text-muted-foreground/40" />}
              {i < breadcrumbs.length - 1 ? (
                <Link
                  to={crumb.path}
                  className="text-muted-foreground hover:text-foreground transition-colors"
                >
                  {crumb.label}
                </Link>
              ) : (
                <span className="font-medium text-foreground">{crumb.label}</span>
              )}
            </span>
          ))}
        </div>

        {/* Center: Cmd+K search trigger */}
        <button
          onClick={openCommandPalette}
          className="hidden md:flex items-center max-w-xs flex-1 mx-8 h-8 rounded-lg border border-border/40 bg-white/[0.02] px-3 gap-2 text-sm text-muted-foreground/50 hover:bg-white/[0.04] hover:border-primary/30 hover:shadow-[0_0_12px_-4px_rgba(16,185,129,0.15)] transition-all cursor-pointer"
        >
          <Search size={13} />
          <span className="flex-1 text-left text-xs">Search or jump to…</span>
          <kbd className="rounded border border-border/40 bg-white/[0.03] px-1.5 py-0.5 text-[10px] font-mono">
            Ctrl K
          </kbd>
        </button>

        {/* Right: theme + notifications + user info */}
        <div className="flex items-center gap-1.5">
          {/* Theme toggle */}
          <button
            onClick={cycleTheme}
            className="flex h-8 w-8 items-center justify-center rounded-lg text-muted-foreground hover:text-foreground hover:bg-white/[0.04] transition-all cursor-pointer hover:shadow-[0_0_12px_-4px_rgba(16,185,129,0.12)]"
            title={`Theme: ${mode}`}
          >
            {THEME_ICONS[mode]}
          </button>

          {/* Notification dropdown */}
          <NotificationDropdown />

          <div className="h-5 w-px bg-border/30 mx-1" />

          {/* User info — clickable glassmorphism card */}
          <div className="relative">
            <button
              onClick={() => setUserCardOpen((v) => !v)}
              className="flex items-center gap-2.5 px-2 py-1 rounded-lg hover:bg-white/[0.04] transition-all cursor-pointer"
            >
              <UserAvatar email={user?.email} role={user?.role} />
              <div className="hidden lg:flex flex-col">
                <span className="text-xs font-semibold text-foreground leading-none">
                  {user?.name ?? user?.email?.split("@")[0] ?? "—"}
                </span>
                <span className="text-[10px] text-muted-foreground capitalize mt-0.5">
                  {user?.role}
                </span>
              </div>
              <ChevronRight
                size={11}
                className={`hidden lg:block text-muted-foreground/40 transition-transform duration-200 ${userCardOpen ? "rotate-90" : ""}`}
              />
            </button>

            {userCardOpen && (
              <UserCard
                email={user?.email}
                name={user?.name ?? undefined}
                role={user?.role}
                onClose={() => setUserCardOpen(false)}
                onLogout={() => {
                  setUserCardOpen(false)
                  logout()
                }}
                onChangePassword={() => {
                  setUserCardOpen(false)
                  setChangePwOpen(true)
                }}
              />
            )}
          </div>
        </div>
      </header>

      {/* Change password dialog (voluntary) */}
      {changePwOpen && <ChangePasswordDialog onClose={() => setChangePwOpen(false)} />}
    </div>
  )
}
