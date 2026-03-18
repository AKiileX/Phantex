// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Sidebar navigation (enterprise collapsible layout).
 *
 * Features:
 *   - Collapsible: full (224px) → icon rail (56px)
 *   - Grouped navigation like CrowdStrike Falcon
 *   - Environment badge (DEV / STAGING / PROD)
 *   - Live open-alert count badge
 *   - Tooltip labels in collapsed mode
 *   - Keyboard shortcut: [ to toggle
 *   - Collapse persists in localStorage
 */

import { useEffect } from "react"
import { NavLink } from "react-router-dom"
import {
  LayoutDashboard,
  Monitor,
  Activity,
  Bell,
  ShieldAlert,
  Shield,
  FileStack,
  ShieldOff,
  Route,
  Calendar,
  Settings,
  Network,
  Radar,
  Upload,
  Radio,
  Brain,
  PanelLeftClose,
  PanelLeftOpen,
  Orbit,
  PlayCircle,
  Grid3X3,
  Swords,
  HeartPulse,
  Eye,
  Hexagon,
  Crosshair,
  KeyRound,
  ShieldCheck,
  Building2,
  RefreshCw,
  ClipboardCheck,
  Cpu,
  Sparkles,
  Zap,
  Unplug,
  Cable,
  Ghost,
  GitCompareArrows,
  FlaskConical,
  BarChart3,
  PieChart,
  Gauge,
  ScanSearch,
  Video,
} from "lucide-react"
import { cn } from "@/lib/utils"
import { useAuthStore, selectIsAdmin } from "@/stores/authStore"
import { usePermissionStore } from "@/stores/permissionStore"
import { useSidebarStore } from "@/stores/sidebarStore"
import { PhantexLogo } from "@/components/PhantexLogo"
import { useAlerts } from "@/api/alerts"

/* ── Environment badge ─────────────────────────────────── */
const ENV = (import.meta.env.VITE_ENV ?? "development").toString().toLowerCase()
const envLabel = ENV.startsWith("prod")
  ? "PROD"
  : ENV.startsWith("stag")
    ? "STAGING"
    : "DEV"
const envColor: Record<string, string> = {
  DEV: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  STAGING: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  PROD: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
}

/* ── Nav structure ─────────────────────────────────────── */
interface NavItem {
  to: string
  label: string
  icon: React.ReactNode
  badge?: "alerts"
}

interface NavGroup {
  label: string
  items: (NavItem & {
    adminOnly?: boolean
    analystOnly?: boolean
    /** Granular permission gate — item shown only if user has ANY of these */
    requiredPermissions?: string[]
  })[]
}

const navGroups: NavGroup[] = [
  {
    label: "Overview",
    items: [
      { to: "/", label: "Dashboard", icon: <LayoutDashboard size={18} />, requiredPermissions: ["dashboard.view"] },
    ],
  },
  {
    label: "Detection & Response",
    items: [
      { to: "/alerts", label: "Alerts", icon: <Bell size={18} />, badge: "alerts", requiredPermissions: ["alerts.read"] },
      { to: "/rules", label: "Rules", icon: <ShieldAlert size={18} />, requiredPermissions: ["rules.read"] },
      { to: "/mcp-trust", label: "MCP Observatory", icon: <Eye size={18} />, requiredPermissions: ["trust.read"] },
      { to: "/events", label: "Events", icon: <Activity size={18} />, requiredPermissions: ["events.read"] },
      { to: "/policies", label: "Policies", icon: <FileStack size={18} />, requiredPermissions: ["policies.read"], analystOnly: true },
      { to: "/alert-routing", label: "Alert Routing", icon: <Route size={18} />, requiredPermissions: ["notifications.manage"], analystOnly: true },
      { to: "/exemptions", label: "Exemptions", icon: <ShieldOff size={18} />, requiredPermissions: ["policies.read"], analystOnly: true },
      { to: "/maintenance", label: "Maintenance", icon: <Calendar size={18} />, requiredPermissions: ["policies.write"], analystOnly: true },
    ],
  },
  {
    label: "Investigate",
    items: [
      { to: "/agents", label: "Agents", icon: <Monitor size={18} />, requiredPermissions: ["agents.read"] },
      { to: "/sensors", label: "Sensors", icon: <Radio size={18} />, requiredPermissions: ["agents.read"] },
      { to: "/topology", label: "Topology", icon: <Network size={18} />, requiredPermissions: ["agents.read"] },
      { to: "/trust", label: "Trust Graph", icon: <Shield size={18} />, requiredPermissions: ["trust.read"] },
      { to: "/atlas", label: "ATLAS", icon: <Radar size={18} />, requiredPermissions: ["analytics.view"] },
      { to: "/attack-chain", label: "Attack Chain", icon: <Swords size={18} />, requiredPermissions: ["analytics.view"] },
      { to: "/blast-radius", label: "Blast Radius", icon: <Crosshair size={18} />, requiredPermissions: ["analytics.view"] },
    ],
  },
  {
    label: "Intelligence",
    items: [
      { to: "/live-topology", label: "Live Topology", icon: <Orbit size={18} />, requiredPermissions: ["analytics.view"] },
      { to: "/threat-replay", label: "Threat Replay", icon: <PlayCircle size={18} />, requiredPermissions: ["analytics.view"] },
      { to: "/risk-heatmap", label: "Risk Heatmap", icon: <Grid3X3 size={18} />, requiredPermissions: ["analytics.view"] },
      { to: "/agent-vitals", label: "Agent Vitals", icon: <HeartPulse size={18} />, requiredPermissions: ["agents.read"] },
      { to: "/behavior-radar", label: "Behavior Radar", icon: <Hexagon size={18} />, requiredPermissions: ["analytics.view"] },
      { to: "/compliance", label: "Compliance", icon: <ClipboardCheck size={18} />, requiredPermissions: ["analytics.view"] },
      { to: "/nerve-center", label: "Nerve Center", icon: <Cpu size={18} />, requiredPermissions: ["telemetry.read"] },
      { to: "/agent-drift", label: "Agent Drift", icon: <GitCompareArrows size={18} />, requiredPermissions: ["analytics.view"] },
    ],
  },
  {
    label: "Analytics",
    items: [
      { to: "/analytics/overview", label: "Overview", icon: <PieChart size={18} />, requiredPermissions: ["analytics.view"] },
      { to: "/analytics/threats", label: "Threats", icon: <BarChart3 size={18} />, requiredPermissions: ["analytics.view"] },
      { to: "/analytics/ops", label: "Ops Metrics", icon: <Gauge size={18} />, requiredPermissions: ["analytics.view"] },
      { to: "/verification", label: "Verification", icon: <ScanSearch size={18} />, requiredPermissions: ["analytics.view"] },
      { to: "/data-classification", label: "Data Classification", icon: <Shield size={18} />, requiredPermissions: ["analytics.view"] },
      { to: "/finops", label: "FinOps", icon: <BarChart3 size={18} />, requiredPermissions: ["analytics.view"] },
      { to: "/a2a-protocol", label: "A2A Protocol", icon: <Cable size={18} />, requiredPermissions: ["analytics.view"] },
      { to: "/audit-recording", label: "Audit & DVR", icon: <Video size={18} />, requiredPermissions: ["analytics.view"] },
      { to: "/threat-intel", label: "Threat Intel", icon: <Radar size={18} />, requiredPermissions: ["analytics.view"] },
      { to: "/graphql", label: "GraphQL", icon: <Cable size={18} />, requiredPermissions: ["analytics.view"] },
    ],
  },
  {
    label: "Admin",
    items: [
      { to: "/red-team", label: "Red Team", icon: <FlaskConical size={18} />, requiredPermissions: ["ml.manage"], adminOnly: true },
      { to: "/exports", label: "Exports", icon: <Upload size={18} />, requiredPermissions: ["exports.generate"], adminOnly: true },
      { to: "/telemetry", label: "Telemetry", icon: <Radio size={18} />, requiredPermissions: ["telemetry.read"], adminOnly: true },
      { to: "/ml", label: "ML Models", icon: <Brain size={18} />, requiredPermissions: ["ml.manage"], adminOnly: true },
      { to: "/settings/sso", label: "SSO", icon: <KeyRound size={18} />, requiredPermissions: ["auth.manage"], adminOnly: true },
      { to: "/settings/roles", label: "Roles", icon: <ShieldCheck size={18} />, requiredPermissions: ["auth.manage"], adminOnly: true },
      { to: "/settings/tenants", label: "Tenants", icon: <Building2 size={18} />, requiredPermissions: ["tenants.read", "tenants.manage"], adminOnly: true },
      { to: "/settings/scim", label: "SCIM", icon: <RefreshCw size={18} />, requiredPermissions: ["auth.manage"], adminOnly: true },
      { to: "/settings/copilot", label: "Copilot AI", icon: <Sparkles size={18} />, requiredPermissions: ["auth.manage"], adminOnly: true },
      { to: "/settings/auto-response", label: "Auto-Response", icon: <Zap size={18} />, requiredPermissions: ["auth.manage"], adminOnly: true },
      { to: "/settings/soar", label: "SOAR", icon: <Unplug size={18} />, requiredPermissions: ["auth.manage"], adminOnly: true },
      { to: "/settings/integrations", label: "Integrations", icon: <Cable size={18} />, requiredPermissions: ["auth.manage"], adminOnly: true },
      { to: "/settings/deception", label: "Deception", icon: <Ghost size={18} />, requiredPermissions: ["auth.manage"], adminOnly: true },
      { to: "/settings", label: "Settings", icon: <Settings size={18} />, requiredPermissions: ["auth.manage", "tenants.manage"], adminOnly: true },
    ],
  },
]

export function Sidebar() {
  const isAdmin = useAuthStore(selectIsAdmin)
  const role = useAuthStore((s) => s.user?.role)
  const isAnalystOrAdmin = role === "analyst" || role === "admin"
  const permissions = usePermissionStore((s) => s.permissions)
  const permissionsLoaded = usePermissionStore((s) => s.loaded)
  const { data: openAlerts } = useAlerts({ status: "open" })
  const openCount = openAlerts?.items?.length ?? 0

  const collapsed = useSidebarStore((s) => s.collapsed)
  const toggle = useSidebarStore((s) => s.toggle)

  /* Keyboard shortcut: [ to toggle sidebar */
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "[" && !e.ctrlKey && !e.metaKey && !e.altKey) {
        const tag = (e.target as HTMLElement)?.tagName
        if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return
        toggle()
      }
    }
    window.addEventListener("keydown", handler)
    return () => window.removeEventListener("keydown", handler)
  }, [toggle])

  return (
    <aside
      className={cn(
        "fixed left-0 top-0 z-40 flex h-screen flex-col bg-sidebar border-r border-border/30 transition-all duration-300 ease-[cubic-bezier(0.16,1,0.3,1)] sidebar-mesh",
        collapsed ? "w-[56px]" : "w-56",
      )}
    >
      {/* Logo + env badge + collapse toggle */}
      <div className="flex h-13 items-center border-b border-border/30 px-3 gap-2 relative">
        {/* Subtle glow behind logo */}
        <div className="absolute inset-0 bg-gradient-to-r from-primary/[0.03] via-transparent to-transparent pointer-events-none" />
        <PhantexLogo size={24} animated={false} className="flex-shrink-0 relative z-10" />
        {!collapsed && (
          <>
            <span className="text-sm font-bold tracking-tight text-foreground relative z-10">
              PHANTEX
            </span>
            <span
              className={cn(
                "ml-auto rounded border px-1.5 py-0.5 text-[10px] font-bold uppercase leading-none tracking-wide relative z-10",
                envColor[envLabel],
              )}
            >
              {envLabel}
            </span>
          </>
        )}
      </div>

      {/* Navigation groups */}
      <nav className={cn("flex-1 overflow-y-auto py-3 space-y-4", collapsed ? "px-1" : "px-2")}>
        {navGroups.map((group) => {
          const visibleItems = group.items.filter((item) => {
            // Legacy role gates (backward compat)
            if (item.adminOnly && !isAdmin) return false
            if (item.analystOnly && !isAnalystOrAdmin) return false
            // Granular permission gate (primary)
            if (item.requiredPermissions && permissionsLoaded) {
              return item.requiredPermissions.some((p) => permissions.has(p))
            }
            return true
          })
          if (visibleItems.length === 0) return null

          return (
            <div key={group.label}>
              {!collapsed && (
                <h3 className="mb-1 px-3 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground/60">
                  {group.label}
                </h3>
              )}
              {collapsed && (
                <div className="mb-1 mx-auto h-px w-6 bg-border/30" />
              )}
              <div className="space-y-0.5">
                {visibleItems.map((item) => (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    end={item.to === "/"}
                    title={collapsed ? item.label : undefined}
                    className={({ isActive }) =>
                      cn(
                        "group/nav relative flex items-center rounded-lg text-sm font-medium transition-colors duration-200 nav-glow-hover",
                        collapsed
                          ? "justify-center h-9 w-full"
                          : "gap-2.5 px-3 py-1.5",
                        isActive
                          ? "bg-white/[0.08] text-foreground nav-active-glow"
                          : "text-sidebar-foreground hover:bg-white/[0.04] hover:text-foreground",
                      )
                    }
                  >
                    {({ isActive }) => (
                      <>
                        {/* Active indicator bar */}
                        {isActive && <span className="nav-active-indicator" />}

                        <span className={cn(
                          "flex-shrink-0 transition-colors duration-200",
                          isActive ? "text-primary" : "group-hover/nav:text-primary/70",
                        )}>
                          {item.icon}
                        </span>
                        {!collapsed && <span>{item.label}</span>}

                        {/* Tooltip in collapsed mode */}
                        {collapsed && (
                          <span className="absolute left-full ml-2 hidden group-hover/nav:flex items-center px-2.5 py-1.5 rounded-lg bg-popover border border-border/50 text-xs font-medium text-foreground whitespace-nowrap z-50 shadow-xl shadow-black/30">
                            <span className="absolute -left-1 top-1/2 -translate-y-1/2 h-2 w-2 rotate-45 bg-popover border-l border-b border-border/50" />
                            {item.label}
                          </span>
                        )}

                        {/* Live alert count badge */}
                        {item.badge === "alerts" && openCount > 0 && (
                          <span
                            className={cn(
                              "flex items-center justify-center rounded-full bg-red-500/20 text-[10px] font-bold tabular-nums text-red-400",
                              collapsed
                                ? "absolute -top-0.5 -right-0.5 h-4 min-w-4 px-1"
                                : "ml-auto h-5 min-w-5 px-1.5",
                            )}
                          >
                            {openCount > 99 ? "99+" : openCount}
                          </span>
                        )}
                      </>
                    )}
                  </NavLink>
                ))}
              </div>
            </div>
          )
        })}
      </nav>

      {/* Footer: collapse toggle + status */}
      <div className="border-t border-border/30 p-2 space-y-2">
        {/* Collapse toggle */}
        <button
          onClick={toggle}
          className="flex items-center gap-2 w-full rounded-lg px-2 py-1.5 text-xs font-medium text-muted-foreground hover:text-foreground hover:bg-white/[0.04] transition-colors cursor-pointer nav-glow-hover"
          title={collapsed ? "Expand sidebar ( [ )" : "Collapse sidebar ( [ )"}
        >
          {collapsed ? <PanelLeftOpen size={16} /> : <PanelLeftClose size={16} />}
          {!collapsed && <span>Collapse</span>}
          {!collapsed && (
            <kbd className="ml-auto text-[10px] font-mono text-muted-foreground/50 border border-border/30 rounded px-1">
              [
            </kbd>
          )}
        </button>

        {/* Status indicator */}
        {!collapsed && (
          <div className="flex items-center gap-1.5 px-2">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-status-active opacity-50" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-status-active" />
            </span>
            <span className="text-[11px] text-muted-foreground">
              System Operational
            </span>
          </div>
        )}
        {collapsed && (
          <div className="flex justify-center" title="System Operational">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-status-active opacity-50" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-status-active" />
            </span>
          </div>
        )}
      </div>
    </aside>
  )
}
