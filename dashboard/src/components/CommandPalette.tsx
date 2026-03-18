// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Command Palette (Cmd+K / Ctrl+K).
 *
 * Spotlight-style search overlay:
 *   - Navigate to any page
 *   - Search agents, alerts, events
 *   - Quick actions (toggle sidebar, theme, logout)
 *   - Fuzzy matching with highlighted results
 *   - Keyboard navigation (↑↓ Enter Escape)
 */

import { useState, useEffect, useRef, useCallback, useMemo } from "react"
import { useNavigate } from "react-router-dom"
import {
  Search,
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
  Moon,
  Sun,
  PanelLeftClose,
  LogOut,
  Keyboard,
  ArrowRight,
} from "lucide-react"
import { useAuth } from "@/hooks/useAuth"
import { useSidebarStore } from "@/stores/sidebarStore"
import { useThemeStore } from "@/stores/themeStore"

/* ── Command Item ──────────────────────────────────────── */
interface CommandItem {
  id: string
  label: string
  description?: string
  icon: React.ReactNode
  section: string
  action: () => void
  keywords?: string[]
}

/* ── Component ─────────────────────────────────────────── */
export function CommandPalette() {
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState("")
  const [selectedIndex, setSelectedIndex] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)
  const listRef = useRef<HTMLDivElement>(null)

  const navigate = useNavigate()
  const { logout } = useAuth()
  const toggleSidebar = useSidebarStore((s) => s.toggle)
  const { mode, setMode } = useThemeStore()

  const close = useCallback(() => {
    setOpen(false)
    setQuery("")
    setSelectedIndex(0)
  }, [])

  const go = useCallback(
    (path: string) => {
      navigate(path)
      close()
    },
    [navigate, close],
  )

  /* ── All commands ────────────────────────────────────── */
  const commands = useMemo<CommandItem[]>(
    () => [
      // Navigation
      { id: "nav-dashboard", label: "Dashboard", description: "Overview & metrics", icon: <LayoutDashboard size={16} />, section: "Navigate", action: () => go("/"), keywords: ["home", "overview"] },
      { id: "nav-agents", label: "Agents", description: "Sensor fleet management", icon: <Monitor size={16} />, section: "Navigate", action: () => go("/agents"), keywords: ["sensors", "fleet"] },
      { id: "nav-topology", label: "Topology", description: "Network topology view", icon: <Network size={16} />, section: "Navigate", action: () => go("/topology"), keywords: ["network", "graph"] },
      { id: "nav-trust", label: "Trust Graph", description: "Agent trust relationships", icon: <Shield size={16} />, section: "Navigate", action: () => go("/trust"), keywords: ["trust", "relationships"] },
      { id: "nav-events", label: "Events", description: "Security events timeline", icon: <Activity size={16} />, section: "Navigate", action: () => go("/events"), keywords: ["telemetry", "logs"] },
      { id: "nav-atlas", label: "ATLAS", description: "MITRE ATT&CK technique coverage", icon: <Radar size={16} />, section: "Navigate", action: () => go("/atlas"), keywords: ["mitre", "attack", "technique"] },
      { id: "nav-alerts", label: "Alerts", description: "Security detections & triage", icon: <Bell size={16} />, section: "Navigate", action: () => go("/alerts"), keywords: ["detections", "triage"] },
      { id: "nav-rules", label: "Rules", description: "PRL detection rules", icon: <ShieldAlert size={16} />, section: "Navigate", action: () => go("/rules"), keywords: ["prl", "detection"] },
      { id: "nav-policies", label: "Policies", description: "Security policy management", icon: <FileStack size={16} />, section: "Navigate", action: () => go("/policies"), keywords: ["policy"] },
      { id: "nav-exemptions", label: "Exemptions", description: "Rule exemptions & overrides", icon: <ShieldOff size={16} />, section: "Navigate", action: () => go("/exemptions"), keywords: ["whitelist", "override"] },
      { id: "nav-routing", label: "Alert Routing", description: "Notification routing rules", icon: <Route size={16} />, section: "Navigate", action: () => go("/alert-routing"), keywords: ["notification", "route"] },
      { id: "nav-maintenance", label: "Maintenance", description: "Scheduled maintenance windows", icon: <Calendar size={16} />, section: "Navigate", action: () => go("/maintenance"), keywords: ["schedule", "window"] },
      { id: "nav-exports", label: "Exports", description: "Data export & integrations", icon: <Upload size={16} />, section: "Navigate", action: () => go("/exports"), keywords: ["siem", "export"] },
      { id: "nav-telemetry", label: "Telemetry", description: "System telemetry & health", icon: <Radio size={16} />, section: "Navigate", action: () => go("/telemetry"), keywords: ["health", "metrics"] },
      { id: "nav-ml", label: "ML Models", description: "Machine learning model status", icon: <Brain size={16} />, section: "Navigate", action: () => go("/ml"), keywords: ["machine", "learning", "model"] },
      { id: "nav-settings", label: "Settings", description: "System configuration", icon: <Settings size={16} />, section: "Navigate", action: () => go("/settings"), keywords: ["config", "preferences"] },

      // Actions
      {
        id: "act-sidebar",
        label: "Toggle Sidebar",
        description: "Expand or collapse the sidebar",
        icon: <PanelLeftClose size={16} />,
        section: "Actions",
        action: () => { toggleSidebar(); close() },
        keywords: ["collapse", "expand", "sidebar"],
      },
      {
        id: "act-theme-dark",
        label: "Switch to Dark Mode",
        description: mode === "dark" ? "Currently active" : "Switch theme",
        icon: <Moon size={16} />,
        section: "Actions",
        action: () => { setMode("dark"); close() },
        keywords: ["dark", "theme", "mode"],
      },
      {
        id: "act-theme-light",
        label: "Switch to Light Mode",
        description: mode === "light" ? "Currently active" : "Switch theme",
        icon: <Sun size={16} />,
        section: "Actions",
        action: () => { setMode("light"); close() },
        keywords: ["light", "theme", "mode"],
      },
      {
        id: "act-shortcuts",
        label: "Keyboard Shortcuts",
        description: "View all keyboard shortcuts",
        icon: <Keyboard size={16} />,
        section: "Actions",
        action: () => {
          close()
          window.dispatchEvent(new CustomEvent("phantex:show-shortcuts"))
        },
        keywords: ["keyboard", "shortcuts", "hotkeys"],
      },
      {
        id: "act-logout",
        label: "Sign Out",
        description: "Log out of your session",
        icon: <LogOut size={16} />,
        section: "Actions",
        action: () => { logout(); close() },
        keywords: ["logout", "signout", "exit"],
      },
    ],
    [go, close, toggleSidebar, setMode, mode, logout],
  )

  /* ── Filtered results ────────────────────────────────── */
  const filtered = useMemo(() => {
    if (!query.trim()) return commands
    const q = query.toLowerCase()
    return commands.filter(
      (cmd) =>
        cmd.label.toLowerCase().includes(q) ||
        cmd.description?.toLowerCase().includes(q) ||
        cmd.keywords?.some((k) => k.includes(q)),
    )
  }, [commands, query])

  /* ── Grouped by section ──────────────────────────────── */
  const grouped = useMemo(() => {
    const map = new Map<string, CommandItem[]>()
    for (const item of filtered) {
      const list = map.get(item.section) ?? []
      list.push(item)
      map.set(item.section, list)
    }
    return map
  }, [filtered])

  const flatItems = useMemo(() => filtered, [filtered])

  /* ── Keyboard shortcut to open ───────────────────────── */
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault()
        setOpen((v) => !v)
      }
      // Escape to close
      if (e.key === "Escape" && open) {
        close()
      }
    }
    window.addEventListener("keydown", handler)
    return () => window.removeEventListener("keydown", handler)
  }, [open, close])

  /* Focus input when opened */
  useEffect(() => {
    if (open) {
      requestAnimationFrame(() => inputRef.current?.focus())
    }
  }, [open])

  /* Reset selection when results change */
  useEffect(() => {
    setSelectedIndex(0)
  }, [query])

  /* ── Keyboard navigation ─────────────────────────────── */
  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "ArrowDown") {
        e.preventDefault()
        setSelectedIndex((i) => Math.min(i + 1, flatItems.length - 1))
      } else if (e.key === "ArrowUp") {
        e.preventDefault()
        setSelectedIndex((i) => Math.max(i - 1, 0))
      } else if (e.key === "Enter") {
        e.preventDefault()
        flatItems[selectedIndex]?.action()
      }
    },
    [flatItems, selectedIndex],
  )

  /* Scroll selected item into view */
  useEffect(() => {
    const el = listRef.current?.querySelector(`[data-index="${selectedIndex}"]`)
    el?.scrollIntoView({ block: "nearest" })
  }, [selectedIndex])

  if (!open) return null

  let globalIndex = -1

  return (
    <div className="fixed inset-0 z-[100] flex items-start justify-center pt-[15vh]">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm animate-fade-in"
        onClick={close}
      />

      {/* Palette */}
      <div className="relative w-full max-w-lg mx-4 bg-popover border border-border/50 rounded-xl shadow-2xl shadow-black/40 animate-slide-up overflow-hidden">
        {/* Search input */}
        <div className="flex items-center gap-3 px-4 border-b border-border/30">
          <Search size={16} className="text-muted-foreground flex-shrink-0" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Type a command or search…"
            className="flex-1 h-12 bg-transparent text-sm text-foreground placeholder:text-muted-foreground focus:outline-none"
            autoComplete="off"
            spellCheck={false}
          />
          <kbd className="hidden sm:inline-flex items-center rounded border border-border/50 bg-white/[0.03] px-1.5 py-0.5 text-[10px] text-muted-foreground font-mono">
            ESC
          </kbd>
        </div>

        {/* Results */}
        <div ref={listRef} className="max-h-[360px] overflow-y-auto p-2">
          {flatItems.length === 0 ? (
            <div className="px-4 py-8 text-center text-sm text-muted-foreground">
              No results for "{query}"
            </div>
          ) : (
            Array.from(grouped.entries()).map(([section, items]) => (
              <div key={section}>
                <div className="px-3 py-1.5 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground/60">
                  {section}
                </div>
                {items.map((item) => {
                  globalIndex++
                  const idx = globalIndex
                  const isSelected = idx === selectedIndex
                  return (
                    <button
                      key={item.id}
                      data-index={idx}
                      onClick={item.action}
                      onMouseEnter={() => setSelectedIndex(idx)}
                      className={`flex items-center gap-3 w-full rounded-lg px-3 py-2 text-left transition-colors cursor-pointer ${
                        isSelected
                          ? "bg-white/[0.06] text-foreground"
                          : "text-muted-foreground hover:bg-white/[0.03] hover:text-foreground"
                      }`}
                    >
                      <span className="flex-shrink-0 opacity-60">{item.icon}</span>
                      <div className="flex-1 min-w-0">
                        <span className="text-sm font-medium">{item.label}</span>
                        {item.description && (
                          <span className="ml-2 text-xs text-muted-foreground/60">{item.description}</span>
                        )}
                      </div>
                      {isSelected && (
                        <ArrowRight size={12} className="text-primary flex-shrink-0" />
                      )}
                    </button>
                  )
                })}
              </div>
            ))
          )}
        </div>

        {/* Footer hints */}
        <div className="flex items-center gap-4 px-4 py-2 border-t border-border/30 text-[10px] text-muted-foreground/50">
          <span className="flex items-center gap-1">
            <kbd className="font-mono border border-border/30 rounded px-1">↑↓</kbd> navigate
          </span>
          <span className="flex items-center gap-1">
            <kbd className="font-mono border border-border/30 rounded px-1">↵</kbd> select
          </span>
          <span className="flex items-center gap-1">
            <kbd className="font-mono border border-border/30 rounded px-1">esc</kbd> close
          </span>
        </div>
      </div>
    </div>
  )
}
