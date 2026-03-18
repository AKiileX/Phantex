// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Main layout wrapper (Sidebar + Header + content area).
 *
 * Includes a centered radar sweep overlay (login-page style, muted black tones)
 * to give the dashboard a SOC/SIEM aesthetic without distracting from content.
 *
 * Sidebar width is driven by the sidebar Zustand store (collapsed ↔ full).
 * Global overlays (CommandPalette, KeyboardShortcuts) are mounted here
 * because they need router context (useNavigate).
 */

import { Outlet } from "react-router-dom"
import { Sidebar } from "./Sidebar"
import { Header } from "./Header"
import { CommandPalette } from "@/components/CommandPalette"
import { KeyboardShortcuts } from "@/components/KeyboardShortcuts"
import { CopilotPanel } from "@/components/copilot/CopilotPanel"
import { CopilotToggle } from "@/components/copilot/CopilotToggle"
import { useSidebarStore } from "@/stores/sidebarStore"
import { usePermissions } from "@/hooks/usePermissions"

export function MainLayout() {
  const collapsed = useSidebarStore((s) => s.collapsed)
  const ml = collapsed ? "ml-[56px]" : "ml-56"

  // Fetch + refresh the user's permission set while logged in
  usePermissions()

  return (
    <div className="min-h-screen bg-background">
      <Sidebar />
      <div className={`${ml} transition-[margin] duration-200`}>
        <Header />
        <main className="relative p-5 dot-grid min-h-[calc(100vh-3.5rem)] overflow-hidden">
          {/* ── Radar background (login-page style, muted for dashboard) ── */}
          <div className={`pointer-events-none fixed inset-0 ${ml} transition-[margin] duration-200 flex items-center justify-center`}>
            {/* Ambient glow at center */}
            <div className="absolute h-[420px] w-[420px] rounded-full bg-primary/[0.015] blur-[100px]" />

            {/* Concentric scan rings */}
            {[160, 300, 440, 580, 720].map((size) => (
              <div
                key={size}
                className="absolute rounded-full border border-primary/[0.03]"
                style={{ width: size, height: size }}
              />
            ))}

            {/* Crosshair lines */}
            <div className="absolute h-full w-px bg-gradient-to-b from-transparent via-primary/[0.03] to-transparent" />
            <div className="absolute h-px w-full bg-gradient-to-r from-transparent via-primary/[0.03] to-transparent" />

            {/* Radar sweep — GPU-composited via will-change to avoid layout thrashing */}
            <div
              className="absolute rounded-full will-change-transform"
              style={{
                width: 720,
                height: 720,
                background:
                  "conic-gradient(from 0deg, transparent 0deg, rgba(16,185,129,0.025) 12deg, rgba(16,185,129,0.008) 35deg, transparent 60deg)",
                animation: "radar-sweep 6s linear infinite",
                contain: "strict",
              }}
            />

            {/* Center dot */}
            <div className="absolute h-1 w-1 rounded-full bg-primary/20" />
          </div>

          {/* ── Page content (above radar) ── */}
          <div className="relative z-10">
            <Outlet />
          </div>
        </main>
      </div>

      {/* ── Global overlays (need router context) ── */}
      <CommandPalette />
      <KeyboardShortcuts />
      <CopilotPanel />
      <CopilotToggle />
    </div>
  )
}
