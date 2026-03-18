// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Keyboard Shortcuts Overlay.
 *
 * Triggered by pressing `?` key or from the command palette.
 * Shows all available keyboard shortcuts in a modal overlay.
 */

import { useState, useEffect, useCallback } from "react"
import { X } from "lucide-react"

interface ShortcutGroup {
  title: string
  shortcuts: { keys: string[]; description: string }[]
}

const SHORTCUT_GROUPS: ShortcutGroup[] = [
  {
    title: "Global",
    shortcuts: [
      { keys: ["Ctrl", "K"], description: "Open command palette" },
      { keys: ["["], description: "Toggle sidebar collapse" },
      { keys: ["?"], description: "Show keyboard shortcuts" },
    ],
  },
  {
    title: "Navigation",
    shortcuts: [
      { keys: ["G", "then", "D"], description: "Go to Dashboard" },
      { keys: ["G", "then", "A"], description: "Go to Agents" },
      { keys: ["G", "then", "E"], description: "Go to Events" },
      { keys: ["G", "then", "L"], description: "Go to Alerts" },
      { keys: ["G", "then", "R"], description: "Go to Rules" },
      { keys: ["G", "then", "S"], description: "Go to Settings" },
    ],
  },
  {
    title: "Lists",
    shortcuts: [
      { keys: ["J"], description: "Move down in list" },
      { keys: ["K"], description: "Move up in list" },
      { keys: ["Enter"], description: "Open selected item" },
      { keys: ["Esc"], description: "Close panel / go back" },
    ],
  },
]

export function KeyboardShortcuts() {
  const [open, setOpen] = useState(false)

  const close = useCallback(() => setOpen(false), [])

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      // ? key to open (not in input fields)
      if (e.key === "?" && !e.ctrlKey && !e.metaKey) {
        const tag = (e.target as HTMLElement)?.tagName
        if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return
        e.preventDefault()
        setOpen((v) => !v)
      }
      if (e.key === "Escape" && open) {
        close()
      }
    }
    window.addEventListener("keydown", handler)
    return () => window.removeEventListener("keydown", handler)
  }, [open, close])

  // Custom event from command palette
  useEffect(() => {
    const handler = () => setOpen(true)
    window.addEventListener("phantex:show-shortcuts", handler)
    return () => window.removeEventListener("phantex:show-shortcuts", handler)
  }, [])

  if (!open) return null

  return (
    <div className="fixed inset-0 z-[110] flex items-center justify-center">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm animate-fade-in"
        onClick={close}
      />

      {/* Modal */}
      <div className="relative w-full max-w-xl mx-4 bg-popover border border-border/50 rounded-xl shadow-2xl shadow-black/40 animate-slide-up overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-border/30">
          <h2 className="text-sm font-semibold text-foreground">Keyboard Shortcuts</h2>
          <button
            onClick={close}
            className="flex h-6 w-6 items-center justify-center rounded-md text-muted-foreground hover:text-foreground hover:bg-white/[0.04] transition-colors cursor-pointer"
          >
            <X size={14} />
          </button>
        </div>

        {/* Shortcut groups */}
        <div className="p-5 max-h-[60vh] overflow-y-auto">
          <div className="grid gap-6 sm:grid-cols-2">
            {SHORTCUT_GROUPS.map((group) => (
              <div key={group.title}>
                <h3 className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground/60 mb-3">
                  {group.title}
                </h3>
                <div className="space-y-2">
                  {group.shortcuts.map((shortcut) => (
                    <div
                      key={shortcut.description}
                      className="flex items-center justify-between"
                    >
                      <span className="text-xs text-foreground/80">
                        {shortcut.description}
                      </span>
                      <div className="flex items-center gap-1">
                        {shortcut.keys.map((key, i) =>
                          key === "then" ? (
                            <span key={i} className="text-[10px] text-muted-foreground/40 mx-0.5">
                              then
                            </span>
                          ) : (
                            <kbd
                              key={i}
                              className="inline-flex items-center justify-center min-w-[22px] h-[22px] rounded border border-border/50 bg-white/[0.03] px-1.5 text-[10px] font-mono text-muted-foreground"
                            >
                              {key}
                            </kbd>
                          ),
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Footer */}
        <div className="px-5 py-2.5 border-t border-border/30 text-[10px] text-muted-foreground/40">
          Press <kbd className="font-mono border border-border/30 rounded px-1">?</kbd> anywhere to toggle this panel
        </div>
      </div>
    </div>
  )
}
