// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Lightweight toast notification system.
 *
 * Self-contained: context provider, hook, and rendered output.
 * No external dependencies required.
 */

import {
  createContext,
  useContext,
  useState,
  useCallback,
  useEffect,
  useRef,
  type ReactNode,
} from "react"
import { X } from "lucide-react"
import { cn } from "@/lib/utils"

/* ── Types ─────────────────────────────────────────────────────────────────── */

type ToastVariant = "default" | "success" | "error" | "warning"

interface Toast {
  id: string
  title: string
  description?: string
  variant: ToastVariant
  duration: number
}

interface ToastContextValue {
  toast: (opts: Omit<Toast, "id" | "duration"> & { duration?: number }) => void
}

/* ── Context ───────────────────────────────────────────────────────────────── */

const ToastContext = createContext<ToastContextValue | null>(null)

// eslint-disable-next-line react-refresh/only-export-components
export function useToast() {
  const ctx = useContext(ToastContext)
  if (!ctx) throw new Error("useToast must be used within ToastProvider")
  return ctx
}

/* ── Variant styles ────────────────────────────────────────────────────────── */

const VARIANT_STYLES: Record<ToastVariant, string> = {
  default:
    "bg-surface-2 border-border text-foreground",
  success:
    "bg-emerald-900/80 border-emerald-500/40 text-emerald-100",
  error:
    "bg-red-900/80 border-red-500/40 text-red-100",
  warning:
    "bg-amber-900/80 border-amber-500/40 text-amber-100",
}

/* ── Single toast item ─────────────────────────────────────────────────────── */

function ToastItem({
  toast: t,
  onDismiss,
}: {
  toast: Toast
  onDismiss: (id: string) => void
}) {
  const [exiting, setExiting] = useState(false)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    timerRef.current = setTimeout(() => {
      setExiting(true)
      setTimeout(() => onDismiss(t.id), 200) // wait for exit animation
    }, t.duration)
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current)
    }
  }, [t.id, t.duration, onDismiss])

  return (
    <div
      className={cn(
        "pointer-events-auto flex items-start gap-2 rounded-lg border px-4 py-3 shadow-lg backdrop-blur-sm transition-all duration-200",
        VARIANT_STYLES[t.variant],
        exiting ? "translate-x-full opacity-0" : "translate-x-0 opacity-100",
      )}
    >
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium">{t.title}</p>
        {t.description && (
          <p className="mt-0.5 text-xs opacity-80">{t.description}</p>
        )}
      </div>
      <button
        onClick={() => {
          setExiting(true)
          setTimeout(() => onDismiss(t.id), 200)
        }}
        className="shrink-0 rounded p-0.5 hover:bg-white/10 transition-colors cursor-pointer"
      >
        <X size={14} />
      </button>
    </div>
  )
}

/* ── Provider ──────────────────────────────────────────────────────────────── */

let toastCounter = 0

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])

  const addToast = useCallback(
    (opts: Omit<Toast, "id" | "duration"> & { duration?: number }) => {
      const id = `toast-${++toastCounter}`
      setToasts((prev) => [
        ...prev.slice(-4), // keep max 5 visible
        { id, duration: opts.duration ?? 5000, ...opts },
      ])
    },
    [],
  )

  const dismissToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id))
  }, [])

  return (
    <ToastContext.Provider value={{ toast: addToast }}>
      {children}
      {/* Toast container — bottom-right */}
      <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 pointer-events-none w-80">
        {toasts.map((t) => (
          <ToastItem key={t.id} toast={t} onDismiss={dismissToast} />
        ))}
      </div>
    </ToastContext.Provider>
  )
}
