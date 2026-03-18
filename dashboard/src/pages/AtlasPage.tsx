// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — MITRE ATLAS Coverage Page (O8).
 *
 * Shows coverage of the 14 MITRE ATLAS techniques with:
 *   - Summary cards (total, detected, coverage %)
 *   - Color-coded coverage matrix (CoverageMatrix)
 *   - Click-to-detail panel (TechniqueDetail)
 *   - CSV/JSON export with injection sanitization
 *
 * @module pages/AtlasPage
 */

import { useState, useCallback, useMemo } from "react"
import {
  ShieldCheck,
  FileJson,
  FileSpreadsheet,
  Crosshair,
  BarChart3,
  HelpCircle,
} from "lucide-react"
import { useAtlasCoverage } from "@/api/atlas"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { AnimatedNumber } from "@/components/ui/animated-number"
import { CoverageMatrix } from "@/components/atlas/CoverageMatrix"
import { TechniqueDetail } from "@/components/atlas/TechniqueDetail"
import type { AtlasTechnique } from "@/types"

/* ── CSV injection sanitization ────────────────────────────────────────────── */

/**
 * Prefix dangerous chars that spreadsheet apps interpret as formulas.
 * See OWASP CSV Injection cheat sheet.
 */
function sanitizeCsvCell(value: string): string {
  if (/^[=+\-@\t\r]/.test(value)) {
    return `'${value}`
  }
  // Wrap in quotes if it contains commas, quotes, or newlines
  if (/[",\n]/.test(value)) {
    return `"${value.replace(/"/g, '""')}"`
  }
  return value
}

function exportCsv(techniques: AtlasTechnique[]) {
  const header = "ID,Name,Tactic,Detected,Confidence,Detectors"
  const rows = techniques.map((t) => {
    const detectors = t.detected_by.map((d) => `${d.name}(${d.source})`).join("; ")
    return [
      sanitizeCsvCell(t.id),
      sanitizeCsvCell(t.name),
      sanitizeCsvCell(t.tactic),
      t.detected ? "Yes" : "No",
      t.best_confidence,
      sanitizeCsvCell(detectors),
    ].join(",")
  })
  const csv = [header, ...rows].join("\n")
  downloadBlob(csv, "atlas-coverage.csv", "text/csv;charset=utf-8;")
}

function exportJson(techniques: AtlasTechnique[]) {
  const json = JSON.stringify(
    techniques.map((t) => ({
      id: t.id,
      name: t.name,
      tactic: t.tactic,
      detected: t.detected,
      best_confidence: t.best_confidence,
      detectors: t.detected_by.map((d) => ({
        name: d.name,
        source: d.source,
        confidence: d.confidence,
      })),
    })),
    null,
    2,
  )
  downloadBlob(json, "atlas-coverage.json", "application/json")
}

function downloadBlob(content: string, filename: string, mime: string) {
  const blob = new Blob([content], { type: mime })
  const url = URL.createObjectURL(blob)
  const a = document.createElement("a")
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

/* ── Summary Card ──────────────────────────────────────────────────────────── */

interface StatCardProps {
  label: string
  value: number
  suffix?: string
  icon: React.ElementType
}

function StatCard({ label, value, suffix, icon: Icon }: StatCardProps) {
  return (
    <Card className="relative overflow-hidden">
      <CardContent className="p-4">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-[10px] uppercase tracking-widest text-muted-foreground">
              {label}
            </p>
            <div className="flex items-baseline gap-1 mt-1">
              <span className="text-2xl font-bold">
                <AnimatedNumber value={value} />
              </span>
              {suffix && (
                <span className="text-sm font-medium text-muted-foreground">
                  {suffix}
                </span>
              )}
            </div>
          </div>
          <Icon className="h-5 w-5 text-muted-foreground/40" />
        </div>
      </CardContent>
    </Card>
  )
}

/* ── Page ───────────────────────────────────────────────────────────────────── */

export default function AtlasPage() {
  const { data, isLoading, error } = useAtlasCoverage()
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [showGuide, setShowGuide] = useState(false)

  const handleSelect = useCallback((id: string) => {
    setSelectedId((prev) => (prev === id ? null : id))
  }, [])

  const handleClose = useCallback(() => {
    setSelectedId(null)
  }, [])

  const handleExportCsv = useCallback(() => {
    if (data?.techniques) exportCsv(data.techniques)
  }, [data])

  const handleExportJson = useCallback(() => {
    if (data?.techniques) exportJson(data.techniques)
  }, [data])

  const coveragePctRounded = useMemo(
    () => (data ? Math.round(data.coverage_pct) : 0),
    [data],
  )

  /* ── Loading state ───────────────────────────────────────────────────────── */

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-24">
        <div className="h-6 w-6 animate-spin rounded-full border-2 border-primary/20 border-t-primary" />
      </div>
    )
  }

  if (error || !data) {
    return (
      <div className="p-6">
        <p className="text-sm text-destructive" role="alert">
          Failed to load ATLAS coverage data.
        </p>
      </div>
    )
  }

  /* ── Render ──────────────────────────────────────────────────────────────── */

  return (
    <div className="flex flex-col gap-6 p-6">
      {/* ── Page Header ─────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <ShieldCheck className="h-5 w-5 text-primary/70" />
          <div>
            <h1 className="text-lg font-semibold">MITRE ATLAS Coverage</h1>
            <p className="text-xs text-muted-foreground">
              Detection coverage across {data.total_techniques} adversarial ML
              techniques
            </p>
          </div>
          <button onClick={() => setShowGuide(!showGuide)} className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"><HelpCircle size={14} />{showGuide ? "Hide Guide" : "How does this work?"}</button>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={handleExportCsv}
            className="gap-1.5"
          >
            <FileSpreadsheet className="h-3.5 w-3.5" />
            CSV
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={handleExportJson}
            className="gap-1.5"
          >
            <FileJson className="h-3.5 w-3.5" />
            JSON
          </Button>
        </div>
      </div>

      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5 space-y-3 text-sm text-muted-foreground">
          <h3 className="text-base font-semibold text-foreground">How does MITRE ATLAS Coverage work?</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">ATLAS Framework</p>
              <p>MITRE ATLAS (Adversarial Threat Landscape for AI Systems) catalogs real-world attacks against ML/AI systems. This page maps your PRL detection rules to ATLAS technique IDs, showing which attack vectors you can detect.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Coverage API</p>
              <p>Fetches from <code className="text-xs bg-white/5 px-1 rounded">GET /api/v1/atlas/coverage</code> which returns total techniques, detected count, coverage percentage, and per-technique detection status. Rules that reference ATLAS IDs are automatically mapped.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Export</p>
              <p>Export coverage data as CSV or JSON for compliance reporting, security audits, or integration with GRC platforms. The export includes technique ID, name, tactic, detection status, and matched rule count.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Gap Analysis</p>
              <p>Techniques without matching rules appear as gaps. Click any technique card to see its detail, including attack description, prerequisites, and recommendations for building detection rules to close the gap.</p>
            </div>
          </div>
        </div>
      )}

      {/* ── Summary Cards ───────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <StatCard
          label="Total Techniques"
          value={data.total_techniques}
          icon={BarChart3}
        />
        <StatCard
          label="Detected"
          value={data.detected_techniques}
          suffix={`/ ${data.total_techniques}`}
          icon={Crosshair}
        />
        <StatCard
          label="Coverage"
          value={coveragePctRounded}
          suffix="%"
          icon={ShieldCheck}
        />
      </div>

      {/* ── Matrix + Detail ─────────────────────────────────────────────────── */}
      <div className="flex gap-4">
        <div className={selectedId ? "flex-1 min-w-0" : "w-full"}>
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm">Coverage Matrix</CardTitle>
            </CardHeader>
            <CardContent>
              <CoverageMatrix
                techniques={data.techniques}
                selectedId={selectedId}
                onSelect={handleSelect}
              />
            </CardContent>
          </Card>
        </div>

        {selectedId && (
          <div className="w-80 shrink-0">
            <TechniqueDetail
              techniqueId={selectedId}
              onClose={handleClose}
            />
          </div>
        )}
      </div>
    </div>
  )
}
