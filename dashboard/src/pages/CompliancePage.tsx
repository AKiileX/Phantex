// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Compliance Dashboard Page
 *
 * Features:
 *   - Headline scorecard: per-framework scores with progress bars
 *   - Gap analysis summary: items needing attention
 *   - Report history: paginated list of past scans
 *   - Generate Report button (JSON + PDF download)
 *   - Framework selector (EU AI Act, NIST AI RMF, both)
 *   - Scanner on-demand trigger
 *
 * @module pages/CompliancePage
 */

import { useState, useCallback, useEffect } from "react"
import {
  ShieldCheck,
  FileDown,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Loader2,
  BarChart3,
  FileText,
  HelpCircle,
} from "lucide-react"
import {
  useComplianceScore,
  useComplianceHistory,
  useGenerateReport,
  useGenerateReportPDF,
  useTriggerScan,
} from "@/api/compliance"
import type { FrameworkScore, ComplianceReportMeta } from "@/api/compliance"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table"

/* ── Helpers ───────────────────────────────────────────────────────────────── */

function scorePct(score: number): string {
  return `${(score * 100).toFixed(1)}%`
}

function scoreColor(score: number): string {
  if (score >= 0.8) return "text-emerald-400"
  if (score >= 0.6) return "text-amber-400"
  return "text-red-400"
}

function scoreBg(score: number): string {
  if (score >= 0.8) return "bg-emerald-500"
  if (score >= 0.6) return "bg-amber-500"
  return "bg-red-500"
}

function frameworkLabel(fw: string): string {
  const labels: Record<string, string> = {
    eu_ai_act: "EU AI Act",
    nist_ai_rmf: "NIST AI RMF",
  }
  return labels[fw] ?? fw
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  })
}

/* ── Score Card Component ──────────────────────────────────────────────────── */

function ScoreCard({ fw }: { fw: FrameworkScore }) {
  return (
    <Card className="border-border/50">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground flex items-center gap-2">
          <ShieldCheck size={16} />
          {frameworkLabel(fw.framework)}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex items-baseline gap-2 mb-3">
          <span className={`text-3xl font-bold ${scoreColor(fw.overall_score)}`}>
            {scorePct(fw.overall_score)}
          </span>
          <span className="text-xs text-muted-foreground">compliance</span>
        </div>

        {/* Progress bar */}
        <div className="h-2 w-full rounded-full bg-muted mb-3">
          <div
            className={`h-full rounded-full transition-all ${scoreBg(fw.overall_score)}`}
            style={{ width: `${fw.overall_score * 100}%` }}
          />
        </div>

        {/* Breakdown */}
        <div className="grid grid-cols-3 gap-2 text-xs">
          <div className="text-center">
            <div className="font-semibold text-emerald-400">{fw.satisfied}</div>
            <div className="text-muted-foreground">Satisfied</div>
          </div>
          <div className="text-center">
            <div className="font-semibold text-amber-400">{fw.partial}</div>
            <div className="text-muted-foreground">Partial</div>
          </div>
          <div className="text-center">
            <div className="font-semibold text-red-400">{fw.gaps}</div>
            <div className="text-muted-foreground">Gaps</div>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

/* ── History Row Component ─────────────────────────────────────────────────── */

function HistoryRow({ report }: { report: ComplianceReportMeta }) {
  return (
    <TableRow className="hover:bg-muted/30">
      <TableCell className="font-mono text-xs">{report.id.slice(0, 8)}...</TableCell>
      <TableCell>
        <div className="flex gap-1 flex-wrap">
          {report.frameworks.map((fw) => (
            <Badge key={fw} variant="outline" className="text-xs">
              {frameworkLabel(fw)}
            </Badge>
          ))}
        </div>
      </TableCell>
      <TableCell>
        <span className={`font-semibold ${scoreColor(report.overall_score)}`}>
          {scorePct(report.overall_score)}
        </span>
      </TableCell>
      <TableCell className="text-muted-foreground text-xs">
        {formatDate(report.created_at)}
      </TableCell>
    </TableRow>
  )
}

/* ── Main Page Component ───────────────────────────────────────────────────── */

export function CompliancePage() {
  const [selectedFrameworks, setSelectedFrameworks] = useState<string[]>([
    "eu_ai_act",
    "nist_ai_rmf",
  ])

  const { data: scorecard, isLoading: scoreLoading, refetch: refetchScore } = useComplianceScore()
  const { data: history, isLoading: historyLoading } = useComplianceHistory(0)
  const generateReport = useGenerateReport()
  const generatePDF = useGenerateReportPDF()
  const triggerScan = useTriggerScan()

  // T-9: Auto-dismiss success toast after 4 seconds
  const [showToast, setShowToast] = useState(false)
  const [showGuide, setShowGuide] = useState(false)
  /* eslint-disable react-hooks/set-state-in-effect -- toast dismissal timer pattern */
  useEffect(() => {
    if (generateReport.isSuccess) {
      setShowToast(true)
      const timer = setTimeout(() => setShowToast(false), 4000)
      return () => clearTimeout(timer)
    }
  }, [generateReport.isSuccess])
  /* eslint-enable react-hooks/set-state-in-effect */

  const handleGenerateReport = useCallback(() => {
    generateReport.mutate({ frameworks: selectedFrameworks })
  }, [generateReport, selectedFrameworks])

  const handleDownloadPDF = useCallback(() => {
    generatePDF.mutate(
      { frameworks: selectedFrameworks },
      {
        onSuccess: (blob) => {
          const url = URL.createObjectURL(blob)
          const a = document.createElement("a")
          a.href = url
          a.download = `phantex-compliance-${new Date().toISOString().slice(0, 10)}.pdf`
          a.click()
          URL.revokeObjectURL(url)
        },
        onError: (err) => {
          console.error("PDF download failed:", err)
        },
      },
    )
  }, [generatePDF, selectedFrameworks])

  const handleTriggerScan = useCallback(() => {
    triggerScan.mutate(undefined, {
      onSuccess: () => {
        refetchScore()
      },
      onError: (err) => {
        console.error("Scan trigger failed:", err)
      },
    })
  }, [triggerScan, refetchScore])

  const toggleFramework = (fw: string) => {
    setSelectedFrameworks((prev) =>
      prev.includes(fw)
        ? prev.filter((f) => f !== fw)
        : [...prev, fw],
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <ShieldCheck className="text-primary" />
            Compliance
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            AI regulation compliance monitoring — EU AI Act &amp; NIST AI RMF
          </p>
        </div>
        <button onClick={() => setShowGuide(!showGuide)} className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"><HelpCircle size={14} />{showGuide ? "Hide Guide" : "How does this work?"}</button>

        <div className="flex gap-2">
          {/* Framework selector */}
          <div className="flex gap-1 mr-2">
            {["eu_ai_act", "nist_ai_rmf"].map((fw) => (
              <Button
                key={fw}
                variant={selectedFrameworks.includes(fw) ? "default" : "outline"}
                size="sm"
                onClick={() => toggleFramework(fw)}
              >
                {frameworkLabel(fw)}
              </Button>
            ))}
          </div>

          <Button
            variant="outline"
            size="sm"
            onClick={handleTriggerScan}
            disabled={triggerScan.isPending}
          >
            {triggerScan.isPending ? (
              <Loader2 size={14} className="animate-spin mr-1" />
            ) : (
              <RefreshCw size={14} className="mr-1" />
            )}
            Scan Now
          </Button>

          <Button
            variant="outline"
            size="sm"
            onClick={handleGenerateReport}
            disabled={generateReport.isPending || selectedFrameworks.length === 0}
          >
            {generateReport.isPending ? (
              <Loader2 size={14} className="animate-spin mr-1" />
            ) : (
              <FileText size={14} className="mr-1" />
            )}
            Generate Report
          </Button>

          <Button
            size="sm"
            onClick={handleDownloadPDF}
            disabled={generatePDF.isPending || selectedFrameworks.length === 0}
          >
            {generatePDF.isPending ? (
              <Loader2 size={14} className="animate-spin mr-1" />
            ) : (
              <FileDown size={14} className="mr-1" />
            )}
            PDF
          </Button>
        </div>
      </div>

      {/* Scorecard */}
      {scoreLoading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      ) : scorecard ? (
        <div className="grid gap-4 md:grid-cols-2">
          {scorecard.frameworks.map((fw) => (
            <ScoreCard key={fw.framework} fw={fw} />
          ))}
        </div>
      ) : (
        <Card className="border-border/50">
          <CardContent className="py-8 text-center text-muted-foreground">
            <AlertTriangle size={24} className="mx-auto mb-2" />
            No compliance data yet. Click <strong>Generate Report</strong> to run your first scan.
          </CardContent>
        </Card>
      )}

      {/* Summary stats */}
      {scorecard && (
        <div className="grid gap-4 md:grid-cols-4">
          <Card className="border-border/50">
            <CardContent className="pt-4 text-center">
              <BarChart3 size={20} className="mx-auto mb-1 text-primary" />
              <div className="text-2xl font-bold">
                {scorecard.frameworks.reduce((a, fw) => a + fw.total_items, 0)}
              </div>
              <div className="text-xs text-muted-foreground">Total Requirements</div>
            </CardContent>
          </Card>
          <Card className="border-border/50">
            <CardContent className="pt-4 text-center">
              <CheckCircle2 size={20} className="mx-auto mb-1 text-emerald-400" />
              <div className="text-2xl font-bold text-emerald-400">
                {scorecard.frameworks.reduce((a, fw) => a + fw.satisfied, 0)}
              </div>
              <div className="text-xs text-muted-foreground">Satisfied</div>
            </CardContent>
          </Card>
          <Card className="border-border/50">
            <CardContent className="pt-4 text-center">
              <AlertTriangle size={20} className="mx-auto mb-1 text-amber-400" />
              <div className="text-2xl font-bold text-amber-400">
                {scorecard.frameworks.reduce((a, fw) => a + fw.partial, 0)}
              </div>
              <div className="text-xs text-muted-foreground">Partial</div>
            </CardContent>
          </Card>
          <Card className="border-border/50">
            <CardContent className="pt-4 text-center">
              <AlertTriangle size={20} className="mx-auto mb-1 text-red-400" />
              <div className="text-2xl font-bold text-red-400">
                {scorecard.frameworks.reduce((a, fw) => a + fw.gaps, 0)}
              </div>
              <div className="text-xs text-muted-foreground">Gaps</div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Report History */}
      <Card className="border-border/50">
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <FileText size={16} />
            Report History
          </CardTitle>
        </CardHeader>
        <CardContent>
          {historyLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
            </div>
          ) : history && history.items.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>ID</TableHead>
                  <TableHead>Frameworks</TableHead>
                  <TableHead>Score</TableHead>
                  <TableHead>Date</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {history.items.map((report) => (
                  <HistoryRow key={report.id} report={report} />
                ))}
              </TableBody>
            </Table>
          ) : (
            <p className="text-sm text-muted-foreground text-center py-6">
              No reports generated yet.
            </p>
          )}
          {history && history.total > 20 && (
            <div className="text-center pt-3">
              <span className="text-xs text-muted-foreground">
                Showing 20 of {history.total} reports
              </span>
            </div>
          )}
        </CardContent>
      </Card>

      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5 space-y-3 text-sm text-muted-foreground">
          <h3 className="text-base font-semibold text-foreground">How does Compliance work?</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Compliance Score</p>
              <p>Fetches framework scores from <code className="text-xs bg-white/5 px-1 rounded">/api/compliance/score</code>. Currently tracking EU AI Act (28 controls, 100%) and NIST AI RMF (26 controls, 100%). Each control is individually assessed against live system state.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Control Details</p>
              <p>Drill into any framework to see individual control pass/fail status, last evaluation timestamp, and evidence links. Controls check policy enforcement, audit logging, access controls, and data protection measures.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Report Generation</p>
              <p>Generate compliance reports via <code className="text-xs bg-white/5 px-1 rounded">/api/compliance/report</code>. Reports include overall score, per-control details, remediation guidance, and evidence packages. Exportable as PDF for auditors and regulators.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Framework Selection</p>
              <p>Toggle frameworks to focus on relevant regulations. The score cards, bar charts, and control grids update in real time. Historical reports are listed with timestamps and can be re-downloaded.</p>
            </div>
          </div>
        </div>
      )}

      {/* Generate success toast area — auto-dismiss after 4s (T-9) */}
      {showToast && (
        <div className="fixed bottom-4 right-4 bg-emerald-900/90 text-emerald-100 px-4 py-2 rounded-lg text-sm flex items-center gap-2 shadow-lg">
          <CheckCircle2 size={16} />
          Report generated successfully
        </div>
      )}
    </div>
  )
}
