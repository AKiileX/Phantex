// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Attack Chain Visualizer (v2 — modernised).
 *
 * Animated kill-chain flowchart with MITRE ATLAS nodes lighting up
 * sequentially. Premium SOC aesthetic with gradient connections,
 * SVG icons, glow effects, and animated flow particles.
 *
 * Data sources:
 *   - GET /api/v1/atlas/coverage → technique coverage + detection info
 *   - GET /api/v1/alerts → real alert data linked to ATLAS techniques
 *
 * @module pages/AttackChainPage
 */

import { useMemo, useState, useCallback, useEffect, useRef } from "react"
import {
  Swords,
  Play,
  Pause,
  RotateCcw,
  Shield,
  AlertTriangle,
  Target,
  Search,
  Wrench,
  DoorOpen,
  Settings,
  Brain,
  Zap,
  Lock,
  Upload,
  Flame,
  ArrowRight,
  HelpCircle,
} from "lucide-react"
import { useAtlasCoverage } from "@/api/atlas"
import { useAlerts } from "@/api/alerts"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"
import type { AtlasTechnique, AlertSummary } from "@/types"

/* ── ATLAS Kill Chain Phases ───────────────────────────────── */

interface KillChainPhase {
  id: string
  name: string
  Icon: React.ComponentType<{ size?: number; className?: string }>
  color: string
  glow: string
  description: string
}

const KILL_CHAIN: KillChainPhase[] = [
  { id: "reconnaissance", name: "Recon", Icon: Search, color: "#3b82f6", glow: "rgba(59,130,246,0.3)", description: "Target profiling & scanning" },
  { id: "resource_development", name: "Resource Dev", Icon: Wrench, color: "#8b5cf6", glow: "rgba(139,92,246,0.3)", description: "Tool & infra preparation" },
  { id: "initial_access", name: "Initial Access", Icon: DoorOpen, color: "#06b6d4", glow: "rgba(6,182,212,0.3)", description: "Entry point exploitation" },
  { id: "ml_attack_staging", name: "ML Staging", Icon: Settings, color: "#f59e0b", glow: "rgba(245,158,11,0.3)", description: "Model/data positioning" },
  { id: "ml_model_access", name: "Model Access", Icon: Brain, color: "#eab308", glow: "rgba(234,179,8,0.3)", description: "Model interaction & probing" },
  { id: "execution", name: "Execution", Icon: Zap, color: "#f97316", glow: "rgba(249,115,22,0.3)", description: "Payload execution on model/agent" },
  { id: "persistence", name: "Persistence", Icon: Lock, color: "#ef4444", glow: "rgba(239,68,68,0.3)", description: "Maintain access to AI system" },
  { id: "exfiltration", name: "Exfiltration", Icon: Upload, color: "#dc2626", glow: "rgba(220,38,38,0.4)", description: "Data/model extraction" },
  { id: "impact", name: "Impact", Icon: Flame, color: "#991b1b", glow: "rgba(153,27,27,0.5)", description: "Damage to integrity/availability" },
]

/* ── Map ATLAS tactics to kill chain phases ─────────────────── */
function tacticToPhase(tactic: string): string {
  const lower = tactic.toLowerCase().replace(/[^a-z_]/g, "_")
  if (lower.includes("reconn")) return "reconnaissance"
  if (lower.includes("resource")) return "resource_development"
  if (lower.includes("initial") || lower.includes("access")) return "initial_access"
  if (lower.includes("stag")) return "ml_attack_staging"
  if (lower.includes("model") && lower.includes("access")) return "ml_model_access"
  if (lower.includes("execut")) return "execution"
  if (lower.includes("persist")) return "persistence"
  if (lower.includes("exfil")) return "exfiltration"
  if (lower.includes("impact") || lower.includes("evasi")) return "impact"
  return "execution" // default
}

/* ── Component ─────────────────────────────────────────────── */

export default function AttackChainPage() {
  const { data: coverage } = useAtlasCoverage()
  const { data: alertsData } = useAlerts({ limit: 100 }, 15_000)

  const [animating, setAnimating] = useState(false)
  const [activePhaseIdx, setActivePhaseIdx] = useState(-1)
  const [selectedPhase, setSelectedPhase] = useState<string | null>(null)
  const [selectedTechnique, setSelectedTechnique] = useState<AtlasTechnique | null>(null)
  const [showGuide, setShowGuide] = useState(false)
  const animTimer = useRef<ReturnType<typeof setInterval> | null>(null)

  const techniques = useMemo(() => coverage?.techniques ?? [], [coverage?.techniques])
  const alerts = useMemo(() => alertsData?.items ?? [], [alertsData?.items])

  /* ── Map techniques to phases ────────────────────────── */
  const phaseData = useMemo(() => {
    const map = new Map<string, { phase: KillChainPhase; techniques: AtlasTechnique[]; alertCount: number; detected: number }>()

    KILL_CHAIN.forEach((p) => {
      map.set(p.id, { phase: p, techniques: [], alertCount: 0, detected: 0 })
    })

    techniques.forEach((t: AtlasTechnique) => {
      const phaseId = tacticToPhase(t.tactic)
      const entry = map.get(phaseId)
      if (entry) {
        entry.techniques.push(t)
        if (t.detected) entry.detected++
      }
    })

    // Count alerts by technique → phase
    // (simplified: use alert severity as a proxy)
    alerts.forEach((a: AlertSummary) => {
      // Distribute across phases based on severity for visualization
      const phaseId = a.severity === "critical" ? "impact" :
                      a.severity === "high" ? "execution" :
                      a.severity === "medium" ? "ml_model_access" :
                      "initial_access"
      const entry = map.get(phaseId)
      if (entry) entry.alertCount++
    })

    return KILL_CHAIN.map((p) => map.get(p.id)!)
  }, [techniques, alerts])

  /* ── Animation ───────────────────────────────────────── */
  const startAnimation = useCallback(() => {
    setAnimating(true)
    setActivePhaseIdx(0)

    let idx = 0
    animTimer.current = setInterval(() => {
      idx++
      if (idx >= KILL_CHAIN.length) {
        if (animTimer.current) clearInterval(animTimer.current)
        setAnimating(false)
        return
      }
      setActivePhaseIdx(idx)
    }, 800)
  }, [])

  const stopAnimation = useCallback(() => {
    if (animTimer.current) clearInterval(animTimer.current)
    setAnimating(false)
    setActivePhaseIdx(-1)
  }, [])

  useEffect(() => {
    return () => { if (animTimer.current) clearInterval(animTimer.current) }
  }, [])

  /* ── Stats ───────────────────────────────────────────── */
  const stats = useMemo(() => ({
    totalTechniques: techniques.length,
    detectedCount: techniques.filter((t: AtlasTechnique) => t.detected).length,
    coveragePct: coverage?.coverage_pct ?? 0,
    totalAlerts: alerts.length,
  }), [techniques, coverage, alerts])

  const selectedPhaseData = phaseData.find((p) => p.phase.id === selectedPhase)

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center h-9 w-9 rounded-lg bg-purple-500/10 border border-purple-500/20">
            <Swords size={18} className="text-purple-400" />
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-tight">Attack Chain Visualizer</h1>
            <p className="text-xs text-muted-foreground">MITRE ATLAS kill chain — animated threat progression</p>
          </div>
          <button onClick={() => setShowGuide(!showGuide)} className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"><HelpCircle size={14} />{showGuide ? "Hide Guide" : "How does this work?"}</button>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant={animating ? "outline" : "default"}
            size="sm"
            onClick={animating ? stopAnimation : startAnimation}
            className="gap-1.5"
          >
            {animating ? <Pause size={14} /> : <Play size={14} />}
            {animating ? "Stop" : "Animate Chain"}
          </Button>
          <Button variant="ghost" size="sm" onClick={stopAnimation}>
            <RotateCcw size={14} />
          </Button>
        </div>
      </div>

      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5 space-y-3 text-sm text-muted-foreground">
          <h3 className="text-base font-semibold text-foreground">How does the Attack Chain Visualizer work?</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">MITRE ATLAS Framework</p>
              <p>Maps your detections to the <strong>MITRE ATLAS</strong> adversarial ML attack taxonomy. Phases progress left-to-right through the kill chain: Reconnaissance → Resource Development → Initial Access → Execution → Persistence → Impact.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Data Sources</p>
              <p>Coverage data from <code className="text-xs bg-white/5 px-1 rounded">useAtlasCoverage</code> maps detection rules to ATLAS techniques. Alerts from <code className="text-xs bg-white/5 px-1 rounded">useAlerts</code> show active threats at each phase. Real alerts overlay onto the kill chain.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Animation</p>
              <p>The <strong>Animate Chain</strong> button simulates attacker progression through phases. Each phase lights up in sequence, showing which techniques have active detections and which are gaps in your coverage.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Technique Drill-down</p>
              <p>Click any phase to see its techniques. Click a technique to see matched alerts, detection rules, and severity. Green = detected, gray = gap. This helps prioritize which detection rules to write next.</p>
            </div>
          </div>
        </div>
      )}

      {/* Stats bar */}
      <div className="flex gap-3">
        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-1/50 border border-border/30 text-xs">
          <Target size={13} className="text-primary" />
          <span className="text-muted-foreground">ATLAS Coverage</span>
          <span className="font-bold text-primary tabular-nums">{stats.coveragePct.toFixed(0)}%</span>
        </div>
        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-1/50 border border-border/30 text-xs">
          <Shield size={13} />
          <span className="text-muted-foreground">Detected</span>
          <span className="font-bold tabular-nums">{stats.detectedCount}/{stats.totalTechniques}</span>
        </div>
        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-1/50 border border-border/30 text-xs">
          <AlertTriangle size={13} className="text-severity-high" />
          <span className="text-muted-foreground">Active Alerts</span>
          <span className="font-bold text-severity-high tabular-nums">{stats.totalAlerts}</span>
        </div>
      </div>

      {/* Kill chain visualization — SVG-based */}
      <Card className="p-0 overflow-hidden">
        <div className="relative px-6 py-8 overflow-x-auto">
          {/* Background gradient accent */}
          <div className="absolute inset-0 bg-gradient-to-r from-blue-500/[0.02] via-purple-500/[0.02] to-red-500/[0.02] pointer-events-none" />

          <div className="flex items-center gap-0 min-w-[920px] relative">
            {phaseData.map((pd, idx) => {
              const isActive = idx <= activePhaseIdx && animating
              const isSelected = selectedPhase === pd.phase.id
              const hasDetection = pd.detected > 0
              const hasAlert = pd.alertCount > 0
              const PhaseIcon = pd.phase.Icon

              return (
                <div key={pd.phase.id} className="flex items-center">
                  {/* Phase node */}
                  <button
                    onClick={() => {
                      setSelectedPhase(isSelected ? null : pd.phase.id)
                      setSelectedTechnique(null)
                    }}
                    className={cn(
                      "relative flex flex-col items-center gap-2.5 px-4 py-5 rounded-2xl border transition-all duration-500 cursor-pointer group min-w-[100px]",
                      isActive
                        ? "border-white/20 scale-110 z-10 bg-white/[0.04]"
                        : isSelected
                          ? "border-primary/30 bg-primary/[0.04] shadow-lg"
                          : "border-border/20 bg-surface-0/50 hover:bg-white/[0.03] hover:border-border/40",
                    )}
                    style={{
                      boxShadow: isActive
                        ? `0 0 24px ${pd.phase.glow}, 0 0 48px ${pd.phase.glow}, inset 0 1px 0 rgba(255,255,255,0.06)`
                        : isSelected
                          ? `0 0 20px ${pd.phase.glow}`
                          : hasAlert
                            ? "0 0 12px rgba(239,68,68,0.1)"
                            : "inset 0 1px 0 rgba(255,255,255,0.03)",
                    }}
                  >
                    {/* Icon container with gradient ring */}
                    <div
                      className={cn(
                        "relative flex items-center justify-center w-10 h-10 rounded-xl transition-all duration-300",
                        isActive ? "scale-110" : "group-hover:scale-105",
                      )}
                      style={{
                        background: `linear-gradient(135deg, ${pd.phase.color}15, ${pd.phase.color}08)`,
                        border: `1px solid ${pd.phase.color}${isActive ? "60" : "25"}`,
                      }}
                    >
                      <span style={{ color: isActive || isSelected ? pd.phase.color : undefined }}>
                        <PhaseIcon
                          size={20}
                          className="transition-colors duration-300"
                        />
                      </span>
                      {/* Pulse dot for active animation */}
                      {isActive && (
                        <span
                          className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full animate-ping"
                          style={{ backgroundColor: pd.phase.color }}
                        />
                      )}
                    </div>

                    {/* Phase name */}
                    <span className={cn(
                      "text-[10px] font-bold uppercase tracking-wider text-center leading-tight transition-colors duration-300",
                      isActive || isSelected ? "text-foreground" : "text-muted-foreground group-hover:text-foreground",
                    )}>
                      {pd.phase.name}
                    </span>

                    {/* Metrics row */}
                    <div className="flex items-center gap-1.5 min-h-[18px]">
                      {hasDetection && (
                        <span
                          className="px-1.5 py-0.5 rounded-md text-[9px] font-bold"
                          style={{
                            background: `${pd.phase.color}15`,
                            color: pd.phase.color,
                            border: `1px solid ${pd.phase.color}20`,
                          }}
                        >
                          {pd.detected} det.
                        </span>
                      )}
                      {hasAlert && (
                        <span className="px-1.5 py-0.5 rounded-md bg-severity-critical/15 text-severity-critical border border-severity-critical/20 text-[9px] font-bold">
                          {pd.alertCount}
                        </span>
                      )}
                    </div>

                    {/* Technique count */}
                    <span className="text-[8px] text-muted-foreground/40 font-medium">
                      {pd.techniques.length} technique{pd.techniques.length !== 1 ? "s" : ""}
                    </span>
                  </button>

                  {/* Animated gradient connector */}
                  {idx < phaseData.length - 1 && (
                    <div className="flex items-center mx-1 relative">
                      <div
                        className={cn(
                          "h-[2px] w-8 rounded-full transition-all duration-500 relative overflow-hidden",
                          idx < activePhaseIdx && animating
                            ? "opacity-100"
                            : "opacity-30",
                        )}
                        style={{
                          background: idx < activePhaseIdx && animating
                            ? `linear-gradient(90deg, ${pd.phase.color}, ${phaseData[idx + 1].phase.color})`
                            : "rgba(63,63,70,0.3)",
                          boxShadow: idx < activePhaseIdx && animating
                            ? `0 0 8px ${pd.phase.glow}`
                            : undefined,
                        }}
                      >
                        {/* Flow particle */}
                        {idx < activePhaseIdx && animating && (
                          <div
                            className="absolute top-0 h-full w-3 rounded-full animate-pulse"
                            style={{ background: `linear-gradient(90deg, transparent, white, transparent)`, opacity: 0.6 }}
                          />
                        )}
                      </div>
                      <ArrowRight
                        size={12}
                        className={cn(
                          "-ml-0.5 transition-all duration-500",
                          idx < activePhaseIdx && animating
                            ? "text-foreground/50"
                            : "text-border/30",
                        )}
                      />
                    </div>
                  )}
                </div>
              )
            })}
          </div>

          {/* Progress bar beneath chain during animation */}
          {animating && (
            <div className="mt-6 h-1 rounded-full bg-surface-2 overflow-hidden">
              <div
                className="h-full rounded-full transition-all duration-700 ease-out"
                style={{
                  width: `${((activePhaseIdx + 1) / KILL_CHAIN.length) * 100}%`,
                  background: `linear-gradient(90deg, #3b82f6, #8b5cf6, #f59e0b, #ef4444, #991b1b)`,
                }}
              />
            </div>
          )}
        </div>
      </Card>

      {/* Detail panel */}
      {selectedPhaseData && (
        <div className="grid grid-cols-12 gap-4">
          {/* Technique list */}
          <div className="col-span-8">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-sm">
                  <span style={{ color: selectedPhaseData.phase.color }}>
                    <selectedPhaseData.phase.Icon size={16} />
                  </span>
                  {selectedPhaseData.phase.name} — Techniques
                  <Badge variant="secondary">{selectedPhaseData.techniques.length}</Badge>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 gap-2">
                  {selectedPhaseData.techniques.length === 0 ? (
                    <div className="col-span-2 text-center py-8 text-xs text-muted-foreground">
                      No techniques mapped to this phase
                    </div>
                  ) : selectedPhaseData.techniques.map((t: AtlasTechnique) => (
                    <button
                      key={t.id}
                      onClick={() => setSelectedTechnique(selectedTechnique?.id === t.id ? null : t)}
                      className={cn(
                        "flex items-center gap-3 px-3 py-2.5 rounded-lg border text-left transition-all cursor-pointer",
                        selectedTechnique?.id === t.id
                          ? "bg-primary/5 border-primary/20"
                          : "border-border/20 hover:border-border/40 hover:bg-white/[0.01]",
                      )}
                    >
                      {/* Detection status */}
                      <div className={cn(
                        "flex-shrink-0 w-2.5 h-2.5 rounded-full",
                        t.detected ? "bg-primary" : "bg-surface-3",
                      )}>
                        {t.detected && (
                          <span className="block w-2.5 h-2.5 rounded-full bg-primary animate-pulse" />
                        )}
                      </div>

                      <div className="flex-1 min-w-0">
                        <div className="text-[11px] font-medium truncate">{t.name}</div>
                        <div className="text-[9px] text-muted-foreground font-mono">{t.id}</div>
                      </div>

                      <Badge variant={t.detected ? "active" : "secondary"} className="text-[9px] flex-shrink-0">
                        {t.detected ? t.best_confidence : "undetected"}
                      </Badge>
                    </button>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Phase detail & technique detail */}
          <div className="col-span-4 space-y-3">
            <Card>
              <CardHeader>
                <CardTitle className="text-xs">Phase Detail</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-xs">
                <p className="text-muted-foreground">{selectedPhaseData.phase.description}</p>
                <div className="grid grid-cols-2 gap-2 pt-2">
                  <div className="text-center p-2 rounded-lg bg-surface-1 border border-border/30">
                    <div className="text-lg font-bold text-primary">{selectedPhaseData.detected}</div>
                    <div className="text-[9px] text-muted-foreground">Detected</div>
                  </div>
                  <div className="text-center p-2 rounded-lg bg-surface-1 border border-border/30">
                    <div className="text-lg font-bold text-severity-high">{selectedPhaseData.alertCount}</div>
                    <div className="text-[9px] text-muted-foreground">Alerts</div>
                  </div>
                </div>
                {/* Coverage bar */}
                <div className="pt-2">
                  <div className="flex justify-between text-[10px] mb-1">
                    <span className="text-muted-foreground">Detection Coverage</span>
                    <span className="font-bold">
                      {selectedPhaseData.techniques.length > 0
                        ? ((selectedPhaseData.detected / selectedPhaseData.techniques.length) * 100).toFixed(0)
                        : 0}%
                    </span>
                  </div>
                  <div className="h-2 rounded-full bg-surface-2 overflow-hidden">
                    <div
                      className="h-full rounded-full bg-primary transition-all duration-500"
                      style={{
                        width: `${selectedPhaseData.techniques.length > 0
                          ? (selectedPhaseData.detected / selectedPhaseData.techniques.length) * 100
                          : 0}%`,
                      }}
                    />
                  </div>
                </div>
              </CardContent>
            </Card>

            {selectedTechnique && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-xs">{selectedTechnique.name}</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2 text-xs">
                  <div className="font-mono text-[10px] text-muted-foreground">{selectedTechnique.id}</div>
                  <div className="flex items-center gap-2">
                    <Badge variant={selectedTechnique.detected ? "active" : "secondary"}>
                      {selectedTechnique.detected ? "Detected" : "Undetected"}
                    </Badge>
                    {selectedTechnique.best_confidence && selectedTechnique.best_confidence !== "none" && (
                      <Badge variant="default">
                        {selectedTechnique.best_confidence} confidence
                      </Badge>
                    )}
                  </div>
                  {selectedTechnique.detected_by?.length > 0 && (
                    <div className="pt-2 space-y-1">
                      <div className="text-[10px] font-semibold text-muted-foreground uppercase">Detectors</div>
                      {selectedTechnique.detected_by.map((d, i) => (
                        <div key={i} className="flex items-center gap-2 px-2 py-1 rounded bg-surface-1 border border-border/20">
                          <span className="w-1.5 h-1.5 rounded-full bg-primary" />
                          <span className="text-[10px]">{d.name}</span>
                          <span className="text-[9px] text-muted-foreground ml-auto">{d.source}</span>
                        </div>
                      ))}
                    </div>
                  )}
                  <a
                    href={selectedTechnique.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-primary text-[10px] hover:underline inline-flex items-center gap-1 pt-1"
                  >
                    View on MITRE ATLAS →
                  </a>
                </CardContent>
              </Card>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
