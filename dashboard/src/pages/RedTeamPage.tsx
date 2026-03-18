// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Red Team Simulator Dashboard.
 *
 * Campaign management, scorecard visualisation, scheduling, and
 * synthetic data generation — all in one page.
 */

import { useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  Swords,
  Play,
  Trash2,
  Plus,
  ShieldCheck,
  Clock,
  ToggleLeft,
  ToggleRight,
  Zap,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Loader2,
  HelpCircle,
  Target,
  FlaskConical,
  BarChart3,
  Shield,
} from "lucide-react"
import apiClient from "@/api/client"

/* ── Types ──────────────────────────────────────────────── */

interface AttackRun {
  attack_class: string
  epsilon: number
  samples_tested: number
  samples_evaded: number
  evasion_rate: number
  mean_perturbation: number
  duration_ms: number
}

interface Campaign {
  campaign_id: string
  campaign_type: string
  tenant_id: string
  status: string
  created_at: string
  started_at: string | null
  completed_at: string | null
  overall_evasion_rate: number
  overall_score: number
  config: Record<string, unknown>
  error: string | null
  attack_runs: AttackRun[]
}

interface CategoryScore {
  category: string
  score: number
  grade: string
  attacks_run: number
  avg_evasion_rate: number
  worst_evasion_rate: number
}

interface Scorecard {
  tenant_id: string
  generated_at: string
  overall_score: number
  overall_grade: string
  campaigns_analyzed: number
  categories: CategoryScore[]
  recommendations: string[]
}

interface Schedule {
  schedule_id: string
  tenant_id: string
  campaign_type: string
  interval_hours: number
  config: Record<string, unknown>
  enabled: boolean
  created_at: string
  last_run_at: string | null
  next_run_at: string | null
  run_count: number
}

/* ── API helpers ─────────────────────────────────────────── */

const redTeamApi = {
  listCampaigns: () => apiClient.get("/red-team/campaigns").then((r: { data: { items: Campaign[]; total: number } }) => r.data.items),
  createCampaign: (body: { campaign_type: string; config?: Record<string, unknown> }) =>
    apiClient.post("/red-team/campaigns", body).then((r: { data: Campaign }) => r.data),
  runCampaign: (id: string) => apiClient.post(`/red-team/campaigns/${encodeURIComponent(id)}/run`).then((r: { data: Campaign }) => r.data),
  deleteCampaign: (id: string) => apiClient.delete(`/red-team/campaigns/${encodeURIComponent(id)}`),
  getScorecard: () => apiClient.get("/red-team/scorecard").then((r: { data: Scorecard }) => r.data),
  listSchedules: () => apiClient.get("/red-team/schedules").then((r: { data: { items: Schedule[] } }) => r.data.items),
  createSchedule: (body: { campaign_type: string; interval_hours: number }) =>
    apiClient.post("/red-team/schedules", body).then((r: { data: Schedule }) => r.data),
  toggleSchedule: (id: string, enabled: boolean) =>
    apiClient.patch(`/red-team/schedules/${encodeURIComponent(id)}`, { enabled }).then((r: { data: Schedule }) => r.data),
  deleteSchedule: (id: string) => apiClient.delete(`/red-team/schedules/${encodeURIComponent(id)}`),
  generateEvents: (count: number) =>
    apiClient.post("/red-team/generate/events", { count }).then((r: { data: { generated: number } }) => r.data),
}

const CAMPAIGN_TYPES = ["evasion", "poisoning", "model_theft", "prompt_inject"] as const

/* ── Grade colour ────────────────────────────────────────── */

function gradeColor(grade: string) {
  switch (grade) {
    case "A": return "text-emerald-400"
    case "B": return "text-blue-400"
    case "C": return "text-amber-400"
    case "D": return "text-orange-400"
    case "F": return "text-red-400"
    default: return "text-muted-foreground"
  }
}

function statusIcon(status: string) {
  switch (status) {
    case "completed": return <CheckCircle2 size={14} className="text-emerald-400" />
    case "running": return <Loader2 size={14} className="animate-spin text-blue-400" />
    case "failed": return <XCircle size={14} className="text-red-400" />
    default: return <Clock size={14} className="text-muted-foreground" />
  }
}

/* ── Component ───────────────────────────────────────────── */

export function RedTeamPage() {
  const qc = useQueryClient()
  const [newType, setNewType] = useState<string>("evasion")
  const [showGuide, setShowGuide] = useState(false)

  const campaigns = useQuery<Campaign[]>({
    queryKey: ["red-team", "campaigns"],
    queryFn: redTeamApi.listCampaigns,
    refetchInterval: 10_000,
  })

  const scorecard = useQuery<Scorecard>({
    queryKey: ["red-team", "scorecard"],
    queryFn: redTeamApi.getScorecard,
  })

  const schedules = useQuery<Schedule[]>({
    queryKey: ["red-team", "schedules"],
    queryFn: redTeamApi.listSchedules,
  })

  const createMut = useMutation({
    mutationFn: () => redTeamApi.createCampaign({ campaign_type: newType }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["red-team"] }),
  })

  const runMut = useMutation({
    mutationFn: (id: string) => redTeamApi.runCampaign(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["red-team"] }),
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) => redTeamApi.deleteCampaign(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["red-team"] }),
  })

  const schedCreateMut = useMutation({
    mutationFn: () => redTeamApi.createSchedule({ campaign_type: newType, interval_hours: 24 }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["red-team", "schedules"] }),
  })

  const schedToggleMut = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      redTeamApi.toggleSchedule(id, enabled),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["red-team", "schedules"] }),
  })

  const schedDeleteMut = useMutation({
    mutationFn: (id: string) => redTeamApi.deleteSchedule(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["red-team", "schedules"] }),
  })

  const genEventsMut = useMutation({
    mutationFn: () => redTeamApi.generateEvents(100),
  })

  const sc = scorecard.data
  const campaignList = campaigns.data ?? []
  const scheduleList = schedules.data ?? []

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div className="flex items-center gap-3">
          <Swords size={24} className="text-red-400" />
          <div>
            <h1 className="text-xl font-bold">Red Team Simulator</h1>
            <p className="text-sm text-muted-foreground">
              Adversarial campaign management &amp; ML resilience testing
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowGuide(!showGuide)}
            className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"
          >
            <HelpCircle size={14} />
            {showGuide ? "Hide Guide" : "How does this work?"}
          </button>
          <button
            onClick={() => {
              qc.invalidateQueries({ queryKey: ["red-team"] })
            }}
            disabled={campaigns.isRefetching || scorecard.isRefetching}
            className="inline-flex items-center gap-1.5 rounded-md border border-border/50 px-3 py-1.5 text-xs hover:bg-muted/50 disabled:opacity-50 transition-colors"
          >
            <RefreshCw size={14} className={(campaigns.isRefetching || scorecard.isRefetching) ? "animate-spin" : ""} />
            Refresh
          </button>
        </div>
      </div>

      {/* How It Works Guide */}
      {showGuide && <RedTeamGuide />}

      {/* ── Scorecard ─────────────────────────────────── */}
      {sc && (
        <div className="rounded-lg border border-border/50 bg-card p-5">
          <div className="flex items-center gap-2 mb-4">
            <ShieldCheck size={18} className="text-primary" />
            <h2 className="text-sm font-semibold uppercase tracking-wide">Security Scorecard</h2>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-4">
            <div className="text-center">
              <div className={`text-3xl font-black ${gradeColor(sc.overall_grade)}`}>
                {sc.overall_grade}
              </div>
              <div className="text-xs text-muted-foreground">Overall Grade</div>
            </div>
            <div className="text-center">
              <div className="text-3xl font-black text-foreground">{sc.overall_score.toFixed(1)}</div>
              <div className="text-xs text-muted-foreground">Score / 100</div>
            </div>
            <div className="text-center">
              <div className="text-3xl font-black text-foreground">{sc.campaigns_analyzed}</div>
              <div className="text-xs text-muted-foreground">Campaigns</div>
            </div>
            <div className="text-center">
              <div className="text-3xl font-black text-foreground">{sc.categories.length}</div>
              <div className="text-xs text-muted-foreground">Categories</div>
            </div>
          </div>

          {sc.categories.length > 0 && (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 mb-4">
              {sc.categories.map((cat) => (
                <div key={cat.category} className="rounded-md border border-border/30 bg-background/50 p-3">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-medium capitalize">{cat.category.replace(/_/g, " ")}</span>
                    <span className={`text-sm font-black ${gradeColor(cat.grade)}`}>{cat.grade}</span>
                  </div>
                  <div className="h-1.5 rounded-full bg-muted/30 overflow-hidden">
                    <div
                      className="h-full rounded-full bg-primary transition-all"
                      style={{ width: `${Math.min(100, cat.score)}%` }}
                    />
                  </div>
                  <div className="flex justify-between mt-1 text-[10px] text-muted-foreground">
                    <span>{cat.attacks_run} attacks</span>
                    <span>Evasion: {(cat.avg_evasion_rate * 100).toFixed(1)}%</span>
                  </div>
                </div>
              ))}
            </div>
          )}

          {sc.recommendations.length > 0 && (
            <div className="rounded-md border border-amber-500/20 bg-amber-500/5 p-3">
              <div className="flex items-center gap-1.5 mb-1">
                <AlertTriangle size={14} className="text-amber-400" />
                <span className="text-xs font-semibold text-amber-400">Recommendations</span>
              </div>
              <ul className="list-disc list-inside text-xs text-muted-foreground space-y-0.5">
                {sc.recommendations.map((r, i) => <li key={i}>{r}</li>)}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* ── Create + Generate ─────────────────────────── */}
      <div className="flex flex-wrap items-center gap-3">
        <select
          value={newType}
          onChange={(e) => setNewType(e.target.value)}
          className="rounded-md border border-border/50 bg-background px-3 py-1.5 text-sm"
        >
          {CAMPAIGN_TYPES.map((t) => (
            <option key={t} value={t}>{t.replace(/_/g, " ")}</option>
          ))}
        </select>
        <button
          disabled={createMut.isPending}
          onClick={() => createMut.mutate()}
          className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50 transition-colors"
        >
          <Plus size={14} />
          New Campaign
        </button>
        <button
          disabled={schedCreateMut.isPending}
          onClick={() => schedCreateMut.mutate()}
          className="inline-flex items-center gap-1.5 rounded-md border border-border/50 px-3 py-1.5 text-xs hover:bg-muted/50 disabled:opacity-50 transition-colors"
        >
          <Clock size={14} />
          Schedule (24h)
        </button>
        <button
          disabled={genEventsMut.isPending}
          onClick={() => genEventsMut.mutate()}
          className="inline-flex items-center gap-1.5 rounded-md border border-border/50 px-3 py-1.5 text-xs hover:bg-muted/50 disabled:opacity-50 transition-colors"
        >
          <Zap size={14} />
          Generate 100 Events
        </button>
        {genEventsMut.isSuccess && (
          <span className="text-xs text-emerald-400">
            Generated {(genEventsMut.data as { generated: number }).generated} events
          </span>
        )}
      </div>

      {/* ── Campaign List ─────────────────────────────── */}
      <div className="rounded-lg border border-border/50 bg-card">
        <div className="border-b border-border/30 px-4 py-3">
          <h2 className="text-sm font-semibold">Campaigns ({campaignList.length})</h2>
        </div>
        {campaignList.length === 0 ? (
          <div className="px-4 py-8 text-center text-sm text-muted-foreground">
            No campaigns yet. Create one above to start adversarial testing.
          </div>
        ) : (
          <div className="divide-y divide-border/20">
            {campaignList.map((c) => (
              <div key={c.campaign_id} className="px-4 py-3 flex items-center gap-4">
                <div className="flex items-center gap-2 min-w-0 flex-1">
                  {statusIcon(c.status)}
                  <span className="text-xs font-mono truncate">{c.campaign_id.slice(0, 8)}</span>
                  <span className="rounded bg-muted/30 px-1.5 py-0.5 text-[10px] uppercase font-medium">
                    {c.campaign_type.replace(/_/g, " ")}
                  </span>
                  <span className="text-[10px] text-muted-foreground capitalize">{c.status}</span>
                </div>
                {c.status === "completed" && (
                  <div className="text-xs text-right">
                    <span className="font-semibold">{c.overall_score.toFixed(1)}</span>
                    <span className="text-muted-foreground">/100</span>
                    <span className="ml-2 text-muted-foreground">
                      evasion {(c.overall_evasion_rate * 100).toFixed(1)}%
                    </span>
                  </div>
                )}
                <div className="flex items-center gap-1">
                  {(c.status === "pending" || c.status === "failed") && (
                    <button
                      onClick={() => runMut.mutate(c.campaign_id)}
                      disabled={runMut.isPending}
                      className="rounded p-1 hover:bg-muted/50 text-blue-400"
                      title="Run campaign"
                    >
                      <Play size={14} />
                    </button>
                  )}
                  <button
                    onClick={() => deleteMut.mutate(c.campaign_id)}
                    disabled={deleteMut.isPending}
                    className="rounded p-1 hover:bg-muted/50 text-red-400"
                    title="Delete campaign"
                  >
                    <Trash2 size={14} />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ── Schedules ─────────────────────────────────── */}
      {scheduleList.length > 0 && (
        <div className="rounded-lg border border-border/50 bg-card">
          <div className="border-b border-border/30 px-4 py-3">
            <h2 className="text-sm font-semibold">Schedules ({scheduleList.length})</h2>
          </div>
          <div className="divide-y divide-border/20">
            {scheduleList.map((s) => (
              <div key={s.schedule_id} className="px-4 py-3 flex items-center gap-4">
                <div className="flex items-center gap-2 flex-1 min-w-0">
                  <Clock size={14} className="text-muted-foreground" />
                  <span className="text-xs font-mono truncate">{s.schedule_id.slice(0, 8)}</span>
                  <span className="rounded bg-muted/30 px-1.5 py-0.5 text-[10px] uppercase font-medium">
                    {s.campaign_type.replace(/_/g, " ")}
                  </span>
                  <span className="text-[10px] text-muted-foreground">
                    every {s.interval_hours}h &middot; {s.run_count} runs
                  </span>
                </div>
                <button
                  onClick={() => schedToggleMut.mutate({ id: s.schedule_id, enabled: !s.enabled })}
                  className="rounded p-1 hover:bg-muted/50"
                  title={s.enabled ? "Disable" : "Enable"}
                >
                  {s.enabled
                    ? <ToggleRight size={18} className="text-emerald-400" />
                    : <ToggleLeft size={18} className="text-muted-foreground" />
                  }
                </button>
                <button
                  onClick={() => schedDeleteMut.mutate(s.schedule_id)}
                  className="rounded p-1 hover:bg-muted/50 text-red-400"
                  title="Delete schedule"
                >
                  <Trash2 size={14} />
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Attack Run Details (expanded for completed campaigns) ── */}
      {campaignList.filter((c: Campaign) => c.status === "completed" && c.attack_runs.length > 0).length > 0 && (
        <div className="rounded-lg border border-border/50 bg-card">
          <div className="border-b border-border/30 px-4 py-3">
            <h2 className="text-sm font-semibold">Attack Run Details</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border/20 text-muted-foreground">
                  <th className="px-4 py-2 text-left font-medium">Campaign</th>
                  <th className="px-4 py-2 text-left font-medium">Attack</th>
                  <th className="px-4 py-2 text-right font-medium">Epsilon</th>
                  <th className="px-4 py-2 text-right font-medium">Tested</th>
                  <th className="px-4 py-2 text-right font-medium">Evaded</th>
                  <th className="px-4 py-2 text-right font-medium">Evasion %</th>
                  <th className="px-4 py-2 text-right font-medium">Duration</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/10">
                {campaignList
                  .filter((c: Campaign) => c.status === "completed")
                  .flatMap((c: Campaign) =>
                    c.attack_runs.map((r, i) => (
                      <tr key={`${c.campaign_id}-${i}`} className="hover:bg-muted/20">
                        <td className="px-4 py-2 font-mono">{c.campaign_id.slice(0, 8)}</td>
                        <td className="px-4 py-2 capitalize">{r.attack_class.replace(/_/g, " ")}</td>
                        <td className="px-4 py-2 text-right">{r.epsilon.toFixed(3)}</td>
                        <td className="px-4 py-2 text-right">{r.samples_tested}</td>
                        <td className="px-4 py-2 text-right">{r.samples_evaded}</td>
                        <td className="px-4 py-2 text-right font-medium">
                          <span className={r.evasion_rate > 0.15 ? "text-red-400" : r.evasion_rate > 0.05 ? "text-amber-400" : "text-emerald-400"}>
                            {(r.evasion_rate * 100).toFixed(1)}%
                          </span>
                        </td>
                        <td className="px-4 py-2 text-right text-muted-foreground">{r.duration_ms.toFixed(0)}ms</td>
                      </tr>
                    ))
                  )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}

/* ── How It Works Guide ───────────────────────────────────── */

function RedTeamGuide() {
  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
          <Swords size={16} className="text-red-400" />
          What is the Red Team Simulator?
        </h3>
        <p className="mt-1.5 text-xs text-muted-foreground leading-relaxed">
          The Red Team Simulator is an <strong className="text-foreground">adversarial testing tool</strong> that assesses
          how resilient your ML threat detection models are against real attack techniques. It generates controlled attacks
          (like evasion, poisoning, model theft, and prompt injection) against your deployed models, then measures whether
          the model can still correctly detect threats. Think of it as a security audit for your AI — it tries to break your
          defenses so you can fix weaknesses before real attackers find them.
        </p>
      </div>

      <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
          <Target size={16} className="text-red-400" />
          How It Works
        </h3>
        <p className="mt-1.5 text-xs text-muted-foreground">Here&apos;s the testing pipeline:</p>
        <div className="mt-3 flex flex-wrap items-center gap-1.5 text-xs font-medium">
          {[
            { label: "Create Campaign", color: "bg-blue-500/15 text-blue-400 border border-blue-500/20" },
            { label: "→" },
            { label: "Select attack type", color: "bg-cyan-500/15 text-cyan-400 border border-cyan-500/20" },
            { label: "→" },
            { label: "Run against model", color: "bg-amber-500/15 text-amber-400 border border-amber-500/20" },
            { label: "→" },
            { label: "Measure evasion rate", color: "bg-orange-500/15 text-orange-400 border border-orange-500/20" },
            { label: "→" },
            { label: "Generate scorecard", color: "bg-red-500/15 text-red-400 border border-red-500/20" },
            { label: "→" },
            { label: "Get recommendations", color: "bg-emerald-500/15 text-emerald-400 border border-emerald-500/20" },
          ].map((step, i) =>
            step.color ? (
              <span key={i} className={`rounded-full px-2.5 py-1 ${step.color}`}>{step.label}</span>
            ) : (
              <span key={i} className="text-muted-foreground/40">{step.label}</span>
            )
          )}
        </div>
      </div>

      <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
          <FlaskConical size={16} className="text-red-400" />
          Attack Categories
        </h3>
        <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          {[
            { name: "Evasion", desc: "Crafts adversarial inputs that try to avoid model detection (FGSM, PGD, Feature Perturbation)", sev: "critical", color: "text-red-400 bg-red-500/10 border-red-500/20" },
            { name: "Poisoning", desc: "Injects malicious training data to degrade model accuracy over time", sev: "critical", color: "text-red-400 bg-red-500/10 border-red-500/20" },
            { name: "Model Theft", desc: "Tries to extract or replicate your model through query probing", sev: "high", color: "text-orange-400 bg-orange-500/10 border-orange-500/20" },
            { name: "Prompt Injection", desc: "Attempts to override system prompts with adversarial instructions", sev: "high", color: "text-orange-400 bg-orange-500/10 border-orange-500/20" },
          ].map((d) => (
            <div key={d.name} className={`rounded-lg border p-3 ${d.color}`}>
              <p className="text-xs font-semibold">{d.name}</p>
              <p className="mt-0.5 text-[11px] opacity-80">{d.desc}</p>
              <span className="mt-1.5 inline-block rounded-full bg-black/20 px-2 py-0.5 text-[9px] uppercase tracking-wider font-bold">
                {d.sev}
              </span>
            </div>
          ))}
        </div>
      </div>

      <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
          <BarChart3 size={16} className="text-red-400" />
          Understanding the Scorecard
        </h3>
        <p className="mt-1.5 text-xs text-muted-foreground leading-relaxed">
          After running campaigns, the <strong className="text-foreground">Security Scorecard</strong> grades
          your model&apos;s resilience from <strong className="text-emerald-400">A</strong> (excellent — nearly
          no evasions) to <strong className="text-red-400">F</strong> (critical — attackers can easily bypass).
          Each attack category gets its own grade based on the <strong className="text-foreground">evasion rate</strong> —
          the percentage of adversarial samples that successfully fooled the model.
          A lower evasion rate means better security.
        </p>
        <div className="mt-3 grid grid-cols-5 gap-2 text-center text-xs">
          {[
            { grade: "A", range: "0–5%", color: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20" },
            { grade: "B", range: "5–10%", color: "text-blue-400 bg-blue-500/10 border-blue-500/20" },
            { grade: "C", range: "10–20%", color: "text-amber-400 bg-amber-500/10 border-amber-500/20" },
            { grade: "D", range: "20–35%", color: "text-orange-400 bg-orange-500/10 border-orange-500/20" },
            { grade: "F", range: "35%+", color: "text-red-400 bg-red-500/10 border-red-500/20" },
          ].map((g) => (
            <div key={g.grade} className={`rounded-lg border p-2 ${g.color}`}>
              <div className="text-lg font-black">{g.grade}</div>
              <div className="text-[10px] opacity-70">{g.range} evasion</div>
            </div>
          ))}
        </div>
      </div>

      <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
          <Shield size={16} className="text-red-400" />
          Quick Start
        </h3>
        <div className="mt-2 space-y-1.5 text-xs text-muted-foreground">
          <p><strong className="text-foreground">1.</strong> Select an attack type from the dropdown (start with <strong className="text-foreground">evasion</strong>)</p>
          <p><strong className="text-foreground">2.</strong> Click <strong className="text-foreground">+ New Campaign</strong> to create it</p>
          <p><strong className="text-foreground">3.</strong> Click the <strong className="text-blue-400">▶ play button</strong> next to the campaign to run it</p>
          <p><strong className="text-foreground">4.</strong> Wait for completion — the scorecard updates automatically</p>
          <p><strong className="text-foreground">5.</strong> Use <strong className="text-foreground">Schedule (24h)</strong> for recurring automated testing</p>
          <p><strong className="text-foreground">6.</strong> <strong className="text-foreground">Generate 100 Events</strong> creates synthetic security events for testing</p>
        </div>
      </div>
    </div>
  )
}

export default RedTeamPage
