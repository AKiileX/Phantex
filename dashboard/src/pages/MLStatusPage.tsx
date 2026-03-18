// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — ML Model Status Page (O11).
 *
 * Admin-only dashboard for ML model health:
 *   - Global model info (version, loaded, training indicator)
 *   - Current tenant model with accuracy metrics
 *   - Fusion weights (global vs tenant)
 *   - Retrain scheduler status + manual trigger
 *   - Model version history (ModelCard grid)
 *   - Retrain timeline (RetrainHistory)
 *   - Worker stats
 *   - Shadow mode + accuracy + drift indicators
 *   - Meta-detection alerts
 *
 * @module pages/MLStatusPage
 */

import { useState } from "react"
import {
  Brain,
  Globe,
  RefreshCw,
  Activity,
  ShieldAlert,
  Gauge,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  Loader2,
  BarChart3,
  Table2,
  Grid2X2,
  HelpCircle,
  Layers,
  Target,
  TrendingUp,
  Zap,
} from "lucide-react"
import {
  useMLDashboard,
  useTriggerRetrain,
} from "@/api/ml"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { AnimatedNumber } from "@/components/ui/animated-number"
import { ModelCard } from "@/components/ml/ModelCard"
import { RetrainHistory } from "@/components/ml/RetrainHistory"
import { useAuditLog } from "@/hooks/useAuditLog"

/* ── Page ───────────────────────────────────────────────────────────────────── */

export default function MLStatusPage() {
  const { data, isLoading, error } = useMLDashboard()
  const triggerRetrain = useTriggerRetrain()
  const logAction = useAuditLog()
  const [confirmRetrain, setConfirmRetrain] = useState(false)
  const [showGuide, setShowGuide] = useState(false)

  /* ── Loading ─────────────────────────────────────────────────────────────── */

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-24">
        <div className="h-6 w-6 animate-spin rounded-full border-2 border-primary/20 border-t-primary" />
      </div>
    )
  }

  if (error || !data) {
    return (
      <div className="flex flex-col items-center justify-center py-24 gap-3">
        <AlertTriangle className="h-8 w-8 text-amber-400" />
        <p className="text-sm text-muted-foreground">
          Failed to load ML status. Backend endpoints may not be deployed yet.
        </p>
      </div>
    )
  }

  const {
    global_model,
    models,
    fusion_weights,
    retrain_status,
    retrain_history,
    worker_stats,
    shadow,
    accuracy,
    drift,
    meta_alerts,
    feature_importance = [],
    confusion_matrix,
    recent_predictions = [],
  } = data

  /* ── Render ──────────────────────────────────────────────────────────────── */

  return (
    <div className="flex flex-col gap-6 p-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div className="flex items-center gap-3">
          <Brain className="h-5 w-5 text-primary/70" />
          <div>
            <h1 className="text-lg font-semibold">ML Model Status</h1>
            <p className="text-xs text-muted-foreground">
              Training pipeline, model versions, and detection health
            </p>
          </div>
        </div>
        <button
          onClick={() => setShowGuide(!showGuide)}
          className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"
        >
          <HelpCircle size={14} />
          {showGuide ? "Hide Guide" : "How does this work?"}
        </button>
      </div>

      {/* How It Works Guide */}
      {showGuide && <MLGuide />}

      {/* ── Row 1: Global Model + Current Model + Fusion ───────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Global Model */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Globe className="h-4 w-4 text-muted-foreground/60" />
              Global Model
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs text-muted-foreground">Status</span>
              <Badge variant={global_model.loaded ? "active" : "terminated"}>
                {global_model.loaded ? "Loaded" : "Not Loaded"}
              </Badge>
            </div>
            {global_model.version && (
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">Version</span>
                <span className="font-mono text-xs">{global_model.version}</span>
              </div>
            )}
            <div className="flex items-center justify-between">
              <span className="text-xs text-muted-foreground">Features</span>
              <span className="text-xs tabular-nums">{global_model.n_features}</span>
            </div>
            {global_model.training_in_progress && (
              <div className="flex items-center gap-2 text-xs text-amber-400">
                <Loader2 className="h-3 w-3 animate-spin" />
                Training in progress…
              </div>
            )}
          </CardContent>
        </Card>

        {/* Retrain Status */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <RefreshCw className="h-4 w-4 text-muted-foreground/60" />
              Retrain Pipeline
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs text-muted-foreground">Auto-retrain</span>
              <Badge variant={retrain_status.enabled ? "active" : "terminated"}>
                {retrain_status.enabled ? "Enabled" : "Disabled"}
              </Badge>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-xs text-muted-foreground">Status</span>
              {retrain_status.is_retraining ? (
                <span className="flex items-center gap-1.5 text-xs text-amber-400">
                  <Loader2 className="h-3 w-3 animate-spin" />
                  Retraining ({retrain_status.active_retrains}/{retrain_status.max_concurrent})
                </span>
              ) : (
                <span className="text-xs text-muted-foreground">Idle</span>
              )}
            </div>
            <div className="flex items-center justify-between">
              <span className="text-xs text-muted-foreground">New labels</span>
              <span className="text-xs tabular-nums">
                {retrain_status.new_labels} / {retrain_status.total_labels} total
              </span>
            </div>
            {retrain_status.last_retrain && (
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">Last retrain</span>
                <span className="text-xs text-muted-foreground">
                  {new Date(retrain_status.last_retrain * 1000).toLocaleString()}
                </span>
              </div>
            )}
            {/* Manual trigger */}
            <div className="pt-1">
              {!confirmRetrain ? (
                <Button
                  variant="outline"
                  size="sm"
                  className="w-full"
                  onClick={() => setConfirmRetrain(true)}
                  disabled={retrain_status.is_retraining || triggerRetrain.isPending}
                >
                  <RefreshCw className="h-3 w-3 mr-1.5" />
                  Trigger Retrain
                </Button>
              ) : (
                <div className="flex gap-2">
                  <Button
                    variant="default"
                    size="sm"
                    className="flex-1"
                    onClick={() => {
                      triggerRetrain.mutate()
                      logAction({ action: "ml.retrain.trigger" })
                      setConfirmRetrain(false)
                    }}
                    disabled={triggerRetrain.isPending}
                  >
                    Confirm
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setConfirmRetrain(false)}
                  >
                    Cancel
                  </Button>
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Fusion Weights */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Gauge className="h-4 w-4 text-muted-foreground/60" />
              Ensemble Fusion
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {fusion_weights ? (
              <>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-muted-foreground">Global weight</span>
                  <span className="text-xs font-bold tabular-nums">
                    {(fusion_weights.global_weight * 100).toFixed(1)}%
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-muted-foreground">Tenant weight</span>
                  <span className="text-xs font-bold tabular-nums">
                    {(fusion_weights.tenant_weight * 100).toFixed(1)}%
                  </span>
                </div>
                {/* Weight bar */}
                <div className="h-2 rounded-full bg-muted/30 overflow-hidden">
                  <div
                    className="h-full bg-primary/60 rounded-full transition-all duration-500"
                    style={{ width: `${fusion_weights.global_weight * 100}%` }}
                  />
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-muted-foreground">Samples</span>
                  <span className="text-xs tabular-nums">
                    {fusion_weights.tenant_samples.toLocaleString()}
                  </span>
                </div>
                <p className="text-[10px] text-muted-foreground/70 italic">
                  {fusion_weights.reason}
                </p>
              </>
            ) : (
              <p className="text-xs text-muted-foreground py-4 text-center">
                No fusion weights available
              </p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* ── Row 2: Metrics cards ───────────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <MetricTile
          label="Precision"
          value={accuracy?.precision}
          threshold={0.9}
          icon={CheckCircle2}
        />
        <MetricTile
          label="Recall"
          value={accuracy?.recall}
          threshold={0.8}
          icon={Activity}
        />
        <MetricTile
          label="FPR"
          value={accuracy?.fpr}
          threshold={0.05}
          invert
          icon={ShieldAlert}
        />
        <Card className="relative overflow-hidden">
          <CardContent className="p-4">
            <p className="text-[10px] uppercase tracking-widest text-muted-foreground">
              Retrains Completed
            </p>
            <span className="text-2xl font-bold mt-1 block">
              <AnimatedNumber value={worker_stats.retrains_completed} />
            </span>
            {worker_stats.retrains_failed > 0 && (
              <p className="text-[10px] text-destructive mt-1">
                {worker_stats.retrains_failed} failed
              </p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* ── Row 3: Shadow + Drift + Meta Alerts ────────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Shadow Mode */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Shadow Mode</CardTitle>
          </CardHeader>
          <CardContent>
            {shadow ? (
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-muted-foreground">Status</span>
                  <Badge variant={shadow.in_shadow ? "info" : "active"}>
                    {shadow.in_shadow ? "In Shadow" : "Production"}
                  </Badge>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-muted-foreground">Alert rate</span>
                  <span className="text-xs tabular-nums">
                    {(shadow.alert_rate * 100).toFixed(2)}% (max {(shadow.max_alert_rate * 100).toFixed(0)}%)
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-muted-foreground">Scored</span>
                  <span className="text-xs tabular-nums">{shadow.total_scored}</span>
                </div>
              </div>
            ) : (
              <p className="text-xs text-muted-foreground py-2 text-center">No shadow data</p>
            )}
          </CardContent>
        </Card>

        {/* Drift */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Drift Detection</CardTitle>
          </CardHeader>
          <CardContent>
            {drift ? (
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-muted-foreground">Status</span>
                  <Badge variant={drift.drifted ? "critical" : "active"}>
                    {drift.drifted ? "Drift Detected" : "Stable"}
                  </Badge>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-muted-foreground">Metric</span>
                  <span className="text-xs">{drift.metric_name}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-muted-foreground">Value / Threshold</span>
                  <span className="text-xs tabular-nums">
                    {drift.metric_value.toFixed(4)} / {drift.threshold.toFixed(4)}
                  </span>
                </div>
              </div>
            ) : (
              <p className="text-xs text-muted-foreground py-2 text-center">No drift data</p>
            )}
          </CardContent>
        </Card>

        {/* Meta Alerts */}
        <Card>
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm">Meta-Detection Alerts</CardTitle>
              {meta_alerts.length > 0 && (
                <Badge variant="critical" className="text-[10px]">
                  {meta_alerts.length}
                </Badge>
              )}
            </div>
          </CardHeader>
          <CardContent>
            {meta_alerts.length === 0 ? (
              <p className="text-xs text-muted-foreground py-2 text-center">
                No meta-detection alerts
              </p>
            ) : (
              <div className="space-y-2 max-h-40 overflow-y-auto">
                {meta_alerts.slice(0, 10).map((a) => (
                  <div
                    key={a.id}
                    className="flex items-start gap-2 text-xs"
                  >
                    <AlertIcon severity={a.severity} />
                    <div className="min-w-0 flex-1">
                      <p className="font-medium truncate">{a.alert_type}</p>
                      <p className="text-muted-foreground truncate">{a.message}</p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* ── Row 4: ML Interpretability ──────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Feature Importance */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-muted-foreground/60" />
              Feature Importance
            </CardTitle>
          </CardHeader>
          <CardContent>
            {feature_importance.length === 0 ? (
              <p className="text-xs text-muted-foreground py-6 text-center">
                No feature importance data — model needs training data
              </p>
            ) : (
              <div className="space-y-1.5 max-h-[280px] overflow-y-auto">
                {feature_importance.slice(0, 20).map((f, i) => {
                  const maxImp = feature_importance[0]?.importance || 1
                  const pct = maxImp > 0 ? (f.importance / maxImp) * 100 : 0
                  return (
                    <div key={f.feature} className="flex items-center gap-2">
                      <span className="text-[10px] text-muted-foreground w-4 text-right tabular-nums">
                        {i + 1}
                      </span>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between mb-0.5">
                          <span className="text-[11px] font-mono truncate" title={f.description || f.feature}>
                            {f.feature}
                          </span>
                          <span className="text-[10px] tabular-nums text-muted-foreground ml-2">
                            {(f.importance * 100).toFixed(1)}%
                          </span>
                        </div>
                        <div className="h-1.5 rounded-full bg-muted/30 overflow-hidden">
                          <div
                            className="h-full rounded-full transition-all duration-500"
                            style={{
                              width: `${pct}%`,
                              backgroundColor:
                                f.source === "xgboost" ? "#06b6d4"
                                  : f.source === "isolation_forest" ? "#8b5cf6"
                                    : "#6b7280",
                            }}
                          />
                        </div>
                      </div>
                      {f.category && (
                        <Badge variant="outline" className="text-[8px] px-1 py-0 shrink-0">
                          {f.category}
                        </Badge>
                      )}
                    </div>
                  )
                })}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Confusion Matrix */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Grid2X2 className="h-4 w-4 text-muted-foreground/60" />
              Confusion Matrix
            </CardTitle>
          </CardHeader>
          <CardContent>
            {!confusion_matrix || confusion_matrix.total === 0 ? (
              <p className="text-xs text-muted-foreground py-6 text-center">
                No confusion matrix data — waiting for labeled events
              </p>
            ) : (
              <div className="space-y-4">
                {/* 2x2 grid */}
                <div className="grid grid-cols-[auto_1fr_1fr] gap-0 text-center">
                  {/* Header row */}
                  <div />
                  <div className="text-[10px] text-muted-foreground font-medium py-1 border-b border-border/30">
                    Predicted Positive
                  </div>
                  <div className="text-[10px] text-muted-foreground font-medium py-1 border-b border-border/30">
                    Predicted Negative
                  </div>
                  {/* Actual Positive */}
                  <div className="text-[10px] text-muted-foreground font-medium pr-2 flex items-center justify-end border-r border-border/30">
                    Actual +
                  </div>
                  <div className="p-3 bg-emerald-500/10 border-r border-b border-border/10">
                    <span className="text-lg font-bold text-emerald-400 tabular-nums">{confusion_matrix.tp}</span>
                    <p className="text-[9px] text-emerald-400/70">TP</p>
                  </div>
                  <div className="p-3 bg-amber-500/10 border-b border-border/10">
                    <span className="text-lg font-bold text-amber-400 tabular-nums">{confusion_matrix.fn}</span>
                    <p className="text-[9px] text-amber-400/70">FN</p>
                  </div>
                  {/* Actual Negative */}
                  <div className="text-[10px] text-muted-foreground font-medium pr-2 flex items-center justify-end border-r border-border/30">
                    Actual −
                  </div>
                  <div className="p-3 bg-red-500/10 border-r border-border/10">
                    <span className="text-lg font-bold text-red-400 tabular-nums">{confusion_matrix.fp}</span>
                    <p className="text-[9px] text-red-400/70">FP</p>
                  </div>
                  <div className="p-3 bg-emerald-500/10">
                    <span className="text-lg font-bold text-emerald-400 tabular-nums">{confusion_matrix.tn}</span>
                    <p className="text-[9px] text-emerald-400/70">TN</p>
                  </div>
                </div>

                {/* Derived metrics */}
                <div className="grid grid-cols-4 gap-2 text-center">
                  {[
                    { label: "Precision", value: confusion_matrix.precision },
                    { label: "Recall", value: confusion_matrix.recall },
                    { label: "F1 Score", value: confusion_matrix.f1 },
                    { label: "Accuracy", value: confusion_matrix.accuracy ?? 0 },
                  ].map((m) => (
                    <div key={m.label}>
                      <p className="text-[9px] text-muted-foreground uppercase tracking-wider">{m.label}</p>
                      <p className="text-sm font-bold tabular-nums">{(m.value * 100).toFixed(1)}%</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* ── Row 5: Recent Predictions ──────────────────────────────────────── */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <Table2 className="h-4 w-4 text-muted-foreground/60" />
            Recent Predictions ({recent_predictions.length})
          </CardTitle>
        </CardHeader>
        <CardContent>
          {recent_predictions.length === 0 ? (
            <p className="text-xs text-muted-foreground py-6 text-center">
              No recent predictions — buffer is empty
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-border/30">
                    <th className="text-left py-2 px-2 font-medium text-muted-foreground">Time</th>
                    <th className="text-left py-2 px-2 font-medium text-muted-foreground">Agent</th>
                    <th className="text-right py-2 px-2 font-medium text-muted-foreground">Score</th>
                    <th className="text-left py-2 px-2 font-medium text-muted-foreground">Class</th>
                    <th className="text-left py-2 px-2 font-medium text-muted-foreground">Stages</th>
                    <th className="text-center py-2 px-2 font-medium text-muted-foreground">Alert</th>
                  </tr>
                </thead>
                <tbody>
                  {recent_predictions.slice(-20).reverse().map((p, i) => (
                    <tr key={i} className="border-b border-border/10 hover:bg-white/[0.02]">
                      <td className="py-1.5 px-2 tabular-nums text-muted-foreground">
                        {p.timestamp ? new Date(p.timestamp * 1000).toLocaleTimeString() : "—"}
                      </td>
                      <td className="py-1.5 px-2 font-mono truncate max-w-[120px]">
                        {p.agent_id ?? "—"}
                      </td>
                      <td className="py-1.5 px-2 text-right tabular-nums font-bold">
                        <span
                          className={
                            p.score > 0.7
                              ? "text-red-400"
                              : p.score > 0.4
                                ? "text-amber-400"
                                : "text-emerald-400"
                          }
                        >
                          {p.score.toFixed(3)}
                        </span>
                      </td>
                      <td className="py-1.5 px-2">
                        <Badge
                          variant="outline"
                          className="text-[9px] py-0 px-1"
                        >
                          {p.attack_class}
                        </Badge>
                      </td>
                      <td className="py-1.5 px-2">
                        <div className="flex gap-1">
                          {Object.entries(p.stage_scores ?? {}).map(([stage, score]) => (
                            <span
                              key={stage}
                              className="text-[9px] px-1 py-0 rounded bg-muted/30 tabular-nums"
                              title={stage}
                            >
                              {stage.slice(0, 2).toUpperCase()}: {(score as number).toFixed(2)}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="py-1.5 px-2 text-center">
                        {p.should_alert ? (
                          <span className="h-2 w-2 inline-block rounded-full bg-red-400" />
                        ) : (
                          <span className="h-2 w-2 inline-block rounded-full bg-emerald-400/30" />
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* ── Row 6: Model Versions ──────────────────────────────────────────── */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm">
            Model Versions ({models.models.length})
          </CardTitle>
        </CardHeader>
        <CardContent>
          {models.models.length === 0 ? (
            <p className="text-sm text-muted-foreground py-6 text-center">
              No model versions registered.
            </p>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {models.models.map((m) => (
                <ModelCard
                  key={m.version}
                  model={m}
                  isCurrent={m.version === models.current_version}
                />
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* ── Row 7: Retrain History ─────────────────────────────────────── */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm">
            Retrain History ({retrain_history.length} runs)
          </CardTitle>
        </CardHeader>
        <CardContent>
          <RetrainHistory results={retrain_history} />
        </CardContent>
      </Card>

      {/* ── Row 8: Worker Stats ────────────────────────────────────────── */}
      <div className="flex flex-wrap gap-4 text-xs text-muted-foreground border-t border-border/30 pt-4">
        <span className="flex items-center gap-1.5">
          <span
            className={`h-2 w-2 rounded-full ${
              worker_stats.running ? "bg-emerald-400" : "bg-muted-foreground/30"
            }`}
          />
          Worker: {worker_stats.running ? "Running" : "Stopped"}
        </span>
        <span>Check interval: {worker_stats.check_interval_seconds}s</span>
        <span>Completed: {worker_stats.retrains_completed}</span>
        {worker_stats.retrains_failed > 0 && (
          <span className="text-destructive">Failed: {worker_stats.retrains_failed}</span>
        )}
      </div>
    </div>
  )
}

/* ── Small helpers ─────────────────────────────────────────────────────────── */

function MetricTile({
  label,
  value,
  threshold,
  invert,
  icon: Icon,
}: {
  label: string
  value: number | undefined
  threshold: number
  invert?: boolean
  icon: React.ElementType
}) {
  if (value == null) {
    return (
      <Card>
        <CardContent className="p-4">
          <p className="text-[10px] uppercase tracking-widest text-muted-foreground">
            {label}
          </p>
          <span className="text-2xl font-bold mt-1 block text-muted-foreground/40">—</span>
        </CardContent>
      </Card>
    )
  }

  const good = invert ? value <= threshold : value >= threshold

  return (
    <Card>
      <CardContent className="p-4">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-[10px] uppercase tracking-widest text-muted-foreground">
              {label}
            </p>
            <span className={`text-2xl font-bold mt-1 block tabular-nums ${good ? "text-emerald-400" : "text-amber-400"}`}>
              {(value * 100).toFixed(1)}%
            </span>
          </div>
          <Icon className={`h-5 w-5 ${good ? "text-emerald-400/40" : "text-amber-400/40"}`} />
        </div>
      </CardContent>
    </Card>
  )
}

function AlertIcon({ severity }: { severity: string }) {
  switch (severity) {
    case "critical":
      return <XCircle className="h-3.5 w-3.5 text-destructive shrink-0 mt-0.5" />
    case "warning":
      return <AlertTriangle className="h-3.5 w-3.5 text-amber-400 shrink-0 mt-0.5" />
    default:
      return <Clock className="h-3.5 w-3.5 text-blue-400 shrink-0 mt-0.5" />
  }
}

/* ── How It Works Guide ────────────────────────────────────────────────────── */

function MLGuide() {
  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
          <Brain size={16} className="text-primary" />
          What is the ML Detection Engine?
        </h3>
        <p className="mt-1.5 text-xs text-muted-foreground leading-relaxed">
          PhanTeX uses a <strong className="text-foreground">three-stage ensemble ML model</strong> to detect
          anomalous agent behavior in real time. Instead of relying on static rules, the ML engine learns what
          &quot;normal&quot; looks like for each agent (file access patterns, network connections, tool usage,
          response times) and flags anything that deviates. This catches zero-day attacks, prompt injection,
          and lateral movement that rules would miss.
        </p>
      </div>

      <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
          <Layers size={16} className="text-primary" />
          Three-Stage Pipeline
        </h3>
        <p className="mt-1.5 text-xs text-muted-foreground">How detection works under the hood:</p>
        <div className="mt-3 flex flex-wrap items-center gap-1.5 text-xs font-medium">
          {[
            { label: "Events ingested", color: "bg-blue-500/15 text-blue-400 border border-blue-500/20" },
            { label: "→" },
            { label: "62 features extracted", color: "bg-cyan-500/15 text-cyan-400 border border-cyan-500/20" },
            { label: "→" },
            { label: "Stage 1: Isolation Forest", color: "bg-amber-500/15 text-amber-400 border border-amber-500/20" },
            { label: "→" },
            { label: "Stage 2: XGBoost", color: "bg-orange-500/15 text-orange-400 border border-orange-500/20" },
            { label: "→" },
            { label: "Stage 3: Autoencoder", color: "bg-red-500/15 text-red-400 border border-red-500/20" },
            { label: "→" },
            { label: "Ensemble fusion score", color: "bg-emerald-500/15 text-emerald-400 border border-emerald-500/20" },
          ].map((step, i) =>
            step.color ? (
              <span key={i} className={`rounded-full px-2.5 py-1 ${step.color}`}>{step.label}</span>
            ) : (
              <span key={i} className="text-muted-foreground/40">{step.label}</span>
            )
          )}
        </div>
        <p className="mt-3 text-[11px] text-muted-foreground/70">
          Each stage votes independently. The ensemble fusion combines all three scores — weighted between the
          global model (trained on all tenants) and the tenant-specific model (trained on your data alone).
        </p>
      </div>

      <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
          <Target size={16} className="text-primary" />
          Understanding the Metrics
        </h3>
        <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          {[
            { name: "Precision", desc: "Of all alerts raised, what % were real threats (not false positives)", color: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20" },
            { name: "Recall", desc: "Of all real threats, what % did the model catch (detection rate)", color: "text-blue-400 bg-blue-500/10 border-blue-500/20" },
            { name: "FPR", desc: "False Positive Rate — how often normal behavior triggers a false alert", color: "text-amber-400 bg-amber-500/10 border-amber-500/20" },
            { name: "Drift (PSI)", desc: "Population Stability Index — measures if agent behavior patterns have shifted", color: "text-purple-400 bg-purple-500/10 border-purple-500/20" },
          ].map((d) => (
            <div key={d.name} className={`rounded-lg border p-3 ${d.color}`}>
              <p className="text-xs font-semibold">{d.name}</p>
              <p className="mt-0.5 text-[11px] opacity-80">{d.desc}</p>
            </div>
          ))}
        </div>
      </div>

      <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
          <TrendingUp size={16} className="text-primary" />
          Training &amp; Retraining
        </h3>
        <p className="mt-1.5 text-xs text-muted-foreground leading-relaxed">
          The <strong className="text-foreground">Global Model</strong> is pre-trained on cross-tenant behavioral
          data and ships with PhanTeX. As your agents generate events, PhanTeX automatically builds a
          <strong className="text-foreground"> Tenant-Specific Model</strong> tailored to your environment.
          The <strong className="text-foreground">Ensemble Fusion</strong> weights determine how much each model
          contributes — starting at 100% global, then gradually shifting towards your tenant model as it matures.
        </p>
        <div className="mt-2 space-y-1.5 text-xs text-muted-foreground">
          <p><strong className="text-foreground">Auto-Retrain:</strong> When enabled, the system periodically checks for new labeled events and retrains the tenant model automatically.</p>
          <p><strong className="text-foreground">Trigger Retrain:</strong> Click the button to manually start a retrain cycle right now.</p>
          <p><strong className="text-foreground">Shadow Mode:</strong> New model versions are tested in shadow mode first — scoring events without affecting production — to ensure they don&apos;t increase false positives.</p>
        </div>
      </div>

      <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
          <Zap size={16} className="text-primary" />
          Quick Start
        </h3>
        <div className="mt-2 space-y-1.5 text-xs text-muted-foreground">
          <p><strong className="text-foreground">1.</strong> The global model loads automatically — check that &quot;Status&quot; shows <strong className="text-emerald-400">Loaded</strong></p>
          <p><strong className="text-foreground">2.</strong> Ensure <strong className="text-foreground">Auto-retrain</strong> is enabled for continuous improvement</p>
          <p><strong className="text-foreground">3.</strong> Monitor <strong className="text-foreground">Precision</strong> and <strong className="text-foreground">Recall</strong> — both should be above 80% for production use</p>
          <p><strong className="text-foreground">4.</strong> Watch <strong className="text-foreground">Drift Detection</strong> — if PSI exceeds the threshold (0.15), consider triggering a retrain</p>
          <p><strong className="text-foreground">5.</strong> Use the <strong className="text-foreground">Red Team Simulator</strong> to test model resilience against adversarial attacks</p>
          <p><strong className="text-foreground">6.</strong> Review <strong className="text-foreground">Feature Importance</strong> to understand which behavioral signals matter most</p>
        </div>
      </div>
    </div>
  )
}
