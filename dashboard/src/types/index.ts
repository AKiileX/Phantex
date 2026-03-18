// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/* Phantex — Shared type definitions for the dashboard frontend. */

// ── Auth & Users ─────────────────────────────────────────────────────────────

export type Role = "admin" | "analyst" | "viewer"

export interface User {
  id: string
  tenant_id: string
  email: string
  role: Role
  name: string | null
  is_active: boolean
  created_at: string
  last_login: string | null
  must_change_password?: boolean
}

export interface TokenResponse {
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
  must_change_password?: boolean
}

// ── Agents ───────────────────────────────────────────────────────────────────

export type AgentStatus = "active" | "stale" | "offline" | "terminated" | "quarantined"

/** Compact agent summary for list views (from GET /api/v1/agents). */
export interface AgentSummary {
  id: string
  paid: string
  name: string | null
  framework: string | null
  status: AgentStatus
  ip_address: string | null
  hostname: string | null
  os_type: string | null
  last_seen: string
}

/** Full agent detail (from GET /api/v1/agents/{id}). */
export interface Agent {
  id: string
  tenant_id: string
  paid: string
  name: string | null
  status: AgentStatus
  framework: string | null
  framework_ver: string | null
  process_pid: number | null
  exe_path: string | null
  cmdline: string | null
  container_id: string | null
  container_image: string | null
  host_id: string | null
  sensor_id: string | null
  ip_address: string | null
  hostname: string | null
  os_type: string | null
  os_version: string | null
  cpu_usage_pct: number | null
  memory_mb: number | null
  first_seen: string
  last_seen: string
  updated_at: string
  metadata: Record<string, unknown>
}

// ── Events ───────────────────────────────────────────────────────────────────

export type Severity = "critical" | "high" | "medium" | "low" | "info"

/** Compact event for list views (from GET /api/v1/events). */
export interface EventSummary {
  id: string
  agent_id: string | null
  event_type: string
  severity: Severity
  timestamp: string
}

/** Full event detail (from GET /api/v1/events/{id}). */
export interface SecurityEvent {
  id: string
  tenant_id: string
  agent_id: string | null
  sensor_id: string | null
  event_type: string
  severity: Severity
  timestamp: string
  raw_data: Record<string, unknown>
  created_at: string
}

// ── Alerts ───────────────────────────────────────────────────────────────────

export type AlertStatus = "open" | "acknowledged" | "resolved" | "false_positive"

/** Compact alert for list views (from GET /api/v1/alerts). */
export interface AlertSummary {
  id: string
  severity: Severity
  title: string
  status: AlertStatus
  created_at: string
  agent_id: string | null
  rule_id: string | null
  event_id: string | null
}

/** Full alert detail (from GET /api/v1/alerts/{id}). */
export interface Alert {
  id: string
  tenant_id: string
  agent_id: string | null
  event_id: string | null
  rule_id: string | null
  severity: Severity
  title: string
  description: string | null
  status: AlertStatus
  context: Record<string, unknown>
  created_at: string
  updated_at: string
  resolved_at: string | null
  resolved_by: string | null
}

// ── Rules ────────────────────────────────────────────────────────────────────

export interface Rule {
  id: string
  tenant_id: string | null
  name: string
  description: string | null
  prl_source: string
  severity: Severity
  attack_class: string | null
  enabled: boolean
  version: number
  author: string | null
  created_at: string
  updated_at: string
}

// ── Sensors ──────────────────────────────────────────────────────────────────

export type SensorStatus = "online" | "degraded" | "offline" | "decommissioned"

/** Compact sensor summary for list views (from GET /api/v1/sensors). */
export interface SensorSummary {
  id: string
  sensor_id: string
  hostname: string | null
  ip_address: string | null
  version: string | null
  os_type: string | null
  status: SensorStatus
  probes_loaded: number
  probes_total: number
  events_sent: number
  events_dropped: number
  agents_tracked: number
  cpu_percent: number | null
  memory_bytes: number | null
  last_heartbeat: string
}

/** Full sensor detail (from GET /api/v1/sensors/{id}). */
export interface SensorDetail extends SensorSummary {
  tenant_id: string
  kernel: string | null
  arch: string | null
  events_read: number
  parse_errors: number
  buffer_used: number | null
  first_seen: string
  uptime_seconds: number
  tags: Record<string, unknown>
  metadata: Record<string, unknown>
  updated_at: string
  decommissioned_at: string | null
  decommissioned_by: string | null
  decommission_reason: string | null
}

// ── API Helpers ──────────────────────────────────────────────────────────────

/** Offset-based pagination (legacy — used by events/alerts endpoints). */
export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page: number
  page_size: number
}

/** Cursor-based pagination (used by agents endpoint). */
export interface CursorPage<T> {
  items: T[]
  next_cursor: string | null
  has_more: boolean
}

// ── WebSocket ────────────────────────────────────────────────────────────────

export interface WsMessage {
  type: "alert" | "welcome" | "heartbeat" | "error"
  data?: unknown
  message?: string
}

// ── Timeline / Investigation (O3) ────────────────────────────────────────────

export type TimelineSource = "postgres" | "clickhouse" | "neo4j" | "trust_engine"

export interface TimelineEvent {
  id: string
  source: TimelineSource
  event_type: string
  severity: Severity
  timestamp: string
  agent_id: string | null
  description: string
  raw_data: Record<string, unknown>
  trust_score: number | null
  atlas_techniques: Array<Record<string, unknown>>
  attack_chain_position: number | null
  session_id: string | null
}

export interface TimelineSession {
  session_id: string
  start: string
  end: string
  event_count: number
  severities: Record<string, number>
}

export interface DataSourceStatus {
  source: string
  available: boolean
  event_count: number
  error: string | null
  latency_ms: number | null
}

export interface TimelineResponse {
  agent_id: string | null
  alert_id: string | null
  range_hours: number
  total_events: number
  events: TimelineEvent[]
  sessions: TimelineSession[]
  data_sources: DataSourceStatus[]
  has_more: boolean
  next_cursor: string | null
}

// ── Trust Graph (O4) ─────────────────────────────────────────────────────────

export type TrustEntityType = "agent" | "tool" | "file" | "network" | "tenant"

export interface TrustFactor {
  name: string
  weight: number
  value: number
}

export interface TrustScore {
  entity_id: string
  entity_type: string
  trust_score: number
  factors: TrustFactor[]
  last_updated: number | null
}

export interface TrustGraphNode {
  id: string
  entity_type: string
  trust_score: number
  metadata: Record<string, string>
}

export interface TrustGraphEdge {
  source_id: string
  target_id: string
  edge_type: string
  count: number
  weight: number
}

export interface TrustGraphResponse {
  nodes: TrustGraphNode[]
  edges: TrustGraphEdge[]
  truncated: boolean
}

// ── Policies (O5) ────────────────────────────────────────────────────────────

export type PolicySeverity = "info" | "low" | "medium" | "high" | "critical"

export interface PolicyRuleOverride {
  name: string
  enabled: boolean
  severity_override: PolicySeverity | null
  parameters: Record<string, unknown>
  notifications: Record<string, unknown>[]
}

export interface PolicySchedule {
  active_hours: string | null
  weekend: "suppress" | "alert" | "inherit" | null
}

export interface PolicyScope {
  agent_tags: string[]
  frameworks: string[]
}

export interface PolicyDefinition {
  rules: PolicyRuleOverride[]
  schedule: PolicySchedule | null
  scope: PolicyScope
}

export interface Policy {
  id: string
  tenant_id: string
  name: string
  description: string
  version: number
  enabled: boolean
  definition: PolicyDefinition
  scope_agent_tags: string[]
  scope_frameworks: string[]
  created_by: string
  updated_by: string | null
  created_at: string
  updated_at: string
}

export interface PolicyVersion {
  id: string
  policy_id: string
  version: number
  definition: PolicyDefinition
  change_summary: string
  created_by: string
  created_at: string
}

export interface PolicyValidationResult {
  valid: boolean
  errors: string[]
  warnings: string[]
  parsed: Record<string, unknown> | null
}

// ── Agent Tags ──────────────────────────────────────────────────────

export interface AgentTagsResponse {
  agent_id: string
  tags: Record<string, string>
  updated_at: string
}

// ── Exemptions ──────────────────────────────────────────────────────

export interface Exemption {
  id: string
  tenant_id: string
  rule_name: string
  match_tags: Record<string, string>
  reason: string
  enabled: boolean
  expires_at: string | null
  hit_count: number
  last_hit_at: string | null
  created_by: string
  created_at: string
  updated_at: string
}

export interface ExemptionCreate {
  rule_name: string
  match_tags: Record<string, string>
  reason: string
  expires_at?: string | null
}

export interface ExemptionUpdate {
  rule_name?: string
  match_tags?: Record<string, string>
  reason?: string
  enabled?: boolean
  expires_at?: string | null
}

// ── Alert Routing ────────────────────────────────────────────────────

export type RoutingSeverity = "info" | "low" | "medium" | "high" | "critical"

export interface RoutingRule {
  id: string
  tenant_id: string
  name: string
  description: string | null
  match_tags: Record<string, string>
  severity_min: RoutingSeverity
  channels: string[]
  enabled: boolean
  priority: number
  created_by: string
  updated_by: string | null
  created_at: string
  updated_at: string
}

export interface RoutingRuleCreate {
  name: string
  description?: string
  match_tags: Record<string, string>
  severity_min: RoutingSeverity
  channels: string[]
  priority?: number
}

export interface RoutingRuleUpdate {
  name?: string
  description?: string
  match_tags?: Record<string, string>
  severity_min?: RoutingSeverity
  channels?: string[]
  enabled?: boolean
  priority?: number
}

export interface RoutingSimulationRequest {
  severity: RoutingSeverity
  agent_tags: Record<string, string>
  rule_name?: string
}

export interface RoutingSimulationResult {
  matched_rules: RoutingRule[]
  channels: string[]
  would_be_exempted: boolean
  exemption_reason: string | null
}

// ── Maintenance Windows ──────────────────────────────────────────────

export interface MaintenanceWindow {
  id: string
  tenant_id: string
  name: string
  description: string | null
  cron_schedule: string
  duration_minutes: number
  rules: string[]
  match_tags: Record<string, string>
  enabled: boolean
  next_start: string | null
  last_started_at: string | null
  last_ended_at: string | null
  force_ended_by: string | null
  created_by: string
  created_at: string
  updated_at: string
}

export interface MaintenanceWindowCreate {
  name: string
  description?: string
  cron_schedule: string
  duration_minutes: number
  rules: string[]
  match_tags?: Record<string, string>
}

export interface MaintenanceWindowUpdate {
  name?: string
  description?: string
  cron_schedule?: string
  duration_minutes?: number
  rules?: string[]
  match_tags?: Record<string, string>
  enabled?: boolean
}

// ── MITRE ATLAS (O8) ─────────────────────────────────────────────────────────

export type AtlasConfidence = "none" | "low" | "medium" | "high"
export type DetectionSource = "prl_rule" | "ml_model" | "content_classifier"

export interface DetectorEntry {
  name: string
  source: DetectionSource
  confidence: AtlasConfidence
}

export interface AtlasTechnique {
  id: string
  name: string
  tactic: string
  url: string
  detected: boolean
  detected_by: DetectorEntry[]
  best_confidence: AtlasConfidence
}

export interface AtlasCoverageResponse {
  total_techniques: number
  detected_techniques: number
  coverage_pct: number
  techniques: AtlasTechnique[]
}

export interface AtlasTechniqueDetail {
  id: string
  name: string
  tactic: string
  url: string
  description: string
  detected?: boolean
  detected_by?: DetectorEntry[]
  best_confidence?: AtlasConfidence
}

export interface AtlasRuleTechnique {
  id: string
  name: string
  url: string
}

export interface AtlasRuleMappingResponse {
  rule_name: string
  atlas_techniques: AtlasRuleTechnique[]
  confidence: AtlasConfidence
  rationale: string
}

/* ── O9: PDR Export Channels ───────────────────────────────────────────────── */

export type PDRChannelType = "s3" | "webhook" | "kafka_mirror"

export interface PDRChannelResponse {
  id: string
  tenant_id: string
  name: string
  channel_type: PDRChannelType
  config_masked: Record<string, unknown>
  pii_fields: string[] | null
  enabled: boolean
  created_at: string
  updated_at: string
}

export interface PDRChannelCreate {
  name: string
  channel_type: PDRChannelType
  config: Record<string, unknown>
  pii_fields?: string[] | null
  enabled?: boolean
}

export interface PDRChannelUpdate {
  name?: string
  config?: Record<string, unknown>
  pii_fields?: string[] | null
  enabled?: boolean
}

export interface PDRChannelListResponse {
  channels: PDRChannelResponse[]
}

export interface PDRChannelTypeInfo {
  type: PDRChannelType
  name: string
  description: string
  config_fields: string[]
}

export interface PDRChannelTypesResponse {
  channel_types: PDRChannelTypeInfo[]
  ocsf_event_types: string[]
}

export interface PDRTestResult {
  success: boolean
  result?: Record<string, unknown>
  message?: string
}

export interface PDRScheduleResponse {
  id: string
  tenant_id: string
  channel_id: string
  name: string
  cron_schedule: string
  lookback_minutes: number
  event_types: string[] | null
  max_events: number
  enabled: boolean
  next_run_at: string | null
  last_run_at: string | null
  last_run_status: string | null
  last_run_message: string | null
  created_at: string
  updated_at: string
}

export interface PDRScheduleCreate {
  name: string
  channel_id: string
  cron_schedule: string
  lookback_minutes?: number
  event_types?: string[] | null
  max_events?: number
  enabled?: boolean
}

export interface PDRScheduleUpdate {
  name?: string
  cron_schedule?: string
  lookback_minutes?: number
  event_types?: string[] | null
  max_events?: number
  enabled?: boolean
}

export interface PDRScheduleListResponse {
  schedules: PDRScheduleResponse[]
}

/* ── O10: Telemetry Admin ──────────────────────────────────────────────────── */

export interface TelemetryConfigResponse {
  tenant_id: string
  enabled: boolean
  dp_epsilon: number
  global_kill_switch_active: boolean
  cloud_endpoint_configured: boolean
  created_at: string | null
  updated_at: string | null
}

export interface TelemetryConfigUpdate {
  enabled: boolean
  dp_epsilon?: number | null
}

export interface TelemetryStatusMetrics {
  batches_sent: number
  batches_failed: number
  records_exported: number
  records_dropped: number
  last_export_at: string | null
  last_error: string | null
}

export interface TelemetryStatusResponse {
  enabled: boolean
  global_kill_switch_active: boolean
  cloud_endpoint_configured: boolean
  buffer_size: number
  metrics: TelemetryStatusMetrics
}

export interface TelemetryViewerEntry {
  payload_preview: Record<string, unknown>[]
  record_count: number
  exported_at: number
  destination: string
  success: boolean
  error: string | null
}

export interface TelemetryViewerResponse {
  entries: TelemetryViewerEntry[]
  total_entries: number
  pending_records: number
}

/* ── O11: ML Model Status ──────────────────────────────────────────────────── */

/** Global model summary from GlobalModelManager.get_info() */
export interface MLGlobalModelInfo {
  loaded: boolean
  version: string | null
  n_features: number
  training_in_progress: boolean
}

/** Per-stage validation metrics */
export interface MLStageMetrics {
  precision: number
  recall: number
  fpr: number
  f1?: number
}

/** Stored metrics for a model version manifest */
export interface MLVersionMetrics {
  stage1_validation?: MLStageMetrics
  training_samples?: number
  retrain_trigger?: "auto" | "manual"
}

/** A single model version from the registry */
export interface MLModelVersion {
  version: string
  tenant_id: string
  created_at: number
  stages: { stage1: boolean; stage2: boolean; stage3: boolean }
  metrics: MLVersionMetrics | null
  feature_names: string[]
  signature?: string
}

/** Tenant model list response */
export interface MLModelListResponse {
  models: MLModelVersion[]
  current_version: string | null
}

/** Fusion weights for ensemble scoring */
export interface MLFusionWeights {
  global_weight: number
  tenant_weight: number
  tenant_samples: number
  reason: string
}

/** Retrain scheduler status */
export interface MLRetrainStatus {
  new_labels: number
  total_labels: number
  last_retrain: number | null
  is_retraining: boolean
  active_retrains: number
  max_concurrent: number
  enabled: boolean
}

/** Result of a retrain run */
export interface MLRetrainResult {
  success: boolean
  tenant_id: string
  version: string | null
  training_time_seconds: number
  reason: string
  metrics: Record<string, unknown>
}

/** Retrain history list */
export interface MLRetrainHistoryResponse {
  results: MLRetrainResult[]
}

/** Retrain worker runtime stats */
export interface MLWorkerStats {
  running: boolean
  retrains_completed: number
  retrains_failed: number
  check_interval_seconds: number
  enabled: boolean
}

/** Shadow mode evaluation state */
export interface MLShadowStatus {
  in_shadow: boolean
  passed: boolean
  alert_rate: number
  total_scored: number
  total_alerts: number
  version: string
  max_alert_rate: number
}

/** Rolling accuracy snapshot */
export interface MLAccuracySnapshot {
  timestamp: number
  precision: number
  recall: number
  fpr: number
  tp: number
  fp: number
  fn: number
  tn: number
}

/** Drift detection result */
export interface MLDriftResult {
  drifted: boolean
  metric_name: string
  metric_value: number
  threshold: number
  details: Record<string, unknown>
}

/** Meta-detection alert severity */
export type MLMetaAlertSeverity = "info" | "warning" | "critical"

/** Meta-detection alert */
export interface MLMetaAlert {
  id: string
  alert_type: string
  severity: MLMetaAlertSeverity
  message: string
  details: Record<string, unknown>
  timestamp: number
}

/** Aggregate ML dashboard response (single call) */
export interface MLDashboardResponse {
  global_model: MLGlobalModelInfo
  models: MLModelListResponse
  fusion_weights: MLFusionWeights | null
  retrain_status: MLRetrainStatus
  retrain_history: MLRetrainResult[]
  worker_stats: MLWorkerStats
  shadow: MLShadowStatus | null
  accuracy: MLAccuracySnapshot | null
  drift: MLDriftResult | null
  meta_alerts: MLMetaAlert[]
  /** ML Interpretability */
  feature_importance: MLFeatureImportance[]
  confusion_matrix: MLConfusionMatrix | null
  recent_predictions: MLPredictionEntry[]
}

/* ── ML Interpretability Types ─────────────────────────────────────────────── */

/** Single feature importance entry */
export interface MLFeatureImportance {
  feature: string
  importance: number
  source: "xgboost" | "isolation_forest" | "uniform"
  category?: string
  description?: string
}

/** Confusion matrix with derived metrics */
export interface MLConfusionMatrix {
  tp: number
  fp: number
  fn: number
  tn: number
  precision: number
  recall: number
  f1: number
  total: number
  accuracy?: number
  fpr?: number
}

/** A single prediction log entry */
export interface MLPredictionEntry {
  tenant_id: string
  agent_id?: string
  timestamp: number
  score: number
  should_alert: boolean
  stage_scores: Record<string, number>
  attack_class: string
  feature_contributions?: Record<string, number>
}

/** Feature importance response */
export interface MLFeatureImportanceResponse {
  features: MLFeatureImportance[]
  model_version: string
  total_features: number
}

/** Predictions log response */
export interface MLPredictionsResponse {
  predictions: MLPredictionEntry[]
  total: number
  buffer_size: number
}

/** Training data summary response */
export interface MLTrainingSummary {
  feature_names: string[]
  feature_count: number
  feature_registry: {
    name: string
    category: string
    description: string
    window: string | null
    default: number
  }[]
  training_samples: number
  label_distribution: Record<string, number>
  last_retrain: Record<string, unknown> | null
  retrain_count: number
}

/* ── System Nerve Center Types ─────────────────────────────────────────────── */

/** Health probe result for a single component */
export interface ComponentHealth {
  status: "healthy" | "degraded" | "unhealthy" | "error" | "unknown"
  latency_ms: number
  error?: string
  /** Human-readable diagnostic explanation of what went wrong */
  diagnostic?: string
  /** Specific investigation/troubleshooting steps */
  troubleshooting?: string[]
  /** Postgres-specific */
  pool_size?: number
  pool_checked_in?: number
  pool_checked_out?: number
  pool_overflow?: number
  /** Redis-specific */
  used_memory_mb?: number
  connected_clients?: number
  /** ClickHouse-specific */
  events_last_60s?: number
  events_per_sec?: number
  /** Kafka-specific */
  broker_count?: number
  topic_count?: number
  active_consumers?: number
  /** Backend-specific */
  pid?: number
  uptime_seconds?: number
  memory_rss_mb?: number
  cpu_percent?: number
  threads?: number
}

/** Pipeline node definition */
export interface PipelineNode {
  id: string
  label: string
  type: "source" | "service" | "queue" | "database" | "cache" | "external"
  group: "ingress" | "transport" | "processing" | "storage" | "agents" | "presentation"
  detail?: string
}

/** Pipeline connection definition */
export interface PipelineConnection {
  from: string
  to: string
  label: string
}

/** Throughput snapshot */
export interface ThroughputResponse {
  events_ingested: number
  events_processed: number
  events_dropped: number
  events_per_sec: number
  last_event_at: number | null
  uptime_seconds: number
}

/** Full nerve center response */
export interface NerveCenterResponse {
  status: "operational" | "degraded" | "partial"
  timestamp: number
  components: Record<string, ComponentHealth>
  throughput: ThroughputResponse
  pipeline: PipelineNode[]
  connections: PipelineConnection[]
}

/* ======================================================================
   MCP Supply Chain
   ====================================================================== */

export type MCPTrustLevel = "verified" | "known" | "unknown" | "suspicious" | "blocked"
export type MCPRiskLevel = "critical" | "high" | "medium" | "low" | "minimal"

export interface MCPServerSummary {
  id: string
  server_id: string
  name: string | null
  trust_level: MCPTrustLevel
  risk_score: number
  risk_level: MCPRiskLevel
  content_hash: string | null
  protocol_version: string | null
  capabilities: string[]
  metadata: Record<string, string>
  connection_count: number
  anomaly_count: number
  error_rate: number
  last_seen: string | null
  first_seen: string | null
  blocked_at: string | null
  blocked_reason: string | null
}

export interface MCPServerListResponse {
  items: MCPServerSummary[]
  total: number
}

export interface MCPScanResult {
  id: string
  server_id: string
  scan_type: string
  ecosystem: string | null
  total_packages: number
  clean_packages: number
  vulnerable: number
  malicious: number
  typosquat: number
  reputation_avg: number
  findings: MCPScanFinding[]
  scanned_at: string | null
}

export interface MCPScanFinding {
  type: "vulnerability" | "typosquat"
  package?: string
  severity?: string
  description?: string
  target?: string
  distance?: number
  confidence?: number
}

export interface MCPScanListResponse {
  items: MCPScanResult[]
  total: number
}

export interface MCPAnomaly {
  id: string
  server_id: string
  anomaly_type: string
  severity: string
  detail: string
  raw_evidence: string | null
  detected_at: string | null
}

export interface MCPAnomalyListResponse {
  items: MCPAnomaly[]
  total: number
}

export interface MCPRiskBreakdownComponent {
  score: number
  weight: number
  weighted: number
  details: string
}

export interface MCPRiskAssessment {
  server_id: string
  tenant_id: string
  score: number
  level: MCPRiskLevel
  action: "block" | "quarantine" | "monitor" | "allow"
  breakdown: { components: Record<string, MCPRiskBreakdownComponent> }
  assessed_at: string
  trend: "rising" | "falling" | "stable"
  auto_blocked: boolean
}

export interface MCPSupplyChainStats {
  total_servers: number
  by_trust_level: Record<string, number>
  by_risk_level: Record<string, number>
  total_anomalies: number
  critical_anomalies: number
  total_scans: number
  servers_blocked: number
  avg_risk_score: number
}
