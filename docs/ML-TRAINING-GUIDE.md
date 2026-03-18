# Phantex ML Training Guide

> **Audience:** Platform operators, ML engineers, SOC admins.
> **Last updated:** All ML security audits complete.
> **Companion doc:** See `ML-ARCHITECTURE.md` for full architecture reference (detection stages, file maps, data flow diagrams).

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Prerequisites](#prerequisites)
3. [Agent Onboarding & SDK Wiring](#agent-onboarding--sdk-wiring)
4. [Baseline Learning Lifecycle](#baseline-learning-lifecycle)
5. [Training Data Pipeline](#training-data-pipeline)
6. [Model Training Workflow](#model-training-workflow)
7. [Verification & Validation](#verification--validation)
8. [Operational Runbook](#operational-runbook)
9. [MCP Feature Coverage](#mcp-feature-coverage)
10. [Content Analysis Integration](#content-analysis-integration)
11. [ML Security Hardening (J5)](#ml-security-hardening-j5)
12. [Troubleshooting](#troubleshooting)

---

## Architecture Overview

Phantex uses a **4-layer detection stack**:

| Layer | Engine | Purpose | Latency |
|-------|--------|---------|----------|
| **L1 — Rules** | PRL rule engine | Deterministic pattern matching (known threats) | < 1ms |
| **L2 — Baselines** | Per-agent behavioral profiles | Deviation from learned normal behavior | < 2ms |
| **L3 — ML Ensemble** | 3-stage model pipeline | Anomaly scoring + classification + reconstruction | < 20ms p99 |
| **L4 — Content Analysis** | JB1-JB8 pipeline | Semantic content scanning (prompts, outputs, data) | < 15ms p99 |

### ML Ensemble Stages

| Stage | Model | Role | Training |
|-------|-------|------|----------|
| 1 — Gate | Isolation Forest | Unsupervised anomaly filter (no labels needed) | Per-tenant, offline |
| 2 — Classifier | XGBoost | Multi-class attack classification (8 classes) | Per-tenant, requires labels |
| 3 — Verifier | Autoencoder (PyTorch) | Reconstruction error confirms anomaly | Per-tenant, offline |

**Scoring pipeline:** Event → Feature extraction (62 behavioral features, 8 categories + 8 content features from JB6 = 70 total) → IF anomaly score → XGBoost class prediction → Autoencoder reconstruction error → Ensemble weighted score (0.3 × IF + 0.5 × XGB + 0.2 × AE) → Alert (if score ≥ 0.7).

**XGBoost attack classes (8):** benign, credential_theft, data_exfiltration, dos, lateral_movement, privilege_escalation, prompt_injection, supply_chain.

---

## Prerequisites

### Infrastructure

| Service | Version | Required For |
|---------|---------|--------------|
| PostgreSQL | 16+ | Agent metadata, baselines, alerts |
| ClickHouse | 24.1+ | Hourly feature vectors (`ml_features_hourly`) |
| Redis | 7.2+ | Rate limiting, caching |
| Kafka | 3.7+ | Event transport |

### Python Environment

```bash
cd backend
source .venv/bin/activate
pip install -r requirements.txt  # includes scikit-learn, xgboost, torch
```

### Minimum Data Requirements

| Metric | Minimum | Recommended |
|--------|---------|-------------|
| Agents per tenant | 1 | 10+ |
| Events per agent (learning) | 1,000 | 10,000+ |
| Learning period | 7 days (or early graduation) | 14 days |
| ClickHouse history (for training) | 7 days | 30 days |

---

## Agent Onboarding & SDK Wiring

### 1. Install the Phantex SDK

```python
# Python SDK
from phantex_sdk import PhantexSDK

agent = PhantexSDK(
    gateway_addr="grpc://gateway:50051",
    auth_token="your-api-key",
    agent_id="my-ai-agent",
    tenant_id="your-tenant-uuid",
)
```

### 2. Instrument Your Agent

```python
# Wrap tool calls
with agent.trace_tool("web_search", metadata={"query": "example"}):
    result = web_search("example")

# Wrap LLM calls
with agent.trace_llm("openai/gpt-4", tokens_in=500, tokens_out=200):
    response = llm.chat(messages)

# Wrap file access
with agent.trace_file_read("/data/config.json"):
    data = open("/data/config.json").read()
```

### 3. MCP Tool Server Instrumentation

For agents using MCP (Model Context Protocol) tool servers:

```python
# MCP events are auto-detected by event_type prefix
agent.emit_event(
    event_type="MCP_TOOL_CALL",
    tool_name="web_search",
    tool_duration_ms=150,
)

agent.emit_event(
    event_type="MCP_RESOURCE_READ",
    file_path="/data/sensitive.env",
)
```

The SDK also auto-captures `TOOL_CALL` events with `mcp_` prefixed tool names as MCP activity.

---

## Baseline Learning Lifecycle

Each agent goes through a per-agent behavioral baseline lifecycle:

```
                    ┌─────────────────────────────────────────────────────────┐
                    │                                                         │
   New Agent  ──▶  LEARNING  ──────────────────────▶  ACTIVE  ──▶  STALE     │
                    │   │                              │   │        │         │
                    │   └── Early Graduation ──────────┘   │        │         │
                    │       (variance stable +             │        └── LEARNING
                    │        500+ events)                  │                  │
                    │                                      │                  │
                    │   Alert-aware: flagged events        │   Normal mode:   │
                    │   excluded from metric updates       │   all events     │
                    │   (destinations still tracked)       │   update profile │
                    │                                      │                  │
                    └──────────────────────────────────────┘──────────────────┘
```

### Graduation Requirements

An agent's baseline graduates from LEARNING → ACTIVE when **BOTH** conditions are met:

1. **Time requirement:** `learning_days` elapsed (default: 7 days)
2. **Event requirement:** At least `min_learning_events` observations across all tracked metrics (default: 1,000)

### Early Graduation

If enabled (`early_graduation: true` in config), an agent can graduate before the time window if:

1. At least `early_graduation_min_events` observations (default: 500)
2. Coefficient of variation across all metrics is below `variance_stability_threshold` (default: 0.05)

This benefits high-traffic agents (e.g., 100K events/day) that converge quickly.

### Alert-Aware Learning

When `alert_aware_learning: true` (default), events flagged by PRL rules during the LEARNING phase are **excluded** from baseline metric updates. This prevents attack patterns from contaminating the baseline.

- Flagged events still update destination tracking and histograms (for visibility)
- In ACTIVE mode, flagged events update metrics normally (baseline is already established)

### Configuration

All thresholds are in `ml/config.py` → `BaselineConfig`:

```python
class BaselineConfig(BaseModel):
    learning_days: int = 7
    min_learning_events: int = 1_000
    early_graduation: bool = True
    early_graduation_min_events: int = 500
    variance_stability_threshold: float = 0.05
    alert_aware_learning: bool = True
    ema_alpha: float = 0.1
    stale_days: int = 30
```

---

## Training Data Pipeline

### Data Flow

```
Agent SDK events
      │
      ▼
  Kafka topic: phantex.events
      │
      ├──▶ Feature Extractor ──▶ 62 features per event
      │         │
      │         ▼
      │    ClickHouse: phantex.ml_features_hourly
      │         │
      │         ▼
      │    Training Data Loader ──▶ NumPy arrays (X, y)
      │                                    │
      │                                    ▼
      │                              Model Training
      │                                    │
      │                                    ▼
      │                         Model Registry (disk + Postgres)
      │
      └──▶ Baseline Builder ──▶ Per-agent profiles (Postgres)
```

### Feature Categories (62 total)

| Category | Count | Examples |
|----------|-------|---------|
| Volume | 16 | `event_count_1h`, `file_read_count_1h` |
| Velocity | 8 | `events_per_minute_5m`, `acceleration_ratio` |
| Behavioral | 8 | `tool_call_ratio`, `avg_response_time_1h` |
| Network | 8 | `unique_network_dests_1h`, `bytes_sent_total_1h` |
| Temporal | 4 | `hour_of_day_sin`, `is_weekend` |
| Diversity | 4 | `shannon_entropy_event_types`, `unique_event_types_1h` |
| Sequence | 4 | `max_repeat_event_type`, `top_2gram_ratio` |
| **MCP** | **10** | `mcp_tool_call_count_1h`, `mcp_tool_diversity_ratio` |

### ClickHouse Table

Features are materialized hourly in `phantex.ml_features_hourly`:

```sql
SELECT
    agent_id,
    event_count, tool_call_count, file_read_count,
    network_connect_count, bytes_sent_total, bytes_recv_total,
    unique_dest_ips, unique_dest_ports, unique_event_types,
    unique_tools, unique_files, avg_duration_ms, max_duration_ms
FROM phantex.ml_features_hourly
WHERE tenant_id = {tenant_id:UUID}
  AND hour >= now() - INTERVAL {lookback_days:UInt32} DAY
ORDER BY agent_id, hour
```

---

## Model Training Workflow

### Step 1: Generate or Load Training Data

```python
from ml.training.data_loader import TrainingDataLoader

loader = TrainingDataLoader(clickhouse_client=ch_client)

# Production: load from ClickHouse
X, feature_names, agent_ids = await loader.load_features(
    tenant_id="your-tenant-uuid",
    lookback_days=30,
)

# Development: use synthetic data
X, y, feature_names = loader.generate_synthetic_data(
    n_samples=10_000,
    n_features=30,
    anomaly_fraction=0.05,
)
```

### Step 2: Train Models

```python
from ml.models.isolation_forest import IsolationForestModel
from ml.models.xgboost_model import XGBoostModel
from ml.models.autoencoder import AutoencoderModel

# Stage 1: Isolation Forest (unsupervised — no labels needed)
iso = IsolationForestModel()
iso.fit(X)  # learns "normal" distribution

# Stage 1.5: Sanitize training data (J5b — REQUIRED before Stage 2+3)
from ml.integrity.data_sanitizer import DataSanitizer
sanitizer = DataSanitizer()
keep_mask = sanitizer.sanitize(X, y)  # outliers, label consistency, spectral analysis
X_clean, y_clean = X[keep_mask], y[keep_mask]

# Stage 2: XGBoost (supervised — needs labels)
from ml.training.labeler import Labeler
labeler = Labeler()
y = labeler.label(X, alerts)  # generate labels from confirmed alerts
xgb = XGBoostModel()
xgb.fit(X_clean, y_clean)

# Stage 3: Autoencoder (unsupervised)
ae = AutoencoderModel(input_dim=X_clean.shape[1])
ae.fit(X_clean)  # learns to reconstruct normal patterns
```

### Step 3: Validate

```python
from ml.training.validator import ModelValidator

validator = ModelValidator()

# Validate each model
iso_result = validator.validate(iso, X_test)
xgb_result = validator.validate(xgb, X_test, y_test)
ae_result = validator.validate(ae, X_test)

# Check thresholds
assert iso_result.passed, f"IF failed: {iso_result.reason}"
assert xgb_result.passed, f"XGB failed: {xgb_result.reason}"
assert ae_result.passed, f"AE failed: {ae_result.reason}"
```

### Step 4: Register (with HMAC-SHA256 signing)

```python
from ml.registry.model_registry import ModelRegistry

registry = ModelRegistry(base_dir="/opt/phantex/models")

# Save each model version — HMAC-SHA256 manifest auto-generated
registry.save(iso, tenant_id="your-tenant", model_type="isolation_forest")
registry.save(xgb, tenant_id="your-tenant", model_type="xgboost")
registry.save(ae, tenant_id="your-tenant", model_type="autoencoder")

# Models are verified before loading (J5e provenance)
# Set PHANTEX_SIGNING_KEY env var for production HMAC signing
```

### Step 5: Shadow Mode Deployment

New models run in **shadow mode** for 1 hour before promotion:

```python
from ml.serving.shadow_mode import ShadowModeTracker

# Shadow mode is automatic — new model version detected by ModelLoader
# During shadow period:
#   - New model runs predictions alongside current model
#   - Predictions are LOGGED but NOT alerted
#   - FPR is tracked — if > 0.05, promotion is blocked
#   - After 1 hour with acceptable FPR, new model auto-promotes
```

---

## Verification & Validation

### Post-Training Checklist

| # | Check | How to Verify |
|---|-------|---------------|
| 1 | IF anomaly scores reasonable | `iso.score_samples(X_test)` — 95%+ samples should score < 0.5 |
| 2 | XGBoost accuracy | `xgb_result.accuracy >= 0.85` on held-out test set |
| 3 | Autoencoder reconstruction | Mean reconstruction error on normal samples < threshold |
| 4 | No NaN in feature matrix | `assert not np.any(np.isnan(X))` |
| 5 | Feature count matches | `assert X.shape[1] == len(feature_names)` |
| 6 | Tenant isolation | Training data only contains events from target tenant |
| 7 | Model files saved | `ls /opt/phantex/models/{tenant_id}/` shows 3 model files |
| 8 | HMAC manifest valid | `registry.verify(tenant_id)` — checks HMAC-SHA256 signature |
| 9 | Data sanitization ran | DataSanitizer removed outliers, spectral analysis clean |
| 10 | Shadow mode passed | New model FPR < 0.05 during 1-hour shadow period |
| 11 | Adversarial robustness | FGSM evasion < 5%, PGD < 10% (J5a CI gates) |

### Baseline Health Check

```python
# Check agent baseline status
from ml.baseline.builder import BaselineBuilder
from ml.config import config

builder = BaselineBuilder()
profile = await builder.get_profile(agent_id="agent-123")

print(f"Mode: {profile.mode}")           # LEARNING / ACTIVE / STALE
print(f"Events seen: {profile.total_events}")
print(f"Learning started: {profile.learning_started}")
print(f"Days in learning: {profile.days_in_learning}")
```

---

## Operational Runbook

### Scenario: New Tenant Onboarding

1. Deploy SDK to all tenant agents
2. Wait for baseline learning (7 days or early graduation)
3. Verify ClickHouse has feature data: `SELECT count() FROM phantex.ml_features_hourly WHERE tenant_id = '{id}'`
4. Train initial models (IF only — no labels yet)
5. Monitor alert volume — expect calibration period (2-4 weeks)
6. As SOC confirms/dismisses alerts → labels accumulate → train XGBoost
7. Retrain monthly (or on significant label batch)

### Scenario: High False Positive Rate

1. Check baseline mode: is agent still in LEARNING? (normal during first 7 days)
2. Check min event threshold: agent with < 1,000 events has weak baseline
3. Review MCP features: new MCP tool server may need exemption (Block P)
4. Check for maintenance windows: deploy/CI activity spikes are expected
5. Tune thresholds in `ml/config.py` if needed
6. Add rule exemptions for known-good patterns (Block P when available)

### Scenario: Model Drift

1. Monitor ensemble score distribution over time
2. If P95 anomaly score rises > 20% month-over-month → retraining needed
3. Check for new event types not in training data
4. Verify ClickHouse data pipeline is healthy
5. Retrain with expanded lookback window

### Scenario: Server Shutdown / Data Loss

- **Baselines:** Stored in PostgreSQL — persist across restarts
- **Models:** Stored on disk + registered in PostgreSQL — persist across restarts
- **ClickHouse data:** Stored on disk — survives restart. Configure replication for HA
- **In-flight events:** Kafka provides at-least-once delivery
- **Feature cache:** Redis — volatile, but rebuilt from ClickHouse on cold start

---

## MCP Feature Coverage

The 10 MCP-specific features detect the following attack patterns:

| Feature | Detects |
|---------|---------|
| `mcp_tool_call_count_1h` | Burst of MCP tool activity |
| `mcp_unique_tools_1h` | Tool enumeration / scanning |
| `mcp_tool_diversity_ratio` | High diversity = exploration; low = repetitive abuse |
| `mcp_resource_read_count_1h` | Data exfiltration via resource reads |
| `mcp_unique_resources_1h` | Broad data access pattern |
| `mcp_prompt_to_tool_ratio` | Prompt injection probing (many prompts, few tool calls) |
| `mcp_list_tools_count_1h` | Server capability enumeration |
| `mcp_avg_tool_duration_ms` | Anomalous execution times (very fast = cached/scripted, very slow = exfiltration) |
| `mcp_tool_error_rate` | Brute-force tool probing (high error rate) |
| `mcp_top_tool_dominance` | Single-tool abuse vs. distributed attack |

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Agent stuck in LEARNING | < 1,000 events after 7 days | Increase agent activity or lower `min_learning_events` |
| Empty ClickHouse feature data | Feature extractor not running | Check Kafka consumer logs, verify CH writer is processing |
| Model training returns empty X | No ClickHouse client configured | Set `PHANTEX_CLICKHOUSE_HOST` and `PHANTEX_CLICKHOUSE_PORT` in environment |
| NaN values in features | Missing event fields | Check SDK instrumentation — ensure all required fields are set |
| MCP features all zero | No MCP events emitted | Verify agent uses MCP event types or `mcp_`-prefixed tool names |
| Early graduation not triggering | Variance too high | Agent behavior hasn't converged — wait for full 7-day window |
| Content features all zero | Content consumer not running | Check `phantex-ml-content` is healthy, verify `ml.main_content` and `feature_bridge.py` are loaded |
| Embedding similarity always 0 | No corpus loaded | Populate known-attack corpus via JB8a `corpus.add()` |
| Trained classifier unavailable | Not enough labeled data | Need ≥ 50 labeled samples (default `trained_min_samples`) |
| Shadow mode blocking promotion | FPR too high | New model has > 5% false positive rate — review training data quality |
| HMAC verification failing | Key mismatch | Check `PHANTEX_SIGNING_KEY` matches between training and serving |

---

## Content Analysis Integration

Since Session 36 (Block JB), Phantex has a full **content analysis layer** (L4) that feeds 8 additional features into the ML ensemble:

| # | Content Feature | Source | Description |
|---|----------------|--------|-------------|
| 1 | `prompt_injection_score` | JB1 | Prompt injection classifier score |
| 2 | `data_sensitivity_score` | JB4 | PII/PHI/financial data detection |
| 3 | `output_risk_score` | JB3 | Secret/leak detection in output |
| 4 | `tool_policy_score` | JB2 | Tool authorization violation |
| 5 | `mcp_trust_score` | JB2 | MCP server trust level |
| 6 | `context_drift_score` | JB5 | Content pattern drift from baseline |
| 7 | `embedding_similarity_score` | JB8a | Semantic similarity to known attacks |
| 8 | `trained_classifier_score` | JB8b | Operator-trained classifier verdict |

These 8 scores are normalized to [0, 1] by the **feature bridge** (`ml/content/integration/feature_bridge.py`) and appended to the 62 behavioral features, giving the ensemble **70 total dimensions**.

### How content features reach the ensemble

```
Gateway receives event
  → gateway_hook.py runs content analysis inline
  → ContentVerdict attached as event metadata
  → Kafka → FeatureExtractionConsumer
  → 62 behavioral features (Redis) + 8 content features (metadata)
  → InferenceConsumer runs ensemble on all 70 features
```

### Content classifier fusion (JB8c)

Before content features reach the ensemble, 4 content classifiers are fused:

| Signal | Weight | Source |
|--------|--------|--------|
| Regex patterns | 0.20 | JB1 (41 patterns) |
| ML/SVC classifier | 0.25 | JB1 (TF-IDF + LinearSVC) |
| Embedding similarity | 0.25 | JB8a (sentence-transformer) |
| Trained classifier | 0.30 | JB8b (operator-labeled data) |

See `ML-ARCHITECTURE.md` for full content analysis architecture (JB1-JB8).

---

## ML Security Hardening (J5)

Six sub-blocks protect the ML system itself. These are **mandatory** for production training.

### J5a: Adversarial Robustness

Run after training to verify model resilience:

```python
from ml.adversarial.robustness_test import run_robustness_suite

result = run_robustness_suite(ensemble, X_test, y_test)
assert result.fgsm_evasion_rate < 0.05   # < 5% evasion
assert result.pgd_evasion_rate < 0.10     # < 10% evasion
assert result.feature_flip_rate < 0.08    # < 8% flip rate
assert result.accuracy_drop <= 0.02       # ≤ 2% accuracy loss
```

To improve robustness, use adversarial training augmentation:

```python
from ml.adversarial.adversarial_trainer import AdversarialTrainer

at = AdversarialTrainer()
X_augmented, y_augmented = at.augment(X_clean, y_clean)  # adds adversarial samples
# Retrain on augmented data
```

### J5b: Training Data Integrity

**Always run DataSanitizer before training** (included in Step 2 above):

1. **Outlier detection** — statistical bounds on each feature
2. **Volume anomaly** — detects sudden label distribution shifts
3. **Label consistency** — cross-validation check
4. **Spectral analysis** — SVD-based backdoor cluster detection

Label governance requires **dual approval** for label changes (separation of duties).

### J5c: Model Explainability

Every ML alert includes human-readable explanations:

```python
from ml.explainability.ensemble_explainer import EnsembleExplainer

explainer = EnsembleExplainer(iso, xgb, ae)
explanation = explainer.explain(features)
print(explanation.summary)
# "Alert triggered because file_read_rate_1h was 4.2σ above baseline
#  (normally 12/hour, observed 847/hour). Network destinations included
#  3 IPs never seen before."
```

### J5d: Meta-Detection

8 monitors detect attacks on the ML itself:
- **Drift detector** (KL divergence + KS test)
- **Accuracy tracker** (rolling precision/recall/FPR)
- **Evasion detector** (near-threshold clustering)
- **Extraction detector** (API query rate anomaly)
- **Poisoning monitor** (label dismissal rate)
- **Staleness checker** (model age vs config)

### J5e: Training Provenance

Every model version has an **SLSA-inspired manifest** — data hash, model hash, training params, timestamp, HMAC-SHA256 signature. Models are **verified before deserialization** (prevents pickle attacks).

### J5f: Differential Privacy

Laplace noise on trust score queries. Per-user per-hour ε budget (ε=1.0, total=10.0).

See `ML-ARCHITECTURE.md` for detailed J5 architecture.

---

*For full architecture reference (detection stages, data flow, file maps, BYO-ML integration), see [ML-ARCHITECTURE.md](ML-ARCHITECTURE.md).*
