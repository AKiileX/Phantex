# ML Model Persistence & Restart Behavior

> What happens to the ML model when you stop, restart, or wipe things.

---

## Where Models Live

```
backend/models/
└── global/
    └── v1772330265/
        ├── stage1.pkl      # IsolationForest  (1.3 MB)
        ├── stage2.pkl      # XGBoost          (3.1 MB)
        ├── stage3.pkl      # Autoencoder      (59 KB)
        ├── feature_names.json
        └── manifest.json
```

The model registry is **filesystem-based** — artifacts persist across restarts.

---

## Scenario Table

| Scenario | Model survives? | What happens on next start |
|---|---|---|
| Stop all processes, start again | **Yes** | API + inference load model from `backend/models/` in <1s |
| Reboot WSL / restart Docker | **Yes** | Same — model files are on Windows disk (`/mnt/c/...`) |
| Delete `backend/models/` then start | **No** | Inference consumer auto-trains a new model (~40s) |
| Delete `backend/models/global/` only | **No** | Same — fresh global model trained on demand |
| Stop simulator only | **Yes** | Model stays loaded, just no new events to score |
| Stop inference consumer only | **Yes** | Model files remain, reloaded when consumer restarts |

---

## How Auto-Training Works

When the inference consumer starts and no model is found:

```
1. InferenceConsumer receives first Kafka event
2. ModelLoader.get_fused_ensemble_result() → GlobalModelManager.get_ensemble()
3. get_ensemble() → _try_load_from_registry() → no files → _train_and_register()
4. SyntheticGenerator creates 50K samples (seed=42, deterministic)
5. Trains 3-stage ensemble: IsolationForest → XGBoost → Autoencoder
6. Saves to backend/models/global/vXXXX/
7. ~40 seconds total, then scoring resumes
```

**Key point**: Training uses **synthetic data only** (hardcoded seed=42). It does NOT learn from simulator events or historical data. Every fresh train produces a mathematically identical model.

---

## What to Delete (Reset Cheat Sheet)

| Want to reset... | Delete this | Effect |
|---|---|---|
| ML model only | `backend/models/` | Fresh model trained on next start |
| Global model only | `backend/models/global/` | Same (no tenant models exist yet) |
| All ML + Redis features | `backend/models/` + `redis-cli FLUSHDB` | Clean slate: no model, no cached features |
| Everything (full wipe) | `backend/models/` + Postgres + ClickHouse + Redis + Neo4j data | Factory reset — run migrations again |

### Commands

```bash
# Reset ML model only
rm -rf backend/models/

# Reset ML + Redis feature cache
rm -rf backend/models/
redis-cli -h localhost FLUSHDB

# Nuclear: stop all, wipe everything, start fresh
bash scripts/phantex-up.sh --stop
rm -rf backend/models/
docker compose -f docker-compose.dev.yml down -v   # destroys DB volumes
docker compose -f docker-compose.dev.yml up -d
bash backend/migrations/migrate.sh                  # re-create tables + seed
bash scripts/phantex-up.sh                          # start all + auto-train
```

---

## What Does NOT Reset on Restart

- **Postgres**: Alerts, rules, policies, users, audit logs — all persist in DB
- **ClickHouse**: Event analytics history — persists
- **Neo4j**: Agent relationship graph — persists
- **Kafka**: Topic offsets — consumers resume where they left off (no replay)

---

## Two Separate Processes, One Registry

The API server (uvicorn) and inference consumer are **separate processes**. They share the same filesystem registry:

- **Inference consumer** (`ml.main_inference`): Trains the model on first event, scores all subsequent events
- **API server** (`uvicorn`): Reads model from registry at startup for the ML dashboard page

Both discover the model from `backend/models/`. If you restart just the API, it reloads the existing model. If you restart just the inference consumer, it reloads too — no retraining needed as long as the files exist.

---

## Global Model vs Tenant Models

### What is the Global Model?

The global model is the **baseline protection floor** — every tenant gets it automatically, even brand-new ones with zero historical data. It's the bare minimum detection capability that ships out of the box.

```
backend/models/
├── global/                    ← Global model (shared by ALL tenants)
│   └── v1772330265/
│       ├── stage1.pkl         # IsolationForest
│       ├── stage2.pkl         # XGBoost
│       └── stage3.pkl         # Autoencoder
│
├── tenant_a0000001/           ← Tenant-specific model (future, doesn't exist yet)
│   └── v.../
└── tenant_b0000002/           ← Another tenant model (future)
    └── v.../
```

### How Scoring Works With Both

When an event arrives for a tenant:

1. **Global model** always scores it (baseline)
2. **Tenant model** also scores it (if one exists for that tenant)
3. **EnsembleFusion** blends both scores using adaptive weights

Currently: `global_weight=100%`, `tenant_weight=0%` — because no tenant models exist yet. Once a tenant accumulates enough labeled data and a retrain completes, the fusion weights shift automatically (e.g. 60% global / 40% tenant, then eventually 30/70 as the tenant model proves itself).

### Deleting Global vs Tenant Models

| Action | Safe? | What happens |
|---|---|---|
| Delete `backend/models/global/` | **Yes, safe** | Auto-retrains from synthetic data in ~40s. Identical model every time (seed=42). No data loss. |
| Delete a tenant model folder | **Yes, safe** | That tenant falls back to global-only scoring (100% global weight). No gap in protection. |
| Delete `backend/models/` (everything) | **Yes, safe** | Global retrains automatically. All tenants fall back to global until their models retrain. |
| Delete global while inference is running | **No effect until restart** | The loaded model stays in memory. On next restart it retrains. |

### Key Differences

| | Global Model | Tenant Model |
|---|---|---|
| **Training data** | Synthetic (50K samples, seed=42) | Real labeled events from that tenant |
| **Auto-trains on startup?** | **Yes** — always, if missing | **No** — only when retrain pipeline triggers |
| **Retrain trigger** | Delete files + restart | Enough new labeled data accumulates (auto-retrain scheduler) |
| **Identical after reset?** | **Yes** — deterministic seed | **No** — depends on tenant's actual event history |
| **Can you lose it permanently?** | **No** — always regenerates | **Yes** — if you delete it AND the labeled data in Postgres |
| **Required for scoring?** | **Yes** — fallback for all tenants | **No** — optional enhancement |

### So Is It Safe to Delete?

**Global model**: Always safe. Delete it whenever you want. It regenerates identically every time because it's trained on synthetic data with a fixed seed. The only cost is ~40 seconds of no scoring while it retrains.

**Tenant models**: Safe to delete, but not reversible unless the labeled training data still exists in Postgres. The tenant just falls back to global-only scoring (which is the baseline protection floor anyway).

**Bottom line**: You cannot permanently break ML by deleting model files. The global model is self-healing.

---

## Dev / Testing Mode — What Happens to the ML

When you're running PHANTEX in dev mode (locally, simulator producing events, testing things),
the ML system is fully active but running on **synthetic / simulated data only**. Here's exactly
what's going on and what matters.

### The Data Flow During Dev

```
agent-simulator.py            Kafka              3 ML Consumers
  ┌──────────────┐     ┌─────────────────┐     ┌────────────────────────────────┐
  │ Fake events   │ ──► │ phantex.events.  │ ──► │ 1. Feature Extractor (main_    │
  │ ~2 events/sec │     │ {DEV_TENANT_ID}  │     │    features) → Redis           │
  │ 8% attack mix │     └─────────────────┘     │ 2. Inference (main_inference)  │
  └──────────────┘                               │    → scores → Kafka alerts     │
                                                 │ 3. Baseline (main_baseline)   │
                                                 │    → Postgres baselines        │
                                                 └────────────────────────────────┘
```

Everything runs identically in dev and production. The only differences are:

| Aspect | Dev | Production |
|---|---|---|
| **Event source** | `agent-simulator.py` (fake events) | Real sensors on real hosts |
| **Tenant ID** | Hardcoded `a0000000-0000-0000-0000-000000000001` | Real tenant UUIDs |
| **Event rate** | ~2/sec (configurable via `--rate`) | Depends on deployment size |
| **Attack events** | Randomly injected (8% default via `--attack-chance`) | Real threats or false positives |
| **Model** | Global model trained on synthetic data (seed=42) | Same initially, then tenant models grow |

### What Each Consumer Does With Your Test Data

**1. Feature Extractor** (`ml.main_features`)
- Reads every event from Kafka
- Computes 62 features per agent (volume, velocity, diversity, network, temporal, etc.)
- Writes feature vectors to **Redis** (hot cache, 24h TTL)
- Writes hourly aggregates to **ClickHouse** (`ml_features_hourly` table)
- ⚠️ **This data accumulates** — ClickHouse stores historical feature data from your test runs

**2. Inference Consumer** (`ml.main_inference`)
- Reads every event, pulls features from Redis, scores through the 3-stage ensemble
- Events above the 0.7 threshold generate ML alerts → published to `phantex.alerts.*` Kafka topic
- Alerts land in **Postgres** (`alerts` table) and show on the dashboard
- ⚠️ **Alerts accumulate** — every test run creates more alerts in the database

**3. Baseline Consumer** (`ml.main_baseline`)
- Builds per-agent behavioral profiles over time
- New agents start in **LEARNING** mode (7 days or 1,000 events, whichever comes first)
- After graduation → **ACTIVE** mode: compares each event against the learned baseline
- Deviations generate baseline alerts → Postgres + Kafka
- ⚠️ **Baselines accumulate** — agent profiles persist in Postgres (`agent_baselines` table)

### Does Simulator Data Affect the Model?

**No.** The global model is pre-trained on synthetic data (seed=42, deterministic). It does NOT learn from incoming events. Simulator data only gets **scored** — it flows in, gets a score, and flows out as alerts. The model weights don't change.

The only way to retrain is:
1. An analyst **labels** alerts (confirm/reject) → creates training data
2. The **RetrainScheduler** detects 50+ new labels for a tenant
3. The **RetrainPipeline** trains a new **tenant-specific** model from ClickHouse data
4. The new model goes through 30-min **shadow validation** before replacing the old one

In dev, nobody is labeling alerts, so no retrain ever triggers. The model stays frozen.

### What Accumulates During Testing (and Where)

| Data | Where | Grows? | Size impact |
|---|---|---|---|
| Feature vectors (hot) | Redis | Yes, but 24h TTL auto-cleans | Negligible — <100MB |
| Feature aggregates (cold) | ClickHouse `ml_features_hourly` | Yes, permanently | ~1 KB/agent/hour |
| ML alerts | Postgres `alerts` table | Yes, permanently | ~1 KB/alert |
| Baseline alerts | Postgres `alerts` table | Yes, permanently | ~1 KB/alert |
| Baseline profiles | Postgres `agent_baselines` table | Yes, permanently | ~2 KB/agent |
| ML scores/evasion tracking | In-memory only | No (resets on restart) | 0 |
| Kafka offsets | Kafka `__consumer_offsets` | Yes, compacted | Negligible |
| Drift/staleness metrics | In-memory only | No (resets on restart) | 0 |

### Observing ML Behavior During Testing

Things to look at while testing:

```bash
# See ML alerts flowing in real-time
curl -s http://localhost:8000/api/v1/alerts?limit=5 | python -m json.tool

# Check model status
curl -s http://localhost:8000/api/v1/ml/dashboard | python -m json.tool

# Watch inference scores in logs
wsl -d Ubuntu-24.04 -- bash -c "pgrep -f main_inference | xargs -I{} tail -f /proc/{}/fd/1"

# See how many alerts have accumulated
curl -s http://localhost:8000/api/v1/analytics/summary | python -m json.tool

# Check baseline status for agents
curl -s http://localhost:8000/api/v1/ml/models | python -m json.tool
```

On the **dashboard** (http://localhost:5173):
- **Alerts page**: Shows ML + baseline + rule alerts in real-time
- **ML page**: Shows model status, version, feature count, worker status
- **Analytics page**: Event volume graphs, alert trends over time

### What the Scores Mean During Dev

The global model scores simulator events on a 0.0–1.0 scale:

| Score range | Meaning | Typical dev behavior |
|---|---|---|
| 0.0 – 0.3 | Normal | Most legitimate simulator events land here |
| 0.3 – 0.7 | Suspicious | Some simulator events with unusual patterns |
| 0.7 – 1.0 | **Alert** (above threshold) | ~8% of events (matches `--attack-chance`) |

The model isn't perfectly tuned for simulator data because it was trained on synthetic distributions, not the simulator's specific patterns. You'll see some false positives and missed detections — that's expected. In production, tenant models trained on real labeled data will be more accurate.

---

## Ready to Deploy? How to Start Fresh

When you're done testing and ready to deploy to production (or just want a clean slate),
here's what to clean up and what to keep.

### The Quick Answer

```bash
# Stop everything
bash scripts/phantex-up.sh --stop

# Delete ML artifacts
rm -rf backend/models/

# Flush accumulated test data from databases
# (ONLY if you want a full clean slate — this deletes EVERYTHING)
docker compose -f docker-compose.dev.yml down -v
docker compose -f docker-compose.dev.yml up -d
bash backend/migrations/migrate.sh

# Restart
bash scripts/phantex-up.sh
```

### The Detailed Answer — What to Delete and Why

| What | Delete? | Why / Why not |
|---|---|---|
| `backend/models/` | **Yes** | Wipe trained models. New global model auto-trains in ~40s. For production you'll want tenant models trained on real data anyway. |
| Postgres alerts | **Yes** | Test alerts from simulator are noise. They'd confuse real SOC analysts. |
| Postgres baselines | **Yes** | Baseline profiles learned from simulator agents are meaningless in prod. |
| ClickHouse features | **Yes** | Historical feature data from simulator events isn't representative of real traffic. |
| Redis feature cache | **Auto-cleans** | 24h TTL — if you leave the system off for a day, Redis clears itself. Or `redis-cli FLUSHDB` to force it. |
| Kafka topics | **Yes** | Old Kafka data from test runs. `docker compose down -v` wipes Kafka volumes. |
| Neo4j graph | **Yes** | Agent relationship graph from simulator — not useful in prod. |
| Postgres users/rules/policies | **Keep or re-seed** | If you customized rules/policies, you may want to keep them. Migrations re-create defaults. |
| `migrations/` | **Keep** | These are schema files, not data. Always keep. |
| Source code | **Keep** | Obviously. |
| `docker-compose.dev.yml` | **Swap** | Use a production compose file / Helm chart instead. |

### Selective Reset (Keep Your Config, Wipe Test Data)

If you want to keep your custom rules, policies, and user accounts but wipe only ML-related test data:

```bash
# Stop ML consumers
bash scripts/phantex-up.sh --stop

# Delete model artifacts
rm -rf backend/models/

# Flush Redis feature cache
redis-cli -h localhost FLUSHDB

# Truncate only ML-related tables in Postgres (keeps users, rules, policies)
psql -h localhost -U phantex_admin -d phantex -c "
  TRUNCATE TABLE alerts CASCADE;
  TRUNCATE TABLE agent_baselines CASCADE;
"

# Truncate ClickHouse feature history
clickhouse-client --host localhost --user default --password phantex-ch-dev \
  --query "TRUNCATE TABLE phantex.ml_features_hourly"

# Restart fresh
bash scripts/phantex-up.sh
```

### Dev Mode Guard (PHANTEX_ML_DEV_MODE)

There's a built-in safety mechanism for preventing simulator data from contaminating
production models. Set the environment variable:

```bash
export PHANTEX_ML_DEV_MODE=true
```

When active:
- The **training data loader** refuses to load features from dev tenant IDs
  (default: `a0000000-0000-0000-0000-000000000001` — the simulator's tenant)
- This means even if a retrain triggers, it won't use simulator data
- The global model is unaffected (it uses synthetic data, not tenant data)
- Already set in `docker-compose.dev.yml` for containerized runs

This is a **safety net**, not a cleanup tool. It prevents contamination during development
but doesn't remove data that's already been written. You still need to wipe data manually
when moving to production.

### Production Checklist

Before deploying to production, verify:

- [ ] `backend/models/` directory is empty (auto-trains fresh global model)
- [ ] Postgres has no leftover test alerts (`SELECT COUNT(*) FROM alerts`)
- [ ] ClickHouse has no test feature data (`SELECT COUNT(*) FROM phantex.ml_features_hourly`)
- [ ] Redis is flushed (`redis-cli DBSIZE` → should be 0 or near 0)
- [ ] `PHANTEX_ML_DEV_MODE` is set to `false` (or unset) in production config
- [ ] Real sensors are connected and producing events on real tenant topics
- [ ] Kafka topics are clean (no stale test messages)
- [ ] Neo4j has no simulator agent relationships
- [ ] TLS is enabled for all connections (Kafka, Postgres, Redis, gRPC)
- [ ] Default admin password (`changeme`) is changed

### Timeline: What Happens After a Fresh Production Start

```
T+0s      System starts. No model files found.
T+1s      Feature extractor begins processing real events → Redis + ClickHouse.
T+1s      Baseline consumer begins LEARNING mode for each new agent.
T+5s      First real event reaches inference consumer.
T+40s     Global model auto-trains (synthetic data). Scoring begins.
T+40s     All events now get ML scores. Alerts above 0.7 threshold fire.
          (Global model — generic but immediately protective)

T+7 days  Baselines graduate LEARNING → ACTIVE for agents with 1,000+ events.
          Baseline deviation alerts start firing (more precise, per-agent).

T+weeks   Analysts label alerts (confirm/reject threats).
          Labels accumulate in the retrain scheduler.

T+weeks   50 labels for a tenant → RetrainScheduler triggers.
          RetrainPipeline trains a tenant-specific model from real ClickHouse data.
          30-min shadow validation → if quality gates pass → promoted.
          EnsembleFusion starts blending: global (60%) + tenant (40%).

T+months  Tenant model matures (5,000+ training samples).
          Fusion shifts: global (30%) + tenant (70%).
          Detection improves because model is trained on YOUR data, not synthetic.
```

The system is designed for **zero-downtime cold start** — the global model provides immediate
(if generic) protection while tenant models grow organically from real operational data.
