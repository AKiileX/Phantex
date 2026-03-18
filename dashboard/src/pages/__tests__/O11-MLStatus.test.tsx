// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — O11 tests: ML Model Status.
 *
 * Covers:
 *   - MLStatusPage (global model, retrain, fusion, metrics, versions, history)
 *   - ModelCard component (stages, metrics, current badge)
 *   - RetrainHistory component (timeline, empty state)
 *   - Error / loading states
 *   - Manual retrain trigger (two-click confirm)
 *   - Route + sidebar integration (admin-only)
 */

import { describe, it, expect, vi, beforeEach } from "vitest"
import { screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { renderWithProviders } from "@/test/test-utils"

/* ── Fixtures ──────────────────────────────────────────────────────────────── */

const mockDashboard = {
  global_model: {
    loaded: true,
    version: "v1700000000",
    n_features: 62,
    training_in_progress: false,
  },
  models: {
    models: [
      {
        version: "v1700000000",
        tenant_id: "t1",
        created_at: 1700000000,
        stages: { stage1: true, stage2: true, stage3: false },
        metrics: {
          stage1_validation: { precision: 0.95, recall: 0.88, fpr: 0.03, f1: 0.91 },
          training_samples: 5000,
          retrain_trigger: "auto" as const,
        },
        feature_names: ["f1", "f2"],
        signature: "abc123",
      },
      {
        version: "v1690000000",
        tenant_id: "t1",
        created_at: 1690000000,
        stages: { stage1: true, stage2: false, stage3: false },
        metrics: {
          stage1_validation: { precision: 0.82, recall: 0.75, fpr: 0.08 },
          training_samples: 2000,
          retrain_trigger: "manual" as const,
        },
        feature_names: ["f1"],
      },
    ],
    current_version: "v1700000000",
  },
  fusion_weights: {
    global_weight: 0.65,
    tenant_weight: 0.35,
    tenant_samples: 3000,
    reason: "sigmoid_transition",
  },
  retrain_status: {
    new_labels: 120,
    total_labels: 5000,
    last_retrain: 1700000000,
    is_retraining: false,
    active_retrains: 0,
    max_concurrent: 4,
    enabled: true,
  },
  retrain_history: [
    {
      success: true,
      tenant_id: "t1",
      version: "v1700000000",
      training_time_seconds: 42.5,
      reason: "threshold_met",
      metrics: {},
    },
    {
      success: false,
      tenant_id: "t1",
      version: null,
      training_time_seconds: 12.3,
      reason: "quality_gate_failed",
      metrics: {},
    },
  ],
  worker_stats: {
    running: true,
    retrains_completed: 15,
    retrains_failed: 2,
    check_interval_seconds: 21600,
    enabled: true,
  },
  shadow: {
    in_shadow: false,
    passed: true,
    alert_rate: 0.02,
    total_scored: 500,
    total_alerts: 10,
    version: "v1700000000",
    max_alert_rate: 0.05,
  },
  accuracy: {
    timestamp: 1700000000,
    precision: 0.94,
    recall: 0.87,
    fpr: 0.04,
    tp: 470,
    fp: 30,
    fn: 70,
    tn: 9430,
  },
  drift: {
    drifted: false,
    metric_name: "mean_feature_0",
    metric_value: 0.42,
    threshold: 0.5,
    details: {},
  },
  meta_alerts: [
    {
      id: "ma-1",
      alert_type: "ACCURACY_DRIFT",
      severity: "warning" as const,
      message: "Precision dropped below threshold",
      details: {},
      timestamp: 1700000000,
    },
  ],
}

/* ── Mocks ─────────────────────────────────────────────────────────────────── */

const triggerMutateFn = vi.fn()

vi.mock("@/api/ml", () => ({
  useMLDashboard: vi.fn(() => ({
    data: mockDashboard,
    isLoading: false,
    error: null,
  })),
  useTriggerRetrain: vi.fn(() => ({
    mutate: triggerMutateFn,
    isPending: false,
  })),
}))

import { useMLDashboard, useTriggerRetrain } from "@/api/ml"

const mockedDashboard = vi.mocked(useMLDashboard)
const mockedTrigger = vi.mocked(useTriggerRetrain)

beforeEach(() => {
  vi.clearAllMocks()
  mockedDashboard.mockReturnValue({
    data: mockDashboard,
    isLoading: false,
    error: null,
  } as ReturnType<typeof useMLDashboard>)
  mockedTrigger.mockReturnValue({
    mutate: triggerMutateFn,
    isPending: false,
  } as unknown as ReturnType<typeof useTriggerRetrain>)
})

/* ── Lazy import ───────────────────────────────────────────────────────────── */

async function renderPage() {
  const mod = await import("@/pages/MLStatusPage")
  return renderWithProviders(<mod.default />)
}

async function renderModelCard() {
  const { ModelCard } = await import("@/components/ml/ModelCard")
  return renderWithProviders(
    <ModelCard model={mockDashboard.models.models[0]} isCurrent />
  )
}

async function renderRetrainHistory() {
  const { RetrainHistory } = await import("@/components/ml/RetrainHistory")
  return renderWithProviders(<RetrainHistory results={mockDashboard.retrain_history} />)
}

/* ══════════════════════════════════════════════════════════════════════════════
 * 1. PAGE – GLOBAL MODEL
 * ════════════════════════════════════════════════════════════════════════════ */

describe("MLStatusPage – Global Model", () => {
  it("renders page title", async () => {
    await renderPage()
    expect(screen.getByText("ML Model Status")).toBeInTheDocument()
  })

  it("shows global model loaded status", async () => {
    await renderPage()
    expect(screen.getByText("Loaded")).toBeInTheDocument()
  })

  it("shows global model version", async () => {
    await renderPage()
    expect(screen.getAllByText("v1700000000").length).toBeGreaterThanOrEqual(1)
  })

  it("shows feature count", async () => {
    await renderPage()
    expect(screen.getByText("62")).toBeInTheDocument()
  })

  it("shows training in progress when active", async () => {
    mockedDashboard.mockReturnValue({
      data: {
        ...mockDashboard,
        global_model: { ...mockDashboard.global_model, training_in_progress: true },
      },
      isLoading: false,
      error: null,
    } as ReturnType<typeof useMLDashboard>)
    await renderPage()
    expect(screen.getByText(/Training in progress/)).toBeInTheDocument()
  })
})

/* ══════════════════════════════════════════════════════════════════════════════
 * 2. PAGE – RETRAIN STATUS
 * ════════════════════════════════════════════════════════════════════════════ */

describe("MLStatusPage – Retrain", () => {
  it("shows auto-retrain enabled", async () => {
    await renderPage()
    expect(screen.getByText("Enabled")).toBeInTheDocument()
  })

  it("shows new label count", async () => {
    await renderPage()
    expect(screen.getByText(/120 \/ 5,?000 total/)).toBeInTheDocument()
  })

  it("manual trigger requires confirm", async () => {
    const user = userEvent.setup()
    await renderPage()
    await user.click(screen.getByText("Trigger Retrain"))
    expect(screen.getByText("Confirm")).toBeInTheDocument()
    expect(screen.getByText("Cancel")).toBeInTheDocument()
  })

  it("confirm calls triggerRetrain", async () => {
    const user = userEvent.setup()
    await renderPage()
    await user.click(screen.getByText("Trigger Retrain"))
    await user.click(screen.getByText("Confirm"))
    expect(triggerMutateFn).toHaveBeenCalled()
  })

  it("cancel hides confirm buttons", async () => {
    const user = userEvent.setup()
    await renderPage()
    await user.click(screen.getByText("Trigger Retrain"))
    await user.click(screen.getByText("Cancel"))
    expect(screen.getByText("Trigger Retrain")).toBeInTheDocument()
  })
})

/* ══════════════════════════════════════════════════════════════════════════════
 * 3. PAGE – FUSION WEIGHTS
 * ════════════════════════════════════════════════════════════════════════════ */

describe("MLStatusPage – Fusion Weights", () => {
  it("shows global weight percentage", async () => {
    await renderPage()
    expect(screen.getByText("65.0%")).toBeInTheDocument()
  })

  it("shows tenant weight percentage", async () => {
    await renderPage()
    expect(screen.getByText("35.0%")).toBeInTheDocument()
  })

  it("shows fusion reason", async () => {
    await renderPage()
    expect(screen.getByText("sigmoid_transition")).toBeInTheDocument()
  })
})

/* ══════════════════════════════════════════════════════════════════════════════
 * 4. PAGE – ACCURACY METRICS
 * ════════════════════════════════════════════════════════════════════════════ */

describe("MLStatusPage – Accuracy", () => {
  it("shows precision percentage", async () => {
    await renderPage()
    expect(screen.getByText("94.0%")).toBeInTheDocument()
  })

  it("shows recall percentage", async () => {
    await renderPage()
    expect(screen.getByText("87.0%")).toBeInTheDocument()
  })

  it("shows FPR percentage", async () => {
    await renderPage()
    expect(screen.getByText("4.0%")).toBeInTheDocument()
  })
})

/* ══════════════════════════════════════════════════════════════════════════════
 * 5. PAGE – SHADOW / DRIFT / META
 * ════════════════════════════════════════════════════════════════════════════ */

describe("MLStatusPage – Shadow/Drift/Meta", () => {
  it("shows shadow mode status", async () => {
    await renderPage()
    expect(screen.getByText("Production")).toBeInTheDocument()
  })

  it("shows drift stable status", async () => {
    await renderPage()
    expect(screen.getByText("Stable")).toBeInTheDocument()
  })

  it("shows meta alert count badge", async () => {
    await renderPage()
    // The badge with count "1"
    const badges = screen.getAllByText("1")
    expect(badges.length).toBeGreaterThanOrEqual(1)
  })

  it("shows meta alert message", async () => {
    await renderPage()
    expect(screen.getByText("Precision dropped below threshold")).toBeInTheDocument()
  })

  it("shows drift detected when drifted", async () => {
    mockedDashboard.mockReturnValue({
      data: {
        ...mockDashboard,
        drift: { ...mockDashboard.drift, drifted: true },
      },
      isLoading: false,
      error: null,
    } as ReturnType<typeof useMLDashboard>)
    await renderPage()
    expect(screen.getByText("Drift Detected")).toBeInTheDocument()
  })
})

/* ══════════════════════════════════════════════════════════════════════════════
 * 6. PAGE – MODEL VERSIONS
 * ════════════════════════════════════════════════════════════════════════════ */

describe("MLStatusPage – Model Versions", () => {
  it("shows model version count", async () => {
    await renderPage()
    expect(screen.getByText("Model Versions (2)")).toBeInTheDocument()
  })

  it("renders retrain history count", async () => {
    await renderPage()
    expect(screen.getByText("Retrain History (2 runs)")).toBeInTheDocument()
  })
})

/* ══════════════════════════════════════════════════════════════════════════════
 * 7. PAGE – LOADING / ERROR STATES
 * ════════════════════════════════════════════════════════════════════════════ */

describe("MLStatusPage – Loading/Error", () => {
  it("shows spinner during loading", async () => {
    mockedDashboard.mockReturnValue({
      data: undefined,
      isLoading: true,
      error: null,
    } as ReturnType<typeof useMLDashboard>)
    const { container } = await renderPage()
    expect(container.querySelector(".animate-spin")).not.toBeNull()
  })

  it("shows error fallback on API failure", async () => {
    mockedDashboard.mockReturnValue({
      data: undefined,
      isLoading: false,
      error: new Error("fail"),
    } as unknown as ReturnType<typeof useMLDashboard>)
    await renderPage()
    expect(screen.getByText(/Failed to load ML status/)).toBeInTheDocument()
  })
})

/* ══════════════════════════════════════════════════════════════════════════════
 * 8. MODEL CARD COMPONENT
 * ════════════════════════════════════════════════════════════════════════════ */

describe("ModelCard", () => {
  it("renders version and Active badge", async () => {
    await renderModelCard()
    expect(screen.getByText("v1700000000")).toBeInTheDocument()
    expect(screen.getByText("Active")).toBeInTheDocument()
  })

  it("shows stage chips IF and XGB active, AE inactive", async () => {
    await renderModelCard()
    const ifChip = screen.getByText("IF")
    const xgbChip = screen.getByText("XGB")
    const aeChip = screen.getByText("AE")
    expect(ifChip.className).toContain("emerald")
    expect(xgbChip.className).toContain("emerald")
    expect(aeChip.className).not.toContain("emerald")
  })

  it("shows Signed badge when signature present", async () => {
    await renderModelCard()
    expect(screen.getByText("Signed")).toBeInTheDocument()
  })

  it("shows accuracy metrics", async () => {
    await renderModelCard()
    expect(screen.getByText("95.0%")).toBeInTheDocument() // precision
    expect(screen.getByText("88.0%")).toBeInTheDocument() // recall
    expect(screen.getByText("3.0%")).toBeInTheDocument()  // fpr
  })

  it("shows training samples", async () => {
    await renderModelCard()
    expect(screen.getByText("5,000 samples")).toBeInTheDocument()
  })
})

/* ══════════════════════════════════════════════════════════════════════════════
 * 9. RETRAIN HISTORY COMPONENT
 * ════════════════════════════════════════════════════════════════════════════ */

describe("RetrainHistory", () => {
  it("renders success and failed entries", async () => {
    await renderRetrainHistory()
    expect(screen.getByText("Success")).toBeInTheDocument()
    expect(screen.getByText("Failed")).toBeInTheDocument()
  })

  it("shows training time", async () => {
    await renderRetrainHistory()
    expect(screen.getByText("42.5s")).toBeInTheDocument()
  })

  it("shows reason", async () => {
    await renderRetrainHistory()
    expect(screen.getByText("threshold_met")).toBeInTheDocument()
  })

  it("shows empty state when no results", async () => {
    const { RetrainHistory } = await import("@/components/ml/RetrainHistory")
    renderWithProviders(<RetrainHistory results={[]} />)
    expect(screen.getByText(/No retrain history/)).toBeInTheDocument()
  })
})

/* ══════════════════════════════════════════════════════════════════════════════
 * 10. ROUTE / SIDEBAR
 * ════════════════════════════════════════════════════════════════════════════ */

describe("MLStatusPage – Route/Sidebar", () => {
  it("routes module exports AppRouter", async () => {
    const m = await import("@/routes")
    expect(typeof m.AppRouter).toBe("function")
  })

  it("sidebar module exports Sidebar", async () => {
    const m = await import("@/components/layout/Sidebar")
    expect(typeof m.Sidebar).toBe("function")
  })
})

/* ══════════════════════════════════════════════════════════════════════════════
 * 11. WORKER STATS
 * ════════════════════════════════════════════════════════════════════════════ */

describe("MLStatusPage – Worker Stats", () => {
  it("shows worker running status", async () => {
    await renderPage()
    expect(screen.getByText(/Worker: Running/)).toBeInTheDocument()
  })

  it("shows check interval", async () => {
    await renderPage()
    expect(screen.getByText(/Check interval: 21600s/)).toBeInTheDocument()
  })

  it("shows failed count when > 0", async () => {
    await renderPage()
    expect(screen.getByText(/Failed: 2/)).toBeInTheDocument()
  })
})
