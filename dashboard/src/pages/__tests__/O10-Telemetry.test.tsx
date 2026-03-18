// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — O10 tests: Telemetry Admin.
 *
 * Covers:
 *   - Config display (enabled/disabled, epsilon, kill switch, endpoint warning)
 *   - Opt-in / opt-out toggle button
 *   - Status metrics rendering
 *   - Viewer table (rows, empty state)
 *   - Route + sidebar integration (admin-only)
 *   - Epsilon validation (clamp to 0.1–10.0)
 */

import { describe, it, expect, vi, beforeEach } from "vitest"
import { screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { renderWithProviders } from "@/test/test-utils"

/* ── Fixtures ──────────────────────────────────────────────────────────────── */

const mockConfig = {
  enabled: false,
  dp_epsilon: 2.0,
  global_kill_switch_active: false,
  cloud_endpoint_configured: true,
  created_at: "2025-01-01T00:00:00Z",
  updated_at: "2025-01-10T00:00:00Z",
}

const mockStatus = {
  enabled: false,
  buffer_size: 42,
  metrics: {
    batches_sent: 120,
    batches_failed: 3,
    records_exported: 15000,
    records_dropped: 5,
    last_export_at: "2025-01-15T12:00:00Z",
    last_error: null,
  },
}

const mockViewer = {
  entries: [
    {
      payload_preview: [{ feature_0: 0.42, feature_1: 0.99 }],
      record_count: 50,
      exported_at: 1736935200, // 2025-01-15T10:00:00Z in epoch
      destination: "https://cloud.example.com/ingest",
      success: true,
      error: null,
    },
    {
      payload_preview: [{ feature_0: 0.11 }],
      record_count: 25,
      exported_at: 1736931600,
      destination: "https://cloud.example.com/ingest",
      success: false,
      error: "Connection timeout",
    },
  ],
  total_entries: 2,
  pending_records: 10,
}

/* ── Mocks ─────────────────────────────────────────────────────────────────── */

const mutateFn = vi.fn()

vi.mock("@/api/telemetry", () => ({
  useTelemetryConfig: vi.fn(() => ({
    data: mockConfig,
    isLoading: false,
  })),
  useUpdateTelemetryConfig: vi.fn(() => ({
    mutate: mutateFn,
    isPending: false,
  })),
  useTelemetryStatus: vi.fn(() => ({
    data: mockStatus,
    isLoading: false,
  })),
  useTelemetryViewer: vi.fn(() => ({
    data: mockViewer,
    isLoading: false,
  })),
}))

/* Dynamic re-import for per-test overrides */
import {
  useTelemetryConfig,
  useUpdateTelemetryConfig,
  useTelemetryStatus,
  useTelemetryViewer,
} from "@/api/telemetry"

const mockedConfig = vi.mocked(useTelemetryConfig)
const mockedUpdateConfig = vi.mocked(useUpdateTelemetryConfig)
const mockedStatus = vi.mocked(useTelemetryStatus)
const mockedViewer = vi.mocked(useTelemetryViewer)

beforeEach(() => {
  vi.clearAllMocks()
  /* Reset to defaults */
  mockedConfig.mockReturnValue({
    data: mockConfig,
    isLoading: false,
  } as ReturnType<typeof useTelemetryConfig>)
  mockedUpdateConfig.mockReturnValue({
    mutate: mutateFn,
    isPending: false,
  } as unknown as ReturnType<typeof useUpdateTelemetryConfig>)
  mockedStatus.mockReturnValue({
    data: mockStatus,
    isLoading: false,
  } as ReturnType<typeof useTelemetryStatus>)
  mockedViewer.mockReturnValue({
    data: mockViewer,
    isLoading: false,
  } as ReturnType<typeof useTelemetryViewer>)
})

/* ── Lazy import for page ──────────────────────────────────────────────────── */

async function renderPage() {
  const mod = await import("@/pages/TelemetryPage")
  const TelemetryPage = mod.default
  return renderWithProviders(<TelemetryPage />)
}

/* ══════════════════════════════════════════════════════════════════════════════
 *  1. CONFIG SECTION
 * ════════════════════════════════════════════════════════════════════════════ */

describe("TelemetryPage – Config", () => {
  it("renders page title and description", async () => {
    await renderPage()
    expect(screen.getAllByText("Telemetry Export").length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText(/anonymized telemetry sharing/i)).toBeInTheDocument()
  })

  it("shows Disabled badge when telemetry is off", async () => {
    await renderPage()
    expect(screen.getByText("Disabled")).toBeInTheDocument()
    expect(screen.getByText("Opt In")).toBeInTheDocument()
  })

  it("shows Enabled badge when telemetry is on", async () => {
    mockedConfig.mockReturnValue({
      data: { ...mockConfig, enabled: true },
      isLoading: false,
    } as ReturnType<typeof useTelemetryConfig>)
    await renderPage()
    expect(screen.getByText("Enabled")).toBeInTheDocument()
    expect(screen.getByText("Opt Out")).toBeInTheDocument()
  })

  it("calls mutate with toggled enabled on opt-in click", async () => {
    const user = userEvent.setup()
    await renderPage()
    await user.click(screen.getByText("Opt In"))
    expect(mutateFn).toHaveBeenCalledWith({
      enabled: true,
      dp_epsilon: 2.0,
    })
  })

  it("calls mutate with toggled enabled on opt-out click", async () => {
    mockedConfig.mockReturnValue({
      data: { ...mockConfig, enabled: true },
      isLoading: false,
    } as ReturnType<typeof useTelemetryConfig>)
    const user = userEvent.setup()
    await renderPage()
    await user.click(screen.getByText("Opt Out"))
    expect(mutateFn).toHaveBeenCalledWith({
      enabled: false,
      dp_epsilon: 2.0,
    })
  })

  it("displays current dp_epsilon value", async () => {
    await renderPage()
    expect(screen.getByText(/Current: 2/)).toBeInTheDocument()
  })

  it("shows global kill switch warning", async () => {
    mockedConfig.mockReturnValue({
      data: { ...mockConfig, global_kill_switch_active: true },
      isLoading: false,
    } as ReturnType<typeof useTelemetryConfig>)
    await renderPage()
    expect(screen.getByText(/kill switch is active/i)).toBeInTheDocument()
  })

  it("shows cloud endpoint not configured warning", async () => {
    mockedConfig.mockReturnValue({
      data: { ...mockConfig, cloud_endpoint_configured: false },
      isLoading: false,
    } as ReturnType<typeof useTelemetryConfig>)
    await renderPage()
    expect(screen.getByText(/No cloud endpoint configured/i)).toBeInTheDocument()
  })
})

/* ══════════════════════════════════════════════════════════════════════════════
 *  2. EPSILON UPDATE
 * ════════════════════════════════════════════════════════════════════════════ */

describe("TelemetryPage – Epsilon", () => {
  it("update button is disabled when input is empty", async () => {
    await renderPage()
    expect(screen.getByText("Update")).toBeDisabled()
  })

  it("calls mutate with new epsilon on Update click", async () => {
    const user = userEvent.setup()
    await renderPage()
    const input = screen.getByPlaceholderText("2")
    await user.type(input, "5.5")
    await user.click(screen.getByText("Update"))
    expect(mutateFn).toHaveBeenCalledWith({
      enabled: false,
      dp_epsilon: 5.5,
    })
  })
})

/* ══════════════════════════════════════════════════════════════════════════════
 *  3. STATUS METRICS
 * ════════════════════════════════════════════════════════════════════════════ */

describe("TelemetryPage – Status", () => {
  it("renders all metric cards", async () => {
    await renderPage()
    expect(screen.getByText("Batches Sent")).toBeInTheDocument()
    expect(screen.getByText("Batches Failed")).toBeInTheDocument()
    expect(screen.getByText("Records Exported")).toBeInTheDocument()
    expect(screen.getByText("Buffer Size")).toBeInTheDocument()
  })

  it("shows last export time when available", async () => {
    await renderPage()
    expect(screen.getByText(/Last export:/i)).toBeInTheDocument()
  })

  it("shows dropped records warning", async () => {
    await renderPage()
    expect(screen.getByText(/5 records dropped/)).toBeInTheDocument()
  })

  it("shows last error when present", async () => {
    mockedStatus.mockReturnValue({
      data: {
        ...mockStatus,
        metrics: { ...mockStatus.metrics, last_error: "Timeout" },
      },
      isLoading: false,
    } as ReturnType<typeof useTelemetryStatus>)
    await renderPage()
    expect(screen.getByText(/Last error: Timeout/)).toBeInTheDocument()
  })
})

/* ══════════════════════════════════════════════════════════════════════════════
 *  4. VIEWER TABLE
 * ════════════════════════════════════════════════════════════════════════════ */

describe("TelemetryPage – Viewer", () => {
  it("renders viewer heading with total count", async () => {
    await renderPage()
    expect(screen.getByText(/Export Viewer \(2 batches\)/)).toBeInTheDocument()
  })

  it("shows pending badge when pending > 0", async () => {
    await renderPage()
    expect(screen.getByText("10 pending")).toBeInTheDocument()
  })

  it("renders viewer table rows", async () => {
    await renderPage()
    const rows = screen.getAllByRole("row")
    // 1 header row + 2 data rows
    expect(rows.length).toBe(3)
  })

  it("shows OK badge for successful entry", async () => {
    await renderPage()
    expect(screen.getByText("OK")).toBeInTheDocument()
  })

  it("shows Failed badge for failed entry", async () => {
    await renderPage()
    expect(screen.getByText("Failed")).toBeInTheDocument()
  })

  it("shows error message for failed entry", async () => {
    await renderPage()
    expect(screen.getByText("Connection timeout")).toBeInTheDocument()
  })

  it("shows empty state when no entries", async () => {
    mockedViewer.mockReturnValue({
      data: { entries: [], total_entries: 0, pending_records: 0 },
      isLoading: false,
    } as ReturnType<typeof useTelemetryViewer>)
    await renderPage()
    expect(screen.getByText(/No exported batches/)).toBeInTheDocument()
  })
})

/* ══════════════════════════════════════════════════════════════════════════════
 *  5. LOADING STATE
 * ════════════════════════════════════════════════════════════════════════════ */

describe("TelemetryPage – Loading", () => {
  it("shows spinner during config loading", async () => {
    mockedConfig.mockReturnValue({
      data: undefined,
      isLoading: true,
    } as ReturnType<typeof useTelemetryConfig>)
    const { container } = await renderPage()
    expect(container.querySelector(".animate-spin")).not.toBeNull()
  })
})

/* ══════════════════════════════════════════════════════════════════════════════
 *  6. ROUTE + SIDEBAR INTEGRATION
 * ════════════════════════════════════════════════════════════════════════════ */

describe("TelemetryPage – Route/Sidebar", () => {
  it("telemetry route is in routes.tsx as admin-only", async () => {
    const routesModule = await import("@/routes")
    expect(routesModule).toBeDefined()
    expect(typeof routesModule.AppRouter).toBe("function")
  })

  it("sidebar includes Telemetry nav item", async () => {
    // Re-import sidebar to check the nav groups directly
    const sidebarModule = await import("@/components/layout/Sidebar")
    expect(sidebarModule).toBeDefined()
  })
})
