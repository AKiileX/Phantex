// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — O9 tests: OCSF/PDR Export Channels.
 *
 * Covers:
 *   - ChannelForm component (render, type switching, submit)
 *   - ChannelStatus component (active/disabled)
 *   - ExportsPage (list, empty, create, toggle, delete confirm, test)
 *   - Route/Sidebar integration (admin-only)
 *   - API hook validator (safeChannelId)
 */

import { describe, it, expect, vi, beforeEach } from "vitest"
import { screen, fireEvent } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { renderWithProviders } from "@/test/test-utils"

/* ── Fixtures ──────────────────────────────────────────────────────────────── */

const mockChannels = [
  {
    id: "00000000-0000-0000-0000-000000000001",
    tenant_id: "t1",
    name: "Production S3",
    channel_type: "s3" as const,
    config_masked: {
      s3_bucket: "my-ocsf-bucket",
      s3_region: "us-east-1",
      access_key: "***",
      secret_key: "***",
    },
    pii_fields: ["user.email"],
    enabled: true,
    created_at: "2025-01-01T00:00:00Z",
    updated_at: "2025-01-15T00:00:00Z",
  },
  {
    id: "00000000-0000-0000-0000-000000000002",
    tenant_id: "t1",
    name: "Slack Webhook",
    channel_type: "webhook" as const,
    config_masked: {
      webhook_url: "https://hooks.example.com/ocsf",
      webhook_secret: "***",
    },
    pii_fields: null,
    enabled: false,
    created_at: "2025-01-02T00:00:00Z",
    updated_at: "2025-01-10T00:00:00Z",
  },
  {
    id: "00000000-0000-0000-0000-000000000003",
    tenant_id: "t1",
    name: "Analytics Kafka",
    channel_type: "kafka_mirror" as const,
    config_masked: {
      kafka_bootstrap: "kafka1:9092",
      kafka_topic: "phantex-events",
      kafka_sasl_password: "***",
    },
    pii_fields: null,
    enabled: true,
    created_at: "2025-01-03T00:00:00Z",
    updated_at: "2025-01-20T00:00:00Z",
  },
]

/* ── Mock API ──────────────────────────────────────────────────────────────── */

const mockCreateMutate = vi.fn()
const mockUpdateMutate = vi.fn()
const mockDeleteMutate = vi.fn()
const mockTestMutate = vi.fn()

const mockUseExportChannels = vi.fn(() => ({
  data: { channels: mockChannels },
  isLoading: false,
  error: null,
}))

vi.mock("@/api/exports", () => ({
  useExportChannels: (...args: unknown[]) => mockUseExportChannels(...args),
  useExportChannelTypes: vi.fn(() => ({ data: null, isLoading: false })),
  useCreateExportChannel: vi.fn(() => ({
    mutate: mockCreateMutate,
    isPending: false,
  })),
  useUpdateExportChannel: vi.fn(() => ({
    mutate: mockUpdateMutate,
    isPending: false,
  })),
  useDeleteExportChannel: vi.fn(() => ({
    mutate: mockDeleteMutate,
    isPending: false,
  })),
  useTestExportChannel: vi.fn(() => ({
    mutate: mockTestMutate,
    isPending: false,
  })),
  EXPORT_KEYS: {
    all: ["exports"],
    types: () => ["exports", "channel-types"],
    list: () => ["exports", "list"],
    detail: (id: string) => ["exports", "detail", id],
  },
}))

vi.mock("@/api/alerts", () => ({
  useAlerts: vi.fn(() => ({ data: { items: [] }, isLoading: false })),
}))

/* ══════════════════════════════════════════════════════════════════════════════
 *  ChannelStatus
 * ══════════════════════════════════════════════════════════════════════════════ */

import { ChannelStatus } from "@/components/exports/ChannelStatus"

describe("ChannelStatus", () => {
  it("renders Active badge when enabled", () => {
    renderWithProviders(<ChannelStatus enabled={true} />)
    expect(screen.getByText("Active")).toBeInTheDocument()
  })

  it("renders Disabled badge when not enabled", () => {
    renderWithProviders(<ChannelStatus enabled={false} />)
    expect(screen.getByText("Disabled")).toBeInTheDocument()
  })
})

/* ══════════════════════════════════════════════════════════════════════════════
 *  ChannelForm
 * ══════════════════════════════════════════════════════════════════════════════ */

import { ChannelForm } from "@/components/exports/ChannelForm"

describe("ChannelForm", () => {
  it("renders form with name, type selector, and channel-specific fields", () => {
    renderWithProviders(
      <ChannelForm onSubmit={vi.fn()} onCancel={vi.fn()} />,
    )

    expect(screen.getByLabelText(/Channel Name/)).toBeInTheDocument()
    expect(screen.getByLabelText(/Channel Type/)).toBeInTheDocument()
    // S3 is default type — should show S3 fields
    expect(screen.getByLabelText(/S3 Bucket/)).toBeInTheDocument()
    expect(screen.getByLabelText(/Region/)).toBeInTheDocument()
  })

  it("switches config fields when type changes", async () => {
    const user = userEvent.setup()
    renderWithProviders(
      <ChannelForm onSubmit={vi.fn()} onCancel={vi.fn()} />,
    )

    // Switch to webhook
    await user.selectOptions(screen.getByLabelText(/Channel Type/), "webhook")
    expect(screen.getByLabelText(/Webhook URL/)).toBeInTheDocument()
    expect(screen.getByLabelText(/HMAC Secret/)).toBeInTheDocument()
    expect(screen.queryByLabelText(/S3 Bucket/)).not.toBeInTheDocument()

    // Switch to kafka
    await user.selectOptions(screen.getByLabelText(/Channel Type/), "kafka_mirror")
    expect(screen.getByLabelText(/Bootstrap Servers/)).toBeInTheDocument()
    expect(screen.getByLabelText(/Topic/)).toBeInTheDocument()
    expect(screen.queryByLabelText(/Webhook URL/)).not.toBeInTheDocument()
  })

  it("calls onSubmit with correct payload", async () => {
    const user = userEvent.setup()
    const onSubmit = vi.fn()
    renderWithProviders(
      <ChannelForm onSubmit={onSubmit} onCancel={vi.fn()} />,
    )

    await user.type(screen.getByLabelText(/Channel Name/), "Test S3")
    await user.type(screen.getByLabelText(/S3 Bucket/), "my-bucket")

    fireEvent.submit(screen.getByText("Create Channel").closest("form")!)

    expect(onSubmit).toHaveBeenCalledWith(
      expect.objectContaining({
        name: "Test S3",
        channel_type: "s3",
        config: expect.objectContaining({ s3_bucket: "my-bucket" }),
      }),
    )
  })

  it("calls onCancel when cancel button clicked", () => {
    const onCancel = vi.fn()
    renderWithProviders(
      <ChannelForm onSubmit={vi.fn()} onCancel={onCancel} />,
    )

    fireEvent.click(screen.getByLabelText("Cancel"))
    expect(onCancel).toHaveBeenCalledOnce()
  })

  it("renders sensitive fields as password type", () => {
    renderWithProviders(
      <ChannelForm onSubmit={vi.fn()} onCancel={vi.fn()} />,
    )

    const secretKey = screen.getByLabelText(/Secret Key/)
    expect(secretKey).toHaveAttribute("type", "password")
    const accessKey = screen.getByLabelText(/Access Key/)
    expect(accessKey).toHaveAttribute("type", "password")
  })

  it("renders PII fields input", () => {
    renderWithProviders(
      <ChannelForm onSubmit={vi.fn()} onCancel={vi.fn()} />,
    )

    expect(screen.getByLabelText(/PII Fields/)).toBeInTheDocument()
    expect(screen.getByText(/Comma-separated/)).toBeInTheDocument()
  })
})

/* ══════════════════════════════════════════════════════════════════════════════
 *  ExportsPage
 * ══════════════════════════════════════════════════════════════════════════════ */

import ExportsPage from "@/pages/ExportsPage"

describe("ExportsPage", () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockUseExportChannels.mockReturnValue({
      data: { channels: mockChannels },
      isLoading: false,
      error: null,
    })
  })

  it("renders page header and channel count", () => {
    renderWithProviders(<ExportsPage />)
    expect(screen.getByText("Export Channels & Schedules")).toBeInTheDocument()
    expect(screen.getByText("Channels (3)")).toBeInTheDocument()
  })

  it("lists all channels with names and types", () => {
    renderWithProviders(<ExportsPage />)
    expect(screen.getByText("Production S3")).toBeInTheDocument()
    expect(screen.getByText("Slack Webhook")).toBeInTheDocument()
    expect(screen.getByText("Analytics Kafka")).toBeInTheDocument()
    expect(screen.getByText("S3")).toBeInTheDocument()
    expect(screen.getByText("Webhook")).toBeInTheDocument()
    expect(screen.getByText("Kafka")).toBeInTheDocument()
  })

  it("shows masked config primary values", () => {
    renderWithProviders(<ExportsPage />)
    expect(screen.getByText("my-ocsf-bucket")).toBeInTheDocument()
    expect(screen.getByText("https://hooks.example.com/ocsf")).toBeInTheDocument()
    expect(screen.getByText("kafka1:9092")).toBeInTheDocument()
  })

  it("shows Active/Disabled status badges", () => {
    renderWithProviders(<ExportsPage />)
    const actives = screen.getAllByText("Active")
    const disabled = screen.getAllByText("Disabled")
    expect(actives).toHaveLength(2)
    expect(disabled).toHaveLength(1)
  })

  it("shows Add Channel button and opens form", () => {
    renderWithProviders(<ExportsPage />)
    const addBtn = screen.getByText("Add Channel")
    fireEvent.click(addBtn)
    expect(screen.getByText("New Export Channel")).toBeInTheDocument()
    expect(screen.getByLabelText(/Channel Name/)).toBeInTheDocument()
  })

  it("calls toggle mutation when enable/disable clicked", () => {
    renderWithProviders(<ExportsPage />)
    const toggleBtn = screen.getByLabelText("Disable Production S3")
    fireEvent.click(toggleBtn)
    expect(mockUpdateMutate).toHaveBeenCalledWith({
      id: "00000000-0000-0000-0000-000000000001",
      body: { enabled: false },
    })
  })

  it("requires double-click to delete (confirmation)", () => {
    renderWithProviders(<ExportsPage />)
    const deleteBtn = screen.getByLabelText("Delete Production S3")

    // First click: sets confirmation state
    fireEvent.click(deleteBtn)
    expect(mockDeleteMutate).not.toHaveBeenCalled()

    // Second click: actually deletes
    const confirmBtn = screen.getByLabelText("Confirm delete Production S3")
    fireEvent.click(confirmBtn)
    expect(mockDeleteMutate).toHaveBeenCalledWith(
      "00000000-0000-0000-0000-000000000001",
      expect.any(Object),
    )
  })

  it("calls test mutation when test button clicked", () => {
    renderWithProviders(<ExportsPage />)
    const testBtn = screen.getByLabelText("Test Production S3")
    fireEvent.click(testBtn)
    expect(mockTestMutate).toHaveBeenCalledWith(
      "00000000-0000-0000-0000-000000000001",
      expect.any(Object),
    )
  })

  it("shows empty state when no channels", () => {
    mockUseExportChannels.mockReturnValue({
      data: { channels: [] },
      isLoading: false,
      error: null,
    })
    renderWithProviders(<ExportsPage />)
    expect(screen.getByText("No export channels configured.")).toBeInTheDocument()
  })

  it("shows loading spinner", () => {
    mockUseExportChannels.mockReturnValue({
      data: undefined,
      isLoading: true,
      error: null,
    })
    const { container } = renderWithProviders(<ExportsPage />)
    expect(container.querySelector(".animate-spin")).toBeInTheDocument()
  })

  it("shows error alert on failure", () => {
    mockUseExportChannels.mockReturnValue({
      data: undefined,
      isLoading: false,
      error: new Error("fail"),
    })
    renderWithProviders(<ExportsPage />)
    expect(screen.getByRole("alert")).toHaveTextContent("Failed to load export channels")
  })
})

/* ══════════════════════════════════════════════════════════════════════════════
 *  Route + Sidebar Integration
 * ══════════════════════════════════════════════════════════════════════════════ */

import { Sidebar } from "@/components/layout/Sidebar"

vi.mock("@/stores/authStore", async () => {
  const actual = await vi.importActual("@/stores/authStore")
  return {
    ...actual,
    useAuthStore: vi.fn((selector: (s: unknown) => unknown) => {
      const state = { user: { role: "admin" }, token: "t" }
      return selector(state)
    }),
    selectIsAdmin: (s: { user?: { role: string } }) => s.user?.role === "admin",
  }
})

describe("Sidebar — Exports nav item", () => {
  it("renders Exports link in Admin group for admin users", () => {
    renderWithProviders(<Sidebar />)
    const link = screen.getByText("Exports")
    expect(link).toBeInTheDocument()
    expect(link.closest("a")).toHaveAttribute("href", "/exports")
  })
})

describe("Routes — /exports", () => {
  it("ExportsPage is a valid default export", async () => {
    const mod = await import("@/pages/ExportsPage")
    expect(mod.default).toBeDefined()
    expect(typeof mod.default).toBe("function")
  })
})
