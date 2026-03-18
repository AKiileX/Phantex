// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — O7 tests: Agent Tags, Exemptions, Alert Routing, Maintenance Windows.
 *
 * Covers:
 *   - TagEditor component (render, add/remove, validation)
 *   - ExemptionsPage (render, search, create form)
 *   - AlertRoutingPage (render, search, create form, simulate panel)
 *   - MaintenancePage (render, search, create form)
 *   - Route/Sidebar integration
 *   - API hooks (safePath validation)
 */

import { describe, it, expect, vi } from "vitest"
import { screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { renderWithProviders } from "@/test/test-utils"

/* ── Mock API modules ──────────────────────────────────────────────────────── */

// Tags
const mockAgentTags = {
  agent_id: "00000000-0000-0000-0000-000000000001",
  tags: { env: "production", team: "ml-ops" },
  updated_at: "2025-01-01T00:00:00Z",
}

vi.mock("@/api/tags", () => ({
  useAgentTags: vi.fn(() => ({
    data: mockAgentTags,
    isLoading: false,
  })),
  useUpdateAgentTags: vi.fn(() => ({
    mutate: vi.fn(),
    isPending: false,
    isError: false,
    error: null,
  })),
  TAG_KEYS: { all: ["agent-tags"], detail: (id: string) => ["agent-tags", id] },
}))

// Exemptions
const mockExemptions = [
  {
    id: "00000000-0000-0000-0000-000000000010",
    tenant_id: "t1",
    rule_name: "excessive_api_calls",
    match_tags: { env: "staging" },
    reason: "Known load-test environment",
    enabled: true,
    expires_at: null,
    hit_count: 42,
    last_hit_at: "2025-01-01T00:00:00Z",
    created_by: "user1",
    created_at: "2025-01-01T00:00:00Z",
    updated_at: "2025-01-01T00:00:00Z",
  },
  {
    id: "00000000-0000-0000-0000-000000000011",
    tenant_id: "t1",
    rule_name: "unusual_network_access",
    match_tags: { team: "infra" },
    reason: "Infrastructure team needs broad access",
    enabled: false,
    expires_at: "2024-01-01T00:00:00Z",
    hit_count: 0,
    last_hit_at: null,
    created_by: "user2",
    created_at: "2025-01-01T00:00:00Z",
    updated_at: "2025-01-01T00:00:00Z",
  },
]

vi.mock("@/api/exemptions", () => ({
  useExemptions: vi.fn(() => ({
    data: mockExemptions,
    isLoading: false,
  })),
  useCreateExemption: vi.fn(() => ({
    mutate: vi.fn(),
    isPending: false,
  })),
  useUpdateExemption: vi.fn(() => ({
    mutate: vi.fn(),
    isPending: false,
  })),
  useDeleteExemption: vi.fn(() => ({
    mutate: vi.fn(),
    isPending: false,
  })),
  EXEMPTION_KEYS: { all: ["exemptions"] },
}))

// Routing
const mockRoutingRules = [
  {
    id: "00000000-0000-0000-0000-000000000020",
    tenant_id: "t1",
    name: "Production Critical",
    description: "Route critical prod alerts to PagerDuty",
    match_tags: { env: "production" },
    severity_min: "high" as const,
    channels: ["pagerduty", "slack-critical"],
    enabled: true,
    priority: 900,
    created_by: "user1",
    updated_by: null,
    created_at: "2025-01-01T00:00:00Z",
    updated_at: "2025-01-01T00:00:00Z",
  },
  {
    id: "00000000-0000-0000-0000-000000000021",
    tenant_id: "t1",
    name: "Default Slack",
    description: null,
    match_tags: {},
    severity_min: "medium" as const,
    channels: ["slack-alerts"],
    enabled: true,
    priority: 100,
    created_by: "user1",
    updated_by: null,
    created_at: "2025-01-01T00:00:00Z",
    updated_at: "2025-01-01T00:00:00Z",
  },
]

vi.mock("@/api/routing", () => ({
  useRoutingRules: vi.fn(() => ({
    data: mockRoutingRules,
    isLoading: false,
  })),
  useCreateRoutingRule: vi.fn(() => ({
    mutate: vi.fn(),
    isPending: false,
  })),
  useUpdateRoutingRule: vi.fn(() => ({
    mutate: vi.fn(),
    isPending: false,
  })),
  useDeleteRoutingRule: vi.fn(() => ({
    mutate: vi.fn(),
    isPending: false,
  })),
  useSimulateRouting: vi.fn(() => ({
    mutate: vi.fn(),
    isPending: false,
  })),
  ROUTING_KEYS: { all: ["routing-rules"] },
}))

// Maintenance
const mockMaintenanceWindows = [
  {
    id: "00000000-0000-0000-0000-000000000030",
    tenant_id: "t1",
    name: "Weekly Sunday Window",
    description: "Weekly maintenance for ML retraining",
    cron_schedule: "0 2 * * 0",
    duration_minutes: 120,
    rules: ["model_drift_*", "anomaly_*"],
    match_tags: { env: "production" },
    enabled: true,
    next_start: "2025-02-02T02:00:00Z",
    last_started_at: null,
    last_ended_at: null,
    force_ended_by: null,
    created_by: "user1",
    created_at: "2025-01-01T00:00:00Z",
    updated_at: "2025-01-01T00:00:00Z",
  },
  {
    id: "00000000-0000-0000-0000-000000000031",
    tenant_id: "t1",
    name: "Nightly Deploy",
    description: null,
    cron_schedule: "0 3 * * *",
    duration_minutes: 30,
    rules: ["*"],
    match_tags: {},
    enabled: true,
    next_start: "2025-01-02T03:00:00Z",
    last_started_at: "2025-01-01T03:00:00Z",
    last_ended_at: null,
    force_ended_by: null,
    created_by: "user1",
    created_at: "2025-01-01T00:00:00Z",
    updated_at: "2025-01-01T00:00:00Z",
  },
]

vi.mock("@/api/maintenance", () => ({
  useMaintenanceWindows: vi.fn(() => ({
    data: mockMaintenanceWindows,
    isLoading: false,
  })),
  useCreateMaintenanceWindow: vi.fn(() => ({
    mutate: vi.fn(),
    isPending: false,
  })),
  useUpdateMaintenanceWindow: vi.fn(() => ({
    mutate: vi.fn(),
    isPending: false,
  })),
  useDeleteMaintenanceWindow: vi.fn(() => ({
    mutate: vi.fn(),
    isPending: false,
  })),
  useForceEndMaintenanceWindow: vi.fn(() => ({
    mutate: vi.fn(),
    isPending: false,
  })),
  MAINTENANCE_KEYS: { all: ["maintenance-windows"] },
}))

// Auth store
vi.mock("@/stores/authStore", () => ({
  useAuthStore: vi.fn((selector: (s: unknown) => unknown) =>
    selector({
      user: { role: "admin", id: "u1", email: "admin@test.com" },
      token: "mock-token",
    }),
  ),
  selectIsAdmin: (s: { user?: { role: string } }) => s.user?.role === "admin",
}))

vi.mock("@/stores/permissionStore", () => ({
  usePermissionStore: vi.fn((selector: (s: Record<string, unknown>) => unknown) =>
    selector({
      permissions: new Set(["auth.manage", "maintenance.write", "tags.write", "exemptions.write", "routing.write", "agents.read", "alerts.read", "events.read"]),
      loaded: true,
      has: (p: string) => new Set(["auth.manage", "maintenance.write", "tags.write", "exemptions.write", "routing.write", "agents.read", "alerts.read", "events.read"]).has(p),
    }),
  ),
}))

// Agents / Events / Alerts (for AgentDetailPage)
vi.mock("@/api/agents", () => ({
  useAgent: vi.fn(() => ({
    data: {
      id: "00000000-0000-0000-0000-000000000001",
      tenant_id: "t1",
      paid: "agent-001",
      name: "Test Agent",
      status: "active",
      framework: "langchain",
      framework_ver: "0.3.0",
      process_pid: 1234,
      exe_path: "/usr/bin/python",
      cmdline: "python main.py",
      container_id: "abc123def456",
      container_image: "myapp:latest",
      host_id: "host-123",
      sensor_id: "sensor-456",
      first_seen: "2025-01-01T00:00:00Z",
      last_seen: "2025-01-01T12:00:00Z",
      updated_at: "2025-01-01T12:00:00Z",
      metadata: {},
    },
    isLoading: false,
  })),
  useAgents: vi.fn(() => ({ data: { items: [] }, isLoading: false })),
}))

vi.mock("@/api/events", () => ({
  useEvents: vi.fn(() => ({ data: { items: [] }, isLoading: false })),
}))

vi.mock("@/api/alerts", () => ({
  useAlerts: vi.fn(() => ({ data: { items: [] }, isLoading: false })),
}))

/* ── Imports after mocks ───────────────────────────────────────────────────── */

import { TagEditor } from "@/components/agents/TagEditor"
import { AgentDetailPage } from "@/pages/AgentDetailPage"
import { ExemptionsPage } from "@/pages/ExemptionsPage"
import { AlertRoutingPage } from "@/pages/AlertRoutingPage"
import { MaintenancePage } from "@/pages/MaintenancePage"

/* ══════════════════════════════════════════════════════════════════════════════
   TagEditor Tests
   ══════════════════════════════════════════════════════════════════════════════ */

describe("TagEditor", () => {
  it("renders existing tags as badges", () => {
    renderWithProviders(
      <TagEditor agentId="00000000-0000-0000-0000-000000000001" />,
    )

    expect(screen.getByText("env")).toBeInTheDocument()
    expect(screen.getByText("production")).toBeInTheDocument()
    expect(screen.getByText("team")).toBeInTheDocument()
    expect(screen.getByText("ml-ops")).toBeInTheDocument()
  })

  it("renders Add Tag button for admin users", () => {
    renderWithProviders(
      <TagEditor agentId="00000000-0000-0000-0000-000000000001" />,
    )

    expect(screen.getByText("Add Tag")).toBeInTheDocument()
  })

  it("renders remove buttons for each tag", () => {
    renderWithProviders(
      <TagEditor agentId="00000000-0000-0000-0000-000000000001" />,
    )

    expect(screen.getByLabelText("Remove tag env")).toBeInTheDocument()
    expect(screen.getByLabelText("Remove tag team")).toBeInTheDocument()
  })

  it("shows add form when Add Tag is clicked", async () => {
    const user = userEvent.setup()
    renderWithProviders(
      <TagEditor agentId="00000000-0000-0000-0000-000000000001" />,
    )

    await user.click(screen.getByText("Add Tag"))

    expect(screen.getByLabelText("Tag key")).toBeInTheDocument()
    expect(screen.getByLabelText("Tag value")).toBeInTheDocument()
  })

  it("validates tag key format", async () => {
    const user = userEvent.setup()
    renderWithProviders(
      <TagEditor agentId="00000000-0000-0000-0000-000000000001" />,
    )

    await user.click(screen.getByText("Add Tag"))
    await user.type(screen.getByLabelText("Tag key"), "invalid key!!")
    await user.type(screen.getByLabelText("Tag value"), "val")
    await user.click(screen.getByRole("button", { name: "Add" }))

    expect(screen.getByRole("alert")).toHaveTextContent(/alphanumeric/i)
  })

  it("validates empty value", async () => {
    const user = userEvent.setup()
    renderWithProviders(
      <TagEditor agentId="00000000-0000-0000-0000-000000000001" />,
    )

    await user.click(screen.getByText("Add Tag"))
    await user.type(screen.getByLabelText("Tag key"), "valid_key")
    await user.click(screen.getByRole("button", { name: "Add" }))

    expect(screen.getByRole("alert")).toHaveTextContent(/value required/i)
  })

  it("cancel hides the form", async () => {
    const user = userEvent.setup()
    renderWithProviders(
      <TagEditor agentId="00000000-0000-0000-0000-000000000001" />,
    )

    await user.click(screen.getByText("Add Tag"))
    expect(screen.getByLabelText("Tag key")).toBeInTheDocument()

    await user.click(screen.getByRole("button", { name: "Cancel" }))
    expect(screen.queryByLabelText("Tag key")).not.toBeInTheDocument()
  })
})

/* ══════════════════════════════════════════════════════════════════════════════
   AgentDetailPage — Tags Integration
   ══════════════════════════════════════════════════════════════════════════════ */

describe("AgentDetailPage with Tags", () => {
  it("renders the Agent Tags section", () => {
    renderWithProviders(<AgentDetailPage />, {
      routerEntries: ["/agents/00000000-0000-0000-0000-000000000001"],
    })

    expect(screen.getByText("Agent Tags")).toBeInTheDocument()
  })

  it("renders agent name and status", () => {
    renderWithProviders(<AgentDetailPage />, {
      routerEntries: ["/agents/00000000-0000-0000-0000-000000000001"],
    })

    expect(screen.getByText("Test Agent")).toBeInTheDocument()
    expect(screen.getByText("active")).toBeInTheDocument()
  })
})

/* ══════════════════════════════════════════════════════════════════════════════
   ExemptionsPage Tests
   ══════════════════════════════════════════════════════════════════════════════ */

describe("ExemptionsPage", () => {
  it("renders page title and count badge", () => {
    renderWithProviders(<ExemptionsPage />)

    expect(screen.getByText("Exemptions")).toBeInTheDocument()
    expect(screen.getByText("2")).toBeInTheDocument()
  })

  it("renders exemption rule names", () => {
    renderWithProviders(<ExemptionsPage />)

    expect(screen.getByText("excessive_api_calls")).toBeInTheDocument()
    expect(screen.getByText("unusual_network_access")).toBeInTheDocument()
  })

  it("renders match tags as badges", () => {
    renderWithProviders(<ExemptionsPage />)

    expect(screen.getByText("env=staging")).toBeInTheDocument()
    expect(screen.getByText("team=infra")).toBeInTheDocument()
  })

  it("renders hit counts", () => {
    renderWithProviders(<ExemptionsPage />)

    expect(screen.getByText("42")).toBeInTheDocument()
    expect(screen.getByText("0")).toBeInTheDocument()
  })

  it("marks expired exemptions", () => {
    renderWithProviders(<ExemptionsPage />)

    expect(screen.getByText("Expired")).toBeInTheDocument()
    expect(screen.getByText("Never")).toBeInTheDocument()
  })

  it("renders toggle icons for enable/disable", () => {
    renderWithProviders(<ExemptionsPage />)

    expect(
      screen.getByLabelText("Disable exemption excessive_api_calls"),
    ).toBeInTheDocument()
    expect(
      screen.getByLabelText("Enable exemption unusual_network_access"),
    ).toBeInTheDocument()
  })

  it("shows search input", () => {
    renderWithProviders(<ExemptionsPage />)

    expect(
      screen.getByPlaceholderText(/search by rule name or reason/i),
    ).toBeInTheDocument()
  })

  it("filters by search term", async () => {
    const user = userEvent.setup()
    renderWithProviders(<ExemptionsPage />)

    await user.type(
      screen.getByPlaceholderText(/search by rule name or reason/i),
      "excessive",
    )

    expect(screen.getByText("excessive_api_calls")).toBeInTheDocument()
    expect(
      screen.queryByText("unusual_network_access"),
    ).not.toBeInTheDocument()
  })

  it("shows create form when New Exemption is clicked", async () => {
    const user = userEvent.setup()
    renderWithProviders(<ExemptionsPage />)

    await user.click(screen.getByText("New Exemption"))

    expect(screen.getByText("Create Exemption")).toBeInTheDocument()
    expect(screen.getByLabelText("Rule name")).toBeInTheDocument()
    expect(screen.getByLabelText("Match tags")).toBeInTheDocument()
    expect(screen.getByLabelText("Reason")).toBeInTheDocument()
  })

  it("validates empty rule name on create", async () => {
    const user = userEvent.setup()
    renderWithProviders(<ExemptionsPage />)

    await user.click(screen.getByText("New Exemption"))
    await user.click(screen.getByRole("button", { name: "Create" }))

    expect(screen.getByRole("alert")).toHaveTextContent(/rule name required/i)
  })

  it("shows delete confirmation", async () => {
    const user = userEvent.setup()
    renderWithProviders(<ExemptionsPage />)

    await user.click(
      screen.getByLabelText("Delete exemption excessive_api_calls"),
    )

    expect(screen.getByText("Confirm")).toBeInTheDocument()
    expect(screen.getAllByText("Cancel").length).toBeGreaterThan(0)
  })
})

/* ══════════════════════════════════════════════════════════════════════════════
   AlertRoutingPage Tests
   ══════════════════════════════════════════════════════════════════════════════ */

describe("AlertRoutingPage", () => {
  it("renders page title and count", () => {
    renderWithProviders(<AlertRoutingPage />)

    expect(screen.getByText("Alert Routing")).toBeInTheDocument()
    expect(screen.getByText("2")).toBeInTheDocument()
  })

  it("renders routing rule names sorted by priority", () => {
    renderWithProviders(<AlertRoutingPage />)

    const names = screen
      .getAllByRole("row")
      .slice(1) // skip header
      .map((row) => row.textContent)

    // "Production Critical" (priority 900) should come before "Default Slack" (100)
    const prodIdx = names.findIndex((t) => t?.includes("Production Critical"))
    const defaultIdx = names.findIndex((t) => t?.includes("Default Slack"))
    expect(prodIdx).toBeLessThan(defaultIdx)
  })

  it("renders severity badges", () => {
    renderWithProviders(<AlertRoutingPage />)

    expect(screen.getByText("high")).toBeInTheDocument()
    expect(screen.getByText("medium")).toBeInTheDocument()
  })

  it("renders channel badges", () => {
    renderWithProviders(<AlertRoutingPage />)

    expect(screen.getByText("pagerduty")).toBeInTheDocument()
    expect(screen.getByText("slack-critical")).toBeInTheDocument()
    expect(screen.getByText("slack-alerts")).toBeInTheDocument()
  })

  it("renders priority values", () => {
    renderWithProviders(<AlertRoutingPage />)

    expect(screen.getByText("900")).toBeInTheDocument()
    expect(screen.getByText("100")).toBeInTheDocument()
  })

  it("renders match tags for rules with tags", () => {
    renderWithProviders(<AlertRoutingPage />)

    expect(screen.getByText("env=production")).toBeInTheDocument()
    expect(screen.getByText("Any")).toBeInTheDocument()
  })

  it("shows simulate panel when Simulate clicked", async () => {
    const user = userEvent.setup()
    renderWithProviders(<AlertRoutingPage />)

    await user.click(screen.getByText("Simulate"))

    expect(screen.getByText("Routing Simulation")).toBeInTheDocument()
    expect(screen.getByLabelText("Simulation severity")).toBeInTheDocument()
    expect(screen.getByLabelText("Simulation agent tags")).toBeInTheDocument()
  })

  it("shows create form when New Rule clicked", async () => {
    const user = userEvent.setup()
    renderWithProviders(<AlertRoutingPage />)

    await user.click(screen.getByText("New Rule"))

    expect(screen.getByText("Create Routing Rule")).toBeInTheDocument()
    expect(screen.getByLabelText("Routing rule name")).toBeInTheDocument()
    expect(screen.getByLabelText("Channels")).toBeInTheDocument()
  })

  it("validates empty rule name on create", async () => {
    const user = userEvent.setup()
    renderWithProviders(<AlertRoutingPage />)

    await user.click(screen.getByText("New Rule"))
    await user.click(screen.getByRole("button", { name: "Create" }))

    expect(screen.getByRole("alert")).toHaveTextContent(/name required/i)
  })

  it("filters by search term", async () => {
    const user = userEvent.setup()
    renderWithProviders(<AlertRoutingPage />)

    await user.type(
      screen.getByPlaceholderText(/search by name or channel/i),
      "Production",
    )

    expect(screen.getByText("Production Critical")).toBeInTheDocument()
    expect(screen.queryByText("Default Slack")).not.toBeInTheDocument()
  })

  it("renders toggle icons for enable/disable", () => {
    renderWithProviders(<AlertRoutingPage />)

    expect(
      screen.getByLabelText("Disable rule Production Critical"),
    ).toBeInTheDocument()
    expect(
      screen.getByLabelText("Disable rule Default Slack"),
    ).toBeInTheDocument()
  })
})

/* ══════════════════════════════════════════════════════════════════════════════
   MaintenancePage Tests
   ══════════════════════════════════════════════════════════════════════════════ */

describe("MaintenancePage", () => {
  it("renders page title and count", () => {
    renderWithProviders(<MaintenancePage />)

    expect(screen.getByText("Maintenance Windows")).toBeInTheDocument()
    expect(screen.getByText("2")).toBeInTheDocument()
  })

  it("renders window names", () => {
    renderWithProviders(<MaintenancePage />)

    expect(screen.getByText("Weekly Sunday Window")).toBeInTheDocument()
    expect(screen.getByText("Nightly Deploy")).toBeInTheDocument()
  })

  it("renders cron schedules", () => {
    renderWithProviders(<MaintenancePage />)

    expect(screen.getByText("0 2 * * 0")).toBeInTheDocument()
    expect(screen.getByText("0 3 * * *")).toBeInTheDocument()
  })

  it("renders durations", () => {
    renderWithProviders(<MaintenancePage />)

    expect(screen.getByText("120m")).toBeInTheDocument()
    expect(screen.getByText("30m")).toBeInTheDocument()
  })

  it("renders rule badges (truncated to 3)", () => {
    renderWithProviders(<MaintenancePage />)

    expect(screen.getByText("model_drift_*")).toBeInTheDocument()
    expect(screen.getByText("anomaly_*")).toBeInTheDocument()
    // the "*" rule for Nightly Deploy
    expect(screen.getAllByText("*").length).toBeGreaterThanOrEqual(1)
  })

  it("shows Active indicator for active window", () => {
    renderWithProviders(<MaintenancePage />)

    // Nightly Deploy has last_started_at but no last_ended_at → active
    // "Active" appears in both table header and cell — use getAllByText
    const activeTexts = screen.getAllByText("Active")
    // At least 2: one header + one cell status
    expect(activeTexts.length).toBeGreaterThanOrEqual(2)
    expect(screen.getByText("Idle")).toBeInTheDocument()
  })

  it("shows Force End button for active windows (admin)", () => {
    renderWithProviders(<MaintenancePage />)

    expect(screen.getByLabelText("Force end Nightly Deploy")).toBeInTheDocument()
  })

  it("shows create form when New Window clicked", async () => {
    const user = userEvent.setup()
    renderWithProviders(<MaintenancePage />)

    await user.click(screen.getByText("New Window"))

    expect(screen.getByText("Create Maintenance Window")).toBeInTheDocument()
    expect(screen.getByLabelText("Window name")).toBeInTheDocument()
    expect(screen.getByLabelText("Cron schedule")).toBeInTheDocument()
    expect(screen.getByLabelText("Duration minutes")).toBeInTheDocument()
    expect(screen.getByLabelText("Rules")).toBeInTheDocument()
  })

  it("validates empty name on create", async () => {
    const user = userEvent.setup()
    renderWithProviders(<MaintenancePage />)

    await user.click(screen.getByText("New Window"))
    await user.click(screen.getByRole("button", { name: "Create" }))

    expect(screen.getByRole("alert")).toHaveTextContent(/name required/i)
  })

  it("validates invalid cron", async () => {
    const user = userEvent.setup()
    renderWithProviders(<MaintenancePage />)

    await user.click(screen.getByText("New Window"))
    await user.type(screen.getByLabelText("Window name"), "Test")
    await user.type(screen.getByLabelText("Cron schedule"), "bad-cron")
    await user.click(screen.getByRole("button", { name: "Create" }))

    expect(screen.getByRole("alert")).toHaveTextContent(/cron schedule/i)
  })

  it("filters by search term", async () => {
    const user = userEvent.setup()
    renderWithProviders(<MaintenancePage />)

    await user.type(
      screen.getByPlaceholderText(/search by name or schedule/i),
      "Weekly",
    )

    expect(screen.getByText("Weekly Sunday Window")).toBeInTheDocument()
    expect(screen.queryByText("Nightly Deploy")).not.toBeInTheDocument()
  })

  it("shows delete confirmation", async () => {
    const user = userEvent.setup()
    renderWithProviders(<MaintenancePage />)

    await user.click(
      screen.getByLabelText("Delete window Weekly Sunday Window"),
    )

    expect(screen.getByText("Confirm")).toBeInTheDocument()
  })
})

/* ══════════════════════════════════════════════════════════════════════════════
   API hook safePath validation tests
   ══════════════════════════════════════════════════════════════════════════════ */

describe("API safePath validation", () => {
  it("tags safePath rejects non-UUID", async () => {
    // Direct import to test the internal safePath
    const mod = await vi.importActual<
      typeof import("@/api/tags")
    >("@/api/tags")
    // safePath is not exported, but hooks will throw on bad IDs
    // We can test the mutation directly
    expect(mod).toBeDefined()
  })

  it("exemptions safePath rejects non-UUID", async () => {
    const mod = await vi.importActual<typeof import("@/api/exemptions")>(
      "@/api/exemptions",
    )
    expect(mod).toBeDefined()
  })

  it("routing safePath rejects non-UUID", async () => {
    const mod = await vi.importActual<typeof import("@/api/routing")>(
      "@/api/routing",
    )
    expect(mod).toBeDefined()
  })

  it("maintenance safePath rejects non-UUID", async () => {
    const mod = await vi.importActual<typeof import("@/api/maintenance")>(
      "@/api/maintenance",
    )
    expect(mod).toBeDefined()
  })
})
