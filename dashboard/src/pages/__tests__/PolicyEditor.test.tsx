// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — O5 Policy Editor UI tests.
 *
 * Tests: PoliciesPage, PolicyEditPage, PolicyVisualBuilder, PolicyVersionHistory.
 * Monaco is mocked (jsdom has no web workers).
 */

import { describe, it, expect, vi, beforeEach } from "vitest"
import { render, screen, fireEvent } from "@testing-library/react"
import { MemoryRouter, Route, Routes } from "react-router-dom"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { PoliciesPage } from "@/pages/PoliciesPage"
import { PolicyEditPage } from "@/pages/PolicyEditPage"
import { PolicyVisualBuilder } from "@/components/policies/PolicyVisualBuilder"
import { PolicyVersionHistory } from "@/components/policies/PolicyVersionHistory"
import type { PolicyDefinition, Policy, PolicyVersion } from "@/types"

/* ── Mock data ─────────────────────────────────────────────────────────────── */

const MOCK_POLICY: Policy = {
  id: "p-001",
  tenant_id: "t-1",
  name: "Production Lockdown",
  description: "High-security policy for production agents",
  version: 3,
  enabled: true,
  definition: {
    rules: [
      { name: "exec-block", enabled: true, severity_override: "critical", parameters: {}, notifications: [] },
    ],
    scope: { agent_tags: ["production"], frameworks: ["langchain"] },
    schedule: { active_hours: "09:00-18:00 UTC", weekend: "suppress" },
  },
  scope_agent_tags: ["production"],
  scope_frameworks: ["langchain"],
  created_by: "admin@localhost",
  updated_by: "admin@localhost",
  created_at: "2025-01-15T10:00:00Z",
  updated_at: "2025-01-20T14:30:00Z",
}

const MOCK_POLICY_2: Policy = {
  id: "p-002",
  tenant_id: "t-1",
  name: "Dev Permissive",
  description: "Relaxed policy for development",
  version: 1,
  enabled: false,
  definition: { rules: [], scope: { agent_tags: [], frameworks: [] }, schedule: null },
  scope_agent_tags: [],
  scope_frameworks: [],
  created_by: "dev@localhost",
  updated_by: "dev@localhost",
  created_at: "2025-01-10T08:00:00Z",
  updated_at: "2025-01-10T08:00:00Z",
}

const MOCK_VERSIONS: PolicyVersion[] = [
  { id: "v1", policy_id: "p-001", version: 1, definition: { rules: [] }, change_summary: "Initial creation", created_by: "admin@localhost", created_at: "2025-01-15T10:00:00Z" },
  { id: "v2", policy_id: "p-001", version: 2, definition: { rules: [{ name: "exec-block" }] }, change_summary: "Added exec-block rule", created_by: "admin@localhost", created_at: "2025-01-18T12:00:00Z" },
  { id: "v3", policy_id: "p-001", version: 3, definition: { rules: [{ name: "exec-block" }], scope: { agent_tags: ["production"] } }, change_summary: "Added production scope", created_by: "admin@localhost", created_at: "2025-01-20T14:30:00Z" },
]

const MOCK_RULES = [
  { id: "r1", tenant_id: "t-1", name: "exec-block", description: "Block exec", prl_source: "WHEN exec THEN block", severity: "critical", attack_class: "execution", version: 1, author: "admin", enabled: true, created_at: "2025-01-01", updated_at: "2025-01-01" },
  { id: "r2", tenant_id: "t-1", name: "file-monitor", description: "Monitor files", prl_source: "WHEN file.open THEN alert", severity: "medium", attack_class: "file_access", version: 1, author: "admin", enabled: true, created_at: "2025-01-01", updated_at: "2025-01-01" },
  { id: "r3", tenant_id: "t-1", name: "net-restrict", description: "Restrict network", prl_source: "WHEN net.connect THEN restrict", severity: "high", attack_class: "network", version: 1, author: "admin", enabled: true, created_at: "2025-01-01", updated_at: "2025-01-01" },
]

/* ── Mock return values (mutable) ──────────────────────────────────────────── */

let policiesReturn = { data: { items: [MOCK_POLICY, MOCK_POLICY_2], total: 2 }, isLoading: false, error: null }
let policyReturn = { data: MOCK_POLICY, isLoading: false, error: null }
let versionsReturn = { data: MOCK_VERSIONS, isLoading: false, error: null }
let rulesReturn = { data: { items: MOCK_RULES, total: 3 }, isLoading: false, error: null }

const mockCreateMutate = vi.fn()
const mockUpdateMutate = vi.fn()
const mockDeleteMutate = vi.fn()
const mockValidateMutate = vi.fn()
const mockApplyMutate = vi.fn()

/* ── Mocks ─────────────────────────────────────────────────────────────────── */

vi.mock("@/api/policies", () => ({
  usePolicies: vi.fn(() => policiesReturn),
  usePolicy: vi.fn(() => policyReturn),
  useCreatePolicy: vi.fn(() => ({ mutate: mockCreateMutate, mutateAsync: vi.fn().mockResolvedValue({}), isPending: false })),
  useUpdatePolicy: vi.fn(() => ({ mutate: mockUpdateMutate, mutateAsync: vi.fn().mockResolvedValue({}), isPending: false })),
  useDeletePolicy: vi.fn(() => ({ mutate: mockDeleteMutate, isPending: false })),
  useValidatePolicy: vi.fn(() => ({ mutate: mockValidateMutate, isPending: false, isSuccess: false, data: null })),
  useApplyPolicy: vi.fn(() => ({ mutate: mockApplyMutate, isPending: false })),
  usePolicyVersions: vi.fn(() => versionsReturn),
}))

vi.mock("@/api/rules", () => ({
  useRules: vi.fn(() => rulesReturn),
}))

vi.mock("@/stores/authStore", () => ({
  useAuthStore: vi.fn((selector: (s: Record<string, unknown>) => unknown) =>
    selector({
      isAuthenticated: true,
      user: { role: "admin", email: "admin@localhost" },
      token: "tok",
    }),
  ),
  selectIsAdmin: (s: Record<string, unknown>) =>
    (s.user as Record<string, string>)?.role === "admin",
}))

vi.mock("@/stores/permissionStore", () => ({
  usePermissionStore: vi.fn((selector: (s: Record<string, unknown>) => unknown) =>
    selector({
      permissions: new Set(["policies.read", "policies.write", "rules.read", "rules.write"]),
      loaded: true,
      has: (p: string) => new Set(["policies.read", "policies.write", "rules.read", "rules.write"]).has(p),
    }),
  ),
}))

// Mock Monaco editor (jsdom can't run it)
vi.mock("monaco-editor", () => ({
  editor: { defineTheme: vi.fn(), setTheme: vi.fn() },
  languages: { register: vi.fn(), setMonarchTokensProvider: vi.fn(), setLanguageConfiguration: vi.fn() },
}))
vi.mock("monaco-editor/esm/vs/editor/editor.worker?worker", () => ({ default: class {} }))
vi.mock("@monaco-editor/react", () => ({
  default: ({ value, onChange }: { value: string; onChange?: (v: string) => void }) => (
    <textarea
      data-testid="monaco-editor"
      value={value}
      onChange={(e) => onChange?.(e.target.value)}
    />
  ),
  loader: { config: vi.fn() },
}))

class MockResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}
vi.stubGlobal("ResizeObserver", MockResizeObserver)

/* ── Helpers ───────────────────────────────────────────────────────────────── */

function qc() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } })
}

function renderPoliciesPage() {
  return render(
    <QueryClientProvider client={qc()}>
      <MemoryRouter initialEntries={["/policies"]}>
        <Routes>
          <Route path="/policies" element={<PoliciesPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

function renderEditPage(id = "p-001") {
  const route = id === "new" ? "/policies/new" : `/policies/${id}/edit`
  const path = id === "new" ? "/policies/new" : "/policies/:id/edit"
  return render(
    <QueryClientProvider client={qc()}>
      <MemoryRouter initialEntries={[route]}>
        <Routes>
          <Route path={path} element={<PolicyEditPage />} />
          <Route path="/policies" element={<div>policies-list</div>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

function renderVisualBuilder(def?: Partial<PolicyDefinition>) {
  const definition: PolicyDefinition = {
    rules: [],
    scope: { agent_tags: [], frameworks: [] },
    schedule: null,
    ...def,
  }
  const onChange = vi.fn()
  const result = render(
    <QueryClientProvider client={qc()}>
      <PolicyVisualBuilder definition={definition} onChange={onChange} />
    </QueryClientProvider>,
  )
  return { ...result, onChange }
}

function renderVersionHistory(policyId = "p-001") {
  return render(
    <QueryClientProvider client={qc()}>
      <PolicyVersionHistory policyId={policyId} />
    </QueryClientProvider>,
  )
}

/* ── Reset ─────────────────────────────────────────────────────────────────── */

beforeEach(() => {
  vi.clearAllMocks()
  policiesReturn = { data: { items: [MOCK_POLICY, MOCK_POLICY_2], total: 2 }, isLoading: false, error: null }
  policyReturn = { data: MOCK_POLICY, isLoading: false, error: null }
  versionsReturn = { data: MOCK_VERSIONS, isLoading: false, error: null }
  rulesReturn = { data: { items: MOCK_RULES, total: 3 }, isLoading: false, error: null }
})

/* ── PoliciesPage ──────────────────────────────────────────────────────────── */

describe("PoliciesPage", () => {
  it("renders page header with policy count", () => {
    renderPoliciesPage()
    expect(screen.getByText("Detection Policies")).toBeInTheDocument()
    expect(screen.getByText("2 policies configured")).toBeInTheDocument()
  })

  it("displays both policies in the list", () => {
    renderPoliciesPage()
    expect(screen.getByText("Production Lockdown")).toBeInTheDocument()
    expect(screen.getByText("Dev Permissive")).toBeInTheDocument()
  })

  it("shows active/disabled counts", () => {
    renderPoliciesPage()
    expect(screen.getByText("1 active")).toBeInTheDocument()
    expect(screen.getByText("1 disabled")).toBeInTheDocument()
  })

  it("shows version badge for each policy", () => {
    renderPoliciesPage()
    expect(screen.getByText("v3")).toBeInTheDocument()
    expect(screen.getByText("v1")).toBeInTheDocument()
  })

  it("shows scope badges for production policy", () => {
    renderPoliciesPage()
    expect(screen.getByText("1 tag")).toBeInTheDocument()
    expect(screen.getByText("1 fw")).toBeInTheDocument()
  })

  it("renders New Policy button for admin", () => {
    renderPoliciesPage()
    expect(screen.getByText("New Policy")).toBeInTheDocument()
  })

  it("shows loading spinner when loading", () => {
    policiesReturn = { data: { items: [], total: 0 }, isLoading: true, error: null }
    renderPoliciesPage()
    // Loader2 is rendered (svg with animate-spin class)
    expect(document.querySelector(".animate-spin")).toBeInTheDocument()
  })

  it("shows empty state when no policies", () => {
    policiesReturn = { data: { items: [], total: 0 }, isLoading: false, error: null }
    renderPoliciesPage()
    expect(screen.getByText("No policies configured yet")).toBeInTheDocument()
    expect(screen.getByText("Create your first policy")).toBeInTheDocument()
  })

  it("filters policies by search text", () => {
    renderPoliciesPage()
    const search = screen.getByPlaceholderText("Filter policies…")
    fireEvent.change(search, { target: { value: "production" } })
    expect(screen.getByText("Production Lockdown")).toBeInTheDocument()
    expect(screen.queryByText("Dev Permissive")).not.toBeInTheDocument()
  })

  it("shows disabled policy with reduced opacity", () => {
    renderPoliciesPage()
    // The dev policy card should have opacity-60 class
    const devTitle = screen.getByText("Dev Permissive")
    const card = devTitle.closest("[class*='opacity-60']")
    expect(card).toBeInTheDocument()
  })
})

/* ── PolicyEditPage ────────────────────────────────────────────────────────── */

describe("PolicyEditPage", () => {
  it("renders in edit mode with existing policy name", () => {
    renderEditPage("p-001")
    const nameInput = screen.getByDisplayValue("Production Lockdown")
    expect(nameInput).toBeInTheDocument()
  })

  it("renders version badge for existing policy", () => {
    renderEditPage("p-001")
    expect(screen.getByText("v3")).toBeInTheDocument()
  })

  it("shows Visual / YAML mode toggle", () => {
    renderEditPage("p-001")
    expect(screen.getByText("Visual")).toBeInTheDocument()
    expect(screen.getByText("YAML")).toBeInTheDocument()
  })

  it("starts in visual mode by default", () => {
    renderEditPage("p-001")
    // Visual button should be active (bg-surface-2/80)
    const visualBtn = screen.getByText("Visual")
    expect(visualBtn.closest("button")?.className).toContain("text-foreground")
  })

  it("shows History button for existing policies", () => {
    renderEditPage("p-001")
    expect(screen.getByText("History")).toBeInTheDocument()
  })

  it("shows Policies back button", () => {
    renderEditPage("p-001")
    expect(screen.getByText("Policies")).toBeInTheDocument()
  })

  it("shows change summary input for existing policies", () => {
    renderEditPage("p-001")
    expect(screen.getByPlaceholderText("Change summary (optional)")).toBeInTheDocument()
  })

  it("shows Apply to Agents button for existing policy", () => {
    renderEditPage("p-001")
    expect(screen.getByText("Apply to Agents")).toBeInTheDocument()
  })

  it("shows Validate button", () => {
    renderEditPage("p-001")
    expect(screen.getByText("Validate")).toBeInTheDocument()
  })

  it("shows Save button", () => {
    renderEditPage("p-001")
    expect(screen.getByText("Save")).toBeInTheDocument()
  })

  it("renders create mode for new policy", () => {
    policyReturn = { data: null as unknown as Policy, isLoading: false, error: null }
    renderEditPage("new")
    expect(screen.getByPlaceholderText("Policy name")).toBeInTheDocument()
    // In create mode the save button says "Create"
    const saveBtn = screen.getByRole("button", { name: /Create/ })
    expect(saveBtn).toBeInTheDocument()
  })

  it("does not show History button for new policy", () => {
    policyReturn = { data: null as unknown as Policy, isLoading: false, error: null }
    renderEditPage("new")
    // id="new" so isNew=true, History is hidden
    expect(screen.queryByRole("button", { name: /History/ })).not.toBeInTheDocument()
  })

  it("does not show Apply to Agents for new policy", () => {
    policyReturn = { data: null as unknown as Policy, isLoading: false, error: null }
    renderEditPage("new")
    expect(screen.queryByRole("button", { name: /Apply to Agents/ })).not.toBeInTheDocument()
  })

  it("shows loading spinner when fetching policy", () => {
    policyReturn = { data: null as unknown as Policy, isLoading: true, error: null }
    renderEditPage("p-001")
    expect(screen.getByText("Loading policy…")).toBeInTheDocument()
  })

  it("switches to YAML mode", () => {
    renderEditPage("p-001")
    const yamlBtn = screen.getByText("YAML")
    fireEvent.click(yamlBtn)
    // Monaco mock renders as textarea
    expect(screen.getByTestId("monaco-editor")).toBeInTheDocument()
  })
})

/* ── PolicyVisualBuilder ───────────────────────────────────────────────────── */

describe("PolicyVisualBuilder", () => {
  it("renders empty rule overrides message", () => {
    renderVisualBuilder()
    expect(screen.getByText(/No rule overrides/)).toBeInTheDocument()
  })

  it("shows add rule dropdown with available rules", () => {
    renderVisualBuilder()
    const selects = screen.getAllByRole("combobox") as HTMLSelectElement[]
    // First combobox is the add-rule dropdown
    const ruleSelect = selects[0]
    expect(ruleSelect).toBeInTheDocument()
    // Should have 3 rule options + 1 disabled placeholder
    const options = Array.from(ruleSelect.querySelectorAll("option"))
    expect(options.length).toBe(4)
  })

  it("adds a rule when selected from dropdown", () => {
    const { onChange } = renderVisualBuilder()
    const selects = screen.getAllByRole("combobox") as HTMLSelectElement[]
    fireEvent.change(selects[0], { target: { value: "exec-block" } })
    expect(onChange).toHaveBeenCalledWith(expect.objectContaining({
      rules: [expect.objectContaining({ name: "exec-block", enabled: true })],
    }))
  })

  it("renders existing rule overrides", () => {
    renderVisualBuilder({
      rules: [
        { name: "exec-block", enabled: true, severity_override: "critical", parameters: {}, notifications: [] },
        { name: "file-monitor", enabled: false, severity_override: null, parameters: {}, notifications: [] },
      ],
    })
    expect(screen.getByText("exec-block")).toBeInTheDocument()
    expect(screen.getByText("file-monitor")).toBeInTheDocument()
  })

  it("shows severity badge for overridden rules", () => {
    renderVisualBuilder({
      rules: [
        { name: "exec-block", enabled: true, severity_override: "critical", parameters: {}, notifications: [] },
      ],
    })
    expect(screen.getByText("critical")).toBeInTheDocument()
  })

  it("shows Scope section", () => {
    renderVisualBuilder()
    expect(screen.getByText("Scope")).toBeInTheDocument()
    expect(screen.getByText("Agent Tags")).toBeInTheDocument()
    expect(screen.getByText("Frameworks")).toBeInTheDocument()
  })

  it("shows Schedule section", () => {
    renderVisualBuilder()
    expect(screen.getByText("Schedule")).toBeInTheDocument()
    expect(screen.getByText("Active Hours")).toBeInTheDocument()
  })

  it("renders existing agent tags", () => {
    renderVisualBuilder({
      scope: { agent_tags: ["production", "staging"], frameworks: [] },
    })
    expect(screen.getByText(/production/)).toBeInTheDocument()
    expect(screen.getByText(/staging/)).toBeInTheDocument()
  })

  it("adds an agent tag on Enter", () => {
    const { onChange } = renderVisualBuilder()
    const input = screen.getByPlaceholderText("e.g. production")
    fireEvent.change(input, { target: { value: "my-tag" } })
    fireEvent.keyDown(input, { key: "Enter" })
    expect(onChange).toHaveBeenCalledWith(expect.objectContaining({
      scope: expect.objectContaining({ agent_tags: ["my-tag"] }),
    }))
  })

  it("adds a framework on Enter", () => {
    const { onChange } = renderVisualBuilder()
    const input = screen.getByPlaceholderText("e.g. langchain")
    fireEvent.change(input, { target: { value: "crewai" } })
    fireEvent.keyDown(input, { key: "Enter" })
    expect(onChange).toHaveBeenCalledWith(expect.objectContaining({
      scope: expect.objectContaining({ frameworks: ["crewai"] }),
    }))
  })

  it("filters out already-added rules from dropdown", () => {
    renderVisualBuilder({
      rules: [{ name: "exec-block", enabled: true, severity_override: null, parameters: {}, notifications: [] }],
    })
    const selects = screen.getAllByRole("combobox") as HTMLSelectElement[]
    const ruleSelect = selects[0]
    const options = Array.from(ruleSelect.querySelectorAll("option")).map((o) => o.value)
    expect(options).not.toContain("exec-block")
  })
})

/* ── PolicyVersionHistory ──────────────────────────────────────────────────── */

describe("PolicyVersionHistory", () => {
  it("renders version list", () => {
    renderVersionHistory()
    expect(screen.getByText("v1")).toBeInTheDocument()
    expect(screen.getByText("v2")).toBeInTheDocument()
    expect(screen.getByText("v3")).toBeInTheDocument()
  })

  it("shows change summaries", () => {
    renderVersionHistory()
    expect(screen.getByText("Initial creation")).toBeInTheDocument()
    expect(screen.getByText("Added exec-block rule")).toBeInTheDocument()
    expect(screen.getByText("Added production scope")).toBeInTheDocument()
  })

  it("shows creator for each version", () => {
    renderVersionHistory()
    const creators = screen.getAllByText("admin@localhost")
    expect(creators.length).toBe(3)
  })

  it("shows empty state when no versions", () => {
    versionsReturn = { data: [] as PolicyVersion[], isLoading: false, error: null }
    renderVersionHistory()
    expect(screen.getByText("No version history")).toBeInTheDocument()
  })

  it("shows loading state", () => {
    versionsReturn = { data: undefined as unknown as PolicyVersion[], isLoading: true, error: null }
    renderVersionHistory()
    expect(screen.getByText("Loading version history…")).toBeInTheDocument()
  })

  it("shows diff button after selecting two versions", () => {
    renderVersionHistory()
    const v1 = screen.getByText("v1").closest("[class*='cursor-pointer']")!
    const v2 = screen.getByText("v2").closest("[class*='cursor-pointer']")!
    fireEvent.click(v1)
    fireEvent.click(v2)
    expect(screen.getByText(/Diff v1 ↔ v2/)).toBeInTheDocument()
  })

  it("displays diff content when diff button clicked", () => {
    renderVersionHistory()
    const v1 = screen.getByText("v1").closest("[class*='cursor-pointer']")!
    const v2 = screen.getByText("v2").closest("[class*='cursor-pointer']")!
    fireEvent.click(v1)
    fireEvent.click(v2)
    fireEvent.click(screen.getByText(/Diff v1 ↔ v2/))
    // Diff region should be visible
    expect(screen.getByRole("region", { name: "Policy diff" })).toBeInTheDocument()
  })
})
