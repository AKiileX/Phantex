// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — TrustGraphPage smoke / unit tests (O4).
 *
 * Tests: renders page header, handles empty graph, loading state,
 * filter controls, breakdown panel open/close, truncation warning,
 * low-trust detection.
 */

import { describe, it, expect, vi, beforeEach } from "vitest"
import { render, screen, fireEvent } from "@testing-library/react"
import { MemoryRouter, Route, Routes } from "react-router-dom"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { TrustGraphPage } from "@/pages/TrustGraphPage"

/* ── Mock data ─────────────────────────────────────────────────────────────── */

const MOCK_NODES = [
  { id: "aaa-111", entity_type: "agent", trust_score: 0.85, metadata: { name: "Agent-A" } },
  { id: "bbb-222", entity_type: "tool", trust_score: 0.15, metadata: { name: "Tool-X" } },
  { id: "ccc-333", entity_type: "file", trust_score: 0.55, metadata: { name: "data.csv" } },
]

const MOCK_EDGES = [
  { source_id: "aaa-111", target_id: "bbb-222", edge_type: "uses", count: 5, weight: 0.6 },
  { source_id: "aaa-111", target_id: "ccc-333", edge_type: "accesses", count: 3, weight: 0.4 },
]

let trustGraphReturn: Record<string, unknown> = {
  data: { nodes: MOCK_NODES, edges: MOCK_EDGES, truncated: false },
  isLoading: false,
  error: null,
}

let trustScoreReturn: Record<string, unknown> = {
  data: {
    entity_id: "aaa-111",
    entity_type: "agent",
    trust_score: 0.85,
    factors: [
      { name: "behaviour", weight: 0.4, value: 0.9 },
      { name: "lineage", weight: 0.3, value: 0.8 },
    ],
    last_updated: new Date().toISOString(),
  },
  isLoading: false,
  error: null,
}

/* ── Mocks ─────────────────────────────────────────────────────────────────── */

vi.mock("@/api/trust", () => ({
  useTrustGraph: vi.fn(() => trustGraphReturn),
  useTrustScore: vi.fn(() => trustScoreReturn),
}))

vi.mock("@/stores/authStore", () => ({
  useAuthStore: vi.fn((selector: (s: Record<string, unknown>) => unknown) =>
    selector({
      isAuthenticated: true,
      user: { role: "admin", email: "admin@localhost" },
      token: "tok",
    }),
  ),
}))

// Mock ResizeObserver (not available in jsdom)
class MockResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}
vi.stubGlobal("ResizeObserver", MockResizeObserver)

/* ── Helpers ───────────────────────────────────────────────────────────────── */

function renderPage() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/trust"]}>
        <Routes>
          <Route path="/trust" element={<TrustGraphPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

/* ── Tests ──────────────────────────────────────────────────────────────────── */

describe("TrustGraphPage", () => {
  beforeEach(() => {
    vi.clearAllMocks()
    trustGraphReturn = {
      data: { nodes: MOCK_NODES, edges: MOCK_EDGES, truncated: false },
      isLoading: false,
      error: null,
    }
    trustScoreReturn = {
      data: {
        entity_id: "aaa-111",
        entity_type: "agent",
        trust_score: 0.85,
        factors: [
          { name: "behaviour", weight: 0.4, value: 0.9 },
          { name: "lineage", weight: 0.3, value: 0.8 },
        ],
        last_updated: new Date().toISOString(),
      },
      isLoading: false,
      error: null,
    }
  })

  /* ── Rendering ───────────────────────────────────────── */

  it("renders page title", () => {
    renderPage()
    expect(screen.getByText("Trust Graph")).toBeInTheDocument()
  })

  it("renders depth selector", () => {
    renderPage()
    const select = screen.getByRole("combobox") as HTMLSelectElement
    expect(select.value).toBe("2") // default depth
  })

  it("renders Filters and Refresh buttons", () => {
    renderPage()
    expect(screen.getByText("Filters")).toBeInTheDocument()
    expect(screen.getByText("Refresh")).toBeInTheDocument()
  })

  /* ── Empty / loading / error states ──────────────────── */

  it("shows loading spinner when loading", () => {
    trustGraphReturn = { data: undefined, isLoading: true, error: null }
    renderPage()
    expect(screen.getByText("Loading trust graph…")).toBeInTheDocument()
  })

  it("shows error state on failure", () => {
    trustGraphReturn = { data: undefined, isLoading: false, error: new Error("fail") }
    renderPage()
    expect(screen.getByText("Failed to load trust data")).toBeInTheDocument()
    expect(screen.getByText("Retry")).toBeInTheDocument()
  })

  it("shows empty state when no nodes match", () => {
    trustGraphReturn = { data: { nodes: [], edges: [], truncated: false }, isLoading: false, error: null }
    renderPage()
    expect(screen.getByText("No entities match current filters")).toBeInTheDocument()
  })

  /* ── Truncation warning ──────────────────────────────── */

  it("shows truncation badge when graph is truncated", () => {
    trustGraphReturn = {
      data: { nodes: MOCK_NODES, edges: MOCK_EDGES, truncated: true },
      isLoading: false,
      error: null,
    }
    renderPage()
    expect(screen.getByText(/Truncated/)).toBeInTheDocument()
  })

  it("does not show truncation badge when not truncated", () => {
    renderPage()
    expect(screen.queryByText(/Truncated/)).not.toBeInTheDocument()
  })

  /* ── Filter controls ─────────────────────────────────── */

  it("toggles filter panel on Filters button click", () => {
    renderPage()
    expect(screen.queryByText("Types")).not.toBeInTheDocument()
    fireEvent.click(screen.getByText("Filters"))
    expect(screen.getByText("Types")).toBeInTheDocument()
    expect(screen.getByText("Min Trust")).toBeInTheDocument()
  })

  it("shows entity type filter buttons", () => {
    renderPage()
    fireEvent.click(screen.getByText("Filters"))
    // SVG legend may also contain these words, use getAllByText
    expect(screen.getAllByText("agent").length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText("tool").length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText("file").length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText("network").length).toBeGreaterThanOrEqual(1)
  })

  it("shows node count and edge count in filter panel", () => {
    renderPage()
    fireEvent.click(screen.getByText("Filters"))
    expect(screen.getByText("3 nodes")).toBeInTheDocument()
    expect(screen.getByText("2 edges")).toBeInTheDocument()
  })

  it("detects low-trust nodes", () => {
    renderPage()
    fireEvent.click(screen.getByText("Filters"))
    // bbb-222 has trust 0.15 < 0.3
    expect(screen.getByText("1 low-trust")).toBeInTheDocument()
  })

  /* ── Depth selector ──────────────────────────────────── */

  it("changes depth via select", () => {
    renderPage()
    const select = screen.getByRole("combobox") as HTMLSelectElement
    fireEvent.change(select, { target: { value: "4" } })
    expect(select.value).toBe("4")
  })

  /* ── SVG graph rendered ──────────────────────────────── */

  it("renders an SVG element when nodes exist", () => {
    const { container } = renderPage()
    expect(container.querySelector("svg")).toBeInTheDocument()
  })
})

/* ── TrustGraph component direct tests ─────────────────────────────────────── */

import { TrustGraph } from "@/components/trust/TrustGraph"

describe("TrustGraph component", () => {
  it("shows empty message when nodes are empty", () => {
    render(<TrustGraph nodes={[]} edges={[]} width={400} height={300} />)
    expect(screen.getByText("No trust data available")).toBeInTheDocument()
  })

  it("renders SVG with correct dimensions", () => {
    const { container } = render(
      <TrustGraph nodes={MOCK_NODES} edges={MOCK_EDGES} width={600} height={400} />,
    )
    const svg = container.querySelector("svg")
    expect(svg).toBeInTheDocument()
    expect(svg?.getAttribute("width")).toBe("600")
    expect(svg?.getAttribute("height")).toBe("400")
  })
})

/* ── TrustBreakdown component tests ────────────────────────────────────────── */

import { TrustBreakdown } from "@/components/trust/TrustBreakdown"

describe("TrustBreakdown", () => {
  const node = MOCK_NODES[0]

  it("renders entity name and type badge", () => {
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <TrustBreakdown node={node} />
      </QueryClientProvider>,
    )
    // Name appears as heading + in metadata, so use getAllByText
    expect(screen.getAllByText("Agent-A").length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText("agent").length).toBeGreaterThanOrEqual(1)
  })

  it("shows trust score value", () => {
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <TrustBreakdown node={node} />
      </QueryClientProvider>,
    )
    expect(screen.getByText("0.850")).toBeInTheDocument()
  })

  it("shows High badge for high trust score", () => {
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <TrustBreakdown node={node} />
      </QueryClientProvider>,
    )
    expect(screen.getByText("High")).toBeInTheDocument()
  })

  it("shows Low badge for low trust score", () => {
    const lowNode = { ...MOCK_NODES[1] } // trust 0.15
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <TrustBreakdown node={lowNode} />
      </QueryClientProvider>,
    )
    expect(screen.getByText("Low")).toBeInTheDocument()
  })

  it("renders close button when onClose provided", () => {
    const onClose = vi.fn()
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <TrustBreakdown node={node} onClose={onClose} />
      </QueryClientProvider>,
    )
    const btn = screen.getByLabelText("Close detail panel")
    fireEvent.click(btn)
    expect(onClose).toHaveBeenCalledOnce()
  })

  it("renders factor breakdown when loaded", () => {
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <TrustBreakdown node={node} />
      </QueryClientProvider>,
    )
    expect(screen.getByText("Factor Breakdown")).toBeInTheDocument()
  })

  it("renders entity id in footer", () => {
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <TrustBreakdown node={node} />
      </QueryClientProvider>,
    )
    expect(screen.getByText(node.id)).toBeInTheDocument()
  })
})
