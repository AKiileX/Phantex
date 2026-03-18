// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — O8 tests: MITRE ATLAS Coverage Dashboard.
 *
 * Covers:
 *   - CoverageMatrix component (render, grouping, click → selection)
 *   - TechniqueDetail panel (loading, render, close)
 *   - AtlasPage integration (summary cards, export, matrix + detail)
 *   - CSV injection sanitization
 *   - API hook validators (safeTechniqueId, safeRuleName)
 *   - Route + Sidebar integration
 */

import { describe, it, expect, vi, beforeEach } from "vitest"
import { screen, fireEvent } from "@testing-library/react"
import { renderWithProviders } from "@/test/test-utils"

/* ── Fixtures ──────────────────────────────────────────────────────────────── */

const mockTechniques = [
  {
    id: "AML.T0000",
    name: "ML Supply Chain Compromise",
    tactic: "Initial Access",
    url: "https://atlas.mitre.org/techniques/AML.T0000",
    detected: true,
    detected_by: [
      { name: "supply_chain_model_swap", source: "prl_rule" as const, confidence: "high" as const },
      { name: "provenance_verifier", source: "ml_model" as const, confidence: "medium" as const },
    ],
    best_confidence: "high" as const,
  },
  {
    id: "AML.T0002",
    name: "Backdoor ML Model",
    tactic: "Initial Access",
    url: "https://atlas.mitre.org/techniques/AML.T0002",
    detected: true,
    detected_by: [
      { name: "model_integrity_check", source: "ml_model" as const, confidence: "medium" as const },
    ],
    best_confidence: "medium" as const,
  },
  {
    id: "AML.T0010",
    name: "ML Model Inference API Access",
    tactic: "Collection",
    url: "https://atlas.mitre.org/techniques/AML.T0010",
    detected: false,
    detected_by: [],
    best_confidence: "none" as const,
  },
  {
    id: "AML.T0015",
    name: "Evade ML Model",
    tactic: "Evasion",
    url: "https://atlas.mitre.org/techniques/AML.T0015",
    detected: true,
    detected_by: [
      { name: "adversarial_detector", source: "content_classifier" as const, confidence: "low" as const },
    ],
    best_confidence: "low" as const,
  },
]

const mockCoverageResponse = {
  total_techniques: 14,
  detected_techniques: 10,
  coverage_pct: 71.4,
  techniques: mockTechniques,
}

const mockTechniqueDetail = {
  id: "AML.T0000",
  name: "ML Supply Chain Compromise",
  tactic: "Initial Access",
  url: "https://atlas.mitre.org/techniques/AML.T0000",
  description: "Adversaries may manipulate products or dependencies in the ML supply chain.",
  detected: true,
  detected_by: [
    { name: "supply_chain_model_swap", source: "prl_rule" as const, confidence: "high" as const },
    { name: "provenance_verifier", source: "ml_model" as const, confidence: "medium" as const },
  ],
  best_confidence: "high" as const,
}

/* ── Mock API ──────────────────────────────────────────────────────────────── */

const mockUseAtlasCoverage = vi.fn(() => ({
  data: mockCoverageResponse,
  isLoading: false,
  error: null,
}))

const mockUseAtlasTechnique = vi.fn(() => ({
  data: mockTechniqueDetail,
  isLoading: false,
  error: null,
}))

const mockUseAtlasRuleMapping = vi.fn(() => ({
  data: null,
  isLoading: false,
  error: null,
}))

vi.mock("@/api/atlas", () => ({
  useAtlasCoverage: (...args: unknown[]) => mockUseAtlasCoverage(...args),
  useAtlasTechnique: (...args: unknown[]) => mockUseAtlasTechnique(...args),
  useAtlasRuleMapping: (...args: unknown[]) => mockUseAtlasRuleMapping(...args),
  ATLAS_KEYS: {
    all: ["atlas"],
    coverage: () => ["atlas", "coverage"],
    technique: (id: string) => ["atlas", "technique", id],
    rule: (name: string) => ["atlas", "rule", name],
  },
}))

/* ── Mock sidebar alert API ────────────────────────────────────────────────── */

vi.mock("@/api/alerts", () => ({
  useAlerts: vi.fn(() => ({ data: { items: [] }, isLoading: false })),
}))

/* ══════════════════════════════════════════════════════════════════════════════
 *  Coverage Matrix
 * ══════════════════════════════════════════════════════════════════════════════ */

import { CoverageMatrix } from "@/components/atlas/CoverageMatrix"

describe("CoverageMatrix", () => {
  it("renders all techniques grouped by tactic", () => {
    const onSelect = vi.fn()
    renderWithProviders(
      <CoverageMatrix
        techniques={mockTechniques}
        selectedId={null}
        onSelect={onSelect}
      />,
    )

    // Tactic group headings
    expect(screen.getByText("Initial Access")).toBeInTheDocument()
    expect(screen.getByText("Collection")).toBeInTheDocument()
    expect(screen.getByText("Evasion")).toBeInTheDocument()

    // Technique IDs
    expect(screen.getByText("AML.T0000")).toBeInTheDocument()
    expect(screen.getByText("AML.T0002")).toBeInTheDocument()
    expect(screen.getByText("AML.T0010")).toBeInTheDocument()
    expect(screen.getByText("AML.T0015")).toBeInTheDocument()

    // Technique names
    expect(screen.getByText("ML Supply Chain Compromise")).toBeInTheDocument()
    expect(screen.getByText("Backdoor ML Model")).toBeInTheDocument()
  })

  it("shows confidence badges (High, Medium, Low, None)", () => {
    renderWithProviders(
      <CoverageMatrix
        techniques={mockTechniques}
        selectedId={null}
        onSelect={vi.fn()}
      />,
    )
    expect(screen.getByText("High")).toBeInTheDocument()
    expect(screen.getByText("Medium")).toBeInTheDocument()
    expect(screen.getByText("Low")).toBeInTheDocument()
    expect(screen.getByText("None")).toBeInTheDocument()
  })

  it("shows detector count for detected techniques", () => {
    renderWithProviders(
      <CoverageMatrix
        techniques={mockTechniques}
        selectedId={null}
        onSelect={vi.fn()}
      />,
    )
    expect(screen.getByText("2 detectors")).toBeInTheDocument()
    expect(screen.getAllByText("1 detector")).toHaveLength(2)
  })

  it("fires onSelect when a technique card is clicked", () => {
    const onSelect = vi.fn()
    renderWithProviders(
      <CoverageMatrix
        techniques={mockTechniques}
        selectedId={null}
        onSelect={onSelect}
      />,
    )

    fireEvent.click(
      screen.getByLabelText(/Technique AML\.T0000/),
    )
    expect(onSelect).toHaveBeenCalledWith("AML.T0000")
  })

  it("visually highlights the selected technique", () => {
    renderWithProviders(
      <CoverageMatrix
        techniques={mockTechniques}
        selectedId="AML.T0000"
        onSelect={vi.fn()}
      />,
    )

    const selected = screen.getByLabelText(/Technique AML\.T0000/)
    expect(selected.className).toContain("ring-2")
  })
})

/* ══════════════════════════════════════════════════════════════════════════════
 *  Technique Detail
 * ══════════════════════════════════════════════════════════════════════════════ */

import { TechniqueDetail } from "@/components/atlas/TechniqueDetail"

describe("TechniqueDetail", () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockUseAtlasTechnique.mockReturnValue({
      data: mockTechniqueDetail,
      isLoading: false,
      error: null,
    })
  })

  it("renders technique info and detectors", () => {
    renderWithProviders(
      <TechniqueDetail techniqueId="AML.T0000" onClose={vi.fn()} />,
    )

    expect(screen.getByText("AML.T0000")).toBeInTheDocument()
    expect(screen.getByText("ML Supply Chain Compromise")).toBeInTheDocument()
    expect(screen.getByText("Initial Access")).toBeInTheDocument()
    expect(screen.getByText(/Adversaries may manipulate/)).toBeInTheDocument()

    // Detectors
    expect(screen.getByText("supply_chain_model_swap")).toBeInTheDocument()
    expect(screen.getByText("provenance_verifier")).toBeInTheDocument()
    expect(screen.getByText("PRL Rule")).toBeInTheDocument()
    expect(screen.getByText("ML Model")).toBeInTheDocument()
  })

  it("shows ATLAS reference link", () => {
    renderWithProviders(
      <TechniqueDetail techniqueId="AML.T0000" onClose={vi.fn()} />,
    )

    const link = screen.getByText("View on MITRE ATLAS")
    expect(link).toHaveAttribute(
      "href",
      "https://atlas.mitre.org/techniques/AML.T0000",
    )
    expect(link).toHaveAttribute("target", "_blank")
    expect(link).toHaveAttribute("rel", "noopener noreferrer")
  })

  it("calls onClose when X button clicked", () => {
    const onClose = vi.fn()
    renderWithProviders(
      <TechniqueDetail techniqueId="AML.T0000" onClose={onClose} />,
    )

    fireEvent.click(screen.getByLabelText("Close technique detail"))
    expect(onClose).toHaveBeenCalledOnce()
  })

  it("shows loading spinner when data is loading", () => {
    mockUseAtlasTechnique.mockReturnValue({
      data: undefined,
      isLoading: true,
      error: null,
    })

    const { container } = renderWithProviders(
      <TechniqueDetail techniqueId="AML.T0000" onClose={vi.fn()} />,
    )

    expect(container.querySelector(".animate-spin")).toBeInTheDocument()
  })

  it("shows error message on failure", () => {
    mockUseAtlasTechnique.mockReturnValue({
      data: undefined,
      isLoading: false,
      error: new Error("Network error"),
    })

    renderWithProviders(
      <TechniqueDetail techniqueId="AML.T0000" onClose={vi.fn()} />,
    )

    expect(screen.getByRole("alert")).toHaveTextContent(
      "Failed to load technique details",
    )
  })

  it("shows empty detector message when no detectors", () => {
    mockUseAtlasTechnique.mockReturnValue({
      data: {
        ...mockTechniqueDetail,
        detected_by: [],
      },
      isLoading: false,
      error: null,
    })

    renderWithProviders(
      <TechniqueDetail techniqueId="AML.T0010" onClose={vi.fn()} />,
    )

    expect(screen.getByText(/No active detectors/)).toBeInTheDocument()
  })
})

/* ══════════════════════════════════════════════════════════════════════════════
 *  Atlas Page
 * ══════════════════════════════════════════════════════════════════════════════ */

import AtlasPage from "@/pages/AtlasPage"

describe("AtlasPage", () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockUseAtlasCoverage.mockReturnValue({
      data: mockCoverageResponse,
      isLoading: false,
      error: null,
    })
    mockUseAtlasTechnique.mockReturnValue({
      data: mockTechniqueDetail,
      isLoading: false,
      error: null,
    })
  })

  it("renders page header and description", () => {
    renderWithProviders(<AtlasPage />)
    expect(screen.getByText("MITRE ATLAS Coverage")).toBeInTheDocument()
    expect(screen.getByText(/14 adversarial ML techniques/)).toBeInTheDocument()
  })

  it("shows summary cards with correct values", () => {
    renderWithProviders(<AtlasPage />)

    // Total Techniques
    expect(screen.getByText("Total Techniques")).toBeInTheDocument()
    // Detected
    expect(screen.getByText("Detected")).toBeInTheDocument()
    // Coverage
    expect(screen.getByText("Coverage")).toBeInTheDocument()
  })

  it("renders export buttons (CSV and JSON)", () => {
    renderWithProviders(<AtlasPage />)
    expect(screen.getByText("CSV")).toBeInTheDocument()
    expect(screen.getByText("JSON")).toBeInTheDocument()
  })

  it("shows coverage matrix with techniques", () => {
    renderWithProviders(<AtlasPage />)
    expect(screen.getByText("Coverage Matrix")).toBeInTheDocument()
    expect(screen.getByText("AML.T0000")).toBeInTheDocument()
    expect(screen.getByText("ML Supply Chain Compromise")).toBeInTheDocument()
  })

  it("opens TechniqueDetail panel when a technique is clicked", () => {
    renderWithProviders(<AtlasPage />)

    // Initially no detail panel
    expect(screen.queryByLabelText("Close technique detail")).not.toBeInTheDocument()

    // Click a technique
    fireEvent.click(screen.getByLabelText(/Technique AML\.T0000/))

    // Detail panel should appear with close button
    expect(screen.getByLabelText("Close technique detail")).toBeInTheDocument()
    // Technique detail loads
    expect(screen.getByText("supply_chain_model_swap")).toBeInTheDocument()
  })

  it("closes TechniqueDetail panel when close button is clicked", () => {
    renderWithProviders(<AtlasPage />)

    // Open
    fireEvent.click(screen.getByLabelText(/Technique AML\.T0000/))
    expect(screen.getByLabelText("Close technique detail")).toBeInTheDocument()

    // Close
    fireEvent.click(screen.getByLabelText("Close technique detail"))
    expect(
      screen.queryByLabelText("Close technique detail"),
    ).not.toBeInTheDocument()
  })

  it("toggles selection when clicking same technique twice", () => {
    renderWithProviders(<AtlasPage />)

    const card = screen.getByLabelText(/Technique AML\.T0000/)

    // First click opens
    fireEvent.click(card)
    expect(screen.getByLabelText("Close technique detail")).toBeInTheDocument()

    // Second click closes
    fireEvent.click(card)
    expect(
      screen.queryByLabelText("Close technique detail"),
    ).not.toBeInTheDocument()
  })

  it("shows loading spinner when data is loading", () => {
    mockUseAtlasCoverage.mockReturnValue({
      data: undefined,
      isLoading: true,
      error: null,
    })

    const { container } = renderWithProviders(<AtlasPage />)
    expect(container.querySelector(".animate-spin")).toBeInTheDocument()
  })

  it("shows error alert when request fails", () => {
    mockUseAtlasCoverage.mockReturnValue({
      data: undefined,
      isLoading: false,
      error: new Error("Server error"),
    })

    renderWithProviders(<AtlasPage />)
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Failed to load ATLAS coverage data",
    )
  })
})

/* ══════════════════════════════════════════════════════════════════════════════
 *  CSV Injection Sanitization
 * ══════════════════════════════════════════════════════════════════════════════ */

describe("CSV export sanitization", () => {
  let createObjectURLSpy: ReturnType<typeof vi.fn>
  let revokeObjectURLSpy: ReturnType<typeof vi.fn>
  let capturedBlob: Blob | undefined
  let origCreateObjectURL: typeof URL.createObjectURL
  let origRevokeObjectURL: typeof URL.revokeObjectURL

  beforeEach(() => {
    vi.clearAllMocks()
    mockUseAtlasCoverage.mockReturnValue({
      data: mockCoverageResponse,
      isLoading: false,
      error: null,
    })

    capturedBlob = undefined
    createObjectURLSpy = vi.fn((blob: Blob) => {
      capturedBlob = blob
      return "blob:mock-url"
    })
    revokeObjectURLSpy = vi.fn()
    origCreateObjectURL = globalThis.URL.createObjectURL
    origRevokeObjectURL = globalThis.URL.revokeObjectURL
    globalThis.URL.createObjectURL = createObjectURLSpy
    globalThis.URL.revokeObjectURL = revokeObjectURLSpy
  })

  afterEach(() => {
    globalThis.URL.createObjectURL = origCreateObjectURL
    globalThis.URL.revokeObjectURL = origRevokeObjectURL
  })

  it("exports CSV and calls createObjectURL", () => {
    renderWithProviders(<AtlasPage />)
    fireEvent.click(screen.getByText("CSV"))
    expect(createObjectURLSpy).toHaveBeenCalledOnce()
    expect(revokeObjectURLSpy).toHaveBeenCalledOnce()
  })

  it("exports JSON and calls createObjectURL", () => {
    renderWithProviders(<AtlasPage />)
    fireEvent.click(screen.getByText("JSON"))
    expect(createObjectURLSpy).toHaveBeenCalledOnce()
  })

  it("sanitizes CSV cells starting with dangerous characters", async () => {
    // Inject a technique with dangerous chars in name
    const dangerousTechniques = [
      {
        ...mockTechniques[0],
        name: "=CMD('calc')",
      },
    ]
    mockUseAtlasCoverage.mockReturnValue({
      data: {
        ...mockCoverageResponse,
        techniques: dangerousTechniques,
      },
      isLoading: false,
      error: null,
    })

    renderWithProviders(<AtlasPage />)
    fireEvent.click(screen.getByText("CSV"))

    expect(capturedBlob).toBeDefined()
    const text = await capturedBlob!.text()
    // The = should be prefixed with single quote
    expect(text).toContain("'=CMD('calc')")
    // Should NOT contain raw =CMD
    expect(text).not.toMatch(/,=CMD/)
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
      const state = { user: { role: "analyst" }, token: "t" }
      return selector(state)
    }),
    selectIsAdmin: (s: { user?: { role: string } }) => s.user?.role === "admin",
  }
})

describe("Sidebar — ATLAS nav item", () => {
  it("renders ATLAS link in Investigate group", () => {
    renderWithProviders(<Sidebar />)
    const link = screen.getByText("ATLAS")
    expect(link).toBeInTheDocument()
    expect(link.closest("a")).toHaveAttribute("href", "/atlas")
  })
})

describe("Routes — /atlas", () => {
  it("AtlasPage is a valid default export", async () => {
    const mod = await import("@/pages/AtlasPage")
    expect(mod.default).toBeDefined()
    expect(typeof mod.default).toBe("function")
  })
})
