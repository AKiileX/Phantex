// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Test utilities: render helpers and mock providers.
 */

import type { ReactElement } from "react"
import { render, type RenderOptions } from "@testing-library/react"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { MemoryRouter, type MemoryRouterProps } from "react-router-dom"

/**
 * Create a fresh QueryClient for each test — prevents cache leaking
 * between tests and disables retries for predictable failures.
 */
function createTestQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        gcTime: 0,
      },
      mutations: {
        retry: false,
      },
    },
  })
}

interface WrapperOptions {
  /** Initial route entries for MemoryRouter */
  routerEntries?: MemoryRouterProps["initialEntries"]
}

/**
 * renderWithProviders — wraps component in QueryClient + MemoryRouter.
 */
export function renderWithProviders(
  ui: ReactElement,
  { routerEntries = ["/"], ...renderOptions }: WrapperOptions & RenderOptions = {},
) {
  const queryClient = createTestQueryClient()

  function Wrapper({ children }: { children: React.ReactNode }) {
    return (
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={routerEntries}>
          {children}
        </MemoryRouter>
      </QueryClientProvider>
    )
  }

  return {
    ...render(ui, { wrapper: Wrapper, ...renderOptions }),
    queryClient,
  }
}
