// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — App root component.
 *
 * Wraps the router with TanStack Query, ErrorBoundary,
 * toast notifications, and live WebSocket alerts.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { AppRouter } from "@/routes"
import { ErrorBoundary } from "@/components/ErrorBoundary"
import { SessionHydrator } from "@/components/SessionHydrator"
import { ToastProvider } from "@/components/ui/toast"
import { WsAlertProvider } from "@/providers/WsAlertProvider"
import { EventNotificationProvider } from "@/providers/EventNotificationProvider"
import { useSessionTimeout } from "@/hooks/useSessionTimeout"
import { PwaInstallPrompt, PwaUpdatePrompt } from "@/components/pwa"

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
})

export default function App() {
  useSessionTimeout()

  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <ToastProvider>
          <SessionHydrator>
            <WsAlertProvider>
              <EventNotificationProvider>
                <AppRouter />
                <PwaInstallPrompt />
                <PwaUpdatePrompt />
              </EventNotificationProvider>
            </WsAlertProvider>
          </SessionHydrator>
        </ToastProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  )
}

