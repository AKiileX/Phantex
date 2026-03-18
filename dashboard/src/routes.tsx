// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Route definitions.
 *
 * All page components are lazy-loaded via React.lazy() to enable
 * code-splitting.  Each route chunk is downloaded on first visit,
 * dramatically reducing initial bundle size and eliminating the
 * "freeze on fast tab-switch" problem.
 */

import { lazy, Suspense } from "react"
import { BrowserRouter, Routes, Route } from "react-router-dom"
import { MainLayout } from "@/components/layout/MainLayout"
import { ProtectedRoute } from "@/components/ProtectedRoute"

/* ── Retry wrapper for dynamic imports ───────────────────────────── */
// After a deploy the old chunk hashes no longer exist on the server.
// When a lazy() import fails we force one full page reload so the
// browser picks up the new index.html (and its fresh chunk manifest).
function lazyRetry<T extends { default: React.ComponentType<Record<string, unknown>> }>(
  factory: () => Promise<T>,
): React.LazyExoticComponent<T["default"]> {
  return lazy(() =>
    factory().catch((err: unknown) => {
      const key = "__phantex_chunk_retry__"
      if (!sessionStorage.getItem(key)) {
        sessionStorage.setItem(key, "1")
        window.location.reload()
        // Return a never-resolving promise so React doesn't render the error
        return new Promise<T>(() => {})
      }
      sessionStorage.removeItem(key)
      throw err   // genuine error — let error boundary handle it
    }),
  )
}

/* ── Shared loading spinner (shown while chunks download) ────────── */
function PageSpinner() {
  return (
    <div className="flex items-center justify-center py-24">
      <div className="h-6 w-6 animate-spin rounded-full border-2 border-primary/20 border-t-primary" />
    </div>
  )
}

/* ── Lazy page imports ────────────────────────────────────────────── */
// Pages with default exports use lazyRetry() directly.
// Pages with named exports use .then() to re-export as default.
const LoginPage         = lazyRetry(() => import("@/pages/LoginPage").then(m => ({ default: m.LoginPage })))
const DashboardPage     = lazyRetry(() => import("@/pages/DashboardPage").then(m => ({ default: m.DashboardPage })))
const AgentsPage        = lazyRetry(() => import("@/pages/AgentsPage").then(m => ({ default: m.AgentsPage })))
const AgentDetailPage   = lazyRetry(() => import("@/pages/AgentDetailPage").then(m => ({ default: m.AgentDetailPage })))
const EventsPage        = lazyRetry(() => import("@/pages/EventsPage").then(m => ({ default: m.EventsPage })))
const EventDetailPage   = lazyRetry(() => import("@/pages/EventDetailPage").then(m => ({ default: m.EventDetailPage })))
const AlertsPage        = lazyRetry(() => import("@/pages/AlertsPage").then(m => ({ default: m.AlertsPage })))
const AlertDetailPage   = lazyRetry(() => import("@/pages/AlertDetailPage").then(m => ({ default: m.AlertDetailPage })))
const InvestigationPage = lazyRetry(() => import("@/pages/InvestigationPage").then(m => ({ default: m.InvestigationPage })))
const RulesPage         = lazyRetry(() => import("@/pages/RulesPage").then(m => ({ default: m.RulesPage })))
const PoliciesPage      = lazyRetry(() => import("@/pages/PoliciesPage").then(m => ({ default: m.PoliciesPage })))
const PolicyEditPage    = lazyRetry(() => import("@/pages/PolicyEditPage").then(m => ({ default: m.PolicyEditPage })))
const TopologyPage      = lazyRetry(() => import("@/pages/TopologyPage").then(m => ({ default: m.TopologyPage })))
const TrustGraphPage    = lazyRetry(() => import("@/pages/TrustGraphPage").then(m => ({ default: m.TrustGraphPage })))
const ExemptionsPage    = lazyRetry(() => import("@/pages/ExemptionsPage").then(m => ({ default: m.ExemptionsPage })))
const AlertRoutingPage  = lazyRetry(() => import("@/pages/AlertRoutingPage").then(m => ({ default: m.AlertRoutingPage })))
const MaintenancePage   = lazyRetry(() => import("@/pages/MaintenancePage").then(m => ({ default: m.MaintenancePage })))
const AtlasPage         = lazyRetry(() => import("@/pages/AtlasPage"))
const ExportsPage       = lazyRetry(() => import("@/pages/ExportsPage"))
const TelemetryPage     = lazyRetry(() => import("@/pages/TelemetryPage"))
const MLStatusPage      = lazyRetry(() => import("@/pages/MLStatusPage"))
const SettingsPage      = lazyRetry(() => import("@/pages/SettingsPage").then(m => ({ default: m.SettingsPage })))
const SSOConfigPage     = lazyRetry(() => import("@/pages/SSOConfigPage").then(m => ({ default: m.SSOConfigPage })))
const SSOCallbackPage   = lazyRetry(() => import("@/pages/SSOCallbackPage").then(m => ({ default: m.SSOCallbackPage })))
const RolesPage         = lazyRetry(() => import("@/pages/RolesPage").then(m => ({ default: m.RolesPage })))
const TenantsPage       = lazyRetry(() => import("@/pages/TenantsPage").then(m => ({ default: m.TenantsPage })))
const SCIMSettingsPage      = lazyRetry(() => import("@/pages/SCIMSettingsPage").then(m => ({ default: m.SCIMSettingsPage })))
const CopilotSettingsPage  = lazyRetry(() => import("@/pages/CopilotSettingsPage"))
const SensorsPage           = lazyRetry(() => import("@/pages/SensorsPage").then(m => ({ default: m.SensorsPage })))
const SensorDetailPage      = lazyRetry(() => import("@/pages/SensorDetailPage").then(m => ({ default: m.SensorDetailPage })))
const NotFoundPage          = lazyRetry(() => import("@/pages/NotFoundPage").then(m => ({ default: m.NotFoundPage })))

/* ── Phase 2+ Intelligence pages ──────────────────────── */
const LiveTopologyPage  = lazyRetry(() => import("@/pages/LiveTopologyPage"))
const ThreatReplayPage  = lazyRetry(() => import("@/pages/ThreatReplayPage"))
const RiskHeatmapPage   = lazyRetry(() => import("@/pages/RiskHeatmapPage"))
const AttackChainPage   = lazyRetry(() => import("@/pages/AttackChainPage"))
const AgentVitalsPage   = lazyRetry(() => import("@/pages/AgentVitalsPage"))
const MCPObservatoryPage = lazyRetry(() => import("@/pages/MCPObservatoryPage"))
const BehaviorRadarPage = lazyRetry(() => import("@/pages/BehaviorRadarPage"))
const BlastRadiusPage   = lazyRetry(() => import("@/pages/BlastRadiusPage"))
const CompliancePage    = lazyRetry(() => import("@/pages/CompliancePage").then(m => ({ default: m.CompliancePage })))
const NerveCenterPage   = lazyRetry(() => import("@/pages/NerveCenterPage"))
const AutoResponsePage  = lazyRetry(() => import("@/pages/AutoResponsePage"))
const SOARPage          = lazyRetry(() => import("@/pages/SOARPage"))
const IntegrationsPage  = lazyRetry(() => import("@/pages/IntegrationsPage"))
const DeceptionPage     = lazyRetry(() => import("@/pages/DeceptionPage"))
const AgentDriftPage    = lazyRetry(() => import("@/pages/AgentDriftPage"))

/* ── Phase 4 pages ────────────────────────────────────── */
const RedTeamPage              = lazyRetry(() => import("@/pages/RedTeamPage").then(m => ({ default: m.RedTeamPage })))
const AnalyticsOverviewPage    = lazyRetry(() => import("@/pages/AnalyticsOverviewPage").then(m => ({ default: m.AnalyticsOverviewPage })))
const ThreatLandscapePage      = lazyRetry(() => import("@/pages/ThreatLandscapePage").then(m => ({ default: m.ThreatLandscapePage })))
const OperationalMetricsPage   = lazyRetry(() => import("@/pages/OperationalMetricsPage").then(m => ({ default: m.OperationalMetricsPage })))
const VerificationPage         = lazyRetry(() => import("@/pages/VerificationPage").then(m => ({ default: m.VerificationPage })))
const DataClassificationPage   = lazyRetry(() => import("@/pages/DataClassificationPage").then(m => ({ default: m.DataClassificationPage })))
const FinOpsPage               = lazyRetry(() => import("@/pages/FinOpsPage").then(m => ({ default: m.FinOpsPage })))
const A2AProtocolPage          = lazyRetry(() => import("@/pages/A2AProtocolPage").then(m => ({ default: m.A2AProtocolPage })))
const AuditRecordingPage       = lazyRetry(() => import("@/pages/AuditRecordingPage").then(m => ({ default: m.AuditRecordingPage })))
const ThreatIntelPage          = lazyRetry(() => import("@/pages/ThreatIntelPage"))
const GraphQLExplorerPage      = lazyRetry(() => import("@/pages/GraphQLExplorerPage").then(m => ({ default: m.GraphQLExplorerPage })))

/* ── PWA pages ────────────────────────────────────────── */
const MobileTriagePage  = lazyRetry(() => import("@/components/pwa/MobileAlertTriage").then(m => ({ default: m.MobileAlertTriage })))
const OfflinePage       = lazyRetry(() => import("@/components/pwa/OfflinePage").then(m => ({ default: m.OfflinePage })))

export function AppRouter() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Public route */}
        <Route path="/login" element={<Suspense fallback={<PageSpinner />}><LoginPage /></Suspense>} />
        <Route path="/sso/callback" element={<Suspense fallback={<PageSpinner />}><SSOCallbackPage /></Suspense>} />
        <Route path="/offline" element={<Suspense fallback={<PageSpinner />}><OfflinePage /></Suspense>} />

        {/* Protected routes — all roles */}
        <Route element={<ProtectedRoute />}>
          {/* Mobile PWA triage — fullscreen, no sidebar */}
          <Route path="m/alerts" element={<Suspense fallback={<PageSpinner />}><MobileTriagePage /></Suspense>} />

          <Route element={<MainLayout />}>
            <Route index element={<Suspense fallback={<PageSpinner />}><DashboardPage /></Suspense>} />
            <Route path="agents" element={<Suspense fallback={<PageSpinner />}><AgentsPage /></Suspense>} />
            <Route path="agents/:id" element={<Suspense fallback={<PageSpinner />}><AgentDetailPage /></Suspense>} />
            <Route path="sensors" element={<Suspense fallback={<PageSpinner />}><SensorsPage /></Suspense>} />
            <Route path="sensors/:id" element={<Suspense fallback={<PageSpinner />}><SensorDetailPage /></Suspense>} />
            <Route path="topology" element={<Suspense fallback={<PageSpinner />}><TopologyPage /></Suspense>} />
            <Route path="trust" element={<Suspense fallback={<PageSpinner />}><TrustGraphPage /></Suspense>} />
            <Route path="events" element={<Suspense fallback={<PageSpinner />}><EventsPage /></Suspense>} />
            <Route path="events/:id" element={<Suspense fallback={<PageSpinner />}><EventDetailPage /></Suspense>} />
            <Route path="alerts" element={<Suspense fallback={<PageSpinner />}><AlertsPage /></Suspense>} />
            <Route path="alerts/:id" element={<Suspense fallback={<PageSpinner />}><AlertDetailPage /></Suspense>} />
            <Route path="rules" element={<Suspense fallback={<PageSpinner />}><RulesPage /></Suspense>} />
            <Route path="atlas" element={<Suspense fallback={<PageSpinner />}><AtlasPage /></Suspense>} />

            {/* Intelligence pages — all roles */}
            <Route path="live-topology" element={<Suspense fallback={<PageSpinner />}><LiveTopologyPage /></Suspense>} />
            <Route path="threat-replay" element={<Suspense fallback={<PageSpinner />}><ThreatReplayPage /></Suspense>} />
            <Route path="risk-heatmap" element={<Suspense fallback={<PageSpinner />}><RiskHeatmapPage /></Suspense>} />
            <Route path="attack-chain" element={<Suspense fallback={<PageSpinner />}><AttackChainPage /></Suspense>} />
            <Route path="agent-vitals" element={<Suspense fallback={<PageSpinner />}><AgentVitalsPage /></Suspense>} />
            <Route path="mcp-trust" element={<Suspense fallback={<PageSpinner />}><MCPObservatoryPage /></Suspense>} />
            <Route path="behavior-radar" element={<Suspense fallback={<PageSpinner />}><BehaviorRadarPage /></Suspense>} />
            <Route path="blast-radius" element={<Suspense fallback={<PageSpinner />}><BlastRadiusPage /></Suspense>} />
            <Route path="compliance" element={<Suspense fallback={<PageSpinner />}><CompliancePage /></Suspense>} />
            <Route path="nerve-center" element={<Suspense fallback={<PageSpinner />}><NerveCenterPage /></Suspense>} />
            <Route path="agent-drift" element={<Suspense fallback={<PageSpinner />}><AgentDriftPage /></Suspense>} />

            {/* Advanced Analytics */}
            <Route path="analytics/overview" element={<Suspense fallback={<PageSpinner />}><AnalyticsOverviewPage /></Suspense>} />
            <Route path="analytics/threats" element={<Suspense fallback={<PageSpinner />}><ThreatLandscapePage /></Suspense>} />
            <Route path="analytics/ops" element={<Suspense fallback={<PageSpinner />}><OperationalMetricsPage /></Suspense>} />

            {/* Formal Verification */}
            <Route path="verification" element={<Suspense fallback={<PageSpinner />}><VerificationPage /></Suspense>} />

            {/* Data Classification */}
            <Route path="data-classification" element={<Suspense fallback={<PageSpinner />}><DataClassificationPage /></Suspense>} />

            {/* FinOps */}
            <Route path="finops" element={<Suspense fallback={<PageSpinner />}><FinOpsPage /></Suspense>} />

            {/* A2A Protocol */}
            <Route path="a2a-protocol" element={<Suspense fallback={<PageSpinner />}><A2AProtocolPage /></Suspense>} />

            {/* Audit & DVR Recording */}
            <Route path="audit-recording" element={<Suspense fallback={<PageSpinner />}><AuditRecordingPage /></Suspense>} />

            {/* Threat Intelligence */}
            <Route path="threat-intel" element={<Suspense fallback={<PageSpinner />}><ThreatIntelPage /></Suspense>} />

            {/* GraphQL Explorer */}
            <Route path="graphql" element={<Suspense fallback={<PageSpinner />}><GraphQLExplorerPage /></Suspense>} />

            {/* Policy routes — requires policies.read permission */}
            <Route element={<ProtectedRoute requiredPermissions={["policies.read"]} allowedRoles={["analyst", "admin"]} />}>
              <Route path="policies" element={<Suspense fallback={<PageSpinner />}><PoliciesPage /></Suspense>} />
              <Route path="policies/:id/edit" element={<Suspense fallback={<PageSpinner />}><PolicyEditPage /></Suspense>} />
              <Route path="policies/new" element={<Suspense fallback={<PageSpinner />}><PolicyEditPage /></Suspense>} />
            </Route>

            {/* O7 management routes — requires specific permissions */}
            <Route element={<ProtectedRoute requiredPermissions={["policies.read", "notifications.manage"]} allowedRoles={["analyst", "admin"]} />}>
              <Route path="exemptions" element={<Suspense fallback={<PageSpinner />}><ExemptionsPage /></Suspense>} />
              <Route path="alert-routing" element={<Suspense fallback={<PageSpinner />}><AlertRoutingPage /></Suspense>} />
              <Route path="maintenance" element={<Suspense fallback={<PageSpinner />}><MaintenancePage /></Suspense>} />
            </Route>

            {/* Investigation routes — requires investigation.run */}
            <Route element={<ProtectedRoute requiredPermissions={["investigation.run"]} allowedRoles={["analyst", "admin"]} />}>
              <Route path="investigate/:type/:id" element={<Suspense fallback={<PageSpinner />}><InvestigationPage /></Suspense>} />
            </Route>

            {/* Admin-only routes — permission-gated */}
            <Route element={<ProtectedRoute requiredPermissions={["exports.generate", "telemetry.read", "ml.manage", "auth.manage", "tenants.manage"]} allowedRoles={["admin"]} />}>
              <Route path="exports" element={<Suspense fallback={<PageSpinner />}><ExportsPage /></Suspense>} />
              <Route path="telemetry" element={<Suspense fallback={<PageSpinner />}><TelemetryPage /></Suspense>} />
              <Route path="ml" element={<Suspense fallback={<PageSpinner />}><MLStatusPage /></Suspense>} />
              <Route path="settings" element={<Suspense fallback={<PageSpinner />}><SettingsPage /></Suspense>} />
              <Route path="settings/sso" element={<Suspense fallback={<PageSpinner />}><SSOConfigPage /></Suspense>} />
              <Route path="settings/roles" element={<Suspense fallback={<PageSpinner />}><RolesPage /></Suspense>} />
              <Route path="settings/tenants" element={<Suspense fallback={<PageSpinner />}><TenantsPage /></Suspense>} />
              <Route path="settings/scim" element={<Suspense fallback={<PageSpinner />}><SCIMSettingsPage /></Suspense>} />
              <Route path="settings/copilot" element={<Suspense fallback={<PageSpinner />}><CopilotSettingsPage /></Suspense>} />
              <Route path="settings/auto-response" element={<Suspense fallback={<PageSpinner />}><AutoResponsePage /></Suspense>} />
              <Route path="settings/soar" element={<Suspense fallback={<PageSpinner />}><SOARPage /></Suspense>} />
              <Route path="settings/integrations" element={<Suspense fallback={<PageSpinner />}><IntegrationsPage /></Suspense>} />
              <Route path="settings/deception" element={<Suspense fallback={<PageSpinner />}><DeceptionPage /></Suspense>} />
              <Route path="red-team" element={<Suspense fallback={<PageSpinner />}><RedTeamPage /></Suspense>} />
            </Route>

            {/* 404 catch-all */}
            <Route path="*" element={<Suspense fallback={<PageSpinner />}><NotFoundPage /></Suspense>} />
          </Route>
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
