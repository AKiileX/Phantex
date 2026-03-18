// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Auto-Response Management Page.
 *
 * Admin-only dashboard for controlling the automated response engine:
 * - Kill Switch (emergency stop)
 * - Shadow Mode (log-only / go-live toggle)
 * - Response Policies (CRUD)
 * - Escalation Ladder (view / reset)
 * - Action Log (audit trail)
 * - Human Override
 */

import { useState } from "react"
import {
  useKillSwitch,
  useToggleKillSwitch,
  useShadowStatus,
  useEnableShadow,
  useDisableShadow,
  useResponsePolicies,
  useCreatePolicy,
  useDeletePolicy,
  useEscalationStates,
  useResetEscalation,
  useActionLog,
  useOverrideAction,
  useResponseConfig,
  useUpdateConfig,
  type ResponsePolicy,
} from "@/api/response"

// ── Decision badge colors ────────────────────────────────────────────────────

const decisionColors: Record<string, string> = {
  executed: "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300",
  shadow: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300",
  blocked_kill_switch: "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300",
  cooldown_skip: "bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300",
  escalated: "bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300",
  overridden: "bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-300",
  rate_limited: "bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300",
  error: "bg-red-200 text-red-900 dark:bg-red-900/40 dark:text-red-200",
}

function Badge({ label, className = "" }: { label: string; className?: string }) {
  return (
    <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${className}`}>
      {label}
    </span>
  )
}

// ── Section wrapper ──────────────────────────────────────────────────────────

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-gray-200 bg-white p-6 shadow-sm dark:border-gray-700 dark:bg-gray-800">
      <h2 className="mb-4 text-lg font-semibold text-gray-900 dark:text-white">{title}</h2>
      {children}
    </div>
  )
}

// ══════════════════════════════════════════════════════════════════════════════
//  MAIN PAGE COMPONENT
// ══════════════════════════════════════════════════════════════════════════════

export function AutoResponsePage() {
  const [activeTab, setActiveTab] = useState<"overview" | "policies" | "log" | "escalation">("overview")
  const [showGuide, setShowGuide] = useState(false)

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Auto-Response Engine</h1>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            Automatically respond to threats detected by PRL rules — isolate agents, block IPs,
            kill processes, and more.
          </p>
        </div>
        <button
          onClick={() => setShowGuide(!showGuide)}
          className="rounded-lg border border-indigo-300 px-3 py-1.5 text-xs font-medium text-indigo-600 hover:bg-indigo-50 dark:border-indigo-700 dark:text-indigo-400 dark:hover:bg-indigo-900/20"
        >
          {showGuide ? "Hide Guide" : "How does this work?"}
        </button>
      </div>

      {showGuide && (
        <div className="space-y-4">
          {/* Section 1: End-to-end pipeline */}
          <div className="rounded-lg border border-indigo-200 bg-indigo-50/50 p-5 dark:border-indigo-800 dark:bg-indigo-950/30">
            <h3 className="text-sm font-semibold text-indigo-900 dark:text-indigo-300">End-to-End Pipeline</h3>
            <p className="mt-1 text-xs text-indigo-800/80 dark:text-indigo-300/70">
              When a PRL detection rule fires, here's what happens automatically:
            </p>
            <div className="mt-3 flex flex-wrap items-center gap-1.5 text-xs font-medium">
              {[
                { label: "Sensor detects event", color: "bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-300" },
                { label: "→" },
                { label: "Rule Engine matches PRL rule", color: "bg-purple-100 text-purple-800 dark:bg-purple-900/40 dark:text-purple-300" },
                { label: "→" },
                { label: "Alert fires", color: "bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300" },
                { label: "→" },
                { label: "Auto-Response evaluates policies", color: "bg-indigo-100 text-indigo-800 dark:bg-indigo-900/40 dark:text-indigo-300" },
                { label: "→" },
                { label: "Action dispatched", color: "bg-orange-100 text-orange-800 dark:bg-orange-900/40 dark:text-orange-300" },
                { label: "→" },
                { label: "Logged for audit", color: "bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300" },
              ].map((step, i) =>
                step.color ? (
                  <span key={i} className={`rounded-full px-2.5 py-1 ${step.color}`}>{step.label}</span>
                ) : (
                  <span key={i} className="text-gray-400 dark:text-gray-500">{step.label}</span>
                )
              )}
            </div>
            <div className="mt-3 text-xs text-indigo-800/70 dark:text-indigo-300/60">
              <p>The engine runs these checks in order before executing any action:</p>
              <ol className="mt-1.5 list-inside list-decimal space-y-0.5 pl-1">
                <li><strong>Kill Switch</strong> — if active, all actions are blocked immediately</li>
                <li><strong>Policy Match</strong> — finds the highest-priority policy matching the alert's severity/attack class</li>
                <li><strong>Shadow Mode</strong> — if enabled, logs "would have done X" but doesn't execute</li>
                <li><strong>Cooldown</strong> — skips if the same action was taken for this agent recently</li>
                <li><strong>Rate Limit</strong> — enforces max actions/hour to prevent runaway automation</li>
                <li><strong>Escalation Ladder</strong> — checks if the agent is a repeat offender and escalates severity</li>
                <li><strong>Dispatch</strong> — sends the actual command (isolate, block, kill, etc.)</li>
              </ol>
            </div>
          </div>

          {/* Section 2: Getting started workflow */}
          <div className="rounded-lg border border-indigo-200 bg-indigo-50/50 p-5 dark:border-indigo-800 dark:bg-indigo-950/30">
            <h3 className="text-sm font-semibold text-indigo-900 dark:text-indigo-300">Getting Started</h3>
            <div className="mt-3 grid gap-3 text-xs text-indigo-800/70 dark:text-indigo-300/60 md:grid-cols-2">
              <div className="flex gap-2">
                <span className="mt-0.5 text-sm font-bold text-indigo-500">1.</span>
                <div><strong>Create Policies</strong> — go to the Policies tab and create rules that map alert
                  conditions (severity, attack class) to automated actions. Example: "If severity is critical,
                  isolate the agent."</div>
              </div>
              <div className="flex gap-2">
                <span className="mt-0.5 text-sm font-bold text-indigo-500">2.</span>
                <div><strong>Start in Shadow Mode</strong> — enable Shadow Mode on the Overview tab. The engine will
                  log what it <em>would</em> do, without actually executing. This lets you validate decisions are correct.</div>
              </div>
              <div className="flex gap-2">
                <span className="mt-0.5 text-sm font-bold text-indigo-500">3.</span>
                <div><strong>Review Action Log</strong> — after 1–7 days, check the Log tab. Look for "shadow" entries
                  to see if the engine would have made the right calls. Adjust policies if needed.</div>
              </div>
              <div className="flex gap-2">
                <span className="mt-0.5 text-sm font-bold text-indigo-500">4.</span>
                <div><strong>Go Live</strong> — disable Shadow Mode. Actions now execute for real. Use the
                  <strong> Kill Switch</strong> to instantly halt everything if something goes wrong.</div>
              </div>
            </div>
          </div>

          {/* Section 3: Available actions + escalation */}
          <div className="grid gap-4 md:grid-cols-2">
            <div className="rounded-lg border border-indigo-200 bg-indigo-50/50 p-5 dark:border-indigo-800 dark:bg-indigo-950/30">
              <h3 className="text-sm font-semibold text-indigo-900 dark:text-indigo-300">Available Actions</h3>
              <div className="mt-2 grid grid-cols-2 gap-1.5 text-xs text-indigo-800/70 dark:text-indigo-300/60">
                {[
                  ["isolate_agent", "Cut agent's network access"],
                  ["block_ip", "Block a destination IP"],
                  ["kill_process", "Terminate a suspicious process"],
                  ["quarantine_file", "Move file to quarantine"],
                  ["throttle", "Rate-limit agent's activity"],
                  ["trust_penalty", "Lower agent's trust score"],
                  ["block_mcp_server", "Block an MCP server"],
                  ["collect_forensics", "Capture forensic snapshot"],
                  ["notify_soc", "Send alert to SOC team"],
                  ["log_only", "Log without taking action"],
                ].map(([action, desc]) => (
                  <div key={action} className="flex flex-col">
                    <code className="text-[10px] font-semibold text-indigo-600 dark:text-indigo-400">{action}</code>
                    <span className="text-[10px] text-indigo-700/50 dark:text-indigo-400/40">{desc}</span>
                  </div>
                ))}
              </div>
            </div>
            <div className="rounded-lg border border-indigo-200 bg-indigo-50/50 p-5 dark:border-indigo-800 dark:bg-indigo-950/30">
              <h3 className="text-sm font-semibold text-indigo-900 dark:text-indigo-300">Escalation Ladder</h3>
              <p className="mt-1 text-xs text-indigo-800/70 dark:text-indigo-300/60">
                When the same agent triggers alerts repeatedly, the response automatically escalates:
              </p>
              <div className="mt-2 space-y-1.5">
                {[
                  { level: "Level 1", action: "Warn + trust penalty", color: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300" },
                  { level: "Level 2", action: "Throttle agent activity", color: "bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300" },
                  { level: "Level 3", action: "Isolate agent from network", color: "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300" },
                  { level: "Level 4", action: "Revoke all access", color: "bg-red-200 text-red-900 dark:bg-red-900/50 dark:text-red-200" },
                ].map((s) => (
                  <div key={s.level} className="flex items-center gap-2">
                    <span className={`rounded-full px-2 py-0.5 text-[10px] font-semibold ${s.color}`}>{s.level}</span>
                    <span className="text-xs text-indigo-800/60 dark:text-indigo-300/50">{s.action}</span>
                  </div>
                ))}
              </div>
              <p className="mt-2 text-[10px] text-indigo-700/50 dark:text-indigo-400/40">
                Escalation resets after a configurable window (default: 1 hour). You can reset any agent manually on the Escalation tab.
              </p>
            </div>
          </div>

          {/* Section 4: Example scenario */}
          <div className="rounded-lg border border-amber-200 bg-amber-50/50 p-5 dark:border-amber-800 dark:bg-amber-950/30">
            <h3 className="text-sm font-semibold text-amber-900 dark:text-amber-300">Example: Credential Leak Prevention</h3>
            <div className="mt-2 space-y-2 text-xs text-amber-800/70 dark:text-amber-300/60">
              <p>
                <strong>Scenario:</strong> An AI agent reads <code className="rounded bg-amber-100 px-1 dark:bg-amber-900/30">.env</code> credentials and tries to exfiltrate them over the network.
              </p>
              <div className="space-y-1 pl-2">
                <p>1. <strong>PRL Rule</strong> fires on <code className="rounded bg-amber-100 px-1 dark:bg-amber-900/30">FILE_ACCESS</code> to <code className="rounded bg-amber-100 px-1 dark:bg-amber-900/30">/.env</code> → critical alert</p>
                <p>2. <strong>Policy</strong> "Credential Leak" matches severity=critical → action: <code className="rounded bg-amber-100 px-1 dark:bg-amber-900/30">throttle</code></p>
                <p>3. Agent's outbound network is rate-limited → can't send bulk data</p>
                <p>4. If the agent tries again → <strong>Escalation</strong> kicks in → Level 2: <code className="rounded bg-amber-100 px-1 dark:bg-amber-900/30">isolate_agent</code></p>
                <p>5. SOC analyst sees the full chain in the <strong>Action Log</strong> and can override if false positive</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab navigation */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <nav className="-mb-px flex space-x-6">
          {(["overview", "policies", "log", "escalation"] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`border-b-2 py-3 text-sm font-medium transition-colors ${
                activeTab === tab
                  ? "border-indigo-500 text-indigo-600 dark:text-indigo-400"
                  : "border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700 dark:text-gray-400"
              }`}
            >
              {tab.charAt(0).toUpperCase() + tab.slice(1)}
            </button>
          ))}
        </nav>
      </div>

      {activeTab === "overview" && <OverviewTab />}
      {activeTab === "policies" && <PoliciesTab />}
      {activeTab === "log" && <ActionLogTab />}
      {activeTab === "escalation" && <EscalationTab />}
    </div>
  )
}

// ── Overview Tab ─────────────────────────────────────────────────────────────

function OverviewTab() {
  const killSwitch = useKillSwitch()
  const shadow = useShadowStatus()
  const config = useResponseConfig()
  const toggleKill = useToggleKillSwitch()
  const enableShadow = useEnableShadow()
  const disableShadow = useDisableShadow()
  const updateConfig = useUpdateConfig()

  const [killReason, setKillReason] = useState("")

  return (
    <div className="space-y-6">
      {/* Overview guidance */}
      <div className="rounded border border-gray-200 bg-gray-50 px-4 py-3 text-xs text-gray-500 dark:border-gray-700 dark:bg-gray-800/50 dark:text-gray-400">
        <strong>Overview</strong> — Control the engine's operating mode. Start with
        <strong> Shadow Mode</strong> to observe without executing, then <strong>Go Live</strong> when ready.
        Hit the <strong>Kill Switch</strong> to halt all auto-responses instantly.
      </div>

      <div className="grid gap-6 md:grid-cols-2">
      {/* Kill Switch */}
      <Section title="Kill Switch">
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-sm text-gray-600 dark:text-gray-300">Status</span>
            <Badge
              label={killSwitch.data?.kill_switch ? "ACTIVE — All auto-response halted" : "Inactive"}
              className={killSwitch.data?.kill_switch
                ? "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
                : "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
              }
            />
          </div>
          {killSwitch.data?.kill_switch && killSwitch.data.reason && (
            <p className="text-sm text-gray-500 dark:text-gray-400">Reason: {killSwitch.data.reason}</p>
          )}
          <div className="flex items-center gap-2">
            <input
              type="text"
              placeholder="Reason (optional)"
              value={killReason}
              onChange={(e) => setKillReason(e.target.value)}
              className="flex-1 rounded border border-gray-300 px-3 py-1.5 text-sm dark:border-gray-600 dark:bg-gray-700 dark:text-white"
              maxLength={500}
            />
            <button
              onClick={() => {
                toggleKill.mutate({
                  active: !killSwitch.data?.kill_switch,
                  reason: killReason,
                })
                setKillReason("")
              }}
              disabled={toggleKill.isPending}
              className={`rounded px-4 py-1.5 text-sm font-medium text-white ${
                killSwitch.data?.kill_switch
                  ? "bg-green-600 hover:bg-green-700"
                  : "bg-red-600 hover:bg-red-700"
              }`}
            >
              {killSwitch.data?.kill_switch ? "Deactivate" : "Activate Kill Switch"}
            </button>
          </div>
        </div>
      </Section>

      {/* Shadow Mode */}
      <Section title="Shadow Mode">
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-sm text-gray-600 dark:text-gray-300">Status</span>
            <Badge
              label={shadow.data?.effective ? "Shadow (log-only)" : "LIVE — Enforcement active"}
              className={shadow.data?.effective
                ? "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200"
                : "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
              }
            />
          </div>
          {shadow.data?.expires_at && (
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Expires: {new Date(shadow.data.expires_at).toLocaleString()}
            </p>
          )}
          <div className="flex gap-2">
            {shadow.data?.effective ? (
              <button
                onClick={() => disableShadow.mutate()}
                disabled={disableShadow.isPending}
                className="rounded bg-red-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-red-700"
              >
                Go Live (Disable Shadow)
              </button>
            ) : (
              <>
                <button
                  onClick={() => enableShadow.mutate({})}
                  disabled={enableShadow.isPending}
                  className="rounded bg-yellow-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-yellow-700"
                >
                  Enable Shadow (indefinite)
                </button>
                <button
                  onClick={() => enableShadow.mutate({ duration_hours: 24 })}
                  disabled={enableShadow.isPending}
                  className="rounded bg-yellow-500 px-3 py-1.5 text-sm font-medium text-white hover:bg-yellow-600"
                >
                  24h Shadow
                </button>
              </>
            )}
          </div>
        </div>
      </Section>

      {/* Engine Config */}
      <Section title="Engine Configuration">
        <div className="space-y-3 text-sm">
          <div className="flex justify-between">
            <span className="text-gray-600 dark:text-gray-300">Escalation</span>
            <Badge
              label={config.data?.escalation_enabled ? "Enabled" : "Disabled"}
              className={config.data?.escalation_enabled
                ? "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
                : "bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300"
              }
            />
          </div>
          <div className="flex justify-between">
            <span className="text-gray-600 dark:text-gray-300">Escalation Window</span>
            <span className="text-gray-900 dark:text-white">{config.data?.escalation_window ?? 3600}s</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-600 dark:text-gray-300">Max Actions/Hour</span>
            <span className="text-gray-900 dark:text-white">{config.data?.max_actions_per_hour ?? 50}</span>
          </div>
          <button
            onClick={() => {
              updateConfig.mutate({
                escalation_enabled: !(config.data?.escalation_enabled ?? true),
              })
            }}
            disabled={updateConfig.isPending}
            className="mt-2 rounded bg-indigo-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-indigo-700"
          >
            Toggle Escalation
          </button>
        </div>
      </Section>

      {/* Quick Stats */}
      <Section title="Quick Stats">
        <QuickStats />
      </Section>
      </div>
    </div>
  )
}

function QuickStats() {
  const logAll = useActionLog({ limit: 1 })
  const logExecuted = useActionLog({ decision: "executed", limit: 1 })
  const logShadow = useActionLog({ decision: "shadow", limit: 1 })
  const policies = useResponsePolicies()
  const escalation = useEscalationStates()

  return (
    <div className="grid grid-cols-2 gap-4 text-sm">
      <div>
        <p className="text-gray-500 dark:text-gray-400">Total Decisions</p>
        <p className="text-2xl font-bold text-gray-900 dark:text-white">{logAll.data?.total ?? "—"}</p>
      </div>
      <div>
        <p className="text-gray-500 dark:text-gray-400">Executed</p>
        <p className="text-2xl font-bold text-red-600">{logExecuted.data?.total ?? "—"}</p>
      </div>
      <div>
        <p className="text-gray-500 dark:text-gray-400">Shadow-logged</p>
        <p className="text-2xl font-bold text-yellow-600">{logShadow.data?.total ?? "—"}</p>
      </div>
      <div>
        <p className="text-gray-500 dark:text-gray-400">Active Policies</p>
        <p className="text-2xl font-bold text-indigo-600">{policies.data?.total ?? "—"}</p>
      </div>
      <div className="col-span-2">
        <p className="text-gray-500 dark:text-gray-400">Agents Escalated</p>
        <p className="text-2xl font-bold text-orange-600">{escalation.data?.states?.length ?? "—"}</p>
      </div>
    </div>
  )
}

// ── Policies Tab ─────────────────────────────────────────────────────────────

function PoliciesTab() {
  const { data, isLoading } = useResponsePolicies()
  const createPolicy = useCreatePolicy()
  const deletePolicy = useDeletePolicy()
  const [showCreate, setShowCreate] = useState(false)

  if (isLoading) return <p className="py-8 text-center text-gray-500">Loading policies...</p>

  return (
    <div className="space-y-4">
      <div className="rounded border border-gray-200 bg-gray-50 px-4 py-3 text-xs text-gray-500 dark:border-gray-700 dark:bg-gray-800/50 dark:text-gray-400">
        <strong>Policies</strong> — Each policy maps alert conditions to an automated action.
        When an alert matches a policy's severity/attack-class filter, the engine executes that action
        (e.g. isolate the agent, block an IP). Higher <strong>priority</strong> wins if multiple policies match.
        <strong> Cooldown</strong> prevents the same action from repeating too fast.
      </div>
      <div className="flex justify-end">
        <button
          onClick={() => setShowCreate(!showCreate)}
          className="rounded bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700"
        >
          {showCreate ? "Cancel" : "+ New Policy"}
        </button>
      </div>

      {showCreate && (
        <CreatePolicyForm
          onSubmit={(p) => {
            createPolicy.mutate(p)
            setShowCreate(false)
          }}
        />
      )}

      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="border-b bg-gray-50 text-gray-600 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-400">
            <tr>
              <th className="px-4 py-3">Name</th>
              <th className="px-4 py-3">Action</th>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3">Priority</th>
              <th className="px-4 py-3">Cooldown</th>
              <th className="px-4 py-3">Enabled</th>
              <th className="px-4 py-3">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
            {(data?.policies ?? []).map((p) => (
              <tr key={p.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                <td className="px-4 py-3 font-medium text-gray-900 dark:text-white">{p.name}</td>
                <td className="px-4 py-3">
                  <Badge label={p.action} className="bg-indigo-100 text-indigo-800 dark:bg-indigo-900/30 dark:text-indigo-300" />
                </td>
                <td className="px-4 py-3 text-gray-500">{p.severity.join(", ") || "any"}</td>
                <td className="px-4 py-3 text-gray-500">{p.priority}</td>
                <td className="px-4 py-3 text-gray-500">{p.cooldown_sec}s</td>
                <td className="px-4 py-3">
                  <Badge
                    label={p.enabled ? "Yes" : "No"}
                    className={p.enabled
                      ? "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
                      : "bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300"
                    }
                  />
                </td>
                <td className="px-4 py-3">
                  <button
                    onClick={() => deletePolicy.mutate(p.id)}
                    className="text-xs text-red-600 hover:underline dark:text-red-400"
                    disabled={deletePolicy.isPending}
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}
            {data?.policies?.length === 0 && (
              <tr>
                <td colSpan={7} className="py-8 text-center text-gray-400">
                  No response policies configured. Create one to get started.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function CreatePolicyForm({
  onSubmit,
}: {
  onSubmit: (p: Omit<ResponsePolicy, "id" | "created_by" | "created_at" | "updated_at">) => void
}) {
  const [name, setName] = useState("")
  const [action, setAction] = useState("isolate_agent")
  const [severity, setSeverity] = useState("critical,high")
  const [priority, setPriority] = useState(100)
  const [cooldown, setCooldown] = useState(300)
  const [minConf, setMinConf] = useState(0.7)

  const actions = [
    "isolate_agent", "block_ip", "quarantine_file", "kill_process",
    "disable_user", "collect_forensics", "trust_penalty",
    "block_mcp_server", "log_only", "throttle", "notify_soc",
  ]

  return (
    <div className="rounded border border-gray-200 bg-gray-50 p-4 dark:border-gray-700 dark:bg-gray-900">
      <div className="grid gap-4 md:grid-cols-3">
        <div>
          <label className="block text-xs font-medium text-gray-600 dark:text-gray-400">Name</label>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="mt-1 w-full rounded border px-3 py-1.5 text-sm dark:border-gray-600 dark:bg-gray-800 dark:text-white"
            maxLength={200}
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-600 dark:text-gray-400">Action</label>
          <select
            value={action}
            onChange={(e) => setAction(e.target.value)}
            className="mt-1 w-full rounded border px-3 py-1.5 text-sm dark:border-gray-600 dark:bg-gray-800 dark:text-white"
          >
            {actions.map((a) => (
              <option key={a} value={a}>{a}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-600 dark:text-gray-400">Severity (comma-sep)</label>
          <input
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            className="mt-1 w-full rounded border px-3 py-1.5 text-sm dark:border-gray-600 dark:bg-gray-800 dark:text-white"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-600 dark:text-gray-400">Priority</label>
          <input
            type="number"
            value={priority}
            onChange={(e) => setPriority(Number(e.target.value))}
            min={0}
            max={10000}
            className="mt-1 w-full rounded border px-3 py-1.5 text-sm dark:border-gray-600 dark:bg-gray-800 dark:text-white"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-600 dark:text-gray-400">Cooldown (sec)</label>
          <input
            type="number"
            value={cooldown}
            onChange={(e) => setCooldown(Number(e.target.value))}
            min={0}
            max={86400}
            className="mt-1 w-full rounded border px-3 py-1.5 text-sm dark:border-gray-600 dark:bg-gray-800 dark:text-white"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-600 dark:text-gray-400">Min Confidence</label>
          <input
            type="number"
            value={minConf}
            onChange={(e) => setMinConf(Number(e.target.value))}
            min={0}
            max={1}
            step={0.05}
            className="mt-1 w-full rounded border px-3 py-1.5 text-sm dark:border-gray-600 dark:bg-gray-800 dark:text-white"
          />
        </div>
      </div>
      <button
        onClick={() => {
          if (!name.trim()) return
          onSubmit({
            name,
            description: "",
            severity: severity.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean),
            attack_class: [],
            event_type: [],
            min_confidence: minConf,
            action,
            action_params: {},
            enabled: true,
            priority,
            cooldown_sec: cooldown,
            require_shadow: true,
          })
        }}
        className="mt-4 rounded bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700"
      >
        Create Policy
      </button>
    </div>
  )
}

// ── Action Log Tab ───────────────────────────────────────────────────────────

function ActionLogTab() {
  const [decision, setDecision] = useState<string>("")
  const [page, setPage] = useState(0)
  const limit = 25

  const { data, isLoading } = useActionLog({
    decision: decision || undefined,
    limit,
    offset: page * limit,
  })
  const override = useOverrideAction()
  const [overrideId, setOverrideId] = useState<string | null>(null)
  const [overrideReason, setOverrideReason] = useState("")

  return (
    <div className="space-y-4">
      <div className="rounded border border-gray-200 bg-gray-50 px-4 py-3 text-xs text-gray-500 dark:border-gray-700 dark:bg-gray-800/50 dark:text-gray-400">
        <strong>Action Log</strong> — Every auto-response decision is recorded here.
        <strong> Executed</strong> = action ran. <strong>Shadow</strong> = would have run but Shadow Mode was on.
        <strong> Overridden</strong> = analyst reversed an action. Use the Override button to undo any executed action.
      </div>
      <div className="flex items-center gap-4">
        <select
          value={decision}
          onChange={(e) => { setDecision(e.target.value); setPage(0) }}
          className="rounded border px-3 py-1.5 text-sm dark:border-gray-600 dark:bg-gray-800 dark:text-white"
        >
          <option value="">All decisions</option>
          <option value="executed">Executed</option>
          <option value="shadow">Shadow</option>
          <option value="blocked_kill_switch">Kill-switch blocked</option>
          <option value="cooldown_skip">Cooldown skip</option>
          <option value="rate_limited">Rate-limited</option>
          <option value="overridden">Overridden</option>
          <option value="error">Error</option>
        </select>
        <span className="text-sm text-gray-500">{data?.total ?? 0} entries</span>
      </div>

      {isLoading ? (
        <p className="py-8 text-center text-gray-500">Loading...</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="border-b bg-gray-50 text-gray-600 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-400">
              <tr>
                <th className="px-3 py-2">Time</th>
                <th className="px-3 py-2">Decision</th>
                <th className="px-3 py-2">Action</th>
                <th className="px-3 py-2">Severity</th>
                <th className="px-3 py-2">Level</th>
                <th className="px-3 py-2">Agent</th>
                <th className="px-3 py-2">Override</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
              {(data?.entries ?? []).map((e) => (
                <tr key={e.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                  <td className="px-3 py-2 text-xs text-gray-500">
                    {e.created_at ? new Date(e.created_at).toLocaleString() : "—"}
                  </td>
                  <td className="px-3 py-2">
                    <Badge label={e.decision} className={decisionColors[e.decision] ?? "bg-gray-100 text-gray-700"} />
                  </td>
                  <td className="px-3 py-2 text-gray-700 dark:text-gray-300">{e.action}</td>
                  <td className="px-3 py-2 text-gray-500">{e.alert_severity ?? "—"}</td>
                  <td className="px-3 py-2 text-gray-500">{e.escalation_level ?? "—"}</td>
                  <td className="px-3 py-2 text-xs text-gray-400 font-mono">{e.agent_id?.slice(0, 8) ?? "—"}</td>
                  <td className="px-3 py-2">
                    {e.decision === "executed" && !e.overridden_by ? (
                      overrideId === e.id ? (
                        <div className="flex items-center gap-1">
                          <input
                            value={overrideReason}
                            onChange={(ev) => setOverrideReason(ev.target.value)}
                            placeholder="Reason"
                            className="w-28 rounded border px-2 py-1 text-xs dark:border-gray-600 dark:bg-gray-700"
                            maxLength={500}
                          />
                          <button
                            onClick={() => {
                              if (overrideReason.trim()) {
                                override.mutate({ logId: e.id, reason: overrideReason })
                                setOverrideId(null)
                                setOverrideReason("")
                              }
                            }}
                            className="text-xs text-red-600 hover:underline"
                          >
                            Confirm
                          </button>
                        </div>
                      ) : (
                        <button
                          onClick={() => setOverrideId(e.id)}
                          className="text-xs text-indigo-600 hover:underline dark:text-indigo-400"
                        >
                          Override
                        </button>
                      )
                    ) : e.overridden_by ? (
                      <span className="text-xs text-purple-600">Overridden</span>
                    ) : (
                      <span className="text-xs text-gray-400">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      {(data?.total ?? 0) > limit && (
        <div className="flex justify-center gap-2 pt-2">
          <button
            onClick={() => setPage(Math.max(0, page - 1))}
            disabled={page === 0}
            className="rounded border px-3 py-1 text-sm disabled:opacity-50 dark:border-gray-600"
          >
            Prev
          </button>
          <span className="px-3 py-1 text-sm text-gray-500">
            Page {page + 1} of {Math.ceil((data?.total ?? 0) / limit)}
          </span>
          <button
            onClick={() => setPage(page + 1)}
            disabled={(page + 1) * limit >= (data?.total ?? 0)}
            className="rounded border px-3 py-1 text-sm disabled:opacity-50 dark:border-gray-600"
          >
            Next
          </button>
        </div>
      )}
    </div>
  )
}

// ── Escalation Tab ───────────────────────────────────────────────────────────

function EscalationTab() {
  const { data, isLoading } = useEscalationStates()
  const resetEscalation = useResetEscalation()

  if (isLoading) return <p className="py-8 text-center text-gray-500">Loading...</p>

  return (
    <div className="space-y-4">
      <div className="rounded border border-gray-200 bg-gray-50 px-4 py-3 text-xs text-gray-500 dark:border-gray-700 dark:bg-gray-800/50 dark:text-gray-400">
        <strong>Escalation Ladder</strong> — When the same agent repeatedly triggers alerts, responses
        automatically escalate: <strong>Level 1</strong> (warn) → <strong>Level 2</strong> (throttle/slow down) →
        <strong> Level 3</strong> (isolate agent) → <strong>Level 4</strong> (revoke all access).
        Resetting an agent returns them to Level 0. The escalation window controls how long offenses are remembered.
      </div>

      {data?.states?.length === 0 ? (
        <p className="py-8 text-center text-gray-400">No agents currently escalated.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="border-b bg-gray-50 text-gray-600 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-400">
              <tr>
                <th className="px-4 py-3">Agent ID</th>
                <th className="px-4 py-3">Level</th>
                <th className="px-4 py-3">Offenses</th>
                <th className="px-4 py-3">First Offense</th>
                <th className="px-4 py-3">Last Offense</th>
                <th className="px-4 py-3">Resets At</th>
                <th className="px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
              {(data?.states ?? []).map((s) => (
                <tr key={s.agent_id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                  <td className="px-4 py-3 font-mono text-xs text-gray-700 dark:text-gray-300">
                    {s.agent_id.slice(0, 12)}...
                  </td>
                  <td className="px-4 py-3">
                    <Badge
                      label={`Level ${s.current_level}`}
                      className={
                        s.current_level >= 4
                          ? "bg-red-100 text-red-800"
                          : s.current_level >= 3
                          ? "bg-orange-100 text-orange-800"
                          : s.current_level >= 2
                          ? "bg-yellow-100 text-yellow-800"
                          : "bg-gray-100 text-gray-700"
                      }
                    />
                  </td>
                  <td className="px-4 py-3 text-gray-500">{s.offense_count}</td>
                  <td className="px-4 py-3 text-xs text-gray-400">
                    {s.first_offense ? new Date(s.first_offense).toLocaleString() : "—"}
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-400">
                    {s.last_offense ? new Date(s.last_offense).toLocaleString() : "—"}
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-400">
                    {s.reset_at ? new Date(s.reset_at).toLocaleString() : "—"}
                  </td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => resetEscalation.mutate(s.agent_id)}
                      disabled={resetEscalation.isPending}
                      className="text-xs text-red-600 hover:underline dark:text-red-400"
                    >
                      Reset
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

export default AutoResponsePage
