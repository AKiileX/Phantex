// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — A2A Protocol Monitoring Page.
 *
 * Sections:
 *   1. KPI cards — total cards, verified %, active tasks, correlations
 *   2. Agent Card registry table (verify / revoke actions)
 *   3. Communication graph visualisation (node/edge list)
 *   4. Correlation findings table
 *   5. Inline protocol fingerprinter
 */

import { useState } from "react";
import { HelpCircle } from "lucide-react";
import {
  useA2ACards,
  useA2AStats,
  useA2ATasks,
  useCommGraph,
  useA2ACorrelations,
  useVerifyCard,
  useRevokeCard,
  useFingerprintMessage,
} from "@/api/a2a";
import type { AgentCard, FingerprintResult } from "@/api/a2a";

/* ── helpers ──────────────────────────────────────────────────────────────── */

const badge = (s: string) => {
  const map: Record<string, string> = {
    verified: "bg-emerald-900/60 text-emerald-300",
    unverified: "bg-yellow-900/50 text-yellow-300",
    revoked: "bg-red-900/50 text-red-300",
    high: "bg-red-900/50 text-red-300",
    medium: "bg-yellow-900/50 text-yellow-300",
    low: "bg-blue-900/50 text-blue-300",
  };
  return map[s] ?? "bg-zinc-800 text-zinc-300";
};

/* ── Page ─────────────────────────────────────────────────────────────────── */

export function A2AProtocolPage() {
  const { data: cards = [] } = useA2ACards();
  const { data: stats } = useA2AStats();
  const { data: tasks = [] } = useA2ATasks(undefined, 50);
  const { data: graph } = useCommGraph();
  const { data: correlations = [] } = useA2ACorrelations(undefined, 50);
  const verify = useVerifyCard();
  const revoke = useRevokeCard();
  const fingerprint = useFingerprintMessage();

  const [fpInput, setFpInput] = useState("");
  const [fpResult, setFpResult] = useState<FingerprintResult | null>(null);
  const [showGuide, setShowGuide] = useState(false);

  const verified = cards.filter((c: AgentCard) => c.status === "verified").length;
  const totalCards = cards.length;

  const handleFingerprint = () => {
    try {
      const parsed = JSON.parse(fpInput);
      fingerprint.mutate({ message: parsed }, {
        onSuccess: (r) => setFpResult(r),
      });
    } catch {
      /* ignore invalid JSON */
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">A2A Protocol Monitor</h1>
          <p className="text-sm text-zinc-400 mt-1">
            Agent-to-Agent delegation monitoring, card registry, and protocol conformance
          </p>
        </div>
        <button onClick={() => setShowGuide(!showGuide)} className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"><HelpCircle size={14} />{showGuide ? "Hide Guide" : "How does this work?"}</button>
      </div>

      {/* KPI cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <KPI label="Agent Cards" value={totalCards} />
        <KPI label="Verified" value={totalCards ? `${Math.round((verified / totalCards) * 100)}%` : "—"} />
        <KPI label="Active Tasks" value={stats?.tracker?.active_tasks ?? 0} />
        <KPI label="Recent A2A Tasks" value={stats?.correlator?.recent_a2a_tasks ?? 0} />
      </div>

      {/* Card registry */}
      <section className="bg-zinc-900 rounded-xl border border-zinc-800 overflow-hidden">
        <div className="px-5 py-3 border-b border-zinc-800 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-zinc-200">Agent Card Registry</h2>
          <span className="text-xs text-zinc-500">{totalCards} cards</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-zinc-800/50 text-zinc-400 text-xs uppercase">
              <tr>
                <th className="px-4 py-2 text-left">Name</th>
                <th className="px-4 py-2 text-left">URL</th>
                <th className="px-4 py-2 text-left">Capabilities</th>
                <th className="px-4 py-2 text-left">Status</th>
                <th className="px-4 py-2 text-left">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800">
              {cards.map((c: AgentCard) => (
                <tr key={c.card_id} className="hover:bg-zinc-800/30">
                  <td className="px-4 py-2 text-zinc-200 font-mono text-xs">{c.name}</td>
                  <td className="px-4 py-2 text-zinc-400 text-xs truncate max-w-[200px]">{c.url}</td>
                  <td className="px-4 py-2 text-zinc-400 text-xs">{c.capabilities.slice(0, 3).join(", ")}{c.capabilities.length > 3 && "…"}</td>
                  <td className="px-4 py-2">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${badge(c.status)}`}>{c.status}</span>
                  </td>
                  <td className="px-4 py-2 space-x-2">
                    {c.status !== "verified" && (
                      <button onClick={() => verify.mutate(c.card_id)} className="text-xs text-emerald-400 hover:underline">Verify</button>
                    )}
                    {c.status !== "revoked" && (
                      <button onClick={() => revoke.mutate(c.card_id)} className="text-xs text-red-400 hover:underline">Revoke</button>
                    )}
                  </td>
                </tr>
              ))}
              {cards.length === 0 && (
                <tr><td colSpan={5} className="px-4 py-8 text-center text-zinc-500">No agent cards registered</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* Communication graph (text representation) */}
      <section className="bg-zinc-900 rounded-xl border border-zinc-800 p-5">
        <h2 className="text-sm font-semibold text-zinc-200 mb-3">Communication Graph</h2>
        {graph && graph.nodes.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <h3 className="text-xs text-zinc-400 mb-2 uppercase">Nodes ({graph.nodes.length})</h3>
              <div className="space-y-1 max-h-48 overflow-y-auto">
                {graph.nodes.map(n => (
                  <div key={n.id} className="flex items-center justify-between text-xs bg-zinc-800/50 rounded px-3 py-1.5">
                    <span className="text-zinc-200 font-mono">{n.label}</span>
                    <span className="text-zinc-500">{n.task_count} tasks</span>
                  </div>
                ))}
              </div>
            </div>
            <div>
              <h3 className="text-xs text-zinc-400 mb-2 uppercase">Edges ({graph.edges.length})</h3>
              <div className="space-y-1 max-h-48 overflow-y-auto">
                {graph.edges.map((e: { source: string; target: string; weight: number }, i: number) => (
                  <div key={i} className="flex items-center justify-between text-xs bg-zinc-800/50 rounded px-3 py-1.5">
                    <span className="text-zinc-300">{e.source} → {e.target}</span>
                    <span className="text-zinc-500">×{e.weight}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        ) : (
          <p className="text-sm text-zinc-500">No communication data yet</p>
        )}
      </section>

      {/* Recent tasks */}
      <section className="bg-zinc-900 rounded-xl border border-zinc-800 overflow-hidden">
        <div className="px-5 py-3 border-b border-zinc-800">
          <h2 className="text-sm font-semibold text-zinc-200">Recent Delegation Tasks</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-zinc-800/50 text-zinc-400 text-xs uppercase">
              <tr>
                <th className="px-4 py-2 text-left">Task ID</th>
                <th className="px-4 py-2 text-left">Source → Target</th>
                <th className="px-4 py-2 text-left">Capability</th>
                <th className="px-4 py-2 text-left">Chain Depth</th>
                <th className="px-4 py-2 text-left">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800">
              {tasks.map((t: { task_id: string; source_agent: string; target_agent: string; capability: string; chain_depth: number; status: string }) => (
                <tr key={t.task_id} className="hover:bg-zinc-800/30">
                  <td className="px-4 py-2 text-zinc-400 font-mono text-xs">{t.task_id.slice(0, 12)}…</td>
                  <td className="px-4 py-2 text-zinc-300 text-xs">{t.source_agent} → {t.target_agent}</td>
                  <td className="px-4 py-2 text-zinc-400 text-xs">{t.capability}</td>
                  <td className="px-4 py-2 text-zinc-400 text-xs">{t.chain_depth}</td>
                  <td className="px-4 py-2">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                      t.status === "completed" ? "bg-emerald-900/60 text-emerald-300" :
                      t.status === "failed" ? "bg-red-900/50 text-red-300" :
                      "bg-blue-900/50 text-blue-300"
                    }`}>{t.status}</span>
                  </td>
                </tr>
              ))}
              {tasks.length === 0 && (
                <tr><td colSpan={5} className="px-4 py-8 text-center text-zinc-500">No tasks tracked</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* Correlations */}
      <section className="bg-zinc-900 rounded-xl border border-zinc-800 overflow-hidden">
        <div className="px-5 py-3 border-b border-zinc-800">
          <h2 className="text-sm font-semibold text-zinc-200">A2A ↔ MCP Correlations</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-zinc-800/50 text-zinc-400 text-xs uppercase">
              <tr>
                <th className="px-4 py-2 text-left">A2A Task</th>
                <th className="px-4 py-2 text-left">MCP Tool</th>
                <th className="px-4 py-2 text-left">Severity</th>
                <th className="px-4 py-2 text-left">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800">
              {correlations.map((c: { id: string; a2a_task_id: string; mcp_tool: string; severity: string; description: string }) => (
                <tr key={c.id} className="hover:bg-zinc-800/30">
                  <td className="px-4 py-2 text-zinc-400 font-mono text-xs">{c.a2a_task_id.slice(0, 12)}…</td>
                  <td className="px-4 py-2 text-zinc-300 text-xs font-mono">{c.mcp_tool}</td>
                  <td className="px-4 py-2">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${badge(c.severity)}`}>{c.severity}</span>
                  </td>
                  <td className="px-4 py-2 text-zinc-400 text-xs">{c.description}</td>
                </tr>
              ))}
              {correlations.length === 0 && (
                <tr><td colSpan={4} className="px-4 py-8 text-center text-zinc-500">No correlations found</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* Protocol Fingerprinter */}
      <section className="bg-zinc-900 rounded-xl border border-zinc-800 p-5">
        <h2 className="text-sm font-semibold text-zinc-200 mb-3">Protocol Fingerprinter</h2>
        <p className="text-xs text-zinc-500 mb-3">Paste an A2A message (JSON) to check protocol conformance</p>
        <textarea
          className="w-full h-32 bg-zinc-800 border border-zinc-700 rounded-lg p-3 text-xs font-mono text-zinc-200 focus:outline-none focus:ring-1 focus:ring-blue-500"
          placeholder='{"name": "agent-x", "url": "https://...", "capabilities": ["code_execution"]}'
          value={fpInput}
          onChange={(e) => setFpInput(e.target.value)}
        />
        <button
          onClick={handleFingerprint}
          disabled={!fpInput.trim() || fingerprint.isPending}
          className="mt-2 px-4 py-1.5 text-xs font-medium bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-white rounded-lg transition"
        >
          {fingerprint.isPending ? "Analysing…" : "Fingerprint"}
        </button>

        {fpResult && (
          <div className="mt-4 bg-zinc-800/50 rounded-lg p-4 space-y-2">
            <div className="flex items-center gap-3">
              <span className="text-xs text-zinc-400">Conformance</span>
              <span className={`text-sm font-bold ${fpResult.conformance_score >= 0.8 ? "text-emerald-400" : fpResult.conformance_score >= 0.6 ? "text-yellow-400" : "text-red-400"}`}>
                {(fpResult.conformance_score * 100).toFixed(0)}%
              </span>
              <span className="text-xs text-zinc-500">Type: {fpResult.message_type}</span>
              {fpResult.suspicious && <span className="px-2 py-0.5 rounded text-xs font-medium bg-red-900/50 text-red-300">SUSPICIOUS</span>}
            </div>
            {fpResult.deviations.length > 0 && (
              <div>
                <span className="text-xs text-red-400 font-medium">Deviations:</span>
                <ul className="text-xs text-zinc-400 list-disc ml-4 mt-1 space-y-0.5">
                  {fpResult.deviations.map((d, i) => <li key={i}>{d}</li>)}
                </ul>
              </div>
            )}
            {fpResult.warnings.length > 0 && (
              <div>
                <span className="text-xs text-yellow-400 font-medium">Warnings:</span>
                <ul className="text-xs text-zinc-400 list-disc ml-4 mt-1 space-y-0.5">
                  {fpResult.warnings.map((w, i) => <li key={i}>{w}</li>)}
                </ul>
              </div>
            )}
          </div>
        )}
      </section>

      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5 space-y-3 text-sm text-muted-foreground">
          <h3 className="text-base font-semibold text-foreground">How does the A2A Protocol Monitor work?</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Card Registry</p>
              <p>Fetches agent cards from <code className="text-xs bg-white/5 px-1 rounded">/api/a2a/cards</code>. Each card contains the agent's identity, capabilities, and delegation permissions. Cards can be verified or revoked via the registry actions.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Task Tracking</p>
              <p>Active delegations come from <code className="text-xs bg-white/5 px-1 rounded">/api/a2a/tasks</code>. Tracks task lifecycle: pending → running → completed/failed. The communication graph from <code className="text-xs bg-white/5 px-1 rounded">/api/a2a/comm-graph</code> visualizes agent-to-agent delegation flows.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Protocol Stats</p>
              <p>Overview KPIs from <code className="text-xs bg-white/5 px-1 rounded">/api/a2a/stats</code> show total cards, active tasks, completed delegations, and protocol conformance rate. Correlations from <code className="text-xs bg-white/5 px-1 rounded">/api/a2a/correlations</code> link delegations to security events.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Message Fingerprinting</p>
              <p>Test message integrity with the fingerprint tool. Enter any message payload and the system computes a cryptographic fingerprint via <code className="text-xs bg-white/5 px-1 rounded">/api/a2a/fingerprint</code> — verifying message authenticity across the delegation chain.</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ── Subcomponents ────────────────────────────────────────────────────────── */

function KPI({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
      <p className="text-xs text-zinc-500 uppercase tracking-wider">{label}</p>
      <p className="text-2xl font-bold text-white mt-1">{value}</p>
    </div>
  );
}
