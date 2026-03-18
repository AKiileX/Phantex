// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — GraphQL Explorer Page.
 *
 * Embedded GraphiQL-style explorer for the /graphql endpoint.
 * Sends queries with the user's auth token attached.
 */

import { useState, useCallback } from "react"
import {
  Play,
  Copy,
  Trash2,
  ChevronDown,
  Loader2,
  BookOpen,
  AlertTriangle,
  HelpCircle,
} from "lucide-react"
import { useAuthStore } from "@/stores/authStore"

const API_BASE = import.meta.env.VITE_API_BASE ?? ""
const GQL_ENDPOINT = `${API_BASE}/graphql`

/* ── Example queries ────────────────────────────────────── */
const EXAMPLES: { label: string; query: string; variables?: string }[] = [
  {
    label: "List Alerts",
    query: `query ListAlerts($limit: Int, $offset: Int) {
  alerts(limit: $limit, offset: $offset) {
    items {
      id
      title
      severity
      status
      createdAt
    }
    pageInfo {
      total
      limit
      offset
      hasNext
    }
  }
}`,
    variables: '{ "limit": 10, "offset": 0 }',
  },
  {
    label: "List Agents",
    query: `query ListAgents($limit: Int) {
  agents(limit: $limit) {
    items {
      id
      paid
      name
      framework
      status
      lastSeen
    }
    pageInfo {
      total
      hasNext
    }
  }
}`,
    variables: '{ "limit": 20 }',
  },
  {
    label: "Trust Score",
    query: `query TrustScore($entityId: String!, $entityType: String) {
  trustScore(entityId: $entityId, entityType: $entityType) {
    entityId
    entityType
    trustScore
    factors {
      name
      weight
      value
    }
  }
}`,
    variables: '{ "entityId": "agent-001", "entityType": "agent" }',
  },
  {
    label: "Recent Events",
    query: `query RecentEvents($limit: Int) {
  events(limit: $limit) {
    items {
      id
      eventType
      severity
      agentId
      timestamp
    }
    pageInfo {
      total
      hasNext
    }
  }
}`,
    variables: '{ "limit": 10 }',
  },
  {
    label: "Detection Rules",
    query: `query Rules {
  rules {
    items {
      id
      name
      severity
      enabled
      attackClass
      version
      author
      createdAt
    }
    pageInfo {
      total
      hasNext
    }
  }
}`,
  },
]

/* ── Main page ──────────────────────────────────────────── */
export function GraphQLExplorerPage() {
  const token = useAuthStore((s) => s.token)

  const [query, setQuery] = useState(EXAMPLES[0].query)
  const [variables, setVariables] = useState(EXAMPLES[0].variables ?? "{}")
  const [result, setResult] = useState<string>("")
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [statusCode, setStatusCode] = useState<number | null>(null)
  const [elapsed, setElapsed] = useState<number | null>(null)
  const [showVars, setShowVars] = useState(true)
  const [showExamples, setShowExamples] = useState(false)
  const [showGuide, setShowGuide] = useState(false)

  const executeQuery = useCallback(async () => {
    setLoading(true)
    setError(null)
    setStatusCode(null)
    setElapsed(null)

    let parsedVars: Record<string, unknown> = {}
    try {
      const trimmed = variables.trim()
      if (trimmed && trimmed !== "{}") {
        parsedVars = JSON.parse(trimmed)
      }
    } catch {
      setError("Invalid JSON in variables")
      setLoading(false)
      return
    }

    const start = performance.now()
    try {
      const resp = await fetch(GQL_ENDPOINT, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ query, variables: parsedVars }),
      })
      const ms = performance.now() - start
      setElapsed(Math.round(ms))
      setStatusCode(resp.status)

      const body = await resp.json()
      setResult(JSON.stringify(body, null, 2))
      if (body.errors) {
        setError(`GraphQL Error: ${body.errors[0]?.message ?? "Unknown"}`)
      }
    } catch (err) {
      setElapsed(Math.round(performance.now() - start))
      setError(err instanceof Error ? err.message : "Request failed")
      setResult("")
    } finally {
      setLoading(false)
    }
  }, [query, variables, token])

  const copyResult = useCallback(() => {
    navigator.clipboard.writeText(result)
  }, [result])

  const selectExample = useCallback(
    (idx: number) => {
      const ex = EXAMPLES[idx]
      setQuery(ex.query)
      setVariables(ex.variables ?? "{}")
      setResult("")
      setError(null)
      setStatusCode(null)
      setShowExamples(false)
    },
    [],
  )

  return (
    <div className="flex h-[calc(100vh-64px)] flex-col gap-4 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-zinc-100 flex items-center gap-2">
            <BookOpen size={24} />
            GraphQL Explorer
          </h1>
          <p className="mt-1 text-sm text-zinc-400">
            Query the Phantex GraphQL API — alerts, agents, events, rules, trust scores
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => setShowGuide(!showGuide)} className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"><HelpCircle size={14} />{showGuide ? "Hide Guide" : "How does this work?"}</button>
          {/* Example selector */}
          <div className="relative">
            <button
              onClick={() => setShowExamples(!showExamples)}
              className="inline-flex items-center gap-1.5 rounded-md border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-xs font-medium text-zinc-300 hover:bg-zinc-700"
            >
              Examples <ChevronDown size={12} />
            </button>
            {showExamples && (
              <div className="absolute right-0 top-full mt-1 z-50 rounded-lg border border-zinc-700 bg-zinc-800 py-1 shadow-xl min-w-[200px]">
                {EXAMPLES.map((ex, i) => (
                  <button
                    key={ex.label}
                    onClick={() => selectExample(i)}
                    className="block w-full px-3 py-1.5 text-left text-xs text-zinc-300 hover:bg-zinc-700"
                  >
                    {ex.label}
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Execute button */}
          <button
            onClick={executeQuery}
            disabled={loading || !query.trim()}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-4 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {loading ? <Loader2 size={12} className="animate-spin" /> : <Play size={12} />}
            Execute
          </button>
        </div>
      </div>

      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5 space-y-3 text-sm text-muted-foreground">
          <h3 className="text-base font-semibold text-foreground">How does the GraphQL Explorer work?</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Query Endpoint</p>
              <p>Sends queries to <code className="text-xs bg-white/5 px-1 rounded">/graphql</code> authenticated with your JWT bearer token. Supports queries for alerts, agents, events, rules, trust scores, and compliance data — the full PhanTeX schema.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Examples</p>
              <p>Pre-built example queries cover common use cases: listing alerts, agent details, event search, rule configuration, and trust graph queries. Select an example to populate the editor, then customize as needed.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Variables</p>
              <p>Pass query variables as JSON in the variables panel. Variables are sent alongside the query payload. The editor supports standard GraphQL variable syntax ($varName: Type).</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Response</p>
              <p>Results display formatted JSON with status code and elapsed time. Copy results to clipboard. GraphQL errors are highlighted separately with the specific error message from the server.</p>
            </div>
          </div>
        </div>
      )}

      {/* Editor + Result panes */}
      <div className="flex flex-1 gap-4 min-h-0">
        {/* Left: query editor */}
        <div className="flex flex-1 flex-col gap-2 min-w-0">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-zinc-400">Query</span>
            <button
              onClick={() => { setQuery(""); setVariables("{}"); setResult(""); setError(null) }}
              className="text-zinc-500 hover:text-zinc-300"
              title="Clear"
            >
              <Trash2 size={12} />
            </button>
          </div>
          <textarea
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            spellCheck={false}
            className="flex-1 min-h-[200px] resize-none rounded-lg border border-zinc-700 bg-zinc-900 p-3 font-mono text-xs text-zinc-200 placeholder:text-zinc-600 focus:border-primary/50 focus:outline-none focus:ring-1 focus:ring-primary/30"
            placeholder="Enter your GraphQL query..."
          />

          {/* Variables */}
          <button
            onClick={() => setShowVars(!showVars)}
            className="flex items-center gap-1 text-xs text-zinc-400 hover:text-zinc-300"
          >
            <ChevronDown
              size={12}
              className={`transition-transform ${showVars ? "rotate-0" : "-rotate-90"}`}
            />
            Variables
          </button>
          {showVars && (
            <textarea
              value={variables}
              onChange={(e) => setVariables(e.target.value)}
              spellCheck={false}
              rows={4}
              className="resize-none rounded-lg border border-zinc-700 bg-zinc-900 p-3 font-mono text-xs text-zinc-200 placeholder:text-zinc-600 focus:border-primary/50 focus:outline-none focus:ring-1 focus:ring-primary/30"
              placeholder='{ "key": "value" }'
            />
          )}
        </div>

        {/* Right: result viewer */}
        <div className="flex flex-1 flex-col gap-2 min-w-0">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <span className="text-xs font-medium text-zinc-400">Result</span>
              {statusCode !== null && (
                <span
                  className={`rounded px-1.5 py-0.5 text-[10px] font-mono font-medium ${
                    statusCode === 200
                      ? "bg-emerald-500/20 text-emerald-400"
                      : "bg-red-500/20 text-red-400"
                  }`}
                >
                  {statusCode}
                </span>
              )}
              {elapsed !== null && (
                <span className="text-[10px] text-zinc-500">{elapsed} ms</span>
              )}
            </div>
            {result && (
              <button
                onClick={copyResult}
                className="text-zinc-500 hover:text-zinc-300"
                title="Copy to clipboard"
              >
                <Copy size={12} />
              </button>
            )}
          </div>

          {error && (
            <div className="flex items-center gap-2 rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-300">
              <AlertTriangle size={12} />
              {error}
            </div>
          )}

          <pre className="flex-1 min-h-[200px] overflow-auto rounded-lg border border-zinc-700 bg-zinc-900 p-3 font-mono text-xs text-zinc-300 whitespace-pre">
            {result || (loading ? "Executing..." : "Click Execute to run the query")}
          </pre>
        </div>
      </div>

      {/* Footer info */}
      <div className="flex items-center justify-between border-t border-zinc-800 pt-3 text-[10px] text-zinc-500">
        <span>
          Endpoint: <code className="text-zinc-400">{GQL_ENDPOINT}</code> · Authenticated
          via JWT Bearer token
        </span>
        <span>
          Introspection disabled in production · Use examples above for available queries
        </span>
      </div>
    </div>
  )
}

export default GraphQLExplorerPage
