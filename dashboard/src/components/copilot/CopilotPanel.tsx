// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Copilot AI Panel (Block U5 + AB4).
 *
 * Sliding right panel with:
 *   - Streaming chat via WebSocket (falls back to REST)
 *   - Five modes: Chat (investigation), Triage, Rule Generation, Briefing, Playbooks
 *   - Multi-turn session memory with create/resume/delete
 *   - Context-aware: reads current page/alert/agent from URL
 *   - Quick-action buttons on alert/agent context
 *   - Markdown rendering for responses
 *   - PRL code highlighting
 *   - Admin + Analyst only (via permission store)
 *   - Ctrl+K global shortcut to toggle
 *   - Keyboard: Enter to send, Shift+Enter for newline
 *
 * @module components/copilot/CopilotPanel
 */

import { useCallback, useEffect, useRef, useState } from "react"
import { useLocation } from "react-router-dom"
import {
  X,
  Send,
  Bot,
  User,
  Sparkles,
  AlertTriangle,
  FileCode,
  Loader2,
  Copy,
  Check,
  Zap,
  Shield,
  MessageSquare,
  Newspaper,
  BookOpen,
  Plus,
  Trash2,
  History,
  ChevronRight,
} from "lucide-react"
import { cn } from "@/lib/utils"
import { usePermissionStore } from "@/stores/permissionStore"
import { closeCopilot, toggleCopilot, subscribePanelState, getPanelOpen } from "./copilotState"
import {
  useCopilotChat,
  useCopilotHealth,
  useCopilotTriage,
  useCopilotSuggestRule,
  useCopilotBriefing,
  useCopilotPlaybooks,
  useCopilotPlaybook,
  useCopilotSessions,
  useCopilotCreateSession,
  useCopilotDeleteSession,
  type CopilotMessage,
  type TriageResult,
  type RuleSuggestion,
  type PlaybookSummary,
} from "@/api/copilot"

/* ── Types ─────────────────────────────────────────────────────────────────── */

type CopilotMode = "chat" | "triage" | "rules" | "briefing" | "playbooks"

interface ChatEntry {
  id: string
  role: "user" | "assistant" | "system"
  content: string
  timestamp: number
  toolCalls?: string[]
  usage?: Record<string, unknown>
  isStreaming?: boolean
}

/* ── Zustand-like store for panel open state ───────────────────────────────── */

function usePanelOpen() {
  const [open, setOpen] = useState(getPanelOpen())
  useEffect(() => {
    return subscribePanelState(setOpen)
  }, [])
  return open
}

/* ── Utility helpers ───────────────────────────────────────────────────────── */

let _entryId = 0
function nextId() {
  return `copilot-${++_entryId}`
}

/** Extract context from current URL for copilot awareness. */
function usePageContext(): Record<string, unknown> {
  const loc = useLocation()
  const path = loc.pathname
  const ctx: Record<string, unknown> = { page: path }

  // /alerts/:id → alert context
  const alertMatch = path.match(/^\/alerts\/([a-f0-9-]+)$/i)
  if (alertMatch) ctx.alert_id = alertMatch[1]

  // /agents/:id → agent context
  const agentMatch = path.match(/^\/agents\/([a-f0-9-]+)$/i)
  if (agentMatch) ctx.agent_id = agentMatch[1]

  // /investigate/:type/:id
  const investMatch = path.match(/^\/investigate\/(\w+)\/([a-f0-9-]+)$/i)
  if (investMatch) {
    ctx.investigation_type = investMatch[1]
    ctx.investigation_id = investMatch[2]
  }

  return ctx
}

/** Simple markdown-ish renderer: code blocks, bold, inline code. */
function renderMarkdown(text: string): React.ReactNode[] {
  const nodes: React.ReactNode[] = []
  const lines = text.split("\n")
  let inCodeBlock = false
  let codeBuffer: string[] = []
  let codeLang = ""
  let blockIdx = 0

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]

    if (line.startsWith("```")) {
      if (inCodeBlock) {
        // End code block
        nodes.push(
          <CodeBlock key={`cb-${blockIdx++}`} code={codeBuffer.join("\n")} lang={codeLang} />,
        )
        codeBuffer = []
        codeLang = ""
        inCodeBlock = false
      } else {
        inCodeBlock = true
        codeLang = line.slice(3).trim()
      }
      continue
    }

    if (inCodeBlock) {
      codeBuffer.push(line)
      continue
    }

    // Inline formatting
    nodes.push(
      <span key={`l-${i}`} className="block">
        {formatInline(line)}
      </span>,
    )
  }

  if (inCodeBlock && codeBuffer.length) {
    nodes.push(
      <CodeBlock key={`cb-${blockIdx}`} code={codeBuffer.join("\n")} lang={codeLang} />,
    )
  }

  return nodes
}

/** Bold + inline code formatter. */
function formatInline(text: string): React.ReactNode[] {
  const parts: React.ReactNode[] = []
  // Split by `code` and **bold**
  const regex = /(`[^`]+`|\*\*[^*]+\*\*)/g
  let last = 0
  let match: RegExpExecArray | null

  while ((match = regex.exec(text)) !== null) {
    if (match.index > last) {
      parts.push(text.slice(last, match.index))
    }
    const seg = match[0]
    if (seg.startsWith("`")) {
      parts.push(
        <code key={match.index} className="rounded bg-white/10 px-1 py-0.5 font-mono text-xs text-emerald-300">
          {seg.slice(1, -1)}
        </code>,
      )
    } else {
      parts.push(
        <strong key={match.index} className="font-semibold text-foreground">
          {seg.slice(2, -2)}
        </strong>,
      )
    }
    last = match.index + seg.length
  }

  if (last < text.length) {
    parts.push(text.slice(last))
  }

  return parts.length ? parts : [text]
}

/* ── Code Block sub-component ──────────────────────────────────────────────── */

function CodeBlock({ code, lang }: { code: string; lang: string }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = () => {
    navigator.clipboard.writeText(code)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="group relative my-2 rounded-lg border border-white/10 bg-black/40">
      <div className="flex items-center justify-between border-b border-white/10 px-3 py-1.5">
        <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
          {lang || "text"}
        </span>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] text-muted-foreground hover:bg-white/10 hover:text-foreground transition-colors"
        >
          {copied ? <Check size={10} /> : <Copy size={10} />}
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className="overflow-x-auto p-3 text-xs leading-relaxed">
        <code className={cn("font-mono", lang === "prl" && "text-emerald-300")}>
          {code}
        </code>
      </pre>
    </div>
  )
}

/* ── Triage results renderer ───────────────────────────────────────────────── */

function TriageResults({ results }: { results: TriageResult[] }) {
  const classColors: Record<string, string> = {
    true_positive: "text-red-400 bg-red-500/10 border-red-500/30",
    false_positive: "text-emerald-400 bg-emerald-500/10 border-emerald-500/30",
    needs_investigation: "text-amber-400 bg-amber-500/10 border-amber-500/30",
  }

  return (
    <div className="space-y-2">
      {results.map((r) => (
        <div key={r.alert_id} className="rounded-lg border border-white/10 bg-white/[0.02] p-3">
          <div className="flex items-center justify-between">
            <code className="text-xs text-muted-foreground">{r.alert_id.slice(0, 8)}…</code>
            <span className={cn("rounded-full border px-2 py-0.5 text-[10px] font-medium", classColors[r.classification])}>
              {r.classification.replace("_", " ")}
            </span>
          </div>
          <p className="mt-1 text-xs text-foreground/80">{r.reasoning}</p>
          <div className="mt-1 flex items-center gap-2 text-[10px] text-muted-foreground">
            <span>Confidence: {(r.confidence * 100).toFixed(0)}%</span>
            <span>Priority: {r.priority}</span>
          </div>
          {r.suggested_action && (
            <p className="mt-1 text-xs text-blue-300/80">→ {r.suggested_action}</p>
          )}
        </div>
      ))}
    </div>
  )
}

/* ── Rule suggestion renderer ──────────────────────────────────────────────── */

function RuleResult({ rule }: { rule: RuleSuggestion }) {
  // No rule generated — show guidance or scope error
  if (!rule.rule_text && rule.validation_errors.length > 0) {
    // Detect out-of-scope refusal (mentions SIEM, agent behavior, etc.)
    const isOutOfScope = rule.validation_errors.some(
      (e) => e.includes("SIEM") || e.includes("CANNOT_DETECT") || e.includes("monitors AI agent"),
    )

    return (
      <div className="space-y-2">
        <div className="flex items-center gap-2">
          <span className={cn("text-xs font-medium", isOutOfScope ? "text-blue-400" : "text-amber-400")}>
            {isOutOfScope ? "Outside Phantex Scope" : "Need more detail"}
          </span>
        </div>
        {rule.validation_errors.map((e, i) => (
          <p key={i} className="text-xs text-muted-foreground">{e}</p>
        ))}
        {isOutOfScope ? (
          <div className="mt-1 space-y-1">
            <p className="text-xs text-muted-foreground/80">Phantex monitors AI agent behavior. Try rules like:</p>
            <ul className="list-disc list-inside text-xs text-muted-foreground/60 space-y-0.5">
              <li>"Alert when an agent spawns a reverse shell"</li>
              <li>"Detect prompt injection in MCP tool calls"</li>
              <li>"Flag 10+ file reads in 30 seconds from low-trust agent"</li>
            </ul>
          </div>
        ) : (
          <div className="mt-1 space-y-1">
            <p className="text-xs text-muted-foreground mt-1">Try describing a specific threat pattern, e.g.:</p>
            <ul className="list-disc list-inside text-xs text-muted-foreground/80 space-y-0.5">
              <li>"Alert when curl or wget runs on a low-trust agent"</li>
              <li>"Detect data exfiltration over DNS with large payloads"</li>
              <li>"Flag MCP tool calls from unknown servers"</li>
            </ul>
          </div>
        )}
      </div>
    )
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <span className="text-xs font-medium text-foreground">{rule.name}</span>
        <span className={cn(
          "rounded-full border px-2 py-0.5 text-[10px] font-medium",
          rule.is_valid
            ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/30"
            : "text-red-400 bg-red-500/10 border-red-500/30",
        )}>
          {rule.is_valid ? "Valid PRL" : "Invalid"}
        </span>
        <span className="text-[10px] text-muted-foreground">
          {(rule.confidence * 100).toFixed(0)}% confidence
        </span>
      </div>
      <CodeBlock code={rule.rule_text} lang="prl" />
      {rule.validation_errors.length > 0 && (
        <div className="text-xs text-red-400">
          {rule.validation_errors.map((e, i) => (
            <p key={i}>⚠ {e}</p>
          ))}
        </div>
      )}
    </div>
  )
}

/* ── Main CopilotPanel ─────────────────────────────────────────────────────── */

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

export function CopilotPanel() {
  const open = usePanelOpen()
  const [mode, setMode] = useState<CopilotMode>("chat")
  const [allEntries, setAllEntries] = useState<Record<CopilotMode, ChatEntry[]>>({
    chat: [],
    triage: [],
    rules: [],
    briefing: [],
    playbooks: [],
  })
  // Per-mode accessors
  const entries = allEntries[mode]
  const setEntries: React.Dispatch<React.SetStateAction<ChatEntry[]>> = useCallback(
    (action) => {
      setAllEntries((prev) => ({
        ...prev,
        [mode]: typeof action === "function" ? action(prev[mode]) : action,
      }))
    },
    [mode],
  )
  const [input, setInput] = useState("")
  const [triageIds, setTriageIds] = useState("")
  const [ruleDesc, setRuleDesc] = useState("")
  const [sessionId, setSessionId] = useState<string | null>(null)
  const [showSessions, setShowSessions] = useState(false)
  const [selectedPlaybook, setSelectedPlaybook] = useState<string | null>(null)
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLTextAreaElement>(null)
  const pageContext = usePageContext()

  // API hooks
  const chatMutation = useCopilotChat()
  const triageMutation = useCopilotTriage()
  const ruleGenMutation = useCopilotSuggestRule()
  const briefingMutation = useCopilotBriefing()
  const { data: health } = useCopilotHealth(open)
  const { data: playbooksData } = useCopilotPlaybooks(open && mode === "playbooks")
  const { data: playbookDetail } = useCopilotPlaybook(selectedPlaybook ?? "", open && mode === "playbooks" && !!selectedPlaybook)
  const { data: sessionsData } = useCopilotSessions(open && showSessions)
  const createSessionMut = useCopilotCreateSession()
  const deleteSessionMut = useCopilotDeleteSession()

  // Permission check — copilot.use
  const perms = usePermissionStore((s) => s.permissions)
  const canUse = perms.has("copilot.use") || perms.has("*")

  // Global Ctrl+K shortcut
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "k") {
        e.preventDefault()
        toggleCopilot()
      }
      if (e.key === "Escape" && getPanelOpen()) {
        closeCopilot()
      }
    }
    window.addEventListener("keydown", handler)
    return () => window.removeEventListener("keydown", handler)
  }, [])

  // Auto-scroll
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" })
  }, [entries])

  // Focus input when opened
  useEffect(() => {
    if (open) {
      setTimeout(() => inputRef.current?.focus(), 300)
    }
  }, [open])

  // Build conversation history for API
  const buildHistory = useCallback((): CopilotMessage[] => {
    return entries
      .filter((e) => e.role === "user" || e.role === "assistant")
      .slice(-20)
      .map((e) => ({ role: e.role, content: e.content }))
  }, [entries])

  /* ── Send chat message ──────────────────────────────────────────── */
  const sendChat = useCallback(async () => {
    const msg = input.trim()
    if (!msg) return

    const userEntry: ChatEntry = {
      id: nextId(),
      role: "user",
      content: msg,
      timestamp: Date.now(),
    }
    setEntries((prev) => [...prev, userEntry])
    setInput("")

    const assistantId = nextId()
    setEntries((prev) => [
      ...prev,
      { id: assistantId, role: "assistant", content: "", timestamp: Date.now(), isStreaming: true },
    ])

    try {
      const res = await chatMutation.mutateAsync({
        message: msg,
        history: buildHistory(),
        context: pageContext,
        session_id: sessionId ?? undefined,
      })
      setEntries((prev) =>
        prev.map((e) =>
          e.id === assistantId
            ? {
                ...e,
                content: res.response,
                toolCalls: res.tool_calls,
                usage: res.usage,
                isStreaming: false,
              }
            : e,
        ),
      )
    } catch (err) {
      setEntries((prev) =>
        prev.map((e) =>
          e.id === assistantId
            ? {
                ...e,
                content: `⚠ Error: ${err instanceof Error ? err.message : "Request failed"}`,
                isStreaming: false,
              }
            : e,
        ),
      )
    }
  }, [input, buildHistory, pageContext, chatMutation, setEntries, sessionId])

  /* ── Keyboard handling ─────────────────────────────────────────── */
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault()
      if (mode === "chat") sendChat()
      else if (mode === "triage") runTriage()
      else if (mode === "rules") generateRule()
    }
  }

  /* ── Triage ────────────────────────────────────────────────────── */
  const runTriage = useCallback(async () => {
    const ids = triageIds
      .split(/[\n,]+/)
      .map((s) => s.trim())
      .filter(Boolean)
    if (!ids.length) return

    // Validate UUID format before sending
    const validIds = ids.filter((id) => UUID_RE.test(id))
    const invalidIds = ids.filter((id) => !UUID_RE.test(id))

    if (!validIds.length) {
      setEntries((prev) => [
        ...prev,
        {
          id: nextId(), role: "user", content: `Triage ${ids.length} alert(s)`, timestamp: Date.now(),
        },
        {
          id: nextId(), role: "assistant", timestamp: Date.now(),
          content: `⚠ No valid alert IDs found. Paste UUIDs from the alerts table (e.g. \`550e8400-e29b-41d4-a716-446655440000\`).${invalidIds.length ? `\n\nInvalid inputs: ${invalidIds.slice(0, 5).map((s) => `"${s.slice(0, 40)}"`).join(", ")}` : ""}`,
        },
      ])
      return
    }

    setEntries((prev) => [
      ...prev,
      { id: nextId(), role: "user", content: `Triage ${validIds.length} alert(s)${invalidIds.length ? ` (${invalidIds.length} invalid ID${invalidIds.length > 1 ? "s" : ""} skipped)` : ""}`, timestamp: Date.now() },
    ])

    const loadingId = nextId()
    setEntries((prev) => [
      ...prev,
      { id: loadingId, role: "assistant", content: "Analyzing alerts…", timestamp: Date.now(), isStreaming: true },
    ])

    try {
      const res = await triageMutation.mutateAsync({ alert_ids: validIds })
      setEntries((prev) =>
        prev.map((e) =>
          e.id === loadingId
            ? {
                ...e,
                content: "__triage__",
                isStreaming: false,
                usage: { _triageResults: res.results },
              }
            : e,
        ),
      )
      setTriageIds("")
    } catch (err) {
      setEntries((prev) =>
        prev.map((e) =>
          e.id === loadingId
            ? {
                ...e,
                content: `⚠ Triage failed: ${err instanceof Error ? err.message : "Unknown error"}`,
                isStreaming: false,
              }
            : e,
        ),
      )
    }
  }, [triageIds, triageMutation, setEntries])

  /* ── Rule generation ───────────────────────────────────────────── */
  const generateRule = useCallback(async () => {
    const desc = ruleDesc.trim()
    if (!desc) return

    setEntries((prev) => [
      ...prev,
      { id: nextId(), role: "user", content: `Generate rule: ${desc}`, timestamp: Date.now() },
    ])

    const loadingId = nextId()
    setEntries((prev) => [
      ...prev,
      { id: loadingId, role: "assistant", content: "Generating PRL rule…", timestamp: Date.now(), isStreaming: true },
    ])

    try {
      const res = await ruleGenMutation.mutateAsync({ description: desc })
      setEntries((prev) =>
        prev.map((e) =>
          e.id === loadingId
            ? {
                ...e,
                content: "__rule__",
                isStreaming: false,
                usage: { _ruleSuggestion: res },
              }
            : e,
        ),
      )
      setRuleDesc("")
    } catch (err) {
      setEntries((prev) =>
        prev.map((e) =>
          e.id === loadingId
            ? {
                ...e,
                content: `⚠ Rule generation failed: ${err instanceof Error ? err.message : "Unknown error"}`,
                isStreaming: false,
              }
            : e,
        ),
      )
    }
  }, [ruleDesc, ruleGenMutation, setEntries])

  /* ── Generate briefing ─────────────────────────────────────────── */
  const generateBriefing = useCallback(async () => {
    setEntries((prev) => [
      ...prev,
      { id: nextId(), role: "user", content: "Generate threat briefing", timestamp: Date.now() },
    ])
    const loadingId = nextId()
    setEntries((prev) => [
      ...prev,
      { id: loadingId, role: "assistant", content: "Compiling threat briefing…", timestamp: Date.now(), isStreaming: true },
    ])

    try {
      const res = await briefingMutation.mutateAsync({ hours: 24, use_llm: true })
      setEntries((prev) =>
        prev.map((e) =>
          e.id === loadingId
            ? { ...e, content: res.briefing, isStreaming: false, usage: res.usage }
            : e,
        ),
      )
    } catch (err) {
      setEntries((prev) =>
        prev.map((e) =>
          e.id === loadingId
            ? { ...e, content: `⚠ Briefing failed: ${err instanceof Error ? err.message : "Unknown error"}`, isStreaming: false }
            : e,
        ),
      )
    }
  }, [briefingMutation, setEntries])

  /* ── Session management ────────────────────────────────────────── */
  const handleNewSession = useCallback(async () => {
    try {
      const s = await createSessionMut.mutateAsync({ title: "Investigation" })
      setSessionId(s.session_id)
      setAllEntries((prev) => ({ ...prev, chat: [] }))
      setShowSessions(false)
    } catch {
      // ignore
    }
  }, [createSessionMut])

  const handleDeleteSession = useCallback(async (sid: string) => {
    try {
      await deleteSessionMut.mutateAsync(sid)
      if (sessionId === sid) {
        setSessionId(null)
        setAllEntries((prev) => ({ ...prev, chat: [] }))
      }
    } catch {
      // ignore
    }
  }, [deleteSessionMut, sessionId])

  /* ── Quick actions from context ────────────────────────────────── */
  const quickInvestigate = useCallback(() => {
    setMode("chat")
    const alertId = pageContext.alert_id as string | undefined
    const agentId = pageContext.agent_id as string | undefined
    const msg = alertId
      ? `Investigate alert ${alertId}`
      : agentId
        ? `Investigate agent ${agentId}`
        : ""
    if (msg) {
      setInput(msg)
      setTimeout(() => inputRef.current?.focus(), 50)
    }
  }, [pageContext])

  /* ── Clear conversation (current mode only) ────────────────────── */
  const clearConversation = () => {
    setEntries([])
    if (mode === "chat") setInput("")
    else if (mode === "triage") setTriageIds("")
    else if (mode === "rules") setRuleDesc("")
    else if (mode === "playbooks") setSelectedPlaybook(null)
  }

  // Don't render if no permission
  if (!canUse) return null

  return (
    <>
      {/* Backdrop */}
      {open && (
        <div
          className="fixed inset-0 z-50 bg-black/40 backdrop-blur-sm transition-opacity"
          onClick={closeCopilot}
        />
      )}

      {/* Panel */}
      <div
        className={cn(
          "fixed right-0 top-0 z-50 flex h-screen w-[520px] flex-col border-l border-white/10 bg-[#0a0a0e]/95 backdrop-blur-xl shadow-2xl transition-transform duration-300 ease-[cubic-bezier(0.16,1,0.3,1)]",
          open ? "translate-x-0" : "translate-x-full",
        )}
      >
        {/* ── Header ──────────────────────────────────────────────── */}
        <div className="flex items-center justify-between border-b border-white/10 px-4 py-3">
          <div className="flex items-center gap-2">
            <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-gradient-to-br from-emerald-500/20 to-cyan-500/20 border border-emerald-500/30">
              <Sparkles size={14} className="text-emerald-400" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-foreground">Phantex Copilot</h3>
              <span className="text-[10px] text-muted-foreground">
                {health?.provider ?? "connecting"} · {health?.model ?? "…"}
              </span>
            </div>
          </div>
          <div className="flex items-center gap-1">
            {/* Status dot */}
            <div
              className={cn(
                "h-1.5 w-1.5 rounded-full",
                health?.copilot_status === "healthy"
                  ? "bg-emerald-400 shadow-[0_0_6px_rgb(52,211,153)]"
                  : "bg-amber-400",
              )}
            />
            <button
              onClick={closeCopilot}
              className="flex h-7 w-7 items-center justify-center rounded-md text-muted-foreground hover:bg-white/10 hover:text-foreground transition-colors"
              title="Close (Esc)"
            >
              <X size={14} />
            </button>
          </div>
        </div>

        {/* ── Mode Tabs ───────────────────────────────────────────── */}
        <div className="flex border-b border-white/10 px-1 gap-0.5">
          {([
            { key: "chat" as const, label: "Investigate", icon: MessageSquare },
            { key: "briefing" as const, label: "Briefing", icon: Newspaper },
            { key: "playbooks" as const, label: "Playbooks", icon: BookOpen },
            { key: "triage" as const, label: "Triage", icon: AlertTriangle },
            { key: "rules" as const, label: "Rules", icon: FileCode },
          ]).map((tab) => (
            <button
              key={tab.key}
              onClick={() => setMode(tab.key)}
              className={cn(
                "flex flex-1 items-center justify-center gap-1.5 py-2.5 text-[11px] font-medium transition-colors border-b-2 min-w-0",
                mode === tab.key
                  ? "border-emerald-500 text-emerald-400"
                  : "border-transparent text-muted-foreground hover:text-foreground hover:bg-white/[0.03]",
              )}
              title={tab.label}
            >
              <tab.icon size={14} className="shrink-0" />
              <span className="truncate">{tab.label}</span>
            </button>
          ))}
        </div>

        {/* ── Messages area ───────────────────────────────────────── */}
        <div className="flex-1 overflow-y-auto px-4 py-3 space-y-3 scrollbar-thin scrollbar-thumb-white/10">
          {entries.length === 0 && mode !== "playbooks" && (
            <div className="flex flex-col items-center justify-center h-full text-center">
              <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-gradient-to-br from-emerald-500/10 to-cyan-500/10 border border-emerald-500/20">
                <Bot size={28} className="text-emerald-400/60" />
              </div>
              <h4 className="mt-4 text-sm font-medium text-foreground">
                {mode === "chat"
                  ? "How can I help investigate?"
                  : mode === "triage"
                    ? "Paste alert IDs to triage"
                    : mode === "briefing"
                      ? "Threat Briefing"
                      : "Describe what to detect"}
              </h4>
              <p className="mt-1 max-w-[260px] text-xs text-muted-foreground">
                {mode === "chat"
                  ? "Ask about alerts, events, agents, or trust scores. I'll query your data in real time."
                  : mode === "triage"
                    ? "I'll classify each alert as TP, FP, or needs investigation with confidence scores."
                    : mode === "briefing"
                      ? "Generate an executive summary of threats, trends, and anomalies from the last 24 hours."
                      : "Describe a threat pattern in plain English and I'll generate a PRL detection rule."}
              </p>
              {mode === "briefing" && (
                <button
                  onClick={generateBriefing}
                  disabled={briefingMutation.isPending}
                  className="mt-4 flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-2 text-xs font-medium text-emerald-400 hover:bg-emerald-500/20 disabled:opacity-40 transition-colors"
                >
                  {briefingMutation.isPending ? <Loader2 size={12} className="animate-spin" /> : <Newspaper size={12} />}
                  Generate Briefing
                </button>
              )}
              {mode === "chat" && !!(pageContext.alert_id || pageContext.agent_id) && (
                <button
                  onClick={quickInvestigate}
                  className="mt-4 flex items-center gap-2 rounded-lg border border-blue-500/30 bg-blue-500/10 px-4 py-2 text-xs font-medium text-blue-400 hover:bg-blue-500/20 transition-colors"
                >
                  <Zap size={12} />
                  {pageContext.alert_id
                    ? `Investigate this alert`
                    : `Investigate this agent`}
                </button>
              )}
              {mode === "chat" && (
                <div className="mt-4 flex flex-col gap-1.5 w-full max-w-[280px]">
                  {[
                    "Show me the latest critical alerts",
                    "What's the trust score for agent dc01?",
                    "Are there brute force attempts today?",
                  ].map((q) => (
                    <button
                      key={q}
                      onClick={() => {
                        setInput(q)
                        setTimeout(() => inputRef.current?.focus(), 50)
                      }}
                      className="rounded-lg border border-white/10 bg-white/[0.02] px-3 py-2 text-left text-xs text-muted-foreground hover:bg-white/[0.05] hover:text-foreground transition-colors"
                    >
                      {q}
                    </button>
                  ))}
                </div>
              )}
              {mode === "rules" && (
                <div className="mt-4 flex flex-col gap-1.5 w-full max-w-[300px]">
                  {[
                    "Detect when curl or wget runs on a low-trust agent",
                    "Alert on data exfiltration over DNS with large payloads",
                    "Flag MCP tool calls from unknown servers",
                    "Alert on 5+ sensitive file reads from one agent in 1 minute",
                  ].map((q) => (
                    <button
                      key={q}
                      onClick={() => {
                        setRuleDesc(q)
                        setTimeout(() => inputRef.current?.focus(), 50)
                      }}
                      className="rounded-lg border border-white/10 bg-white/[0.02] px-3 py-2 text-left text-xs text-muted-foreground hover:bg-white/[0.05] hover:text-foreground transition-colors"
                    >
                      {q}
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}

          {entries.map((entry) => (
            <div key={entry.id} className={cn("flex gap-2", entry.role === "user" ? "justify-end" : "")}>
              {entry.role === "assistant" && (
                <div className="mt-1 flex h-5 w-5 shrink-0 items-center justify-center rounded-md bg-emerald-500/10 border border-emerald-500/20">
                  <Bot size={11} className="text-emerald-400" />
                </div>
              )}
              <div
                className={cn(
                  "max-w-[85%] rounded-xl px-3 py-2 text-xs leading-relaxed",
                  entry.role === "user"
                    ? "bg-primary/20 text-foreground border border-primary/20"
                    : "bg-white/[0.03] text-foreground/90 border border-white/[0.06]",
                )}
              >
                {entry.isStreaming ? (
                  <div className="flex items-center gap-2 text-muted-foreground">
                    <Loader2 size={12} className="animate-spin" />
                    <span>{entry.content || "Thinking…"}</span>
                  </div>
                ) : entry.content === "__triage__" ? (
                  <TriageResults results={(entry.usage?._triageResults as TriageResult[]) ?? []} />
                ) : entry.content === "__rule__" ? (
                  <RuleResult rule={entry.usage?._ruleSuggestion as RuleSuggestion} />
                ) : (
                  <div className="space-y-0.5">{renderMarkdown(entry.content)}</div>
                )}

                {/* Tool calls indicator */}
                {entry.toolCalls && entry.toolCalls.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {entry.toolCalls.map((tc, i) => (
                      <span
                        key={i}
                        className="inline-flex items-center gap-1 rounded-full bg-blue-500/10 border border-blue-500/20 px-2 py-0.5 text-[9px] text-blue-400"
                      >
                        <Zap size={8} />
                        {tc}
                      </span>
                    ))}
                  </div>
                )}

                {/* Usage stats */}
                {entry.usage && !entry.isStreaming && entry.content !== "__triage__" && entry.content !== "__rule__" && (
                  <div className="mt-1.5 text-[9px] text-muted-foreground/50">
                    {entry.usage.model != null && <span>{String(entry.usage.model)}</span>}
                    {entry.usage.latency_ms != null && <span> · {String(entry.usage.latency_ms)}ms</span>}
                    {entry.usage.total_tokens != null && <span> · {String(entry.usage.total_tokens)} tokens</span>}
                  </div>
                )}
              </div>
              {entry.role === "user" && (
                <div className="mt-1 flex h-5 w-5 shrink-0 items-center justify-center rounded-md bg-primary/10 border border-primary/20">
                  <User size={11} className="text-primary" />
                </div>
              )}
            </div>
          ))}

          {/* ── Playbooks browser (replaces entries area) ───────── */}
          {mode === "playbooks" && !selectedPlaybook && (
            <div className="space-y-2">
              <h4 className="text-xs font-semibold text-foreground">IR Playbooks</h4>
              <p className="text-[10px] text-muted-foreground">
                Step-by-step incident response guides for each attack class.
              </p>
              {playbooksData?.playbooks?.map((pb: PlaybookSummary) => (
                <button
                  key={pb.attack_class}
                  onClick={() => setSelectedPlaybook(pb.attack_class)}
                  className="flex w-full items-center justify-between rounded-lg border border-white/10 bg-white/[0.02] px-3 py-2.5 text-left hover:bg-white/[0.05] transition-colors"
                >
                  <div>
                    <span className="text-xs font-medium text-foreground">{pb.name}</span>
                    <p className="mt-0.5 text-[10px] text-muted-foreground line-clamp-1">{pb.description}</p>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <span className={cn(
                      "rounded-full border px-2 py-0.5 text-[9px] font-medium",
                      pb.severity === "critical" ? "text-red-400 bg-red-500/10 border-red-500/30"
                        : pb.severity === "high" ? "text-amber-400 bg-amber-500/10 border-amber-500/30"
                        : "text-blue-400 bg-blue-500/10 border-blue-500/30",
                    )}>
                      {pb.severity}
                    </span>
                    <ChevronRight size={12} className="text-muted-foreground" />
                  </div>
                </button>
              ))}
              {!playbooksData && (
                <div className="flex items-center justify-center py-8">
                  <Loader2 size={16} className="animate-spin text-muted-foreground" />
                </div>
              )}
            </div>
          )}

          {/* ── Single playbook detail ──────────────────────────── */}
          {mode === "playbooks" && selectedPlaybook && (
            <div className="space-y-3">
              <button
                onClick={() => setSelectedPlaybook(null)}
                className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
              >
                <ChevronRight size={10} className="rotate-180" />
                All playbooks
              </button>
              {playbookDetail ? (
                <div className="space-y-0.5">{renderMarkdown(playbookDetail.markdown)}</div>
              ) : (
                <div className="flex items-center justify-center py-8">
                  <Loader2 size={16} className="animate-spin text-muted-foreground" />
                </div>
              )}
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* ── Input area ──────────────────────────────────────────── */}
        <div className="border-t border-white/10 p-3">
          {/* Session bar (chat mode only) */}
          {mode === "chat" && (
            <div className="mb-2 flex items-center gap-1.5 text-[10px] text-muted-foreground">
              <History size={10} />
              {sessionId ? (
                <span className="text-emerald-400">Session active</span>
              ) : (
                <span>No session</span>
              )}
              <div className="ml-auto flex items-center gap-1">
                <button
                  onClick={handleNewSession}
                  disabled={createSessionMut.isPending}
                  className="flex items-center gap-0.5 rounded px-1.5 py-0.5 hover:bg-white/10 hover:text-foreground transition-colors"
                  title="New session"
                >
                  <Plus size={9} />
                  New
                </button>
                <button
                  onClick={() => setShowSessions(!showSessions)}
                  className="flex items-center gap-0.5 rounded px-1.5 py-0.5 hover:bg-white/10 hover:text-foreground transition-colors"
                  title="Browse sessions"
                >
                  <History size={9} />
                  Sessions
                </button>
              </div>
            </div>
          )}

          {/* Session browser dropdown */}
          {showSessions && mode === "chat" && (
            <div className="mb-2 max-h-32 overflow-y-auto rounded-lg border border-white/10 bg-white/[0.03]">
              {sessionsData?.sessions?.length ? (
                sessionsData.sessions.map((s) => (
                  <div
                    key={s.session_id}
                    className={cn(
                      "flex items-center justify-between px-2 py-1.5 text-[10px] hover:bg-white/[0.05] cursor-pointer transition-colors",
                      sessionId === s.session_id && "bg-emerald-500/10 text-emerald-400",
                    )}
                  >
                    <button
                      className="flex-1 text-left"
                      onClick={() => { setSessionId(s.session_id); setShowSessions(false) }}
                    >
                      <span className="font-medium">{s.title}</span>
                      <span className="ml-2 text-muted-foreground">{s.message_count} msgs</span>
                    </button>
                    <button
                      onClick={() => handleDeleteSession(s.session_id)}
                      className="shrink-0 p-0.5 text-muted-foreground hover:text-red-400 transition-colors"
                      title="Delete session"
                    >
                      <Trash2 size={9} />
                    </button>
                  </div>
                ))
              ) : (
                <p className="px-2 py-2 text-[10px] text-muted-foreground text-center">No sessions yet</p>
              )}
            </div>
          )}

          {/* Context indicator */}
          {!!pageContext.alert_id && (
            <div className="mb-2 flex items-center gap-1.5 rounded-md bg-blue-500/10 border border-blue-500/20 px-2 py-1 text-[10px] text-blue-400">
              <Shield size={10} />
              Viewing alert {String(pageContext.alert_id).slice(0, 8)}…
              {mode === "triage" && !triageIds.includes(String(pageContext.alert_id)) && (
                <button
                  onClick={() => setTriageIds(String(pageContext.alert_id))}
                  className="ml-auto underline hover:text-blue-300 cursor-pointer"
                >
                  Auto-fill for triage
                </button>
              )}
            </div>
          )}
          {!!pageContext.agent_id && (
            <div className="mb-2 flex items-center gap-1.5 rounded-md bg-purple-500/10 border border-purple-500/20 px-2 py-1 text-[10px] text-purple-400">
              <Shield size={10} />
              Viewing agent {String(pageContext.agent_id).slice(0, 8)}…
            </div>
          )}

          {mode === "chat" && (
            <div className="flex gap-2">
              <textarea
                ref={inputRef}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Ask about your security data…"
                rows={1}
                className="flex-1 resize-none rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-xs text-foreground placeholder:text-muted-foreground/50 focus:border-emerald-500/50 focus:outline-none focus:ring-1 focus:ring-emerald-500/20"
                style={{ minHeight: 36, maxHeight: 120 }}
              />
              <button
                onClick={sendChat}
                disabled={!input.trim() || chatMutation.isPending}
                className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-emerald-600 text-white hover:bg-emerald-500 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                title="Send (Enter)"
              >
                {chatMutation.isPending ? (
                  <Loader2 size={14} className="animate-spin" />
                ) : (
                  <Send size={14} />
                )}
              </button>
            </div>
          )}

          {mode === "triage" && (
            <div className="flex gap-2">
              <textarea
                value={triageIds}
                onChange={(e) => setTriageIds(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Paste alert UUIDs (one per line or comma-separated)…"
                rows={3}
                className="flex-1 resize-none rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-xs font-mono text-foreground placeholder:text-muted-foreground/50 focus:border-emerald-500/50 focus:outline-none focus:ring-1 focus:ring-emerald-500/20"
              />
              <button
                onClick={runTriage}
                disabled={!triageIds.trim() || triageMutation.isPending}
                className="flex h-full w-9 shrink-0 items-center justify-center rounded-lg bg-amber-600 text-white hover:bg-amber-500 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                title="Triage (Enter)"
              >
                {triageMutation.isPending ? (
                  <Loader2 size={14} className="animate-spin" />
                ) : (
                  <AlertTriangle size={14} />
                )}
              </button>
            </div>
          )}

          {mode === "rules" && (
            <div className="flex gap-2">
              <textarea
                value={ruleDesc}
                onChange={(e) => setRuleDesc(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Describe what to detect, e.g.: 'Detect when a user fails login 5+ times in 60 seconds'"
                rows={3}
                className="flex-1 resize-none rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-xs text-foreground placeholder:text-muted-foreground/50 focus:border-emerald-500/50 focus:outline-none focus:ring-1 focus:ring-emerald-500/20"
              />
              <button
                onClick={generateRule}
                disabled={!ruleDesc.trim() || ruleGenMutation.isPending}
                className="flex h-full w-9 shrink-0 items-center justify-center rounded-lg bg-blue-600 text-white hover:bg-blue-500 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                title="Generate (Enter)"
              >
                {ruleGenMutation.isPending ? (
                  <Loader2 size={14} className="animate-spin" />
                ) : (
                  <FileCode size={14} />
                )}
              </button>
            </div>
          )}

          {mode === "briefing" && entries.length > 0 && (
            <button
              onClick={generateBriefing}
              disabled={briefingMutation.isPending}
              className="flex w-full items-center justify-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs font-medium text-emerald-400 hover:bg-emerald-500/20 disabled:opacity-40 transition-colors"
            >
              {briefingMutation.isPending ? <Loader2 size={12} className="animate-spin" /> : <Newspaper size={12} />}
              Regenerate Briefing
            </button>
          )}

          {/* Footer bar */}
          <div className="mt-2 flex items-center justify-between text-[9px] text-muted-foreground/40">
            <div className="flex items-center gap-3">
              <span>Ctrl+K to toggle</span>
              <span>Enter to send</span>
              <span>Esc to close</span>
            </div>
            {entries.length > 0 && (
              <button
                onClick={clearConversation}
                className="hover:text-muted-foreground transition-colors"
              >
                Clear
              </button>
            )}
          </div>
        </div>
      </div>
    </>
  )
}
