// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — PolicyEditPage: create or edit a policy (O5).
 *
 * Dual-mode editor:
 *   - Visual Builder (form)
 *   - YAML Editor (Monaco)
 * State is preserved when switching modes.
 *
 * Also includes a version history sidebar.
 *
 * @module pages/PolicyEditPage
 */

import { useState, useCallback, useEffect } from "react"
import { useParams, useNavigate, Navigate } from "react-router-dom"
import {
  Save,
  ArrowLeft,
  Eye,
  Code2,
  Wand2,
  History,
  Rocket,
  Loader2,
  CheckCircle2,
  AlertCircle,
  HelpCircle,
} from "lucide-react"
import { usePolicy, useCreatePolicy, useUpdatePolicy, useApplyPolicy, useValidatePolicy } from "@/api/policies"
import { PolicyVisualBuilder } from "@/components/policies/PolicyVisualBuilder"
import { PolicyYamlEditor } from "@/components/policies/PolicyYamlEditor"
import { PolicyVersionHistory } from "@/components/policies/PolicyVersionHistory"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { usePermissionStore } from "@/stores/permissionStore"
import type { PolicyDefinition } from "@/types"

/* ── Helpers ───────────────────────────────────────────────────────────────── */

const EMPTY_DEFINITION: PolicyDefinition = {
  rules: [],
  schedule: null,
  scope: { agent_tags: [], frameworks: [] },
}

/** Quick & dirty JSON → YAML for mode switch (display-only) */
function defToYaml(def: PolicyDefinition): string {
  const lines: string[] = []

  lines.push("rules:")
  if (def.rules.length === 0) lines.push("  []")
  for (const r of def.rules) {
    lines.push(`  - name: ${JSON.stringify(r.name)}`)
    lines.push(`    enabled: ${r.enabled}`)
    if (r.severity_override) lines.push(`    severity_override: ${r.severity_override}`)
    if (Object.keys(r.parameters).length > 0)
      lines.push(`    parameters: ${JSON.stringify(r.parameters)}`)
    if (r.notifications.length > 0)
      lines.push(`    notifications: ${JSON.stringify(r.notifications)}`)
  }

  lines.push("")
  lines.push("scope:")
  lines.push(`  agent_tags: [${def.scope.agent_tags.map((t) => JSON.stringify(t)).join(", ")}]`)
  lines.push(`  frameworks: [${def.scope.frameworks.map((f) => JSON.stringify(f)).join(", ")}]`)

  if (def.schedule) {
    lines.push("")
    lines.push("schedule:")
    if (def.schedule.active_hours) lines.push(`  active_hours: ${JSON.stringify(def.schedule.active_hours)}`)
    if (def.schedule.weekend) lines.push(`  weekend: ${def.schedule.weekend}`)
  }

  return lines.join("\n") + "\n"
}

/* ── Component ─────────────────────────────────────────────────────────────── */

type EditorMode = "visual" | "yaml"

export function PolicyEditPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const isNew = !id || id === "new"

  /* Permission guard — only users with policies.write can access the editor */
  const permissions = usePermissionStore((s) => s.permissions)
  const canEdit = permissions.has("policies.write")

  /* ── API hooks ─────────────────────────────────────────── */
  const { data: existing, isLoading } = usePolicy(id === "new" ? undefined : id, !isNew)
  const createMutation = useCreatePolicy()
  const updateMutation = useUpdatePolicy()
  const applyMutation = useApplyPolicy()
  const validateMutation = useValidatePolicy()

  /* ── Local state ───────────────────────────────────────── */
  const [name, setName] = useState("")
  const [description, setDescription] = useState("")
  const [enabled, setEnabled] = useState(true)
  const [changeSummary, setChangeSummary] = useState("")

  const [definition, setDefinition] = useState<PolicyDefinition>(EMPTY_DEFINITION)
  const [yaml, setYaml] = useState(() => defToYaml(EMPTY_DEFINITION))

  const [mode, setMode] = useState<EditorMode>("visual")
  const [showHistory, setShowHistory] = useState(false)
  const [saveStatus, setSaveStatus] = useState<"idle" | "saving" | "saved" | "error">("idle")
  const [showGuide, setShowGuide] = useState(false)

  /* ── Seed from existing policy ─────────────────────────── */
  /* eslint-disable react-hooks/set-state-in-effect -- form hydration from API data */
  useEffect(() => {
    if (!existing) return
    setName(existing.name)
    setDescription(existing.description ?? "")
    setEnabled(existing.enabled)
    const def = parseExistingDef(existing.definition as unknown as Record<string, unknown>)
    setDefinition(def)
    setYaml(defToYaml(def))
  }, [existing])
  /* eslint-enable react-hooks/set-state-in-effect */

  /* ── Mode switch — sync state ──────────────────────────── */
  const switchMode = useCallback(
    (target: EditorMode) => {
      if (target === mode) return
      if (target === "yaml") {
        // Visual → YAML: serialize current definition
        setYaml(defToYaml(definition))
      }
      // YAML → Visual: we don't auto-parse (could be invalid); user has visual state from last builder edit
      setMode(target)
    },
    [mode, definition],
  )

  /* ── Save ──────────────────────────────────────────────── */
  const handleSave = useCallback(async () => {
    setSaveStatus("saving")

    const definitionPayload = mode === "yaml" ? undefined : definition

    try {
      if (isNew) {
        await createMutation.mutateAsync({
          name,
          description: description || undefined,
          enabled,
          definition: definitionPayload ?? EMPTY_DEFINITION,
        })
      } else if (id) {
        await updateMutation.mutateAsync({
          id,
          name,
          description: description || undefined,
          enabled,
          definition: definitionPayload ?? undefined,
          change_summary: changeSummary || undefined,
        })
      }
      setSaveStatus("saved")
      setTimeout(() => setSaveStatus("idle"), 2000)
      if (isNew) navigate("/policies")
    } catch {
      setSaveStatus("error")
      setTimeout(() => setSaveStatus("idle"), 3000)
    }
  }, [isNew, id, name, description, enabled, definition, changeSummary, mode, createMutation, updateMutation, navigate])

  /* ── Apply to agents ───────────────────────────────────── */
  const handleApply = useCallback(() => {
    if (!id || isNew) return
    applyMutation.mutate(id)
  }, [id, isNew, applyMutation])

  /* ── Validate ──────────────────────────────────────────── */
  const handleValidate = useCallback(() => {
    if (mode === "yaml") {
      validateMutation.mutate({ yaml_content: yaml })
    } else {
      validateMutation.mutate({ json_content: definition })
    }
  }, [mode, yaml, definition, validateMutation])

  /* ── Permission guard ──────────────────────────────────── */
  if (!canEdit) return <Navigate to="/policies" replace />
  if (!isNew && isLoading) {
    return (
      <div className="flex items-center justify-center py-24 text-muted-foreground">
        <Loader2 className="size-5 animate-spin mr-2" /> Loading policy…
      </div>
    )
  }

  return (
    <div className="flex flex-col h-[calc(100vh-4rem)] animate-fade-in">
      {/* ── Top bar ────────────────────────────────────────── */}
      <div className="flex items-center gap-3 pb-4 border-b border-border/30">
        <Button variant="ghost" size="sm" onClick={() => navigate("/policies")} className="gap-1">
          <ArrowLeft className="size-3.5" /> Policies
        </Button>

        <div className="flex-1 min-w-0">
          <Input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Policy name"
            className="text-lg font-semibold h-9 border-0 bg-transparent focus-visible:ring-0 px-0"
          />
        </div>

        {!isNew && existing && (
          <Badge variant="outline" className="text-[10px] shrink-0">
            v{existing.version}
          </Badge>
        )}

        {/* Mode toggle */}
        <div className="flex rounded-lg border border-border/40 p-0.5 shrink-0">
          <button
            onClick={() => switchMode("visual")}
            className={`flex items-center gap-1 rounded-md px-2 py-1 text-xs cursor-pointer transition-colors
              ${mode === "visual" ? "bg-surface-2/80 text-foreground" : "text-muted-foreground hover:text-foreground"}`}
          >
            <Wand2 className="size-3" /> Visual
          </button>
          <button
            onClick={() => switchMode("yaml")}
            className={`flex items-center gap-1 rounded-md px-2 py-1 text-xs cursor-pointer transition-colors
              ${mode === "yaml" ? "bg-surface-2/80 text-foreground" : "text-muted-foreground hover:text-foreground"}`}
          >
            <Code2 className="size-3" /> YAML
          </button>
        </div>

        <button onClick={() => setShowGuide(!showGuide)} className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer shrink-0"><HelpCircle size={14} />{showGuide ? "Hide Guide" : "How does this work?"}</button>

        {/* History toggle */}
        {!isNew && (
          <Button
            variant={showHistory ? "secondary" : "outline"}
            size="sm"
            className="gap-1 text-xs"
            onClick={() => setShowHistory(!showHistory)}
          >
            <History className="size-3" />
            {showHistory ? "Hide" : "History"}
          </Button>
        )}
      </div>

      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5 space-y-3 text-sm text-muted-foreground">
          <h3 className="text-base font-semibold text-foreground">How does the Policy Editor work?</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Visual Builder</p>
              <p>Drag-and-drop policy creation with condition blocks, severity selectors, and scope targeting. The visual builder generates valid policy YAML behind the scenes. Switch to YAML mode to see or edit the raw definition.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">YAML Editor</p>
              <p>Full YAML editing with syntax highlighting. Validate syntax in real time via <code className="text-xs bg-white/5 px-1 rounded">/api/policies/validate</code>. Supports both JSON and YAML payloads. Switching modes preserves your definition.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Version History</p>
              <p>Every save creates a new version. View previous versions, compare changes, and restore any prior state. Change summaries document what was modified and why for audit trails.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Save &amp; Apply</p>
              <p>Save persists the policy via <code className="text-xs bg-white/5 px-1 rounded">/api/policies</code> (POST for new, PUT for updates). Apply pushes the policy to the live evaluation engine. Enable/disable toggles control whether the policy is actively evaluated.</p>
            </div>
          </div>
        </div>
      )}

      {/* ── Body ───────────────────────────────────────────── */}
      <div className="flex flex-1 min-h-0 gap-4 pt-4">
        {/* Main editor area */}
        <div className="flex-1 min-w-0 flex flex-col">
          {/* Description */}
          <div className="mb-3">
            <Input
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Policy description (optional)"
              className="text-xs h-7"
            />
          </div>

          {/* Editor content */}
          <div className="flex-1 min-h-0 overflow-y-auto">
            {mode === "visual" ? (
              <PolicyVisualBuilder definition={definition} onChange={setDefinition} />
            ) : (
              <PolicyYamlEditor
                value={yaml}
                onChange={setYaml}
              />
            )}
          </div>
        </div>

        {/* Version history sidebar */}
        {showHistory && id && !isNew && (
          <div className="w-80 shrink-0 border-l border-border/30 pl-4 overflow-y-auto">
            <h3 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-1.5">
              <History className="size-3.5" /> Version History
            </h3>
            <PolicyVersionHistory policyId={id} />
          </div>
        )}
      </div>

      {/* ── Footer bar ─────────────────────────────────────── */}
      <div className="flex items-center gap-2 pt-3 border-t border-border/30 mt-3">
        {/* Change summary (for updates) */}
        {!isNew && (
          <Input
            value={changeSummary}
            onChange={(e) => setChangeSummary(e.target.value)}
            placeholder="Change summary (optional)"
            className="text-xs h-8 max-w-sm"
          />
        )}

        <div className="flex-1" />

        {/* Validate */}
        <Button
          variant="outline"
          size="sm"
          className="gap-1 text-xs"
          onClick={handleValidate}
          disabled={validateMutation.isPending}
        >
          <Eye className="size-3" />
          {validateMutation.isPending ? "Validating…" : "Validate"}
        </Button>

        {/* Validation result toast */}
        {validateMutation.isSuccess && (
          <Badge
            variant="outline"
            className={`text-[10px] ${
              validateMutation.data?.valid
                ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                : "bg-red-500/10 text-red-400 border-red-500/30"
            }`}
          >
            {validateMutation.data?.valid ? (
              <><CheckCircle2 className="size-3 mr-1" /> Valid</>
            ) : (
              <><AlertCircle className="size-3 mr-1" /> {validateMutation.data?.errors?.length ?? 0} errors</>
            )}
          </Badge>
        )}

        {/* Apply (edit mode only) */}
        {!isNew && (
          <Button
            variant="outline"
            size="sm"
            className="gap-1 text-xs"
            onClick={handleApply}
            disabled={applyMutation.isPending}
          >
            <Rocket className="size-3" />
            {applyMutation.isPending ? "Applying…" : "Apply to Agents"}
          </Button>
        )}

        {/* Save */}
        <Button
          size="sm"
          className="gap-1"
          onClick={handleSave}
          disabled={!name.trim() || saveStatus === "saving"}
        >
          {saveStatus === "saving" ? (
            <Loader2 className="size-3 animate-spin" />
          ) : saveStatus === "saved" ? (
            <CheckCircle2 className="size-3" />
          ) : saveStatus === "error" ? (
            <AlertCircle className="size-3" />
          ) : (
            <Save className="size-3" />
          )}
          {saveStatus === "saving" ? "Saving…" : saveStatus === "saved" ? "Saved!" : saveStatus === "error" ? "Error" : isNew ? "Create" : "Save"}
        </Button>
      </div>
    </div>
  )
}

/* ── Parse existing definition from backend ────────────────────────────────── */

function parseExistingDef(raw: Record<string, unknown> | null | undefined): PolicyDefinition {
  if (!raw) return { ...EMPTY_DEFINITION }

  try {
    return {
      rules: Array.isArray(raw.rules)
        ? raw.rules.map((r: Record<string, unknown>) => ({
            name: String(r.name ?? ""),
            enabled: Boolean(r.enabled ?? true),
            severity_override: (r.severity_override as PolicyDefinition["rules"][0]["severity_override"]) ?? null,
            parameters: (r.parameters as Record<string, unknown>) ?? {},
            notifications: Array.isArray(r.notifications) ? r.notifications : [],
          }))
        : [],
      schedule: raw.schedule
        ? {
            active_hours: (raw.schedule as Record<string, unknown>).active_hours as string | null ?? null,
            weekend: (raw.schedule as Record<string, unknown>).weekend as PolicyDefinition["schedule"] extends null ? never : NonNullable<PolicyDefinition["schedule"]>["weekend"] ?? null,
          }
        : null,
      scope: {
        agent_tags: Array.isArray((raw.scope as Record<string, unknown>)?.agent_tags)
          ? ((raw.scope as Record<string, unknown>).agent_tags as string[])
          : [],
        frameworks: Array.isArray((raw.scope as Record<string, unknown>)?.frameworks)
          ? ((raw.scope as Record<string, unknown>).frameworks as string[])
          : [],
      },
    }
  } catch {
    return { ...EMPTY_DEFINITION }
  }
}
