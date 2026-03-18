// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — PolicyVisualBuilder: form-based policy builder (O5).
 *
 * Structured form with:
 *   - Rule selector (multi-select from available PRL rules)
 *   - Per-rule severity override, enable/disable, parameters
 *   - Scope: agent tags + frameworks
 *   - Schedule: active hours + weekend behaviour
 *   - Notification channel config per rule
 *
 * @module components/policies/PolicyVisualBuilder
 */

import { useState, useCallback, useMemo } from "react"
import {
  Plus,
  Trash2,
  ChevronDown,
  ChevronUp,
  ToggleLeft,
  ToggleRight,
  Tag,
  Clock,
} from "lucide-react"
import { useRules } from "@/api/rules"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import type {
  PolicyDefinition,
  PolicyRuleOverride,
  PolicySchedule,
  PolicySeverity,
} from "@/types"

/* ── Constants ─────────────────────────────────────────────────────────────── */

const SEVERITIES: PolicySeverity[] = ["info", "low", "medium", "high", "critical"]
const WEEKEND_OPTIONS = [
  { value: "inherit", label: "Inherit default" },
  { value: "suppress", label: "Suppress non-critical" },
  { value: "alert", label: "Alert all" },
] as const

const TAG_PATTERN = /^[a-zA-Z0-9_\-:.]{1,64}$/

const SEVERITY_COLORS: Record<string, string> = {
  info: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  low: "bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
  medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
}

/* ── Props ─────────────────────────────────────────────────────────────────── */

interface PolicyVisualBuilderProps {
  definition: PolicyDefinition
  onChange: (def: PolicyDefinition) => void
}

/* ── Component ─────────────────────────────────────────────────────────────── */

export function PolicyVisualBuilder({ definition, onChange }: PolicyVisualBuilderProps) {
  const { data: rulesData } = useRules({ page_size: 200 })
  const availableRules = useMemo(() => rulesData?.items ?? [], [rulesData?.items])

  const [expandedRule, setExpandedRule] = useState<string | null>(null)
  const [tagInput, setTagInput] = useState("")
  const [frameworkInput, setFrameworkInput] = useState("")

  const selectedRuleNames = useMemo(
    () => new Set(definition.rules.map((r) => r.name)),
    [definition.rules],
  )

  /* ── Rule management ─────────────────────────────────── */

  const addRule = useCallback(
    (ruleName: string) => {
      const rule = availableRules.find((r) => r.name === ruleName)
      if (!rule || selectedRuleNames.has(ruleName)) return
      const override: PolicyRuleOverride = {
        name: ruleName,
        enabled: true,
        severity_override: null,
        parameters: {},
        notifications: [],
      }
      onChange({ ...definition, rules: [...definition.rules, override] })
    },
    [availableRules, selectedRuleNames, definition, onChange],
  )

  const removeRule = useCallback(
    (name: string) => {
      onChange({
        ...definition,
        rules: definition.rules.filter((r) => r.name !== name),
      })
    },
    [definition, onChange],
  )

  const updateRule = useCallback(
    (name: string, updates: Partial<PolicyRuleOverride>) => {
      onChange({
        ...definition,
        rules: definition.rules.map((r) =>
          r.name === name ? { ...r, ...updates } : r,
        ),
      })
    },
    [definition, onChange],
  )

  /* ── Scope management ────────────────────────────────── */

  const addTag = useCallback(() => {
    const tag = tagInput.trim()
    if (!tag || !TAG_PATTERN.test(tag) || definition.scope.agent_tags.includes(tag)) return
    onChange({
      ...definition,
      scope: { ...definition.scope, agent_tags: [...definition.scope.agent_tags, tag] },
    })
    setTagInput("")
  }, [tagInput, definition, onChange])

  const removeTag = useCallback(
    (tag: string) => {
      onChange({
        ...definition,
        scope: {
          ...definition.scope,
          agent_tags: definition.scope.agent_tags.filter((t) => t !== tag),
        },
      })
    },
    [definition, onChange],
  )

  const addFramework = useCallback(() => {
    const fw = frameworkInput.trim()
    if (!fw || !TAG_PATTERN.test(fw) || definition.scope.frameworks.includes(fw)) return
    onChange({
      ...definition,
      scope: { ...definition.scope, frameworks: [...definition.scope.frameworks, fw] },
    })
    setFrameworkInput("")
  }, [frameworkInput, definition, onChange])

  const removeFramework = useCallback(
    (fw: string) => {
      onChange({
        ...definition,
        scope: {
          ...definition.scope,
          frameworks: definition.scope.frameworks.filter((f) => f !== fw),
        },
      })
    },
    [definition, onChange],
  )

  /* ── Schedule management ─────────────────────────────── */

  const updateSchedule = useCallback(
    (updates: Partial<PolicySchedule>) => {
      onChange({
        ...definition,
        schedule: { ...(definition.schedule ?? { active_hours: null, weekend: null }), ...updates },
      })
    },
    [definition, onChange],
  )

  return (
    <div className="flex flex-col gap-6">
      {/* ── Rules Section ────────────────────────────────── */}
      <section>
        <h3 className="text-sm font-semibold text-foreground mb-3">Rule Overrides</h3>

        {/* Add rule dropdown */}
        <div className="mb-3">
          <select
            onChange={(e) => {
              if (e.target.value) addRule(e.target.value)
              e.target.value = ""
            }}
            className="w-full rounded-md bg-surface-2/60 border border-border/50
                       px-3 py-1.5 text-xs text-foreground outline-none cursor-pointer"
            defaultValue=""
          >
            <option value="" disabled>
              + Add rule override…
            </option>
            {availableRules
              .filter((r) => !selectedRuleNames.has(r.name))
              .map((r) => (
                <option key={r.id} value={r.name}>
                  {r.name} ({r.severity})
                </option>
              ))}
          </select>
        </div>

        {/* Rule list */}
        {definition.rules.length === 0 ? (
          <p className="text-xs text-muted-foreground italic py-4 text-center">
            No rule overrides — all rules will use their default settings
          </p>
        ) : (
          <div className="space-y-2">
            {definition.rules.map((rule) => {
              const isExpanded = expandedRule === rule.name
              const srcRule = availableRules.find((r) => r.name === rule.name)

              return (
                <div
                  key={rule.name}
                  className="rounded-lg border border-border/40 bg-card/60 overflow-hidden"
                >
                  {/* Rule header */}
                  <div className="flex items-center gap-2 px-3 py-2">
                    <button
                      onClick={() => setExpandedRule(isExpanded ? null : rule.name)}
                      className="text-muted-foreground hover:text-foreground cursor-pointer"
                    >
                      {isExpanded ? <ChevronUp className="size-3.5" /> : <ChevronDown className="size-3.5" />}
                    </button>

                    <button
                      onClick={() => updateRule(rule.name, { enabled: !rule.enabled })}
                      className="cursor-pointer"
                      title={rule.enabled ? "Disable" : "Enable"}
                    >
                      {rule.enabled ? (
                        <ToggleRight className="size-4 text-emerald-400" />
                      ) : (
                        <ToggleLeft className="size-4 text-muted-foreground" />
                      )}
                    </button>

                    <span className={`text-xs font-medium ${rule.enabled ? "text-foreground" : "text-muted-foreground line-through"}`}>
                      {rule.name}
                    </span>

                    {rule.severity_override && (
                      <Badge variant="outline" className={`text-[9px] py-0 ${SEVERITY_COLORS[rule.severity_override] ?? ""}`}>
                        {rule.severity_override}
                      </Badge>
                    )}

                    {srcRule && !rule.severity_override && (
                      <span className="text-[10px] text-muted-foreground/50">
                        default: {srcRule.severity}
                      </span>
                    )}

                    <div className="ml-auto">
                      <button
                        onClick={() => removeRule(rule.name)}
                        className="text-muted-foreground hover:text-red-400 cursor-pointer p-1"
                        title="Remove rule"
                      >
                        <Trash2 className="size-3" />
                      </button>
                    </div>
                  </div>

                  {/* Expanded: severity override */}
                  {isExpanded && (
                    <div className="border-t border-border/30 px-3 py-3 space-y-3">
                      <div>
                        <label className="text-[10px] text-muted-foreground uppercase tracking-wider">
                          Severity Override
                        </label>
                        <div className="flex gap-1 mt-1">
                          <button
                            onClick={() => updateRule(rule.name, { severity_override: null })}
                            className={`rounded px-2 py-0.5 text-[10px] border cursor-pointer transition-colors
                              ${!rule.severity_override
                                ? "bg-violet-500/15 text-violet-400 border-violet-500/30"
                                : "bg-surface-2/30 text-muted-foreground/50 border-border/20"}`}
                          >
                            Default
                          </button>
                          {SEVERITIES.map((sev) => (
                            <button
                              key={sev}
                              onClick={() => updateRule(rule.name, { severity_override: sev })}
                              className={`rounded px-2 py-0.5 text-[10px] border capitalize cursor-pointer transition-colors
                                ${rule.severity_override === sev
                                  ? SEVERITY_COLORS[sev]
                                  : "bg-surface-2/30 text-muted-foreground/50 border-border/20"}`}
                            >
                              {sev}
                            </button>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </section>

      {/* ── Scope Section ────────────────────────────────── */}
      <section>
        <h3 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-1.5">
          <Tag className="size-3.5" /> Scope
        </h3>

        {/* Agent tags */}
        <div className="mb-3">
          <label className="text-[10px] text-muted-foreground uppercase tracking-wider">
            Agent Tags
          </label>
          <div className="flex gap-1.5 mt-1">
            <Input
              value={tagInput}
              onChange={(e) => setTagInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && (e.preventDefault(), addTag())}
              placeholder="e.g. production"
              className="text-xs h-7 flex-1"
            />
            <Button variant="outline" size="sm" className="h-7 text-xs" onClick={addTag}>
              <Plus className="size-3" />
            </Button>
          </div>
          {definition.scope.agent_tags.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-2">
              {definition.scope.agent_tags.map((tag) => (
                <Badge
                  key={tag}
                  variant="outline"
                  className="text-[10px] gap-1 cursor-pointer hover:bg-red-500/10"
                  onClick={() => removeTag(tag)}
                >
                  {tag} ×
                </Badge>
              ))}
            </div>
          )}
        </div>

        {/* Frameworks */}
        <div>
          <label className="text-[10px] text-muted-foreground uppercase tracking-wider">
            Frameworks
          </label>
          <div className="flex gap-1.5 mt-1">
            <Input
              value={frameworkInput}
              onChange={(e) => setFrameworkInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && (e.preventDefault(), addFramework())}
              placeholder="e.g. langchain"
              className="text-xs h-7 flex-1"
            />
            <Button variant="outline" size="sm" className="h-7 text-xs" onClick={addFramework}>
              <Plus className="size-3" />
            </Button>
          </div>
          {definition.scope.frameworks.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-2">
              {definition.scope.frameworks.map((fw) => (
                <Badge
                  key={fw}
                  variant="outline"
                  className="text-[10px] gap-1 cursor-pointer hover:bg-red-500/10"
                  onClick={() => removeFramework(fw)}
                >
                  {fw} ×
                </Badge>
              ))}
            </div>
          )}
        </div>
      </section>

      {/* ── Schedule Section ─────────────────────────────── */}
      <section>
        <h3 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-1.5">
          <Clock className="size-3.5" /> Schedule
        </h3>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="text-[10px] text-muted-foreground uppercase tracking-wider">
              Active Hours
            </label>
            <Input
              value={definition.schedule?.active_hours ?? ""}
              onChange={(e) => updateSchedule({ active_hours: e.target.value || null })}
              placeholder="09:00-18:00 UTC"
              className="text-xs h-7 mt-1"
            />
          </div>
          <div>
            <label className="text-[10px] text-muted-foreground uppercase tracking-wider">
              Weekend
            </label>
            <select
              value={definition.schedule?.weekend ?? "inherit"}
              onChange={(e) =>
                updateSchedule({ weekend: e.target.value as PolicySchedule["weekend"] })
              }
              className="mt-1 w-full rounded-md bg-surface-2/60 border border-border/50
                         px-2 py-1 text-xs text-foreground outline-none cursor-pointer"
            >
              {WEEKEND_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>
        </div>
      </section>
    </div>
  )
}
