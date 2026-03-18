// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Agent Tag Editor.
 *
 * Key-value tag management component:
 *   - Displays current tags as badges
 *   - Inline add/remove for admin/analyst roles
 *   - Tag key validation (alphanumeric + _-. max 64)
 *   - Tag value max 256 chars
 *   - Max 50 tags per agent
 *
 * @module components/agents/TagEditor
 */

import { useState, useCallback, useMemo } from "react"
import { Plus, X, Tag } from "lucide-react"
import { useAgentTags, useUpdateAgentTags } from "@/api/tags"
import { useAuthStore } from "@/stores/authStore"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"

/* ── Validation ────────────────────────────────────────────────────────────── */

const TAG_KEY_RE = /^[a-zA-Z0-9_.-]{1,64}$/
const TAG_VALUE_MAX = 256
const MAX_TAGS = 50

/** Strip control characters, keep printable content, trim whitespace. */
function sanitizeValue(v: string): string {
  // eslint-disable-next-line no-control-regex
  return v.replace(/[\x00-\x1f\x7f]/g, "").trim()
}

/* ── Component ─────────────────────────────────────────────────────────────── */

interface TagEditorProps {
  agentId: string
}

export function TagEditor({ agentId }: TagEditorProps) {
  const role = useAuthStore((s) => s.user?.role)
  const canEdit = role === "admin" || role === "analyst"

  const { data: tagsData, isLoading } = useAgentTags(agentId)
  const updateTags = useUpdateAgentTags()

  const [adding, setAdding] = useState(false)
  const [newKey, setNewKey] = useState("")
  const [newValue, setNewValue] = useState("")
  const [error, setError] = useState<string | null>(null)

  const tags = useMemo(() => tagsData?.tags ?? {}, [tagsData?.tags])
  const tagEntries = Object.entries(tags)

  const handleRemove = useCallback(
    (key: string) => {
      const next = { ...tags }
      delete next[key]
      updateTags.mutate({ agentId, tags: next })
    },
    [tags, agentId, updateTags],
  )

  const handleAdd = useCallback(() => {
    setError(null)

    const key = newKey.trim()
    const value = sanitizeValue(newValue)

    if (!TAG_KEY_RE.test(key)) {
      setError("Key: alphanumeric, _, -, . only (max 64 chars)")
      return
    }
    if (!value || value.length > TAG_VALUE_MAX) {
      setError(`Value required (max ${TAG_VALUE_MAX} chars)`)
      return
    }
    if (tagEntries.length >= MAX_TAGS && !(key in tags)) {
      setError(`Maximum ${MAX_TAGS} tags reached`)
      return
    }

    updateTags.mutate(
      { agentId, tags: { ...tags, [key]: value } },
      {
        onSuccess: () => {
          setNewKey("")
          setNewValue("")
          setAdding(false)
        },
      },
    )
  }, [newKey, newValue, tags, tagEntries.length, agentId, updateTags])

  if (isLoading) {
    return (
      <div className="text-xs text-muted-foreground py-2">Loading tags…</div>
    )
  }

  return (
    <div className="space-y-2">
      {/* Tag badges */}
      {tagEntries.length === 0 && !adding && (
        <p className="text-xs text-muted-foreground py-1">
          No tags assigned.
        </p>
      )}

      <div className="flex flex-wrap gap-1.5">
        {tagEntries.map(([k, v]) => (
          <Badge
            key={k}
            variant="secondary"
            className="gap-1 pl-2 pr-1 py-0.5 text-xs font-mono"
          >
            <Tag size={10} className="shrink-0 text-muted-foreground" />
            <span>{k}</span>
            <span className="text-muted-foreground">=</span>
            <span className="text-foreground">{v}</span>
            {canEdit && (
              <button
                type="button"
                onClick={() => handleRemove(k)}
                className="ml-0.5 rounded-full p-0.5 hover:bg-white/10 transition-colors"
                aria-label={`Remove tag ${k}`}
                disabled={updateTags.isPending}
              >
                <X size={10} />
              </button>
            )}
          </Badge>
        ))}
      </div>

      {/* Add tag form */}
      {canEdit && !adding && (
        <Button
          variant="ghost"
          size="sm"
          onClick={() => setAdding(true)}
          className="gap-1 text-xs"
        >
          <Plus size={12} /> Add Tag
        </Button>
      )}

      {canEdit && adding && (
        <div className="space-y-1.5">
          <div className="flex gap-1.5">
            <Input
              placeholder="key"
              value={newKey}
              onChange={(e) => setNewKey(e.target.value)}
              className="h-7 w-32 font-mono text-xs"
              maxLength={64}
              aria-label="Tag key"
            />
            <Input
              placeholder="value"
              value={newValue}
              onChange={(e) => setNewValue(e.target.value)}
              className="h-7 flex-1 font-mono text-xs"
              maxLength={TAG_VALUE_MAX}
              aria-label="Tag value"
            />
            <Button
              size="sm"
              onClick={handleAdd}
              disabled={updateTags.isPending}
              className="h-7 text-xs"
            >
              Add
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                setAdding(false)
                setError(null)
                setNewKey("")
                setNewValue("")
              }}
              className="h-7 text-xs"
            >
              Cancel
            </Button>
          </div>
          {error && (
            <p className="text-xs text-destructive" role="alert">{error}</p>
          )}
        </div>
      )}

      {/* Mutation error */}
      {updateTags.isError && (
        <p className="text-xs text-destructive" role="alert">
          Failed to update tags: {updateTags.error.message}
        </p>
      )}
    </div>
  )
}
