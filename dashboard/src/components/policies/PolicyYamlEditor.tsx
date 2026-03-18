// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — PolicyYamlEditor: Monaco-based YAML editor (O5).
 *
 * Features:
 *   - Syntax highlighting (YAML language)
 *   - Live validation via backend (debounced)
 *   - Inline error markers
 *   - Read-only mode for non-admin users
 *
 * @module components/policies/PolicyYamlEditor
 */

import { useRef, useCallback, useEffect, useState } from "react"
import Editor, { type OnMount, type OnChange, loader } from "@monaco-editor/react"
import * as monaco from "monaco-editor"
import editorWorker from "monaco-editor/esm/vs/editor/editor.worker?worker"
import { useValidatePolicy } from "@/api/policies"
import { AlertCircle, CheckCircle2, Loader2 } from "lucide-react"
import type { PolicyValidationResult } from "@/types"

/* Configure Monaco to use locally-bundled workers instead of CDN
   (CSP script-src 'self' blocks cdn.jsdelivr.net). */
self.MonacoEnvironment = {
  getWorker() {
    return new editorWorker()
  },
}
loader.config({ monaco })

/* ── Props ─────────────────────────────────────────────────────────────────── */

interface PolicyYamlEditorProps {
  value: string
  onChange: (yaml: string) => void
  readOnly?: boolean
}

/* ── Debounce interval (ms) ────────────────────────────────────────────────── */
const VALIDATION_DELAY = 800

/* ── Component ─────────────────────────────────────────────────────────────── */

export function PolicyYamlEditor({ value, onChange, readOnly = false }: PolicyYamlEditorProps) {
  const editorRef = useRef<monaco.editor.IStandaloneCodeEditor | null>(null)
  const monacoRef = useRef<typeof monaco | null>(null)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const [validation, setValidation] = useState<PolicyValidationResult | null>(null)
  const [validating, setValidating] = useState(false)

  const validateMutation = useValidatePolicy()

  /* ── Handle mount ────────────────────────────────────── */
  const handleMount: OnMount = useCallback((editor, m) => {
    editorRef.current = editor
    monacoRef.current = m
  }, [])

  /* ── Validate helper ─────────────────────────────────── */
  const runValidation = useCallback(
    (yaml: string) => {
      if (!yaml.trim()) {
        setValidation(null)
        return
      }
      setValidating(true)
      validateMutation.mutate(
        { yaml_content: yaml },
        {
          onSuccess: (result) => {
            setValidation(result)
            setValidating(false)
            applyMarkers(result)
          },
          onError: () => {
            setValidation({ valid: false, errors: ["Validation request failed"], warnings: [], parsed: null })
            setValidating(false)
          },
        },
      )
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [validateMutation.mutate],
  )

  /* ── Apply error markers to Monaco ──────────────────── */
  const applyMarkers = useCallback(
    (result: PolicyValidationResult) => {
      const editor = editorRef.current
      const m = monacoRef.current
      if (!editor || !m) return

      const model = editor.getModel()
      if (!model) return

      const markers: monaco.editor.IMarkerData[] = [
        ...result.errors.map((msg, i) => ({
          severity: m.MarkerSeverity.Error,
          message: msg,
          startLineNumber: extractLine(msg) ?? i + 1,
          startColumn: 1,
          endLineNumber: extractLine(msg) ?? i + 1,
          endColumn: 1000,
        })),
        ...result.warnings.map((msg, i) => ({
          severity: m.MarkerSeverity.Warning,
          message: msg,
          startLineNumber: extractLine(msg) ?? i + 1,
          startColumn: 1,
          endLineNumber: extractLine(msg) ?? i + 1,
          endColumn: 1000,
        })),
      ]

      m.editor.setModelMarkers(model, "phantex-policy", markers)
    },
    [],
  )

  /* ── Handle change (debounced validation) ────────────── */
  const handleChange: OnChange = useCallback(
    (val) => {
      const yaml = val ?? ""
      onChange(yaml)

      if (timerRef.current) clearTimeout(timerRef.current)
      timerRef.current = setTimeout(() => runValidation(yaml), VALIDATION_DELAY)
    },
    [onChange, runValidation],
  )

  /* cleanup timer */
  useEffect(() => () => { if (timerRef.current) clearTimeout(timerRef.current) }, [])

  return (
    <div className="flex flex-col h-full">
      {/* Editor */}
      <div className="flex-1 min-h-0 rounded-lg overflow-hidden border border-border/40">
        <Editor
          height="100%"
          language="yaml"
          theme="vs-dark"
          value={value}
          onChange={handleChange}
          onMount={handleMount}
          options={{
            readOnly,
            fontSize: 12,
            lineNumbers: "on",
            minimap: { enabled: false },
            scrollBeyondLastLine: false,
            wordWrap: "on",
            tabSize: 2,
            automaticLayout: true,
            renderValidationDecorations: "on",
          }}
          loading={
            <div className="flex items-center justify-center h-full text-muted-foreground text-xs">
              <Loader2 className="size-4 animate-spin mr-2" /> Loading editor…
            </div>
          }
        />
      </div>

      {/* Validation status bar */}
      <div className="flex items-center gap-2 px-3 py-1.5 text-xs border-t border-border/30 bg-surface-2/30">
        {validating ? (
          <>
            <Loader2 className="size-3 animate-spin text-blue-400" />
            <span className="text-muted-foreground">Validating…</span>
          </>
        ) : validation ? (
          validation.valid ? (
            <>
              <CheckCircle2 className="size-3 text-emerald-400" />
              <span className="text-emerald-400">Valid</span>
              {validation.warnings.length > 0 && (
                <span className="text-yellow-400 ml-1">
                  ({validation.warnings.length} warning{validation.warnings.length > 1 ? "s" : ""})
                </span>
              )}
            </>
          ) : (
            <>
              <AlertCircle className="size-3 text-red-400" />
              <span className="text-red-400">
                {validation.errors.length} error{validation.errors.length !== 1 ? "s" : ""}
              </span>
              {validation.warnings.length > 0 && (
                <span className="text-yellow-400 ml-1">
                  · {validation.warnings.length} warning{validation.warnings.length > 1 ? "s" : ""}
                </span>
              )}
            </>
          )
        ) : (
          <span className="text-muted-foreground">YAML · ready</span>
        )}
      </div>
    </div>
  )
}

/* ── Helpers ───────────────────────────────────────────────────────────────── */

/** Try to extract a line number from an error message like "line 5: ..." */
function extractLine(msg: string): number | null {
  const m = /line\s+(\d+)/i.exec(msg)
  return m ? parseInt(m[1], 10) : null
}
