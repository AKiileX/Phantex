// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — PDR Export Channel Form (O9).
 *
 * Dynamic form for creating/editing export channels.
 * Renders type-specific config fields:
 *   - S3: bucket, region, prefix, IAM role, access/secret keys
 *   - Webhook: URL, secret, custom headers
 *   - Kafka Mirror: bootstrap servers, topic, SASL config
 *
 * Sensitive fields marked with type="password" and masked in edit mode.
 *
 * @module components/exports/ChannelForm
 */

import { useState, useCallback } from "react"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { X } from "lucide-react"
import type { PDRChannelType, PDRChannelCreate } from "@/types"

/* ── Channel type metadata ─────────────────────────────────────────────────── */

interface FieldDef {
  key: string
  label: string
  required?: boolean
  sensitive?: boolean
  placeholder?: string
}

const CHANNEL_FIELDS: Record<PDRChannelType, FieldDef[]> = {
  s3: [
    { key: "s3_bucket", label: "S3 Bucket", required: true, placeholder: "my-ocsf-exports" },
    { key: "s3_region", label: "Region", placeholder: "us-east-1" },
    { key: "s3_prefix", label: "Key Prefix", placeholder: "phantex/events" },
    { key: "s3_iam_role", label: "IAM Role ARN", sensitive: true, placeholder: "arn:aws:iam::..." },
    { key: "access_key", label: "Access Key", sensitive: true },
    { key: "secret_key", label: "Secret Key", sensitive: true },
  ],
  webhook: [
    { key: "webhook_url", label: "Webhook URL", required: true, placeholder: "https://example.com/webhook" },
    { key: "webhook_secret", label: "HMAC Secret", sensitive: true },
  ],
  kafka_mirror: [
    { key: "kafka_bootstrap", label: "Bootstrap Servers", required: true, placeholder: "kafka1:9092,kafka2:9092" },
    { key: "kafka_topic", label: "Topic", placeholder: "phantex-ocsf-events" },
    { key: "kafka_sasl_mechanism", label: "SASL Mechanism", placeholder: "PLAIN" },
    { key: "kafka_sasl_username", label: "SASL Username" },
    { key: "kafka_sasl_password", label: "SASL Password", sensitive: true },
  ],
}

const TYPE_LABELS: Record<PDRChannelType, string> = {
  s3: "S3 Drops",
  webhook: "Webhook Push",
  kafka_mirror: "Kafka Mirror",
}

/* ── Component ─────────────────────────────────────────────────────────────── */

interface ChannelFormProps {
  onSubmit: (payload: PDRChannelCreate) => void
  onCancel: () => void
  isPending?: boolean
}

export function ChannelForm({ onSubmit, onCancel, isPending }: ChannelFormProps) {
  const [name, setName] = useState("")
  const [channelType, setChannelType] = useState<PDRChannelType>("s3")
  const [config, setConfig] = useState<Record<string, string>>({})
  const [piiFields, setPiiFields] = useState("")
  const [enabled, setEnabled] = useState(true)

  const fields = CHANNEL_FIELDS[channelType]

  const handleConfigChange = useCallback(
    (key: string, value: string) => {
      setConfig((prev) => ({ ...prev, [key]: value }))
    },
    [],
  )

  const handleTypeChange = useCallback(
    (e: React.ChangeEvent<HTMLSelectElement>) => {
      setChannelType(e.target.value as PDRChannelType)
      setConfig({}) // reset config when type changes
    },
    [],
  )

  const handleSubmit = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault()
      if (!name.trim()) return

      // Build config object, omitting empty strings
      const cleanConfig: Record<string, unknown> = {}
      for (const [k, v] of Object.entries(config)) {
        if (v.trim()) cleanConfig[k] = v.trim()
      }

      // Parse PII fields
      const pii = piiFields
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean)

      onSubmit({
        name: name.trim(),
        channel_type: channelType,
        config: cleanConfig,
        pii_fields: pii.length > 0 ? pii : null,
        enabled,
      })
    },
    [name, channelType, config, piiFields, enabled, onSubmit],
  )

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm">New Export Channel</CardTitle>
          <Button
            variant="ghost"
            size="icon"
            onClick={onCancel}
            aria-label="Cancel"
          >
            <X className="h-4 w-4" />
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Name */}
          <div>
            <label
              htmlFor="channel-name"
              className="text-[10px] uppercase tracking-widest text-muted-foreground"
            >
              Channel Name *
            </label>
            <Input
              id="channel-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Production S3 Export"
              maxLength={128}
              required
              className="mt-1"
            />
          </div>

          {/* Type */}
          <div>
            <label
              htmlFor="channel-type"
              className="text-[10px] uppercase tracking-widest text-muted-foreground"
            >
              Channel Type *
            </label>
            <select
              id="channel-type"
              value={channelType}
              onChange={handleTypeChange}
              className="mt-1 w-full rounded-md border border-border/50 bg-background px-3 py-2 text-sm"
            >
              <option value="s3">{TYPE_LABELS.s3}</option>
              <option value="webhook">{TYPE_LABELS.webhook}</option>
              <option value="kafka_mirror">{TYPE_LABELS.kafka_mirror}</option>
            </select>
          </div>

          {/* Type-specific config fields */}
          <fieldset className="space-y-3 border border-border/30 rounded-lg p-3">
            <legend className="text-[10px] uppercase tracking-widest text-muted-foreground px-1">
              {TYPE_LABELS[channelType]} Configuration
            </legend>
            {fields.map((f) => (
              <div key={f.key}>
                <label
                  htmlFor={`config-${f.key}`}
                  className="text-[10px] uppercase tracking-widest text-muted-foreground"
                >
                  {f.label}
                  {f.required ? " *" : ""}
                </label>
                <Input
                  id={`config-${f.key}`}
                  type={f.sensitive ? "password" : "text"}
                  value={config[f.key] ?? ""}
                  onChange={(e) => handleConfigChange(f.key, e.target.value)}
                  placeholder={f.placeholder}
                  required={f.required}
                  maxLength={2048}
                  autoComplete="off"
                  className="mt-1"
                />
              </div>
            ))}
          </fieldset>

          {/* PII Fields */}
          <div>
            <label
              htmlFor="pii-fields"
              className="text-[10px] uppercase tracking-widest text-muted-foreground"
            >
              PII Fields to Redact
            </label>
            <Input
              id="pii-fields"
              value={piiFields}
              onChange={(e) => setPiiFields(e.target.value)}
              placeholder="user.email, user.name"
              maxLength={1024}
              className="mt-1"
            />
            <p className="text-[10px] text-muted-foreground mt-1">
              Comma-separated dotted-path field names
            </p>
          </div>

          {/* Enabled */}
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
              className="rounded border-border"
            />
            <span className="text-xs">Enable immediately</span>
          </label>

          {/* Actions */}
          <div className="flex items-center gap-2 pt-2">
            <Button type="submit" size="sm" disabled={isPending}>
              {isPending ? "Creating…" : "Create Channel"}
            </Button>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={onCancel}
            >
              Cancel
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  )
}
