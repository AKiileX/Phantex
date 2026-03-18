// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — PDR Channel Status Indicator (O9).
 *
 * Visual indicator for export channel status (active, error, disabled).
 * Used in the channel list table.
 *
 * @module components/exports/ChannelStatus
 */

import { Badge } from "@/components/ui/badge"

interface ChannelStatusProps {
  enabled: boolean
}

export function ChannelStatus({ enabled }: ChannelStatusProps) {
  if (!enabled) {
    return <Badge variant="terminated">Disabled</Badge>
  }
  return <Badge variant="active">Active</Badge>
}
