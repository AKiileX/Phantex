// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Lightweight pub-sub store for Copilot panel open/close state.
 * Separated from CopilotPanel.tsx to avoid react-refresh full reloads.
 */

let _panelListeners: Array<(open: boolean) => void> = []
let _panelOpen = false

export function openCopilot() {
  _panelOpen = true
  _panelListeners.forEach((l) => l(true))
}
export function closeCopilot() {
  _panelOpen = false
  _panelListeners.forEach((l) => l(false))
}
export function toggleCopilot() {
  _panelOpen = !_panelOpen
  _panelListeners.forEach((l) => l(_panelOpen))
}

export function subscribePanelState(listener: (open: boolean) => void): () => void {
  _panelListeners.push(listener)
  return () => {
    _panelListeners = _panelListeners.filter((l) => l !== listener)
  }
}

export function getPanelOpen(): boolean {
  return _panelOpen
}
