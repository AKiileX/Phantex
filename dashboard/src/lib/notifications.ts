// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Push notification service for PWA.
 *
 * Handles:
 *   - Requesting notification permission
 *   - Sending browser notifications for critical/high alerts
 *   - Notification click → navigate to alert detail
 */

/** Check if notifications are supported and permitted. */
export function canNotify(): boolean {
  return "Notification" in window && Notification.permission === "granted"
}

/** Request notification permission. Returns true if granted. */
export async function requestNotificationPermission(): Promise<boolean> {
  if (!("Notification" in window)) return false
  if (Notification.permission === "granted") return true
  if (Notification.permission === "denied") return false

  const result = await Notification.requestPermission()
  return result === "granted"
}

/** Severity → notification urgency mapping. */
const SEVERITY_LABELS: Record<string, string> = {
  critical: "🔴 CRITICAL",
  high: "🟠 HIGH",
  medium: "🟡 MEDIUM",
  low: "🔵 LOW",
  info: "ℹ️ INFO",
}

interface AlertNotificationPayload {
  id: string
  title: string
  severity: string
  agent_id?: string | null
}

/**
 * Show a browser notification for an alert.
 * Clicking the notification navigates to the alert detail page.
 */
export function notifyAlert(alert: AlertNotificationPayload): void {
  if (!canNotify()) return

  const severityLabel = SEVERITY_LABELS[alert.severity] ?? alert.severity
  const body = alert.agent_id
    ? `${severityLabel} — Agent: ${alert.agent_id}`
    : severityLabel

  const notification = new Notification(`PhanTeX Alert: ${alert.title}`, {
    body,
    icon: "/icons/pwa-192x192.png",
    badge: "/icons/pwa-192x192.png",
    tag: `phantex-alert-${alert.id}`,
    requireInteraction: alert.severity === "critical",
  } as NotificationOptions)

  notification.onclick = () => {
    window.focus()
    window.location.href = `/alerts/${alert.id}`
    notification.close()
  }
}
