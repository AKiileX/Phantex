// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Threat Intelligence API Hooks.
 *
 * TanStack Query hooks for the threat intel endpoints.
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import apiClient from './client';

// ── Types ────────────────────────────────────────────────────────────────

export interface Indicator {
  id: string;
  tenant_id: string;
  ioc_type: string;
  hashed_value: string;
  severity: string;
  source: string;
  confidence: number;
  first_seen: string;
  last_seen: string;
  sighting_count: number;
  tags: string[];
  active: boolean;
  expired: boolean;
}

export interface CorrelationMatch {
  id: string;
  indicator_id: string;
  tenant_id: string;
  matched_value: string;
  matched_ioc_type: string;
  severity: string;
  matched_at: string;
  event_context: Record<string, unknown>;
}

export interface ExportDestination {
  id: string;
  tenant_id: string;
  name: string;
  destination_type: string;
  url: string;
  has_api_key: boolean;
  enabled: boolean;
  created_at: string;
  last_export_at: string | null;
  export_count: number;
}

export interface ExportResult {
  destination_id: string;
  destination_name: string;
  destination_type: string;
  indicator_count: number;
  success: boolean;
  exported_at: string;
  error: string | null;
  bundle_id: string | null;
}

export interface FeedConfig {
  id: string;
  tenant_id: string;
  name: string;
  feed_type: string;
  url: string;
  has_api_key: boolean;
  enabled: boolean;
  polling_interval_seconds: number;
  created_at: string;
  last_sync_at: string | null;
  last_sync_count: number;
  status: string;
  error_message: string | null;
}

export interface ImportResult {
  feed_id: string;
  feed_name: string;
  imported_count: number;
  duplicate_count: number;
  correlation_matches: number;
  imported_at: string;
  success: boolean;
  error: string | null;
}

export interface ThreatIntelStats {
  ioc: {
    total_indicators: number;
    active_indicators: number;
    total_matches: number;
    by_type: Record<string, number>;
    by_severity: Record<string, number>;
  };
  export: {
    destinations: number;
    enabled_destinations: number;
    total_exports: number;
    successful_exports: number;
    total_indicators_exported: number;
  };
  import: {
    total_feeds: number;
    active_feeds: number;
    total_imports: number;
    total_imported: number;
    total_correlation_matches: number;
  };
}

// ── API Helpers ──────────────────────────────────────────────────────────

const BASE = '/threat-intel';

async function api<T>(path: string, init?: { method?: string; body?: string }): Promise<T> {
  const method = init?.method ?? 'GET';
  const config: Record<string, unknown> = {};
  if (init?.body) config.data = JSON.parse(init.body);
  const res = await apiClient.request<T>({ url: `${BASE}${path}`, method, ...config });
  return res.data;
}

// ── Query keys ──────────────────────────────────────────────────────────

const keys = {
  indicators: ['threat-intel', 'indicators'] as const,
  matches: ['threat-intel', 'matches'] as const,
  stats: ['threat-intel', 'stats'] as const,
  destinations: ['threat-intel', 'destinations'] as const,
  exportHistory: ['threat-intel', 'export-history'] as const,
  feeds: ['threat-intel', 'feeds'] as const,
  importHistory: ['threat-intel', 'import-history'] as const,
};

// ── IoC Queries ─────────────────────────────────────────────────────────

export function useIndicators(params?: { ioc_type?: string; severity?: string; limit?: number }) {
  const qs = new URLSearchParams();
  if (params?.ioc_type) qs.set('ioc_type', params.ioc_type);
  if (params?.severity) qs.set('severity', params.severity);
  if (params?.limit) qs.set('limit', String(params.limit));
  const q = qs.toString();
  return useQuery({
    queryKey: [...keys.indicators, params],
    queryFn: () => api<{ indicators: Indicator[]; count: number }>(`/indicators${q ? `?${q}` : ''}`),
  });
}

export function useAddIndicator() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { value: string; ioc_type: string; severity: string; confidence?: number; tags?: string[] }) =>
      api<Indicator>('/indicators', { method: 'POST', body: JSON.stringify(body) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.indicators }),
  });
}

export function useBulkAddIndicators() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (indicators: Array<{ value: string; ioc_type: string; severity?: string }>) =>
      api<{ added: number; total: number; duplicates: number }>('/indicators/bulk', {
        method: 'POST',
        body: JSON.stringify({ indicators }),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.indicators }),
  });
}

export function useDeactivateIndicator() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (value: string) =>
      api<{ deactivated: boolean }>('/indicators', { method: 'DELETE', body: JSON.stringify({ value }) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.indicators }),
  });
}

export function useExpireStale() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api<{ expired_count: number }>('/expire', { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.indicators }),
  });
}

// ── Correlation ─────────────────────────────────────────────────────────

export function useCorrelate() {
  return useMutation({
    mutationFn: (body: { value: string; context?: Record<string, unknown> }) =>
      api<{ match: boolean; correlation: CorrelationMatch | null }>('/correlate', {
        method: 'POST',
        body: JSON.stringify(body),
      }),
  });
}

export function useCorrelationMatches(params?: { severity?: string; limit?: number }) {
  const qs = new URLSearchParams();
  if (params?.severity) qs.set('severity', params.severity);
  if (params?.limit) qs.set('limit', String(params.limit));
  const q = qs.toString();
  return useQuery({
    queryKey: [...keys.matches, params],
    queryFn: () => api<{ matches: CorrelationMatch[]; count: number }>(`/matches${q ? `?${q}` : ''}`),
  });
}

// ── Stats ───────────────────────────────────────────────────────────────

export function useThreatIntelStats() {
  return useQuery({
    queryKey: keys.stats,
    queryFn: () => api<ThreatIntelStats>('/stats'),
    refetchInterval: 30_000,
  });
}

// ── Export ───────────────────────────────────────────────────────────────

export function useExportDestinations() {
  return useQuery({
    queryKey: keys.destinations,
    queryFn: () => api<{ destinations: ExportDestination[]; count: number }>('/export/destinations'),
  });
}

export function useAddDestination() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { name: string; destination_type: string; url?: string; api_key?: string }) =>
      api<ExportDestination>('/export/destinations', { method: 'POST', body: JSON.stringify(body) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.destinations }),
  });
}

export function useRemoveDestination() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (destination_id: string) =>
      api<{ removed: boolean }>('/export/destinations', {
        method: 'DELETE',
        body: JSON.stringify({ destination_id }),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.destinations }),
  });
}

export function useExportLocal() {
  return useMutation({
    mutationFn: (body: { ioc_type?: string; severity?: string; limit?: number }) =>
      api<Record<string, unknown>>('/export/local', { method: 'POST', body: JSON.stringify(body) }),
  });
}

export function useExportPush() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { destination_id: string; ioc_type?: string; severity?: string; limit?: number }) =>
      api<ExportResult>('/export/push', { method: 'POST', body: JSON.stringify(body) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.exportHistory }),
  });
}

export function useExportHistory(limit = 50) {
  return useQuery({
    queryKey: [...keys.exportHistory, limit],
    queryFn: () => api<{ exports: ExportResult[]; count: number }>(`/export/history?limit=${limit}`),
  });
}

// ── Feeds / Import ──────────────────────────────────────────────────────

export function useFeeds() {
  return useQuery({
    queryKey: keys.feeds,
    queryFn: () => api<{ feeds: FeedConfig[]; count: number }>('/feeds'),
  });
}

export function useAddFeed() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { name: string; feed_type: string; url?: string; api_key?: string; polling_interval_seconds?: number }) =>
      api<FeedConfig>('/feeds', { method: 'POST', body: JSON.stringify(body) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.feeds }),
  });
}

export function useRemoveFeed() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (feed_id: string) =>
      api<{ removed: boolean }>('/feeds', { method: 'DELETE', body: JSON.stringify({ feed_id }) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.feeds }),
  });
}

export function useToggleFeed() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { feed_id: string; enabled: boolean }) =>
      api<FeedConfig>('/feeds/toggle', { method: 'POST', body: JSON.stringify(body) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.feeds }),
  });
}

export function useImportSTIX() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { feed_id?: string; bundle: Record<string, unknown> }) =>
      api<ImportResult>('/import/stix', { method: 'POST', body: JSON.stringify(body) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: keys.indicators });
      qc.invalidateQueries({ queryKey: keys.importHistory });
    },
  });
}

export function useImportCSV() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { feed_id?: string; csv_text: string }) =>
      api<ImportResult>('/import/csv', { method: 'POST', body: JSON.stringify(body) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: keys.indicators });
      qc.invalidateQueries({ queryKey: keys.importHistory });
    },
  });
}

export function useImportJSON() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { feed_id?: string; json_text: string }) =>
      api<ImportResult>('/import/json', { method: 'POST', body: JSON.stringify(body) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: keys.indicators });
      qc.invalidateQueries({ queryKey: keys.importHistory });
    },
  });
}

export function useImportManual() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (indicators: Array<{ value: string; ioc_type: string; severity?: string; confidence?: number }>) =>
      api<ImportResult>('/import/manual', { method: 'POST', body: JSON.stringify({ indicators }) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: keys.indicators });
      qc.invalidateQueries({ queryKey: keys.importHistory });
    },
  });
}

export function useImportHistory(limit = 50) {
  return useQuery({
    queryKey: [...keys.importHistory, limit],
    queryFn: () => api<{ imports: ImportResult[]; count: number }>(`/import/history?limit=${limit}`),
  });
}
