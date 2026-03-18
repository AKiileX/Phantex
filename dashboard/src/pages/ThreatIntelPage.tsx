// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Threat Intelligence Dashboard.
 *
 * 7-tab page: Overview, Indicators, Correlation, Export, Feeds, Import, History
 */

import { useState } from 'react';
import { HelpCircle } from 'lucide-react';
import {
  useIndicators,
  useAddIndicator,
  useDeactivateIndicator,
  useExpireStale,
  useCorrelate,
  useCorrelationMatches,
  useThreatIntelStats,
  useExportDestinations,
  useAddDestination,
  useRemoveDestination,
  useExportLocal,
  useExportPush,
  useExportHistory,
  useFeeds,
  useAddFeed,
  useRemoveFeed,
  useToggleFeed,
  useImportSTIX,
  useImportCSV,
  useImportManual,
  useImportHistory,
} from '../api/threatIntel';
import type { CorrelationMatch } from '../api/threatIntel';

type Tab = 'overview' | 'indicators' | 'correlation' | 'export' | 'feeds' | 'import' | 'history';

const TABS: { key: Tab; label: string }[] = [
  { key: 'overview', label: 'Overview' },
  { key: 'indicators', label: 'Indicators' },
  { key: 'correlation', label: 'Correlation' },
  { key: 'export', label: 'Export' },
  { key: 'feeds', label: 'Feeds' },
  { key: 'import', label: 'Import' },
  { key: 'history', label: 'History' },
];

const IOC_TYPES = ['ipv4', 'ipv6', 'domain', 'url', 'email', 'file_hash', 'attack_signature'];
const SEVERITIES = ['low', 'medium', 'high', 'critical'];
const DEST_TYPES = ['local', 'webhook', 'taxii', 'siem', 'misp'];
const FEED_TYPES = ['stix_taxii', 'csv', 'json', 'misp'];

const sevColor: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
};

export default function ThreatIntelPage() {
  const [tab, setTab] = useState<Tab>('overview');
  const [showGuide, setShowGuide] = useState(false);

  return (
    <div style={{ padding: 24, maxWidth: 1200 }}>
      <div className="flex items-center justify-between">
        <div>
          <h1 style={{ marginBottom: 8 }}>Threat Intelligence</h1>
          <p style={{ color: '#888', marginBottom: 20 }}>
            Local IoC engine &middot; STIX 2.1 export &middot; Pluggable feed import &middot; Live correlation
          </p>
        </div>
        <button onClick={() => setShowGuide(!showGuide)} className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"><HelpCircle size={14} />{showGuide ? "Hide Guide" : "How does this work?"}</button>
      </div>

      {/* Tab bar */}
      <div style={{ display: 'flex', gap: 4, borderBottom: '1px solid #333', marginBottom: 20 }}>
        {TABS.map(t => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            style={{
              padding: '8px 16px',
              background: tab === t.key ? '#2563eb' : 'transparent',
              color: tab === t.key ? '#fff' : '#aaa',
              border: 'none',
              borderRadius: '6px 6px 0 0',
              cursor: 'pointer',
              fontWeight: tab === t.key ? 600 : 400,
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'overview' && <OverviewTab />}
      {tab === 'indicators' && <IndicatorsTab />}
      {tab === 'correlation' && <CorrelationTab />}
      {tab === 'export' && <ExportTab />}
      {tab === 'feeds' && <FeedsTab />}
      {tab === 'import' && <ImportTab />}
      {tab === 'history' && <HistoryTab />}

      {showGuide && (
        <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5 space-y-3 text-sm text-muted-foreground" style={{ marginTop: 20 }}>
          <h3 className="text-base font-semibold text-foreground">How does Threat Intelligence work?</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">IoC Indicators</p>
              <p>Manages Indicators of Compromise via <code className="text-xs bg-white/5 px-1 rounded">/api/threat-intel/indicators</code>. Supports IPv4, domains, hashes, URLs, and emails. Each indicator carries severity, confidence, and active/expired status. Bulk deactivate or expire stale indicators.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Live Correlation</p>
              <p>The correlation engine at <code className="text-xs bg-white/5 px-1 rounded">/api/threat-intel/correlate</code> matches IoC values against incoming events and alerts in real time. Matches appear with confidence scores and timestamps. Stats from <code className="text-xs bg-white/5 px-1 rounded">/api/threat-intel/stats</code>.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Feed Import</p>
              <p>Ingest indicators from external feeds: STIX/TAXII, CSV, or manual entry via <code className="text-xs bg-white/5 px-1 rounded">/api/threat-intel/feeds</code> and <code className="text-xs bg-white/5 px-1 rounded">/api/threat-intel/import/*</code>. Import history tracks counts, duplicates, and correlation matches per ingestion.</p>
            </div>
            <div className="rounded-lg bg-white/[0.02] p-3 border border-border/30">
              <p className="font-medium text-foreground mb-1">Export &amp; Sharing</p>
              <p>Export indicators in STIX 2.1 format via <code className="text-xs bg-white/5 px-1 rounded">/api/threat-intel/export/local</code> or push to configured destinations with <code className="text-xs bg-white/5 px-1 rounded">/api/threat-intel/export/push</code>. Webhook destinations can be managed for automated sharing.</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ─── Overview ───────────────────────────────────────────────────────── */

function OverviewTab() {
  const { data } = useThreatIntelStats();
  if (!data) return <p>Loading...</p>;

  const cards = [
    { label: 'Active Indicators', value: data.ioc.active_indicators },
    { label: 'Total Matches', value: data.ioc.total_matches },
    { label: 'Export Destinations', value: data.export.enabled_destinations },
    { label: 'Active Feeds', value: data.import.active_feeds },
    { label: 'Total Imported', value: data.import.total_imported },
    { label: 'Correlation Matches', value: data.import.total_correlation_matches },
  ];

  return (
    <div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16, marginBottom: 24 }}>
        {cards.map(c => (
          <div key={c.label} style={{ background: '#1e1e2e', padding: 16, borderRadius: 8 }}>
            <div style={{ color: '#888', fontSize: 13 }}>{c.label}</div>
            <div style={{ fontSize: 28, fontWeight: 700 }}>{c.value}</div>
          </div>
        ))}
      </div>

      <h3 style={{ marginBottom: 8 }}>By Type</h3>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 16 }}>
        {Object.entries(data.ioc.by_type).map(([k, v]) => (
          <span key={k} style={{ background: '#1e1e2e', padding: '4px 12px', borderRadius: 4 }}>
            {k}: <strong>{v}</strong>
          </span>
        ))}
      </div>

      <h3 style={{ marginBottom: 8 }}>By Severity</h3>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        {Object.entries(data.ioc.by_severity).map(([k, v]) => (
          <span key={k} style={{ background: '#1e1e2e', padding: '4px 12px', borderRadius: 4, borderLeft: `3px solid ${sevColor[k] || '#666'}` }}>
            {k}: <strong>{v}</strong>
          </span>
        ))}
      </div>
    </div>
  );
}

/* ─── Indicators ─────────────────────────────────────────────────────── */

function IndicatorsTab() {
  const [typeFilter, setTypeFilter] = useState('');
  const [sevFilter, setSevFilter] = useState('');
  const { data } = useIndicators({ ioc_type: typeFilter || undefined, severity: sevFilter || undefined, limit: 100 });
  const addMut = useAddIndicator();
  const deactivateMut = useDeactivateIndicator();
  const expireMut = useExpireStale();
  const [value, setValue] = useState('');
  const [iocType, setIocType] = useState('ipv4');
  const [sev, setSev] = useState('medium');

  return (
    <div>
      {/* Add form */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
        <input
          placeholder="Indicator value (IP, domain, hash...)"
          value={value}
          onChange={e => setValue(e.target.value)}
          style={{ flex: 1, minWidth: 200, padding: '6px 10px', borderRadius: 4, border: '1px solid #444', background: '#1a1a2e', color: '#fff' }}
        />
        <select value={iocType} onChange={e => setIocType(e.target.value)} style={{ padding: '6px 10px', borderRadius: 4, background: '#1a1a2e', color: '#fff', border: '1px solid #444' }}>
          {IOC_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
        <select value={sev} onChange={e => setSev(e.target.value)} style={{ padding: '6px 10px', borderRadius: 4, background: '#1a1a2e', color: '#fff', border: '1px solid #444' }}>
          {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <button
          onClick={() => { if (value.trim()) { addMut.mutate({ value: value.trim(), ioc_type: iocType, severity: sev }); setValue(''); } }}
          style={{ padding: '6px 16px', background: '#2563eb', color: '#fff', border: 'none', borderRadius: 4, cursor: 'pointer' }}
        >
          Add
        </button>
        <button
          onClick={() => expireMut.mutate()}
          style={{ padding: '6px 16px', background: '#444', color: '#fff', border: 'none', borderRadius: 4, cursor: 'pointer' }}
        >
          Expire Stale
        </button>
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
        <select value={typeFilter} onChange={e => setTypeFilter(e.target.value)} style={{ padding: '4px 8px', borderRadius: 4, background: '#1a1a2e', color: '#fff', border: '1px solid #444' }}>
          <option value="">All Types</option>
          {IOC_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
        <select value={sevFilter} onChange={e => setSevFilter(e.target.value)} style={{ padding: '4px 8px', borderRadius: 4, background: '#1a1a2e', color: '#fff', border: '1px solid #444' }}>
          <option value="">All Severities</option>
          {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>

      {/* Table */}
      <div style={{ maxHeight: 500, overflowY: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid #333' }}>
              <th style={{ textAlign: 'left', padding: 8 }}>Type</th>
              <th style={{ textAlign: 'left', padding: 8 }}>Hash (SHA-256)</th>
              <th style={{ textAlign: 'left', padding: 8 }}>Severity</th>
              <th style={{ textAlign: 'left', padding: 8 }}>Source</th>
              <th style={{ textAlign: 'right', padding: 8 }}>Sightings</th>
              <th style={{ textAlign: 'left', padding: 8 }}>Last Seen</th>
              <th style={{ padding: 8 }}></th>
            </tr>
          </thead>
          <tbody>
            {(data?.indicators ?? []).map(ind => (
              <tr key={ind.id} style={{ borderBottom: '1px solid #222' }}>
                <td style={{ padding: 8 }}>{ind.ioc_type}</td>
                <td style={{ padding: 8, fontFamily: 'monospace', fontSize: 11 }}>{ind.hashed_value.slice(0, 16)}…</td>
                <td style={{ padding: 8 }}>
                  <span style={{ color: sevColor[ind.severity] || '#888' }}>{ind.severity}</span>
                </td>
                <td style={{ padding: 8 }}>{ind.source}</td>
                <td style={{ padding: 8, textAlign: 'right' }}>{ind.sighting_count}</td>
                <td style={{ padding: 8, fontSize: 11 }}>{new Date(ind.last_seen).toLocaleString()}</td>
                <td style={{ padding: 8 }}>
                  <button
                    onClick={() => deactivateMut.mutate(ind.hashed_value)}
                    style={{ padding: '2px 8px', background: '#dc2626', color: '#fff', border: 'none', borderRadius: 3, cursor: 'pointer', fontSize: 11 }}
                  >
                    Deactivate
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ─── Correlation ────────────────────────────────────────────────────── */

function CorrelationTab() {
  const [value, setValue] = useState('');
  const [result, setResult] = useState<{ match: boolean; correlation: CorrelationMatch | null } | null>(null);
  const correlateMut = useCorrelate();
  const { data: matchesData } = useCorrelationMatches({ limit: 100 });

  const handleCorrelate = () => {
    if (!value.trim()) return;
    correlateMut.mutate({ value: value.trim() }, { onSuccess: setResult });
  };

  return (
    <div>
      <h3 style={{ marginBottom: 8 }}>Check Value Against IoCs</h3>
      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        <input
          placeholder="IP, domain, hash, URL..."
          value={value}
          onChange={e => setValue(e.target.value)}
          style={{ flex: 1, padding: '6px 10px', borderRadius: 4, border: '1px solid #444', background: '#1a1a2e', color: '#fff' }}
        />
        <button
          onClick={handleCorrelate}
          style={{ padding: '6px 16px', background: '#2563eb', color: '#fff', border: 'none', borderRadius: 4, cursor: 'pointer' }}
        >
          Correlate
        </button>
      </div>

      {result && (
        <div style={{ background: result.match ? '#1a3326' : '#1e1e2e', padding: 12, borderRadius: 6, marginBottom: 20 }}>
          {result.match ? (
            <span style={{ color: '#ef4444', fontWeight: 600 }}>⚠ MATCH FOUND</span>
          ) : (
            <span style={{ color: '#22c55e' }}>✓ No match</span>
          )}
          {result.match && result.correlation && (
            <pre style={{ fontSize: 11, marginTop: 8, color: '#ccc' }}>{JSON.stringify(result.correlation, null, 2)}</pre>
          )}
        </div>
      )}

      <h3 style={{ marginBottom: 8 }}>Recent Matches</h3>
      <div style={{ maxHeight: 400, overflowY: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid #333' }}>
              <th style={{ textAlign: 'left', padding: 8 }}>Type</th>
              <th style={{ textAlign: 'left', padding: 8 }}>Matched Hash</th>
              <th style={{ textAlign: 'left', padding: 8 }}>Severity</th>
              <th style={{ textAlign: 'left', padding: 8 }}>Matched At</th>
            </tr>
          </thead>
          <tbody>
            {(matchesData?.matches ?? []).map(m => (
              <tr key={m.id} style={{ borderBottom: '1px solid #222' }}>
                <td style={{ padding: 8 }}>{m.matched_ioc_type}</td>
                <td style={{ padding: 8, fontFamily: 'monospace', fontSize: 11 }}>{m.matched_value.slice(0, 16)}…</td>
                <td style={{ padding: 8 }}>
                  <span style={{ color: sevColor[m.severity] || '#888' }}>{m.severity}</span>
                </td>
                <td style={{ padding: 8, fontSize: 11 }}>{new Date(m.matched_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ─── Export ──────────────────────────────────────────────────────────── */

function ExportTab() {
  const { data: destsData } = useExportDestinations();
  const { data: historyData } = useExportHistory();
  const addMut = useAddDestination();
  const removeMut = useRemoveDestination();
  const exportLocalMut = useExportLocal();
  const exportPushMut = useExportPush();
  const [name, setName] = useState('');
  const [destType, setDestType] = useState('webhook');
  const [url, setUrl] = useState('');

  return (
    <div>
      <h3 style={{ marginBottom: 8 }}>Export Destinations</h3>
      <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
        <input placeholder="Name" value={name} onChange={e => setName(e.target.value)} style={{ padding: '6px 10px', borderRadius: 4, border: '1px solid #444', background: '#1a1a2e', color: '#fff' }} />
        <select value={destType} onChange={e => setDestType(e.target.value)} style={{ padding: '6px 10px', borderRadius: 4, background: '#1a1a2e', color: '#fff', border: '1px solid #444' }}>
          {DEST_TYPES.map(d => <option key={d} value={d}>{d}</option>)}
        </select>
        <input placeholder="URL (optional)" value={url} onChange={e => setUrl(e.target.value)} style={{ flex: 1, minWidth: 200, padding: '6px 10px', borderRadius: 4, border: '1px solid #444', background: '#1a1a2e', color: '#fff' }} />
        <button
          onClick={() => { if (name.trim()) { addMut.mutate({ name: name.trim(), destination_type: destType, url }); setName(''); setUrl(''); } }}
          style={{ padding: '6px 16px', background: '#2563eb', color: '#fff', border: 'none', borderRadius: 4, cursor: 'pointer' }}
        >
          Add
        </button>
      </div>

      <div style={{ marginBottom: 24 }}>
        {(destsData?.destinations ?? []).map(d => (
          <div key={d.id} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: 8, borderBottom: '1px solid #222' }}>
            <span style={{ background: '#1e1e2e', padding: '2px 8px', borderRadius: 4, fontSize: 11 }}>{d.destination_type}</span>
            <span style={{ fontWeight: 600 }}>{d.name}</span>
            <span style={{ color: '#888', fontSize: 12 }}>{d.url || '(local)'}</span>
            <span style={{ marginLeft: 'auto', color: '#888', fontSize: 11 }}>Exports: {d.export_count}</span>
            <button
              onClick={() => exportPushMut.mutate({ destination_id: d.id })}
              style={{ padding: '2px 10px', background: '#2563eb', color: '#fff', border: 'none', borderRadius: 3, cursor: 'pointer', fontSize: 11 }}
            >
              Push
            </button>
            <button
              onClick={() => removeMut.mutate(d.id)}
              style={{ padding: '2px 10px', background: '#dc2626', color: '#fff', border: 'none', borderRadius: 3, cursor: 'pointer', fontSize: 11 }}
            >
              Remove
            </button>
          </div>
        ))}
      </div>

      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        <button
          onClick={() => exportLocalMut.mutate({})}
          style={{ padding: '8px 20px', background: '#059669', color: '#fff', border: 'none', borderRadius: 4, cursor: 'pointer' }}
        >
          Export STIX Bundle (Local)
        </button>
        {exportLocalMut.data && (
          <span style={{ color: '#22c55e', alignSelf: 'center', fontSize: 12 }}>
            ✓ Bundle generated — {(exportLocalMut.data as Record<string, unknown[]>).objects?.length ?? 0} objects
          </span>
        )}
      </div>

      <h3 style={{ marginBottom: 8 }}>Export History</h3>
      <div style={{ maxHeight: 300, overflowY: 'auto' }}>
        {(historyData?.exports ?? []).map((r, i) => (
          <div key={i} style={{ display: 'flex', gap: 12, padding: 6, borderBottom: '1px solid #222', fontSize: 12 }}>
            <span>{r.destination_name}</span>
            <span style={{ color: r.success ? '#22c55e' : '#ef4444' }}>{r.success ? 'OK' : 'Failed'}</span>
            <span>{r.indicator_count} indicators</span>
            <span style={{ color: '#888' }}>{new Date(r.exported_at).toLocaleString()}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ─── Feeds ──────────────────────────────────────────────────────────── */

function FeedsTab() {
  const { data: feedsData } = useFeeds();
  const addMut = useAddFeed();
  const removeMut = useRemoveFeed();
  const toggleMut = useToggleFeed();
  const [name, setName] = useState('');
  const [feedType, setFeedType] = useState('stix_taxii');
  const [url, setUrl] = useState('');

  return (
    <div>
      <h3 style={{ marginBottom: 8 }}>Import Feeds</h3>
      <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
        <input placeholder="Feed name" value={name} onChange={e => setName(e.target.value)} style={{ padding: '6px 10px', borderRadius: 4, border: '1px solid #444', background: '#1a1a2e', color: '#fff' }} />
        <select value={feedType} onChange={e => setFeedType(e.target.value)} style={{ padding: '6px 10px', borderRadius: 4, background: '#1a1a2e', color: '#fff', border: '1px solid #444' }}>
          {FEED_TYPES.map(f => <option key={f} value={f}>{f}</option>)}
        </select>
        <input placeholder="Feed URL" value={url} onChange={e => setUrl(e.target.value)} style={{ flex: 1, minWidth: 200, padding: '6px 10px', borderRadius: 4, border: '1px solid #444', background: '#1a1a2e', color: '#fff' }} />
        <button
          onClick={() => { if (name.trim()) { addMut.mutate({ name: name.trim(), feed_type: feedType, url }); setName(''); setUrl(''); } }}
          style={{ padding: '6px 16px', background: '#2563eb', color: '#fff', border: 'none', borderRadius: 4, cursor: 'pointer' }}
        >
          Add Feed
        </button>
      </div>

      <div>
        {(feedsData?.feeds ?? []).map(f => (
          <div key={f.id} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: 8, borderBottom: '1px solid #222' }}>
            <span style={{ background: '#1e1e2e', padding: '2px 8px', borderRadius: 4, fontSize: 11 }}>{f.feed_type}</span>
            <span style={{ fontWeight: 600 }}>{f.name}</span>
            <span style={{ color: '#888', fontSize: 12 }}>{f.url || '(no URL)'}</span>
            <span style={{
              padding: '2px 6px',
              borderRadius: 4,
              fontSize: 10,
              background: f.status === 'active' ? '#1a3326' : f.status === 'error' ? '#3b1111' : '#1e1e2e',
              color: f.status === 'active' ? '#22c55e' : f.status === 'error' ? '#ef4444' : '#888',
            }}>
              {f.status}
            </span>
            {f.last_sync_at && (
              <span style={{ color: '#888', fontSize: 11 }}>Last sync: {new Date(f.last_sync_at).toLocaleString()} ({f.last_sync_count})</span>
            )}
            <span style={{ marginLeft: 'auto' }} />
            <button
              onClick={() => toggleMut.mutate({ feed_id: f.id, enabled: !f.enabled })}
              style={{ padding: '2px 10px', background: f.enabled ? '#eab308' : '#22c55e', color: '#000', border: 'none', borderRadius: 3, cursor: 'pointer', fontSize: 11 }}
            >
              {f.enabled ? 'Pause' : 'Enable'}
            </button>
            <button
              onClick={() => removeMut.mutate(f.id)}
              style={{ padding: '2px 10px', background: '#dc2626', color: '#fff', border: 'none', borderRadius: 3, cursor: 'pointer', fontSize: 11 }}
            >
              Remove
            </button>
          </div>
        ))}
        {(feedsData?.feeds ?? []).length === 0 && (
          <p style={{ color: '#666' }}>No feeds configured. Add a STIX/TAXII, CSV, JSON, or MISP feed above.</p>
        )}
      </div>
    </div>
  );
}

/* ─── Import ─────────────────────────────────────────────────────────── */

function ImportTab() {
  const [importType, setImportType] = useState<'csv' | 'stix' | 'manual'>('csv');
  const [text, setText] = useState('');
  const [manualValue, setManualValue] = useState('');
  const [manualType, setManualType] = useState('ipv4');
  const [manualItems, setManualItems] = useState<Array<{ value: string; ioc_type: string }>>([]);
  const importCSV = useImportCSV();
  const importSTIX = useImportSTIX();
  const importManual = useImportManual();
  const [lastResult, setLastResult] = useState<{ imported_count: number; duplicate_count: number; correlation_matches: number } | null>(null);

  const handleImport = () => {
    if (importType === 'csv' && text.trim()) {
      importCSV.mutate({ csv_text: text }, { onSuccess: setLastResult });
    } else if (importType === 'stix' && text.trim()) {
      try {
        const bundle = JSON.parse(text);
        importSTIX.mutate({ bundle }, { onSuccess: setLastResult });
      } catch { /* invalid JSON */ }
    } else if (importType === 'manual' && manualItems.length > 0) {
      importManual.mutate(manualItems, { onSuccess: setLastResult });
    }
  };

  return (
    <div>
      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        {(['csv', 'stix', 'manual'] as const).map(t => (
          <button
            key={t}
            onClick={() => setImportType(t)}
            style={{
              padding: '6px 14px',
              background: importType === t ? '#2563eb' : '#333',
              color: '#fff',
              border: 'none',
              borderRadius: 4,
              cursor: 'pointer',
            }}
          >
            {t.toUpperCase()}
          </button>
        ))}
      </div>

      {importType !== 'manual' ? (
        <div>
          <textarea
            placeholder={importType === 'csv' ? 'value,ioc_type,severity,tags\n1.2.3.4,ipv4,high,malware|botnet' : '{"type": "bundle", "objects": [...]}'}
            value={text}
            onChange={e => setText(e.target.value)}
            style={{ width: '100%', height: 200, padding: 10, borderRadius: 4, border: '1px solid #444', background: '#1a1a2e', color: '#fff', fontFamily: 'monospace', fontSize: 12, resize: 'vertical' }}
          />
          <button
            onClick={handleImport}
            style={{ marginTop: 8, padding: '8px 20px', background: '#2563eb', color: '#fff', border: 'none', borderRadius: 4, cursor: 'pointer' }}
          >
            Import {importType.toUpperCase()}
          </button>
        </div>
      ) : (
        <div>
          <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
            <input placeholder="Value" value={manualValue} onChange={e => setManualValue(e.target.value)} style={{ flex: 1, padding: '6px 10px', borderRadius: 4, border: '1px solid #444', background: '#1a1a2e', color: '#fff' }} />
            <select value={manualType} onChange={e => setManualType(e.target.value)} style={{ padding: '6px 10px', borderRadius: 4, background: '#1a1a2e', color: '#fff', border: '1px solid #444' }}>
              {IOC_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
            </select>
            <button
              onClick={() => { if (manualValue.trim()) { setManualItems(prev => [...prev, { value: manualValue.trim(), ioc_type: manualType }]); setManualValue(''); } }}
              style={{ padding: '6px 14px', background: '#444', color: '#fff', border: 'none', borderRadius: 4, cursor: 'pointer' }}
            >
              + Add
            </button>
          </div>
          {manualItems.length > 0 && (
            <div style={{ marginBottom: 8 }}>
              {manualItems.map((item, i) => (
                <div key={i} style={{ display: 'flex', gap: 8, padding: 4, fontSize: 12 }}>
                  <span>{item.ioc_type}</span>
                  <span style={{ fontFamily: 'monospace' }}>{item.value}</span>
                  <button onClick={() => setManualItems(prev => prev.filter((_, j) => j !== i))} style={{ background: 'none', border: 'none', color: '#ef4444', cursor: 'pointer', fontSize: 11 }}>×</button>
                </div>
              ))}
            </div>
          )}
          <button
            onClick={handleImport}
            disabled={manualItems.length === 0}
            style={{ padding: '8px 20px', background: manualItems.length > 0 ? '#2563eb' : '#333', color: '#fff', border: 'none', borderRadius: 4, cursor: 'pointer' }}
          >
            Import {manualItems.length} indicators
          </button>
        </div>
      )}

      {lastResult && (
        <div style={{ marginTop: 16, padding: 12, background: '#1a3326', borderRadius: 6, fontSize: 13 }}>
          Imported: <strong>{lastResult.imported_count}</strong> &middot;
          Duplicates: <strong>{lastResult.duplicate_count}</strong> &middot;
          Correlation Matches: <strong style={{ color: lastResult.correlation_matches > 0 ? '#ef4444' : '#22c55e' }}>{lastResult.correlation_matches}</strong>
        </div>
      )}
    </div>
  );
}

/* ─── History ────────────────────────────────────────────────────────── */

function HistoryTab() {
  const { data: exportHist } = useExportHistory();
  const { data: importHist } = useImportHistory();

  return (
    <div>
      <h3 style={{ marginBottom: 8 }}>Export History</h3>
      <div style={{ maxHeight: 250, overflowY: 'auto', marginBottom: 24 }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid #333' }}>
              <th style={{ textAlign: 'left', padding: 6 }}>Destination</th>
              <th style={{ textAlign: 'left', padding: 6 }}>Type</th>
              <th style={{ textAlign: 'right', padding: 6 }}>Indicators</th>
              <th style={{ textAlign: 'left', padding: 6 }}>Status</th>
              <th style={{ textAlign: 'left', padding: 6 }}>Time</th>
            </tr>
          </thead>
          <tbody>
            {(exportHist?.exports ?? []).map((r, i) => (
              <tr key={i} style={{ borderBottom: '1px solid #222' }}>
                <td style={{ padding: 6 }}>{r.destination_name}</td>
                <td style={{ padding: 6 }}>{r.destination_type}</td>
                <td style={{ padding: 6, textAlign: 'right' }}>{r.indicator_count}</td>
                <td style={{ padding: 6, color: r.success ? '#22c55e' : '#ef4444' }}>{r.success ? 'OK' : r.error}</td>
                <td style={{ padding: 6, fontSize: 11 }}>{new Date(r.exported_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h3 style={{ marginBottom: 8 }}>Import History</h3>
      <div style={{ maxHeight: 250, overflowY: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid #333' }}>
              <th style={{ textAlign: 'left', padding: 6 }}>Feed</th>
              <th style={{ textAlign: 'right', padding: 6 }}>Imported</th>
              <th style={{ textAlign: 'right', padding: 6 }}>Duplicates</th>
              <th style={{ textAlign: 'right', padding: 6 }}>Matches</th>
              <th style={{ textAlign: 'left', padding: 6 }}>Status</th>
              <th style={{ textAlign: 'left', padding: 6 }}>Time</th>
            </tr>
          </thead>
          <tbody>
            {(importHist?.imports ?? []).map((r, i) => (
              <tr key={i} style={{ borderBottom: '1px solid #222' }}>
                <td style={{ padding: 6 }}>{r.feed_name}</td>
                <td style={{ padding: 6, textAlign: 'right' }}>{r.imported_count}</td>
                <td style={{ padding: 6, textAlign: 'right' }}>{r.duplicate_count}</td>
                <td style={{ padding: 6, textAlign: 'right', color: r.correlation_matches > 0 ? '#ef4444' : '#888' }}>{r.correlation_matches}</td>
                <td style={{ padding: 6, color: r.success ? '#22c55e' : '#ef4444' }}>{r.success ? 'OK' : r.error}</td>
                <td style={{ padding: 6, fontSize: 11 }}>{new Date(r.imported_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
