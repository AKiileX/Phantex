#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

# ============================================================================
# Phantex — Development Seed Data (OPT-IN ONLY)
#
# Fake agents, events, and alerts for development/testing.
# NEVER runs automatically — must be loaded explicitly via:
#
#   bash migrate.sh seed
#
# Both dev and prod start clean by default.
# ============================================================================

set -e

# Only run when explicitly requested via PHANTEX_LOAD_SEED_DATA=true
if [ "${PHANTEX_LOAD_SEED_DATA}" != "true" ]; then
    echo "NOTICE: Skipping dev seed data (set PHANTEX_LOAD_SEED_DATA=true to load)"
    exit 0
fi

echo "NOTICE: Loading development seed data..."

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'EOSQL'

BEGIN;

DO $$
DECLARE
    v_tenant_id     UUID := 'a0000000-0000-0000-0000-000000000001';
    v_admin_id      UUID := 'b0000000-0000-0000-0000-000000000001';
    v_analyst_id    UUID := 'b0000000-0000-0000-0000-000000000002';
    v_viewer_id     UUID := 'b0000000-0000-0000-0000-000000000003';
    v_agent1_id     UUID := 'c0000000-0000-0000-0000-000000000001';
    v_agent2_id     UUID := 'c0000000-0000-0000-0000-000000000002';
    v_agent3_id     UUID := 'c0000000-0000-0000-0000-000000000003';
    v_rule1_id      UUID := 'd0000000-0000-0000-0000-000000000001';
    v_rule2_id      UUID := 'd0000000-0000-0000-0000-000000000002';
    v_event_id      UUID;
    v_alert_events  UUID[] := '{}';
    i               INT;
    v_event_type    TEXT;
    v_severity      TEXT;
    v_agent_id      UUID;
    v_raw           JSONB;
    v_ts            TIMESTAMPTZ;
BEGIN

    -- ─── Dev Users (analyst + viewer) ────────────────────────────────────
    INSERT INTO users (id, tenant_id, email, password_hash, role, name) VALUES
    (v_analyst_id, v_tenant_id, 'analyst@phantex.dev',
     crypt('changeme', gen_salt('bf', 12)),
     'analyst', 'Dev Analyst'),
    (v_viewer_id, v_tenant_id, 'viewer@phantex.dev',
     crypt('changeme', gen_salt('bf', 12)),
     'viewer', 'Dev Viewer')
    ON CONFLICT (id) DO NOTHING;

    RAISE NOTICE 'Dev users created: analyst + viewer';

    -- ─── Agents ──────────────────────────────────────────────────────────
    INSERT INTO agents (id, tenant_id, paid, name, framework, framework_ver, process_pid, exe_path, cmdline, container_id, sensor_id, status) VALUES
    (v_agent1_id, v_tenant_id, 'ptx-default-tenant-dev-a1b2c3d4e5f6',
     'Research Assistant', 'langchain', '0.1.45', 12001,
     '/usr/bin/python3', 'python3 -m research_agent.main', NULL,
     'sensor-dev-001', 'active'),
    (v_agent2_id, v_tenant_id, 'ptx-default-tenant-dev-f6e5d4c3b2a1',
     'Code Generator', 'autogen', '0.4.0', 12050,
     '/usr/bin/python3', 'python3 -m codegen_agent.main', 'abc123def456',
     'sensor-dev-001', 'active'),
    (v_agent3_id, v_tenant_id, 'ptx-default-tenant-dev-112233445566',
     'Data Pipeline Crew', 'crewai', '0.28.0', 12100,
     '/usr/bin/python3', 'python3 -m data_crew.main', NULL,
     'sensor-dev-001', 'terminated')
    ON CONFLICT (id) DO NOTHING;

    RAISE NOTICE 'Dev agents created: 3';

    -- ─── Rules ───────────────────────────────────────────────────────────
    INSERT INTO rules (id, tenant_id, name, description, severity, attack_class, prl_source, enabled, author) VALUES
    (v_rule1_id, NULL,
     'Prompt Injection via File Read',
     'Detects when an agent reads a file that may contain prompt injection payloads',
     'high', 'prompt_injection',
     E'event.type == "FILE_OPEN" AND (contains(event.file.filename, "/tmp/") OR contains(event.file.filename, "/var/tmp/")) AND event.agent_id != ""',
     true, 'phantex'),
    (v_rule2_id, v_tenant_id,
     'Suspicious Outbound Connection',
     'Alerts when an agent process connects to a non-allowlisted external host',
     'critical', 'exfiltration',
     E'event.type == "NETWORK_CONNECT" AND event.network.dst_port IN [80, 443, 8080, 8443] AND NOT in_allowlist(event.network.dst_addr, "allowed_hosts") AND event.agent_id != ""',
     true, 'admin@phantex.dev')
    ON CONFLICT (id) DO NOTHING;

    RAISE NOTICE 'Dev rules created: 2';

    -- ─── Events (1000) ───────────────────────────────────────────────────
    FOR i IN 1..1000 LOOP
        v_event_id := gen_random_uuid();
        v_ts := now() - (random() * INTERVAL '24 hours');

        CASE i % 3
            WHEN 0 THEN v_agent_id := v_agent1_id;
            WHEN 1 THEN v_agent_id := v_agent2_id;
            ELSE         v_agent_id := v_agent3_id;
        END CASE;

        CASE
            WHEN i % 20 < 8  THEN v_event_type := 'PROCESS_EXEC';
            WHEN i % 20 < 13 THEN v_event_type := 'FILE_OPEN';
            WHEN i % 20 < 17 THEN v_event_type := 'NETWORK_CONNECT';
            WHEN i % 20 < 19 THEN v_event_type := 'NETWORK_DNS';
            ELSE                   v_event_type := 'MEMORY_MMAP';
        END CASE;

        CASE
            WHEN i % 50 = 0  THEN v_severity := 'high';
            WHEN i % 25 = 0  THEN v_severity := 'medium';
            WHEN i % 10 = 0  THEN v_severity := 'low';
            ELSE                   v_severity := 'info';
        END CASE;

        CASE v_event_type
            WHEN 'PROCESS_EXEC' THEN
                v_raw := jsonb_build_object(
                    'event_type', 'PROCESS_EXEC',
                    'process_exec', jsonb_build_object(
                        'pid', 12000 + (i % 200), 'ppid', 1, 'uid', 1000,
                        'comm', (ARRAY['python3','node','java','ruby','go'])[1 + (i % 5)],
                        'filename', (ARRAY['/usr/bin/python3','/usr/bin/node','/usr/bin/java'])[1 + (i % 3)],
                        'argv', 'python3 -m agent_' || (i % 10) || '.main'
                    )
                );
            WHEN 'FILE_OPEN' THEN
                v_raw := jsonb_build_object(
                    'event_type', 'FILE_OPEN',
                    'file', jsonb_build_object(
                        'operation', 'OPEN', 'pid', 12000 + (i % 200), 'uid', 1000, 'comm', 'python3',
                        'filename', (ARRAY['/etc/passwd','/tmp/prompt.txt','/home/user/.env','/var/log/syslog','/proc/self/maps'])[1 + (i % 5)],
                        'flags', 0
                    )
                );
            WHEN 'NETWORK_CONNECT' THEN
                v_raw := jsonb_build_object(
                    'event_type', 'NETWORK_CONNECT',
                    'network', jsonb_build_object(
                        'operation', 'CONNECT', 'pid', 12000 + (i % 200), 'comm', 'python3',
                        'src_addr', '10.0.0.' || (1 + (i % 254)),
                        'src_port', 40000 + (i % 10000),
                        'dst_addr', (ARRAY['api.openai.com','huggingface.co','evil-exfil.example.com','172.16.0.1'])[1 + (i % 4)],
                        'dst_port', (ARRAY[443, 80, 8080, 443])[1 + (i % 4)],
                        'protocol', 6
                    )
                );
            WHEN 'NETWORK_DNS' THEN
                v_raw := jsonb_build_object(
                    'event_type', 'NETWORK_DNS',
                    'dns', jsonb_build_object(
                        'pid', 12000 + (i % 200), 'comm', 'python3',
                        'query_name', (ARRAY['api.openai.com','huggingface.co','pypi.org','evil-exfil.example.com'])[1 + (i % 4)],
                        'query_type', 1, 'dst_addr', '8.8.8.8', 'dst_port', 53
                    )
                );
            ELSE
                v_raw := jsonb_build_object(
                    'event_type', 'MEMORY_MMAP',
                    'memory', jsonb_build_object(
                        'pid', 12000 + (i % 200), 'comm', 'python3',
                        'addr', 140000000000000 + (i * 4096),
                        'length', 4096 * (1 + (i % 10)),
                        'prot', 5, 'flags', 2
                    )
                );
        END CASE;

        INSERT INTO events (id, tenant_id, agent_id, sensor_id, event_type, severity, timestamp, raw_data)
        VALUES (v_event_id, v_tenant_id, v_agent_id, 'sensor-dev-001', v_event_type, v_severity, v_ts, v_raw);

        IF i IN (50, 150, 300, 500, 750) THEN
            v_alert_events := v_alert_events || v_event_id;
        END IF;
    END LOOP;

    RAISE NOTICE 'Dev events created: 1000';

    -- ─── Alerts (5) ──────────────────────────────────────────────────────
    INSERT INTO alerts (tenant_id, agent_id, event_id, rule_id, severity, title, description, status, context) VALUES
    (v_tenant_id, v_agent1_id, v_alert_events[1], v_rule1_id,
     'high', 'Prompt injection via /tmp/prompt.txt',
     'Agent "Research Assistant" read /tmp/prompt.txt which may contain injected instructions.',
     'open', '{"matched_file": "/tmp/prompt.txt", "rule_version": 1}'::jsonb),
    (v_tenant_id, v_agent2_id, v_alert_events[2], v_rule2_id,
     'critical', 'Agent connecting to evil-exfil.example.com',
     'Agent "Code Generator" established outbound connection to unknown host evil-exfil.example.com:443.',
     'open', '{"dst_addr": "evil-exfil.example.com", "dst_port": 443}'::jsonb),
    (v_tenant_id, v_agent1_id, v_alert_events[3], v_rule1_id,
     'high', 'Prompt injection via /var/tmp payload',
     'Agent "Research Assistant" accessed a file in /var/tmp containing suspicious content.',
     'acknowledged', '{"matched_file": "/var/tmp/payload.json", "acknowledged_by": "analyst@phantex.dev"}'::jsonb),
    (v_tenant_id, v_agent3_id, v_alert_events[4], v_rule2_id,
     'critical', 'Data Pipeline connecting to suspicious endpoint',
     'Agent "Data Pipeline Crew" attempted connection to evil-exfil.example.com during data processing.',
     'resolved', '{"dst_addr": "evil-exfil.example.com", "resolution": "false positive - internal redirect"}'::jsonb),
    (v_tenant_id, v_agent2_id, v_alert_events[5], v_rule1_id,
     'medium', 'Unusual file read pattern detected',
     'Agent "Code Generator" read /proc/self/maps — possible memory layout reconnaissance.',
     'false_positive', '{"matched_file": "/proc/self/maps", "note": "normal Python behavior"}'::jsonb);

    RAISE NOTICE 'Dev alerts created: 5';

    -- ─── Audit Log ───────────────────────────────────────────────────────
    INSERT INTO audit_log (tenant_id, user_id, action, resource_type, resource_id, details, ip_address) VALUES
    (v_tenant_id, v_admin_id, 'user.login', 'user', v_admin_id,
     '{"method": "password"}'::jsonb, '127.0.0.1'),
    (v_tenant_id, v_analyst_id, 'user.login', 'user', v_analyst_id,
     '{"method": "password"}'::jsonb, '127.0.0.1'),
    (v_tenant_id, v_analyst_id, 'alert.acknowledged', 'alert', NULL,
     '{"alert_title": "Prompt injection via /var/tmp payload"}'::jsonb, '127.0.0.1'),
    (v_tenant_id, v_admin_id, 'rule.created', 'rule', v_rule2_id,
     '{"rule_name": "Suspicious Outbound Connection"}'::jsonb, '127.0.0.1');

    RAISE NOTICE 'Dev audit log entries created: 4';

END
$$;

UPDATE agents SET last_seen = now() - (random() * INTERVAL '1 hour')
WHERE status = 'active';

COMMIT;
EOSQL

echo "NOTICE: Development seed data loaded successfully"
