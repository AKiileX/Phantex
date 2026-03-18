# PHANTEX — On-Premises Upgrade & Rollback

Safe upgrade path for air-gapped and on-premises PHANTEX deployments.

## Upgrade Flow

```
Pre-flight → Backup → Load Images → Migrate DB → Deploy → Health Check
                                                              │
                                                    ┌─────────┴──────────┐
                                                    │                    │
                                                 HEALTHY              UNHEALTHY
                                                    │                    │
                                                 Success          Auto-Rollback
```

## Quick Start

### Upgrade

```bash
./upgrade.sh \
    --version 0.3.0 \
    --bundle phantex-airgap-0.3.0.tar.gz
```

### Rollback

```bash
./upgrade.sh rollback
```

### Status

```bash
./upgrade.sh status
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `--version` | Target version | (required) |
| `--bundle` | Path to air-gap bundle .tar.gz | (required) |
| `--namespace` | Kubernetes namespace | `phantex` |
| `--values` | Helm values override file | auto-detect |
| `--docker-compose` | Use Docker Compose mode | false |
| `--backup-dir` | Backup directory | `/var/lib/phantex/backups` |
| `--health-timeout` | Health check timeout (seconds) | 300 |

## What Gets Backed Up

Before every upgrade, the following is backed up:

| Component | File | Description |
|-----------|------|-------------|
| Helm values | `helm-values.yaml` | Current release configuration |
| Helm manifest | `helm-manifest.yaml` | Current deployed manifests |
| DB schema | `schema.sql` | Complete database schema |
| Response config | `response_config.sql` | Auto-response configuration |
| Response policies | `response_policies.sql` | Response policy definitions |
| Drift policy | `drift_policy.sql` | Drift detection configuration |
| Detection policies | `detection_policies.sql` | Detection rule policies |

## Automatic Rollback

The upgrade uses `helm upgrade --atomic`, which means:
- If any pod fails to reach `Ready` state within the timeout → automatic rollback
- If the health check gate fails after deployment → automatic rollback
- Rollback restores the previous Helm revision

## Upgrade History

All upgrades and rollbacks are logged to `$BACKUP_DIR/upgrade-history.jsonl`:

```jsonl
{"timestamp": "2026-03-06T10:30:00Z", "action": "upgrade", "from": "0.2.0", "to": "0.3.0", "status": "success"}
{"timestamp": "2026-03-07T14:00:00Z", "action": "upgrade", "from": "0.3.0", "to": "0.3.1", "status": "failed"}
{"timestamp": "2026-03-07T14:05:00Z", "action": "rollback", "from": "0.3.1", "to": "0.3.0", "status": "success"}
```

## Database Migration Strategy

- Migrations are **forward-only** (no down migrations)
- Each migration is **idempotent** (`IF NOT EXISTS` / `ON CONFLICT DO NOTHING`)
- Migrations are applied **before** the new code deploys
- Schema changes are **backward-compatible** (add columns, not remove)

If a rollback is needed:
1. Code rolls back to previous version
2. New columns/tables remain but are ignored by old code
3. Data in new columns is preserved for when upgrade is re-attempted

## Supported Platforms

| Platform | Tested | Notes |
|----------|--------|-------|
| K3s 1.28+ | Yes | Default for single-node on-prem |
| RKE2 1.27+ | Yes | Rancher's hardened K8s |
| OpenShift 4.12+ | Yes | Set `podSecurityStandards.enforce: restricted` |
| Docker Compose | Yes | For non-K8s environments |
