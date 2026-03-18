# Phantex — Tines Integration (Block W4)

## Overview

These Tines story templates provide no-code SOAR automation for Phantex EDR:

| Story | Purpose |
|-------|---------|
| `phantex-alert-triage.json` | Auto-triage alerts based on trust score + severity |
| `phantex-forensics.json` | On-demand forensic data collection |

## Setup

### 1. Import Stories

In Tines → Stories → Import Story, upload the JSON files.

### 2. Configure Resources

| Resource | Value |
|----------|-------|
| `phantex_base_url` | Your Phantex API base URL (e.g. `https://phantex.corp.com`) |
| `slack_webhook_url` | Slack incoming webhook for notifications |

### 3. Configure Credentials

| Credential | Where to get it |
|------------|-----------------|
| `phantex_api_key` | Phantex Dashboard → SOAR → API Keys → Create. Scopes: `alerts.read`, `actions.execute`, `enrichment.read` |
| `webhook_secret` | Any random secret string for the forensics trigger webhook |

### 4. Triage Thresholds

The alert triage story uses these trust score thresholds (editable in the Triage Decision agent):

| Trust Score | Action |
|-------------|--------|
| < 30 | Auto-isolate agent + Slack notification |
| 30–59 | Escalate alert for manual review |
| ≥ 60 | Auto-acknowledge (low risk) |

Critical/high severity alerts are always auto-isolated regardless of trust score.

## API Endpoints Used

| Endpoint | Scope Required |
|----------|---------------|
| `GET /api/v1/soar/ext/alerts` | `alerts.read` |
| `GET /api/v1/soar/ext/alerts/{id}/enrich` | `enrichment.read` |
| `POST /api/v1/soar/ext/actions` | `actions.execute` |

## Security Notes

- API keys are stored as Tines credentials (encrypted at rest)
- All requests use HTTPS with `X-Phantex-Api-Key` header
- The forensics story webhook should be protected with a secret
- Trust score thresholds can be adjusted per organizational risk tolerance
