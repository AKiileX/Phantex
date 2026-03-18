# Phantex CLI

Command-line interface for the Phantex AI Agent Security Platform.

## Installation

### From source

```bash
cd cli
go build -o phantex .
sudo mv phantex /usr/local/bin/
```

### Cross-compile

```bash
make cross   # builds linux/mac/windows binaries in bin/
```

## Quick Start

```bash
# Authenticate
phantex login --url https://your-phantex-instance

# Check system health
phantex status

# List agents
phantex agents list
phantex agents list --status online --limit 20

# List alerts
phantex alerts list --severity critical
phantex alerts list --status open --limit 10

# Triage alerts
phantex alerts ack   <alert-id>
phantex alerts resolve <alert-id>
phantex alerts fp    <alert-id>     # mark as false positive

# Manage detection rules
phantex rules list
phantex rules get  <rule-id>
phantex rules create -f rule.json
phantex rules delete <rule-id>
phantex rules toggle <rule-id>      # enable/disable

# Query events
phantex events list --type PROCESS_START --agent <agent-id>

# Version info
phantex version

# Logout
phantex logout
```

## JSON Output

All list/get commands support `--json` for machine-readable output:

```bash
phantex alerts list --json | jq '.items[].severity'
```

## Configuration

Credentials stored at `~/.phantex/config.yaml` with `0600` permissions:

```yaml
base_url: https://your-phantex-instance
access_token: eyJ...
refresh_token: eyJ...
tenant_id: abc-123
user_email: analyst@example.com
```

## Commands

| Command | Description |
|---------|-------------|
| `phantex login` | Authenticate with email/password |
| `phantex logout` | Clear stored credentials |
| `phantex status` | System health check |
| `phantex agents list` | List monitored agents |
| `phantex agents get` | Get agent details |
| `phantex alerts list` | List security alerts |
| `phantex alerts get` | Get alert details |
| `phantex alerts ack` | Acknowledge alert |
| `phantex alerts resolve` | Resolve alert |
| `phantex alerts fp` | Mark as false positive |
| `phantex rules list` | List detection rules |
| `phantex rules get` | Get rule details |
| `phantex rules create` | Create rule from JSON |
| `phantex rules delete` | Delete rule |
| `phantex rules toggle` | Toggle rule enabled state |
| `phantex events list` | Query telemetry events |
| `phantex version` | Print version info |

## License

Apache 2.0 — see [LICENSE](../LICENSE)
