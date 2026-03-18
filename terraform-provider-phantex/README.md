# Phantex Terraform Provider

Terraform provider for managing Phantex AI Agent Security Platform as Infrastructure-as-Code.

## Resources

| Resource | Description |
|----------|-------------|
| `phantex_rule` | Detection rules (PRL syntax) |
| `phantex_response_policy` | Auto-response policies |
| `phantex_soar_integration` | SOAR platform connections (XSOAR, Phantom, Tines) |
| `phantex_soar_webhook` | Outbound webhook subscriptions |
| `phantex_notification` | Notification channels (Slack, email, PagerDuty, Teams) |

## Data Sources

| Data Source | Description |
|-------------|-------------|
| `phantex_alerts` | Query alerts by severity/status |
| `phantex_agents` | List agents by status |

## Authentication

```hcl
provider "phantex" {
  base_url = "https://phantex.corp.com"    # or PHANTEX_BASE_URL env var
  api_key  = var.phantex_api_key           # or PHANTEX_API_KEY env var
}
```

### Required API Key Scopes

| Operation | Scope |
|-----------|-------|
| Read alerts | `alerts.read` |
| Execute actions | `actions.execute` |
| Manage integrations | `webhooks.manage` |
| Full access | `*` |

## Quick Start

```bash
# Build the provider
go build -o terraform-provider-phantex

# Install locally
mkdir -p ~/.terraform.d/plugins/registry.terraform.io/AKiileX/phantex/1.0.0/$(go env GOOS)_$(go env GOARCH)
cp terraform-provider-phantex ~/.terraform.d/plugins/registry.terraform.io/AKiileX/phantex/1.0.0/$(go env GOOS)_$(go env GOARCH)/

# Use it
cd examples/
terraform init
terraform plan
terraform apply
```

## Example

See [examples/main.tf](examples/main.tf) for a complete configuration example.

## Security Notes

- API keys are marked `sensitive` and never stored in state as plaintext
- Integration configs with secrets are masked by the API
- All API calls use HTTPS with the `X-Phantex-Api-Key` header
- The provider enforces TLS by default
