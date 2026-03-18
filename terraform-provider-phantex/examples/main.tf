# Phantex Terraform Provider — Example Configuration
#
# This example shows how to manage Phantex EDR configuration as IaC:
#   - Detection rules
#   - Auto-response policies
#   - SOAR integrations
#   - Outbound webhooks

terraform {
  required_providers {
    phantex = {
      source  = "AKiileX/phantex"
      version = "~> 1.0"
    }
  }
}

provider "phantex" {
  base_url = var.phantex_url
  api_key  = var.phantex_api_key
}

variable "phantex_url" {
  type        = string
  description = "Phantex API base URL"
  default     = "https://phantex.corp.com"
}

variable "phantex_api_key" {
  type        = string
  description = "Phantex SOAR API key"
  sensitive   = true
}

# ── Detection Rules ───────────────────────────────────────────────────────────

resource "phantex_rule" "c2_beacon" {
  name        = "C2 Beacon Detection"
  description = "Detect periodic outbound connections to suspicious endpoints"
  event_type  = "NETWORK_CONNECT"
  severity    = "critical"
  enabled     = true
  rule_body   = <<-PRL
    RULE c2_beacon_detect
    WHEN event_type == "NETWORK_CONNECT"
      AND dst_port IN [443, 8443, 4444]
      AND connection_count > 10
      AND interval_stddev < 5
    THEN
      ALERT severity="critical"
        attack_class="c2_communication"
        title="Possible C2 beacon: {agent_id} -> {dst_ip}:{dst_port}"
  PRL
}

resource "phantex_rule" "credential_access" {
  name        = "Credential File Access"
  description = "Detect reads of sensitive credential files"
  event_type  = "FILE_ACCESS"
  severity    = "high"
  enabled     = true
  rule_body   = <<-PRL
    RULE credential_file_read
    WHEN event_type == "FILE_ACCESS"
      AND operation == "read"
      AND file_path MATCHES ".*/(\.aws/credentials|\.ssh/id_rsa|\.env|shadow|SAM)$"
    THEN
      ALERT severity="high"
        attack_class="credential_access"
        title="Credential file read: {file_path} by {process_name}"
  PRL
}

# ── Auto-Response Policies ────────────────────────────────────────────────────

resource "phantex_response_policy" "isolate_c2" {
  name         = "Isolate C2 Agents"
  description  = "Auto-isolate agents with confirmed C2 communication"
  attack_class = "c2_communication"
  severity     = "critical"
  action       = "isolate_agent"
  mode         = "shadow"     # Start in shadow mode, promote to "live" after validation
  enabled      = true
}

resource "phantex_response_policy" "cred_trust_penalty" {
  name         = "Credential Access Trust Penalty"
  description  = "Apply trust penalty for credential access attempts"
  attack_class = "credential_access"
  severity     = "high"
  action       = "trust_penalty"
  mode         = "live"
  enabled      = true
}

# ── SOAR Integration ─────────────────────────────────────────────────────────

resource "phantex_soar_integration" "xsoar" {
  platform = "xsoar"
  name     = "Production XSOAR"
  enabled  = true
  config   = jsonencode({
    base_url = "https://xsoar.corp.com"
    api_key  = var.xsoar_api_key
  })
}

variable "xsoar_api_key" {
  type      = string
  sensitive = true
  default   = ""
}

# ── Outbound Webhooks ─────────────────────────────────────────────────────────

resource "phantex_soar_webhook" "critical_alerts" {
  name        = "Critical Alert Webhook"
  url         = "https://hooks.corp.com/phantex/critical"
  secret      = var.webhook_secret
  event_types = ["alert.created", "agent.isolated", "escalation.triggered"]
  enabled     = true
}

variable "webhook_secret" {
  type      = string
  sensitive = true
  default   = ""
}

# ── Data Sources ──────────────────────────────────────────────────────────────

data "phantex_alerts" "critical" {
  severity = "critical"
  status   = "open"
  limit    = 10
}

data "phantex_agents" "online" {
  status = "online"
  limit  = 50
}

output "open_critical_alerts" {
  value = data.phantex_alerts.critical.alerts
}

output "online_agents" {
  value = data.phantex_agents.online.agents
}

# ── Notification Channels ────────────────────────────────────────────────────

resource "phantex_notification" "slack_security" {
  name    = "Security Slack Channel"
  type    = "slack"
  enabled = true
  config  = jsonencode({
    webhook_url = var.slack_webhook_url
    channel     = "#security-alerts"
    username    = "Phantex"
  })
}

variable "slack_webhook_url" {
  type      = string
  sensitive = true
  default   = ""
}
