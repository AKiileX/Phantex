// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccRuleResource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read
			{
				Config: `
provider "phantex" {}

resource "phantex_rule" "test" {
  name        = "tf-acc-test-rule"
  description = "Acceptance test rule"
  event_type  = "PROCESS_START"
  rule_body   = "process.name == 'malicious'"
  severity    = "high"
  enabled     = true
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("phantex_rule.test", "id"),
					resource.TestCheckResourceAttr("phantex_rule.test", "name", "tf-acc-test-rule"),
					resource.TestCheckResourceAttr("phantex_rule.test", "severity", "high"),
					resource.TestCheckResourceAttr("phantex_rule.test", "enabled", "true"),
				),
			},
			// Update
			{
				Config: `
provider "phantex" {}

resource "phantex_rule" "test" {
  name        = "tf-acc-test-rule-updated"
  description = "Updated acceptance test rule"
  event_type  = "PROCESS_START"
  rule_body   = "process.name == 'malicious' && process.args contains '--inject'"
  severity    = "critical"
  enabled     = true
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("phantex_rule.test", "name", "tf-acc-test-rule-updated"),
					resource.TestCheckResourceAttr("phantex_rule.test", "severity", "critical"),
				),
			},
		},
	})
}

func TestAccResponsePolicyResource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
provider "phantex" {}

resource "phantex_response_policy" "test" {
  name         = "tf-acc-test-policy"
  description  = "Acceptance test policy"
  attack_class = "AML.T0043"
  severity     = "critical"
  action       = "isolate_agent"
  mode         = "shadow"
  enabled      = true
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("phantex_response_policy.test", "id"),
					resource.TestCheckResourceAttr("phantex_response_policy.test", "name", "tf-acc-test-policy"),
					resource.TestCheckResourceAttr("phantex_response_policy.test", "mode", "shadow"),
				),
			},
		},
	})
}

func TestAccAlertsDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
provider "phantex" {}

data "phantex_alerts" "critical" {
  severity = "critical"
  limit    = 5
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.phantex_alerts.critical", "alerts.#"),
				),
			},
		},
	})
}

func TestAccAgentsDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
provider "phantex" {}

data "phantex_agents" "all" {
  limit = 10
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.phantex_agents.all", "agents.#"),
				),
			},
		},
	})
}
