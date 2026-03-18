// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// Package provider implements the Phantex Terraform provider.
//
// Resources:
//   - phantex_rule              — Detection rules (PRL)
//   - phantex_response_policy   — Auto-response policies
//   - phantex_notification      — Notification channel configs
//   - phantex_soar_integration  — SOAR platform connections
//   - phantex_soar_webhook      — Outbound webhook subscriptions
//
// Data Sources:
//   - phantex_agents            — List agents
//   - phantex_alerts            — Query alerts
package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/AKiileX/Phantex/terraform-provider-phantex/internal/client"
)

var _ provider.Provider = &PhantexProvider{}

// PhantexProvider is the Phantex Terraform provider.
type PhantexProvider struct {
	version string
}

type phantexProviderModel struct {
	BaseURL types.String `tfsdk:"base_url"`
	APIKey  types.String `tfsdk:"api_key"`
}

// New creates a new provider factory function.
func New() provider.Provider {
	return &PhantexProvider{version: "1.0.0"}
}

func (p *PhantexProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "phantex"
	resp.Version = p.version
}

func (p *PhantexProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Terraform provider for Phantex EDR — manage detection rules, response policies, and SOAR integrations as Infrastructure-as-Code.",
		Attributes: map[string]schema.Attribute{
			"base_url": schema.StringAttribute{
				Description: "Phantex API base URL (e.g. https://phantex.corp.com). Can also use PHANTEX_BASE_URL env var.",
				Optional:    true,
			},
			"api_key": schema.StringAttribute{
				Description: "SOAR API key (starts with phx_sk_). Can also use PHANTEX_API_KEY env var.",
				Optional:    true,
				Sensitive:   true,
			},
		},
	}
}

func (p *PhantexProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config phantexProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	baseURL := config.BaseURL.ValueString()
	apiKey := config.APIKey.ValueString()

	// Fall back to environment variables
	if baseURL == "" {
		baseURL = os.Getenv("PHANTEX_BASE_URL")
	}
	if apiKey == "" {
		apiKey = os.Getenv("PHANTEX_API_KEY")
	}

	if baseURL == "" {
		resp.Diagnostics.AddError("Missing base_url", "Set base_url in provider config or PHANTEX_BASE_URL env var")
		return
	}
	if apiKey == "" {
		resp.Diagnostics.AddError("Missing api_key", "Set api_key in provider config or PHANTEX_API_KEY env var")
		return
	}

	c := client.NewClient(baseURL, apiKey)
	resp.DataSourceData = c
	resp.ResourceData = c
}

func (p *PhantexProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewRuleResource,
		NewResponsePolicyResource,
		NewSOARIntegrationResource,
		NewSOARWebhookResource,
		NewNotificationResource,
	}
}

func (p *PhantexProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewAlertsDataSource,
		NewAgentsDataSource,
	}
}
