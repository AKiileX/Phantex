// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/AKiileX/Phantex/terraform-provider-phantex/internal/client"
)

var _ datasource.DataSource = &AgentsDataSource{}

// AgentsDataSource reads Phantex agents.
type AgentsDataSource struct {
	client *client.Client
}

type agentModel struct {
	ID        types.String `tfsdk:"id"`
	Name      types.String `tfsdk:"name"`
	Status    types.String `tfsdk:"status"`
	Framework types.String `tfsdk:"framework"`
	OS        types.String `tfsdk:"os"`
	LastSeen  types.String `tfsdk:"last_seen"`
}

type agentsDataSourceModel struct {
	Status types.String `tfsdk:"status"`
	Limit  types.Int64  `tfsdk:"limit"`
	Agents []agentModel `tfsdk:"agents"`
}

func NewAgentsDataSource() datasource.DataSource {
	return &AgentsDataSource{}
}

func (d *AgentsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_agents"
}

func (d *AgentsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Query Phantex agents.",
		Attributes: map[string]schema.Attribute{
			"status": schema.StringAttribute{Optional: true, Description: "Filter by status (online, offline, isolated)"},
			"limit":  schema.Int64Attribute{Optional: true, Description: "Max results (default 50)"},
			"agents": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id":        schema.StringAttribute{Computed: true},
						"name":      schema.StringAttribute{Computed: true},
						"status":    schema.StringAttribute{Computed: true},
						"framework": schema.StringAttribute{Computed: true},
						"os":        schema.StringAttribute{Computed: true},
						"last_seen": schema.StringAttribute{Computed: true},
					},
				},
			},
		},
	}
}

func (d *AgentsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	d.client = req.ProviderData.(*client.Client)
}

func (d *AgentsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config agentsDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	limit := int64(50)
	if !config.Limit.IsNull() {
		limit = config.Limit.ValueInt64()
	}

	path := fmt.Sprintf("/api/v1/agents?limit=%d", limit)
	if !config.Status.IsNull() {
		path += "&status=" + config.Status.ValueString()
	}

	respBody, err := d.client.Get(ctx, path)
	if err != nil {
		resp.Diagnostics.AddError("Read agents failed", err.Error())
		return
	}

	var result struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		resp.Diagnostics.AddError("Parse agents failed", err.Error())
		return
	}

	var agents []agentModel
	for _, a := range result.Items {
		agents = append(agents, agentModel{
			ID:        toStr(a["id"]),
			Name:      toStr(a["name"]),
			Status:    toStr(a["status"]),
			Framework: toStr(a["framework"]),
			OS:        toStr(a["os"]),
			LastSeen:  toStr(a["last_seen"]),
		})
	}

	config.Agents = agents
	resp.Diagnostics.Append(resp.State.Set(ctx, config)...)
}
