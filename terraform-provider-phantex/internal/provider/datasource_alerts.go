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

var _ datasource.DataSource = &AlertsDataSource{}

// AlertsDataSource reads Phantex alerts.
type AlertsDataSource struct {
	client *client.Client
}

type alertModel struct {
	ID        types.String `tfsdk:"id"`
	Title     types.String `tfsdk:"title"`
	Severity  types.String `tfsdk:"severity"`
	Status    types.String `tfsdk:"status"`
	AgentID   types.String `tfsdk:"agent_id"`
	EventType types.String `tfsdk:"event_type"`
	CreatedAt types.String `tfsdk:"created_at"`
}

type alertsDataSourceModel struct {
	Severity types.String `tfsdk:"severity"`
	Status   types.String `tfsdk:"status"`
	Limit    types.Int64  `tfsdk:"limit"`
	Alerts   []alertModel `tfsdk:"alerts"`
}

func NewAlertsDataSource() datasource.DataSource {
	return &AlertsDataSource{}
}

func (d *AlertsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_alerts"
}

func (d *AlertsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Query Phantex alerts.",
		Attributes: map[string]schema.Attribute{
			"severity": schema.StringAttribute{Optional: true, Description: "Filter by severity"},
			"status":   schema.StringAttribute{Optional: true, Description: "Filter by status"},
			"limit":    schema.Int64Attribute{Optional: true, Description: "Max results (default 50)"},
			"alerts": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id":         schema.StringAttribute{Computed: true},
						"title":      schema.StringAttribute{Computed: true},
						"severity":   schema.StringAttribute{Computed: true},
						"status":     schema.StringAttribute{Computed: true},
						"agent_id":   schema.StringAttribute{Computed: true},
						"event_type": schema.StringAttribute{Computed: true},
						"created_at": schema.StringAttribute{Computed: true},
					},
				},
			},
		},
	}
}

func (d *AlertsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	d.client = req.ProviderData.(*client.Client)
}

func (d *AlertsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config alertsDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	path := "/api/v1/soar/ext/alerts?"
	if !config.Severity.IsNull() {
		path += "severity=" + config.Severity.ValueString() + "&"
	}
	if !config.Status.IsNull() {
		path += "status=" + config.Status.ValueString() + "&"
	}
	limit := int64(50)
	if !config.Limit.IsNull() {
		limit = config.Limit.ValueInt64()
	}
	path += fmt.Sprintf("limit=%d", limit)

	respBody, err := d.client.Get(ctx, path)
	if err != nil {
		resp.Diagnostics.AddError("Read alerts failed", err.Error())
		return
	}

	var result struct {
		Alerts []map[string]any `json:"alerts"`
	}
	json.Unmarshal(respBody, &result)

	var alerts []alertModel
	for _, a := range result.Alerts {
		alerts = append(alerts, alertModel{
			ID:        toStr(a["id"]),
			Title:     toStr(a["title"]),
			Severity:  toStr(a["severity"]),
			Status:    toStr(a["status"]),
			AgentID:   toStr(a["agent_id"]),
			EventType: toStr(a["event_type"]),
			CreatedAt: toStr(a["created_at"]),
		})
	}

	config.Alerts = alerts
	resp.Diagnostics.Append(resp.State.Set(ctx, config)...)
}

func toStr(v any) types.String {
	if v == nil {
		return types.StringValue("")
	}
	return types.StringValue(v.(string))
}
