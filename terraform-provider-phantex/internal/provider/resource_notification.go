// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/AKiileX/Phantex/terraform-provider-phantex/internal/client"
)

var _ resource.Resource = &NotificationResource{}

// NotificationResource manages a Phantex notification channel.
type NotificationResource struct {
	client *client.Client
}

type notificationModel struct {
	ID      types.String `tfsdk:"id"`
	Name    types.String `tfsdk:"name"`
	Type    types.String `tfsdk:"type"`
	Config  types.String `tfsdk:"config"`
	Enabled types.Bool   `tfsdk:"enabled"`
}

func NewNotificationResource() resource.Resource {
	return &NotificationResource{}
}

func (r *NotificationResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_notification"
}

func (r *NotificationResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Phantex notification channel (Slack, email, PagerDuty, etc.).",
		Attributes: map[string]schema.Attribute{
			"id":      schema.StringAttribute{Computed: true, Description: "Notification channel ID"},
			"name":    schema.StringAttribute{Required: true, Description: "Channel name"},
			"type":    schema.StringAttribute{Required: true, Description: "Channel type: slack, email, pagerduty, teams, generic_webhook"},
			"config":  schema.StringAttribute{Required: true, Sensitive: true, Description: "JSON config (webhook URL, credentials, etc.)"},
			"enabled": schema.BoolAttribute{Optional: true, Description: "Whether the channel is enabled"},
		},
	}
}

func (r *NotificationResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(*client.Client)
}

func (r *NotificationResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan notificationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var config map[string]any
	if err := json.Unmarshal([]byte(plan.Config.ValueString()), &config); err != nil {
		resp.Diagnostics.AddError("Invalid config JSON", err.Error())
		return
	}

	body := map[string]any{
		"name":    plan.Name.ValueString(),
		"type":    plan.Type.ValueString(),
		"config":  config,
		"enabled": plan.Enabled.ValueBool(),
	}

	respBody, err := r.client.Post(ctx, "/api/v1/notifications/channels", body)
	if err != nil {
		resp.Diagnostics.AddError("Create notification failed", err.Error())
		return
	}

	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		resp.Diagnostics.AddError("Parse response failed", err.Error())
		return
	}

	plan.ID = types.StringValue(fmt.Sprintf("%v", result["id"]))
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *NotificationResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state notificationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	respBody, err := r.client.Get(ctx, "/api/v1/notifications/channels/"+state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Read notification failed", err.Error())
		return
	}

	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		resp.Diagnostics.AddError("Parse response failed", err.Error())
		return
	}

	state.Name = types.StringValue(fmt.Sprintf("%v", result["name"]))
	state.Type = types.StringValue(fmt.Sprintf("%v", result["type"]))
	if v, ok := result["enabled"].(bool); ok {
		state.Enabled = types.BoolValue(v)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *NotificationResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan notificationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	var state notificationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var config map[string]any
	if err := json.Unmarshal([]byte(plan.Config.ValueString()), &config); err != nil {
		resp.Diagnostics.AddError("Invalid config JSON", err.Error())
		return
	}

	body := map[string]any{
		"name":    plan.Name.ValueString(),
		"type":    plan.Type.ValueString(),
		"config":  config,
		"enabled": plan.Enabled.ValueBool(),
	}

	_, err := r.client.Patch(ctx, "/api/v1/notifications/channels/"+state.ID.ValueString(), body)
	if err != nil {
		resp.Diagnostics.AddError("Update notification failed", err.Error())
		return
	}

	plan.ID = state.ID
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *NotificationResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state notificationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	err := r.client.Delete(ctx, "/api/v1/notifications/channels/"+state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Delete notification failed", err.Error())
	}
}
