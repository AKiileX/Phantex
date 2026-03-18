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

var _ resource.Resource = &SOARWebhookResource{}

// SOARWebhookResource manages a Phantex outbound webhook subscription.
type SOARWebhookResource struct {
	client *client.Client
}

type soarWebhookModel struct {
	ID      types.String `tfsdk:"id"`
	Name    types.String `tfsdk:"name"`
	URL     types.String `tfsdk:"url"`
	Secret  types.String `tfsdk:"secret"`
	Events  types.List   `tfsdk:"event_types"`
	Enabled types.Bool   `tfsdk:"enabled"`
}

func NewSOARWebhookResource() resource.Resource {
	return &SOARWebhookResource{}
}

func (r *SOARWebhookResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_soar_webhook"
}

func (r *SOARWebhookResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Phantex outbound SOAR webhook subscription.",
		Attributes: map[string]schema.Attribute{
			"id":          schema.StringAttribute{Computed: true},
			"name":        schema.StringAttribute{Required: true},
			"url":         schema.StringAttribute{Required: true, Description: "HTTPS webhook URL"},
			"secret":      schema.StringAttribute{Optional: true, Sensitive: true, Description: "HMAC signing secret"},
			"event_types": schema.ListAttribute{Required: true, ElementType: types.StringType, Description: "Event types to subscribe to"},
			"enabled":     schema.BoolAttribute{Optional: true},
		},
	}
}

func (r *SOARWebhookResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(*client.Client)
}

func (r *SOARWebhookResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan soarWebhookModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var events []string
	resp.Diagnostics.Append(plan.Events.ElementsAs(ctx, &events, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	body := map[string]any{
		"name":        plan.Name.ValueString(),
		"url":         plan.URL.ValueString(),
		"secret":      plan.Secret.ValueString(),
		"event_types": events,
		"enabled":     plan.Enabled.ValueBool(),
	}

	respBody, err := r.client.Post(ctx, "/api/v1/soar/webhooks", body)
	if err != nil {
		resp.Diagnostics.AddError("Create webhook failed", err.Error())
		return
	}

	var result map[string]any
	json.Unmarshal(respBody, &result)
	plan.ID = types.StringValue(fmt.Sprintf("%v", result["id"]))
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *SOARWebhookResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state soarWebhookModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.Get(ctx, "/api/v1/soar/webhooks/"+state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Read webhook failed", err.Error())
		return
	}
	// State preserved — webhook secrets are not returned by API
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *SOARWebhookResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan soarWebhookModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	var state soarWebhookModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var events []string
	resp.Diagnostics.Append(plan.Events.ElementsAs(ctx, &events, false)...)

	body := map[string]any{
		"name":        plan.Name.ValueString(),
		"url":         plan.URL.ValueString(),
		"event_types": events,
		"enabled":     plan.Enabled.ValueBool(),
	}
	if !plan.Secret.IsNull() && !plan.Secret.IsUnknown() {
		body["secret"] = plan.Secret.ValueString()
	}

	_, err := r.client.Patch(ctx, "/api/v1/soar/webhooks/"+state.ID.ValueString(), body)
	if err != nil {
		resp.Diagnostics.AddError("Update webhook failed", err.Error())
		return
	}

	plan.ID = state.ID
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *SOARWebhookResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state soarWebhookModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	err := r.client.Delete(ctx, "/api/v1/soar/webhooks/"+state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Delete webhook failed", err.Error())
	}
}
