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

var _ resource.Resource = &ResponsePolicyResource{}

// ResponsePolicyResource manages a Phantex auto-response policy.
type ResponsePolicyResource struct {
	client *client.Client
}

type responsePolicyModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	AttackClass types.String `tfsdk:"attack_class"`
	Severity    types.String `tfsdk:"severity"`
	Action      types.String `tfsdk:"action"`
	Mode        types.String `tfsdk:"mode"`
	Enabled     types.Bool   `tfsdk:"enabled"`
}

func NewResponsePolicyResource() resource.Resource {
	return &ResponsePolicyResource{}
}

func (r *ResponsePolicyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_response_policy"
}

func (r *ResponsePolicyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Phantex auto-response policy.",
		Attributes: map[string]schema.Attribute{
			"id":           schema.StringAttribute{Computed: true, Description: "Policy ID"},
			"name":         schema.StringAttribute{Required: true, Description: "Policy name"},
			"description":  schema.StringAttribute{Optional: true},
			"attack_class": schema.StringAttribute{Required: true, Description: "ATLAS attack class to match"},
			"severity":     schema.StringAttribute{Required: true, Description: "Minimum severity to trigger"},
			"action":       schema.StringAttribute{Required: true, Description: "Action to execute (isolate_agent, block_ip, etc.)"},
			"mode":         schema.StringAttribute{Required: true, Description: "Execution mode: shadow or live"},
			"enabled":      schema.BoolAttribute{Optional: true},
		},
	}
}

func (r *ResponsePolicyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(*client.Client)
}

func (r *ResponsePolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan responsePolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	body := map[string]any{
		"name":         plan.Name.ValueString(),
		"description":  plan.Description.ValueString(),
		"attack_class": plan.AttackClass.ValueString(),
		"severity":     plan.Severity.ValueString(),
		"action":       plan.Action.ValueString(),
		"mode":         plan.Mode.ValueString(),
		"enabled":      plan.Enabled.ValueBool(),
	}

	respBody, err := r.client.Post(ctx, "/api/v1/response/policies", body)
	if err != nil {
		resp.Diagnostics.AddError("Create policy failed", err.Error())
		return
	}

	var result map[string]any
	json.Unmarshal(respBody, &result)
	plan.ID = types.StringValue(fmt.Sprintf("%v", result["id"]))
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *ResponsePolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state responsePolicyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	respBody, err := r.client.Get(ctx, "/api/v1/response/policies/"+state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Read policy failed", err.Error())
		return
	}

	var result map[string]any
	json.Unmarshal(respBody, &result)
	state.Name = types.StringValue(fmt.Sprintf("%v", result["name"]))
	state.AttackClass = types.StringValue(fmt.Sprintf("%v", result["attack_class"]))
	state.Severity = types.StringValue(fmt.Sprintf("%v", result["severity"]))
	state.Action = types.StringValue(fmt.Sprintf("%v", result["action"]))
	state.Mode = types.StringValue(fmt.Sprintf("%v", result["mode"]))
	if v, ok := result["enabled"].(bool); ok {
		state.Enabled = types.BoolValue(v)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *ResponsePolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan responsePolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	var state responsePolicyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	body := map[string]any{
		"name":         plan.Name.ValueString(),
		"description":  plan.Description.ValueString(),
		"attack_class": plan.AttackClass.ValueString(),
		"severity":     plan.Severity.ValueString(),
		"action":       plan.Action.ValueString(),
		"mode":         plan.Mode.ValueString(),
		"enabled":      plan.Enabled.ValueBool(),
	}

	_, err := r.client.Patch(ctx, "/api/v1/response/policies/"+state.ID.ValueString(), body)
	if err != nil {
		resp.Diagnostics.AddError("Update policy failed", err.Error())
		return
	}

	plan.ID = state.ID
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *ResponsePolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state responsePolicyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	err := r.client.Delete(ctx, "/api/v1/response/policies/"+state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Delete policy failed", err.Error())
	}
}
