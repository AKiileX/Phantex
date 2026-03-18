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

var _ resource.Resource = &RuleResource{}

// RuleResource manages a Phantex detection rule.
type RuleResource struct {
	client *client.Client
}

type ruleResourceModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	EventType   types.String `tfsdk:"event_type"`
	RuleBody    types.String `tfsdk:"rule_body"`
	Severity    types.String `tfsdk:"severity"`
	Enabled     types.Bool   `tfsdk:"enabled"`
}

func NewRuleResource() resource.Resource {
	return &RuleResource{}
}

func (r *RuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_rule"
}

func (r *RuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Phantex detection rule (PRL syntax).",
		Attributes: map[string]schema.Attribute{
			"id":          schema.StringAttribute{Computed: true, Description: "Rule ID (UUID)"},
			"name":        schema.StringAttribute{Required: true, Description: "Rule name"},
			"description": schema.StringAttribute{Optional: true, Description: "Rule description"},
			"event_type":  schema.StringAttribute{Required: true, Description: "Event type (PROCESS_START, FILE_ACCESS, etc.)"},
			"rule_body":   schema.StringAttribute{Required: true, Description: "PRL rule body"},
			"severity":    schema.StringAttribute{Required: true, Description: "Severity (info, low, medium, high, critical)"},
			"enabled":     schema.BoolAttribute{Optional: true, Description: "Whether the rule is enabled"},
		},
	}
}

func (r *RuleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(*client.Client)
}

func (r *RuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ruleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	body := map[string]any{
		"name":        plan.Name.ValueString(),
		"description": plan.Description.ValueString(),
		"event_type":  plan.EventType.ValueString(),
		"rule_body":   plan.RuleBody.ValueString(),
		"severity":    plan.Severity.ValueString(),
		"enabled":     plan.Enabled.ValueBool(),
	}

	respBody, err := r.client.Post(ctx, "/api/v1/rules", body)
	if err != nil {
		resp.Diagnostics.AddError("Create rule failed", err.Error())
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

func (r *RuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ruleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	respBody, err := r.client.Get(ctx, "/api/v1/rules/"+state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Read rule failed", err.Error())
		return
	}

	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		resp.Diagnostics.AddError("Parse response failed", err.Error())
		return
	}

	state.Name = types.StringValue(fmt.Sprintf("%v", result["name"]))
	state.Description = types.StringValue(fmt.Sprintf("%v", result["description"]))
	state.EventType = types.StringValue(fmt.Sprintf("%v", result["event_type"]))
	state.RuleBody = types.StringValue(fmt.Sprintf("%v", result["rule_body"]))
	state.Severity = types.StringValue(fmt.Sprintf("%v", result["severity"]))
	if v, ok := result["enabled"].(bool); ok {
		state.Enabled = types.BoolValue(v)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *RuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan ruleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state ruleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	body := map[string]any{
		"name":        plan.Name.ValueString(),
		"description": plan.Description.ValueString(),
		"event_type":  plan.EventType.ValueString(),
		"rule_body":   plan.RuleBody.ValueString(),
		"severity":    plan.Severity.ValueString(),
		"enabled":     plan.Enabled.ValueBool(),
	}

	_, err := r.client.Patch(ctx, "/api/v1/rules/"+state.ID.ValueString(), body)
	if err != nil {
		resp.Diagnostics.AddError("Update rule failed", err.Error())
		return
	}

	plan.ID = state.ID
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *RuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ruleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.client.Delete(ctx, "/api/v1/rules/"+state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Delete rule failed", err.Error())
	}
}
