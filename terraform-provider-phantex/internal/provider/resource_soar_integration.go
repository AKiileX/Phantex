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

var _ resource.Resource = &SOARIntegrationResource{}

// SOARIntegrationResource manages a Phantex SOAR integration.
type SOARIntegrationResource struct {
	client *client.Client
}

type soarIntegrationModel struct {
	ID       types.String `tfsdk:"id"`
	Platform types.String `tfsdk:"platform"`
	Name     types.String `tfsdk:"name"`
	Config   types.String `tfsdk:"config"`
	Enabled  types.Bool   `tfsdk:"enabled"`
}

func NewSOARIntegrationResource() resource.Resource {
	return &SOARIntegrationResource{}
}

func (r *SOARIntegrationResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_soar_integration"
}

func (r *SOARIntegrationResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Phantex SOAR platform integration.",
		Attributes: map[string]schema.Attribute{
			"id":       schema.StringAttribute{Computed: true},
			"platform": schema.StringAttribute{Required: true, Description: "Platform: xsoar, phantom, tines, generic"},
			"name":     schema.StringAttribute{Required: true},
			"config":   schema.StringAttribute{Required: true, Sensitive: true, Description: "JSON config object"},
			"enabled":  schema.BoolAttribute{Optional: true},
		},
	}
}

func (r *SOARIntegrationResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(*client.Client)
}

func (r *SOARIntegrationResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan soarIntegrationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var config map[string]any
	json.Unmarshal([]byte(plan.Config.ValueString()), &config)

	body := map[string]any{
		"platform": plan.Platform.ValueString(),
		"name":     plan.Name.ValueString(),
		"config":   config,
		"enabled":  plan.Enabled.ValueBool(),
	}

	respBody, err := r.client.Post(ctx, "/api/v1/soar/integrations", body)
	if err != nil {
		resp.Diagnostics.AddError("Create integration failed", err.Error())
		return
	}

	var result map[string]any
	json.Unmarshal(respBody, &result)
	plan.ID = types.StringValue(fmt.Sprintf("%v", result["id"]))
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *SOARIntegrationResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state soarIntegrationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	respBody, err := r.client.Get(ctx, "/api/v1/soar/integrations/"+state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Read integration failed", err.Error())
		return
	}

	var result map[string]any
	json.Unmarshal(respBody, &result)

	state.Platform = types.StringValue(fmt.Sprintf("%v", result["platform"]))
	state.Name = types.StringValue(fmt.Sprintf("%v", result["name"]))
	if v, ok := result["enabled"].(bool); ok {
		state.Enabled = types.BoolValue(v)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *SOARIntegrationResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan soarIntegrationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	var state soarIntegrationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var config map[string]any
	json.Unmarshal([]byte(plan.Config.ValueString()), &config)

	body := map[string]any{
		"name":    plan.Name.ValueString(),
		"config":  config,
		"enabled": plan.Enabled.ValueBool(),
	}

	_, err := r.client.Patch(ctx, "/api/v1/soar/integrations/"+state.ID.ValueString(), body)
	if err != nil {
		resp.Diagnostics.AddError("Update integration failed", err.Error())
		return
	}

	plan.ID = state.ID
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *SOARIntegrationResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state soarIntegrationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	err := r.client.Delete(ctx, "/api/v1/soar/integrations/"+state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Delete integration failed", err.Error())
	}
}
