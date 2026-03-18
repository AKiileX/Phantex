// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// Package main is the entry point for the Phantex Terraform provider.
package main

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/AKiileX/Phantex/terraform-provider-phantex/internal/provider"
)

func main() {
	err := providerserver.Serve(context.Background(), provider.New, providerserver.ServeOpts{
		Address: "registry.terraform.io/AKiileX/phantex",
	})
	if err != nil {
		log.Fatal(err)
	}
}
