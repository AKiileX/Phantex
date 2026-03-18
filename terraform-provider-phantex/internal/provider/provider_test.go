// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/AKiileX/Phantex/terraform-provider-phantex/internal/provider"
)

var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"phantex": providerserver.NewProtocol6WithError(provider.New()),
}

func testAccPreCheck(t *testing.T) {
	t.Helper()
	// Require PHANTEX_BASE_URL and PHANTEX_API_KEY for acceptance tests
	// These are checked at test runtime via the provider Configure method
}
