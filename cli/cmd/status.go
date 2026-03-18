// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

package cmd

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/AKiileX/Phantex/cli/internal/client"
	"github.com/AKiileX/Phantex/cli/internal/config"
	"github.com/AKiileX/Phantex/cli/internal/output"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show system health status",
	RunE:  runStatus,
}

func runStatus(_ *cobra.Command, _ []string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if cfg.BaseURL == "" {
		return fmt.Errorf("not configured — run: phantex login --url <base-url>")
	}

	c := client.New(cfg.BaseURL, cfg.AccessToken)

	// Liveness
	liveBody, err := c.Get(context.Background(), "/healthz")
	if err != nil {
		fmt.Printf("  API:       UNREACHABLE (%v)\n", err)
		return nil
	}
	var liveResult struct {
		Status string `json:"status"`
	}
	json.Unmarshal(liveBody, &liveResult)

	// Readiness
	readyBody, err := c.Get(context.Background(), "/readyz")
	var readyResult struct {
		Status   string `json:"status"`
		Database string `json:"database"`
	}
	if err == nil {
		json.Unmarshal(readyBody, &readyResult)
	}

	if outputJSON {
		return output.JSON(map[string]any{
			"base_url": cfg.BaseURL,
			"api":      liveResult.Status,
			"database": readyResult.Database,
			"user":     cfg.UserEmail,
		})
	}

	fmt.Printf("Phantex Instance: %s\n", cfg.BaseURL)
	fmt.Printf("  API:       %s\n", liveResult.Status)
	fmt.Printf("  Database:  %s\n", readyResult.Database)
	if cfg.UserEmail != "" {
		fmt.Printf("  User:      %s\n", cfg.UserEmail)
	}
	return nil
}
