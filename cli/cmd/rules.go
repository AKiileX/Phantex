// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AKiileX/Phantex/cli/internal/client"
	"github.com/AKiileX/Phantex/cli/internal/config"
	"github.com/AKiileX/Phantex/cli/internal/output"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Manage detection rules",
}

var rulesListLimit int

var rulesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List detection rules",
	RunE:  runRulesList,
}

var rulesGetCmd = &cobra.Command{
	Use:   "get [rule-id]",
	Short: "Get rule details",
	Args:  cobra.ExactArgs(1),
	RunE:  runRulesGet,
}

var rulesCreateFile string

var rulesCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a detection rule from JSON or YAML file",
	RunE:  runRulesCreate,
}

var rulesDeleteCmd = &cobra.Command{
	Use:   "delete [rule-id]",
	Short: "Delete a detection rule",
	Args:  cobra.ExactArgs(1),
	RunE:  runRulesDelete,
}

var rulesToggleCmd = &cobra.Command{
	Use:   "toggle [rule-id]",
	Short: "Toggle a rule enabled/disabled",
	Args:  cobra.ExactArgs(1),
	RunE:  runRulesToggle,
}

func init() {
	rulesListCmd.Flags().IntVar(&rulesListLimit, "limit", 50, "Max results")
	rulesCreateCmd.Flags().StringVarP(&rulesCreateFile, "file", "f", "", "JSON or YAML file with rule definition (required)")
	rulesCreateCmd.MarkFlagRequired("file")

	rulesCmd.AddCommand(rulesListCmd)
	rulesCmd.AddCommand(rulesGetCmd)
	rulesCmd.AddCommand(rulesCreateCmd)
	rulesCmd.AddCommand(rulesDeleteCmd)
	rulesCmd.AddCommand(rulesToggleCmd)
}

func runRulesList(_ *cobra.Command, _ []string) error {
	cfg := config.MustLoad()
	c := client.New(cfg.BaseURL, cfg.AccessToken)

	path := fmt.Sprintf("/api/v1/rules?limit=%d", rulesListLimit)
	respBody, err := c.Get(context.Background(), path)
	if err != nil {
		return err
	}

	var result struct {
		Items []struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			Severity  string `json:"severity"`
			EventType string `json:"event_type"`
			Enabled   bool   `json:"enabled"`
		} `json:"items"`
		HasMore bool `json:"has_more"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	if outputJSON {
		return output.JSON(result)
	}

	headers := []string{"ID", "NAME", "SEVERITY", "EVENT TYPE", "ENABLED"}
	var rows [][]string
	for _, r := range result.Items {
		enabled := "✓"
		if !r.Enabled {
			enabled = "✗"
		}
		rows = append(rows, []string{shortID(r.ID), r.Name, r.Severity, r.EventType, enabled})
	}
	output.Table(headers, rows)
	return nil
}

func runRulesGet(_ *cobra.Command, args []string) error {
	cfg := config.MustLoad()
	c := client.New(cfg.BaseURL, cfg.AccessToken)

	respBody, err := c.Get(context.Background(), "/api/v1/rules/"+args[0])
	if err != nil {
		return err
	}

	var rule map[string]any
	json.Unmarshal(respBody, &rule)
	return output.JSON(rule)
}

func runRulesCreate(_ *cobra.Command, _ []string) error {
	cfg := config.MustLoad()
	c := client.New(cfg.BaseURL, cfg.AccessToken)

	data, err := os.ReadFile(rulesCreateFile)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	var rule map[string]any
	ext := strings.ToLower(filepath.Ext(rulesCreateFile))
	switch ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &rule); err != nil {
			return fmt.Errorf("invalid YAML: %w", err)
		}
	default:
		if err := json.Unmarshal(data, &rule); err != nil {
			return fmt.Errorf("invalid JSON: %w", err)
		}
	}

	respBody, err := c.Post(context.Background(), "/api/v1/rules", rule)
	if err != nil {
		return err
	}

	var result map[string]any
	json.Unmarshal(respBody, &result)

	fmt.Printf("Rule created: %v\n", result["id"])
	return nil
}

func runRulesDelete(_ *cobra.Command, args []string) error {
	cfg := config.MustLoad()
	c := client.New(cfg.BaseURL, cfg.AccessToken)

	if err := c.Delete(context.Background(), "/api/v1/rules/"+args[0]); err != nil {
		return err
	}

	fmt.Printf("Rule %s deleted\n", shortID(args[0]))
	return nil
}

func runRulesToggle(_ *cobra.Command, args []string) error {
	cfg := config.MustLoad()
	c := client.New(cfg.BaseURL, cfg.AccessToken)

	// Get current state
	respBody, err := c.Get(context.Background(), "/api/v1/rules/"+args[0])
	if err != nil {
		return err
	}

	var rule map[string]any
	json.Unmarshal(respBody, &rule)

	enabled, _ := rule["enabled"].(bool)
	newState := !enabled

	body := map[string]any{"enabled": newState}
	if _, err := c.Patch(context.Background(), "/api/v1/rules/"+args[0], body); err != nil {
		return err
	}

	state := "enabled"
	if !newState {
		state = "disabled"
	}
	fmt.Printf("Rule %s → %s\n", shortID(args[0]), state)
	return nil
}
