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

var agentsCmd = &cobra.Command{
	Use:   "agents",
	Short: "Manage monitored agents",
}

var agentsListStatus string
var agentsListFramework string
var agentsListLimit int

var agentsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List registered agents",
	RunE:  runAgentsList,
}

var agentsGetCmd = &cobra.Command{
	Use:   "get [agent-id]",
	Short: "Get agent details",
	Args:  cobra.ExactArgs(1),
	RunE:  runAgentsGet,
}

func init() {
	agentsListCmd.Flags().StringVar(&agentsListStatus, "status", "", "Filter by status (online, offline, isolated)")
	agentsListCmd.Flags().StringVar(&agentsListFramework, "framework", "", "Filter by framework")
	agentsListCmd.Flags().IntVar(&agentsListLimit, "limit", 50, "Max results (1-100)")

	agentsCmd.AddCommand(agentsListCmd)
	agentsCmd.AddCommand(agentsGetCmd)
}

func runAgentsList(_ *cobra.Command, _ []string) error {
	cfg := config.MustLoad()
	c := client.New(cfg.BaseURL, cfg.AccessToken)

	path := fmt.Sprintf("/api/v1/agents?limit=%d", agentsListLimit)
	if agentsListStatus != "" {
		path += "&status=" + agentsListStatus
	}
	if agentsListFramework != "" {
		path += "&framework=" + agentsListFramework
	}

	respBody, err := c.Get(context.Background(), path)
	if err != nil {
		return err
	}

	var result struct {
		Items []struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			Status    string `json:"status"`
			Framework string `json:"framework"`
			OS        string `json:"os"`
			LastSeen  string `json:"last_seen"`
		} `json:"items"`
		HasMore bool `json:"has_more"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	if outputJSON {
		return output.JSON(result)
	}

	headers := []string{"ID", "NAME", "STATUS", "FRAMEWORK", "OS", "LAST SEEN"}
	var rows [][]string
	for _, a := range result.Items {
		rows = append(rows, []string{a.ID, a.Name, a.Status, a.Framework, a.OS, a.LastSeen})
	}
	output.Table(headers, rows)

	if result.HasMore {
		fmt.Println("\n(more results available — increase --limit)")
	}
	return nil
}

func runAgentsGet(_ *cobra.Command, args []string) error {
	cfg := config.MustLoad()
	c := client.New(cfg.BaseURL, cfg.AccessToken)

	respBody, err := c.Get(context.Background(), "/api/v1/agents/"+args[0])
	if err != nil {
		return err
	}

	var agent map[string]any
	json.Unmarshal(respBody, &agent)
	return output.JSON(agent)
}
