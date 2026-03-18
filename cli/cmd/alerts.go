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

var alertsCmd = &cobra.Command{
	Use:   "alerts",
	Short: "Manage security alerts",
}

var alertsListSeverity string
var alertsListStatus string
var alertsListLimit int

var alertsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List security alerts",
	RunE:  runAlertsList,
}

var alertsGetCmd = &cobra.Command{
	Use:   "get [alert-id]",
	Short: "Get alert details",
	Args:  cobra.ExactArgs(1),
	RunE:  runAlertsGet,
}

var alertsAckCmd = &cobra.Command{
	Use:   "ack [alert-id]",
	Short: "Acknowledge an alert",
	Args:  cobra.ExactArgs(1),
	RunE:  runAlertsAck,
}

var alertsResolveCmd = &cobra.Command{
	Use:   "resolve [alert-id]",
	Short: "Resolve an alert",
	Args:  cobra.ExactArgs(1),
	RunE:  runAlertsResolve,
}

var alertsFPCmd = &cobra.Command{
	Use:   "fp [alert-id]",
	Short: "Mark alert as false positive",
	Args:  cobra.ExactArgs(1),
	RunE:  runAlertsFP,
}

func init() {
	alertsListCmd.Flags().StringVar(&alertsListSeverity, "severity", "", "Filter by severity (info, low, medium, high, critical)")
	alertsListCmd.Flags().StringVar(&alertsListStatus, "status", "", "Filter by status (open, acknowledged, resolved, false_positive)")
	alertsListCmd.Flags().IntVar(&alertsListLimit, "limit", 50, "Max results (1-100)")

	alertsCmd.AddCommand(alertsListCmd)
	alertsCmd.AddCommand(alertsGetCmd)
	alertsCmd.AddCommand(alertsAckCmd)
	alertsCmd.AddCommand(alertsResolveCmd)
	alertsCmd.AddCommand(alertsFPCmd)
}

func runAlertsList(_ *cobra.Command, _ []string) error {
	cfg := config.MustLoad()
	c := client.New(cfg.BaseURL, cfg.AccessToken)

	path := fmt.Sprintf("/api/v1/alerts?limit=%d", alertsListLimit)
	if alertsListSeverity != "" {
		path += "&severity=" + alertsListSeverity
	}
	if alertsListStatus != "" {
		path += "&status=" + alertsListStatus
	}

	respBody, err := c.Get(context.Background(), path)
	if err != nil {
		return err
	}

	var result struct {
		Items []struct {
			ID        string `json:"id"`
			Title     string `json:"title"`
			Severity  string `json:"severity"`
			Status    string `json:"status"`
			AgentID   string `json:"agent_id"`
			CreatedAt string `json:"created_at"`
		} `json:"items"`
		HasMore bool `json:"has_more"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	if outputJSON {
		return output.JSON(result)
	}

	headers := []string{"ID", "SEVERITY", "STATUS", "TITLE", "AGENT", "CREATED"}
	var rows [][]string
	for _, a := range result.Items {
		title := a.Title
		if len(title) > 50 {
			title = title[:47] + "..."
		}
		rows = append(rows, []string{
			shortID(a.ID), a.Severity, a.Status, title, shortID(a.AgentID), a.CreatedAt,
		})
	}
	output.Table(headers, rows)

	if result.HasMore {
		fmt.Println("\n(more results available — increase --limit)")
	}
	return nil
}

func runAlertsGet(_ *cobra.Command, args []string) error {
	cfg := config.MustLoad()
	c := client.New(cfg.BaseURL, cfg.AccessToken)

	respBody, err := c.Get(context.Background(), "/api/v1/alerts/"+args[0])
	if err != nil {
		return err
	}

	var alert map[string]any
	json.Unmarshal(respBody, &alert)
	return output.JSON(alert)
}

func runAlertsAck(_ *cobra.Command, args []string) error {
	return updateAlertStatus(args[0], "acknowledged")
}

func runAlertsResolve(_ *cobra.Command, args []string) error {
	return updateAlertStatus(args[0], "resolved")
}

func runAlertsFP(_ *cobra.Command, args []string) error {
	return updateAlertStatus(args[0], "false_positive")
}

func updateAlertStatus(alertID, status string) error {
	cfg := config.MustLoad()
	c := client.New(cfg.BaseURL, cfg.AccessToken)

	body := map[string]string{"status": status}
	_, err := c.Patch(context.Background(), "/api/v1/alerts/"+alertID, body)
	if err != nil {
		return err
	}

	fmt.Printf("Alert %s → %s\n", shortID(alertID), status)
	return nil
}

// shortID returns first 8 chars of a UUID for display.
func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
