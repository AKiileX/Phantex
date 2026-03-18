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

var eventsCmd = &cobra.Command{
	Use:   "events",
	Short: "Query telemetry events",
}

var eventsListLimit int
var eventsListAgent string
var eventsListType string

var eventsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List recent telemetry events",
	RunE:  runEventsList,
}

func init() {
	eventsListCmd.Flags().IntVar(&eventsListLimit, "limit", 50, "Max results (1-100)")
	eventsListCmd.Flags().StringVar(&eventsListAgent, "agent", "", "Filter by agent ID")
	eventsListCmd.Flags().StringVar(&eventsListType, "type", "", "Filter by event type")

	eventsCmd.AddCommand(eventsListCmd)

	// "query" is an alias for "list" — both are documented
	eventsQueryCmd := &cobra.Command{
		Use:     "query",
		Short:   "Query telemetry events (alias for list)",
		Aliases: []string{},
		RunE:    runEventsList,
	}
	eventsQueryCmd.Flags().IntVar(&eventsListLimit, "limit", 50, "Max results (1-100)")
	eventsQueryCmd.Flags().StringVar(&eventsListAgent, "agent", "", "Filter by agent ID")
	eventsQueryCmd.Flags().StringVar(&eventsListType, "type", "", "Filter by event type")
	eventsCmd.AddCommand(eventsQueryCmd)
}

func runEventsList(_ *cobra.Command, _ []string) error {
	cfg := config.MustLoad()
	c := client.New(cfg.BaseURL, cfg.AccessToken)

	path := fmt.Sprintf("/api/v1/events?limit=%d", eventsListLimit)
	if eventsListAgent != "" {
		path += "&agent_id=" + eventsListAgent
	}
	if eventsListType != "" {
		path += "&event_type=" + eventsListType
	}

	respBody, err := c.Get(context.Background(), path)
	if err != nil {
		return err
	}

	var result struct {
		Items []struct {
			ID        string `json:"id"`
			EventType string `json:"event_type"`
			AgentID   string `json:"agent_id"`
			Summary   string `json:"summary"`
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

	headers := []string{"ID", "TYPE", "AGENT", "SUMMARY", "TIME"}
	var rows [][]string
	for _, e := range result.Items {
		summary := e.Summary
		if len(summary) > 60 {
			summary = summary[:57] + "..."
		}
		rows = append(rows, []string{
			shortID(e.ID), e.EventType, shortID(e.AgentID), summary, e.CreatedAt,
		})
	}
	output.Table(headers, rows)
	return nil
}
