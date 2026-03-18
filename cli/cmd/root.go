// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// Package cmd implements all phantex CLI commands.
package cmd

import (
	"github.com/spf13/cobra"
)

var (
	outputJSON bool
)

var rootCmd = &cobra.Command{
	Use:   "phantex",
	Short: "Phantex CLI — manage your AI agent security platform",
	Long: `Phantex CLI — Runtime Security Platform for AI Agents.

Manage agents, alerts, detection rules, and system health from the command line.
Authenticate with: phantex login --url https://your-phantex-instance`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&outputJSON, "json", false, "Output in JSON format")

	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(agentsCmd)
	rootCmd.AddCommand(alertsCmd)
	rootCmd.AddCommand(rulesCmd)
	rootCmd.AddCommand(eventsCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(logoutCmd)
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}
