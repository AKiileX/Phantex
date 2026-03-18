// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

package cmd

import (
	"fmt"

	"github.com/AKiileX/Phantex/cli/internal/config"
	"github.com/spf13/cobra"
)

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Clear stored credentials",
	RunE: func(_ *cobra.Command, _ []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		cfg.AccessToken = ""
		cfg.RefreshToken = ""
		cfg.UserEmail = ""
		if err := config.Save(cfg); err != nil {
			return err
		}
		fmt.Println("Logged out. Credentials cleared.")
		return nil
	},
}
