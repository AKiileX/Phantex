// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// Set at build time via -ldflags.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print CLI version",
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Printf("phantex %s\n", Version)
		fmt.Printf("  commit:  %s\n", Commit)
		fmt.Printf("  built:   %s\n", BuildDate)
		fmt.Printf("  go:      %s\n", runtime.Version())
		fmt.Printf("  os/arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	},
}
