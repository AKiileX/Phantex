// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// Package main is the entry point for the phantex CLI.
package main

import (
	"os"

	"github.com/AKiileX/Phantex/cli/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
