// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

//go:build windows

// Command phantex-sensor-ctl provides installer/management operations
// for the Phantex Windows sensor service.
//
// Usage:
//
//	phantex-sensor-ctl.exe install          — registers Windows service
//	phantex-sensor-ctl.exe uninstall        — removes Windows service
//	phantex-sensor-ctl.exe init-config      — creates default sensor.yaml
//	phantex-sensor-ctl.exe status           — shows service status
//	phantex-sensor-ctl.exe version          — prints version
//
// All commands require Administrator privileges.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/AKiileX/Phantex/sensor/internal/platform/service"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "install":
		doInstall()
	case "uninstall":
		doUninstall()
	case "init-config":
		doInitConfig()
	case "status":
		doStatus()
	case "version":
		fmt.Println("phantex-sensor-ctl", version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Phantex Sensor Control (Windows)

Usage: phantex-sensor-ctl.exe <command>

Commands:
  install       Register Phantex sensor as a Windows service
  uninstall     Remove the Phantex sensor service
  init-config   Create default sensor.yaml in %%ProgramData%%\Phantex
  status        Show service status
  version       Print version

All commands require Administrator privileges.
`)
}

func doInstall() {
	// Ensure config directory exists with proper ACLs
	if err := service.EnsureConfigDir(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create config directory: %v\n", err)
		os.Exit(1)
	}

	// Find sensor binary (same directory as this tool, or explicit path)
	sensorExe := filepath.Join(filepath.Dir(os.Args[0]), "phantex-sensor.exe")
	if len(os.Args) > 2 {
		sensorExe = os.Args[2]
	}

	fmt.Printf("Installing Phantex sensor service...\n")
	fmt.Printf("  Binary: %s\n", sensorExe)

	if err := service.Install(sensorExe); err != nil {
		fmt.Fprintf(os.Stderr, "install failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Service installed successfully.")
	fmt.Println("")
	fmt.Println("Next steps:")
	fmt.Println("  1. Set authentication token:  setx PHANTEX_AUTH_TOKEN <token> /M")
	fmt.Println("  2. Configure sensor:          notepad %ProgramData%\\Phantex\\sensor.yaml")
	fmt.Println("  3. Start service:             net start PhantexSensor")
}

func doUninstall() {
	fmt.Println("Uninstalling Phantex sensor service...")

	if err := service.Uninstall(); err != nil {
		fmt.Fprintf(os.Stderr, "uninstall failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Service uninstalled successfully.")
}

func doInitConfig() {
	if err := service.EnsureConfigDir(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create config directory: %v\n", err)
		os.Exit(1)
	}

	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	configPath := filepath.Join(programData, "Phantex", "sensor.yaml")

	// Don't overwrite existing config
	if _, err := os.Stat(configPath); err == nil {
		fmt.Fprintf(os.Stderr, "config already exists: %s\n", configPath)
		fmt.Fprintln(os.Stderr, "use --force to overwrite (not implemented yet)")
		os.Exit(1)
	}

	tenantID := "your-tenant-id"
	sensorID := ""
	if len(os.Args) > 2 {
		tenantID = os.Args[2]
	}
	if len(os.Args) > 3 {
		sensorID = os.Args[3]
	}

	configYAML := service.DefaultConfigYAML(tenantID, sensorID)
	if err := os.WriteFile(configPath, []byte(configYAML), 0640); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write config: %v\n", err)
		os.Exit(1)
	}

	// Also create TLS directory
	tlsDir := filepath.Join(programData, "Phantex", "tls")
	if err := os.MkdirAll(tlsDir, 0750); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to create TLS dir: %v\n", err)
	}

	fmt.Printf("Config created: %s\n", configPath)
	fmt.Printf("TLS directory: %s\n", tlsDir)
	fmt.Println("")
	fmt.Println("Edit the config file and set your tenant_id and gateway_addr.")
}

func doStatus() {
	fmt.Println("Phantex Sensor Status")
	fmt.Println("---------------------")

	if service.IsRunningAsService() {
		fmt.Println("Mode: Windows Service")
	} else {
		fmt.Println("Mode: Standalone (not a service)")
	}

	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	configPath := filepath.Join(programData, "Phantex", "sensor.yaml")
	if _, err := os.Stat(configPath); err == nil {
		fmt.Printf("Config: %s (exists)\n", configPath)
	} else {
		fmt.Printf("Config: %s (NOT FOUND)\n", configPath)
	}

	fmt.Printf("Version: %s\n", version)
}
