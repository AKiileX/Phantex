// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/AKiileX/Phantex/cli/internal/client"
	"github.com/AKiileX/Phantex/cli/internal/config"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var loginURL string

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with a Phantex instance",
	Long:  "Authenticate with email + password and store JWT tokens locally.",
	RunE:  runLogin,
}

func init() {
	loginCmd.Flags().StringVar(&loginURL, "url", "", "Phantex base URL (e.g. https://phantex.corp.com)")
}

func runLogin(_ *cobra.Command, _ []string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	// Use --url flag or existing config
	if loginURL != "" {
		cfg.BaseURL = strings.TrimRight(loginURL, "/")
	}
	if cfg.BaseURL == "" {
		return fmt.Errorf("provide --url flag or set base_url in ~/.phantex/config.yaml")
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Email: ")
	email, _ := reader.ReadString('\n')
	email = strings.TrimSpace(email)

	fmt.Print("Password: ")
	pwBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("read password: %w", err)
	}
	fmt.Println()
	password := string(pwBytes)

	c := client.New(cfg.BaseURL, "")
	body := map[string]string{
		"email":    email,
		"password": password,
	}

	respBody, err := c.Post(context.Background(), "/api/v1/auth/login", body)
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	var result struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TenantID     string `json:"tenant_id"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	cfg.AccessToken = result.AccessToken
	cfg.RefreshToken = result.RefreshToken
	cfg.TenantID = result.TenantID
	cfg.UserEmail = email

	if err := config.Save(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	fmt.Printf("Authenticated as %s\n", email)
	fmt.Printf("Config saved to ~/.phantex/config.yaml\n")
	return nil
}
