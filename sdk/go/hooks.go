// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

package phantex

import (
	"log"
	"strings"
)

// Hook is the interface all framework hooks implement.
type Hook interface {
	Name() string
	Install() bool
	Uninstall()
}

// hookRegistry maps hook names to constructor functions.
var hookRegistry = map[string]func(Transport, *Config) Hook{
	"openai": newOpenAIHook,
	"http":   newHTTPHook,
}

// installHooks detects and installs configured hooks.
func installHooks(transport Transport, cfg *Config) []Hook {
	hooksConfig := strings.ToLower(strings.TrimSpace(cfg.Hooks))

	var names []string
	switch hooksConfig {
	case "none":
		return nil
	case "auto":
		for name := range hookRegistry {
			names = append(names, name)
		}
	default:
		for _, name := range strings.Split(hooksConfig, ",") {
			name = strings.TrimSpace(name)
			if name != "" {
				names = append(names, name)
			}
		}
	}

	var installed []Hook
	for _, name := range names {
		ctor, ok := hookRegistry[name]
		if !ok {
			if cfg.Debug {
				log.Printf("phantex: unknown hook: %s", name)
			}
			continue
		}
		hook := ctor(transport, cfg)
		func() {
			defer func() {
				if r := recover(); r != nil {
					if cfg.Debug {
						log.Printf("phantex: hook '%s' panicked during install: %v", name, r)
					}
				}
			}()
			if hook.Install() {
				installed = append(installed, hook)
				if cfg.Debug {
					log.Printf("phantex: hook '%s' installed", name)
				}
			}
		}()
	}
	return installed
}
