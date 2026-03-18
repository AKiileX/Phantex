// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// Package platform — environ.go
//
// Runtime environment detection for the Phantex sensor.
// Detects WSL2, Docker/container, and platform-specific quirks
// so the sensor can adjust behavior and emit warnings.
package platform

import (
	"os"
	"runtime"
	"strings"
)

// Environment describes the detected runtime environment.
type Environment struct {
	// OS and architecture
	OS   string // "linux", "windows", "darwin"
	Arch string // "amd64", "arm64"

	// Detected platform flags
	IsWSL       bool   // Running inside WSL2
	IsContainer bool   // Running inside Docker/Podman/LXC
	IsK8s       bool   // Running inside Kubernetes pod
	WSLDistro   string // WSL distro name (e.g. "Ubuntu-24.04")

	// Warnings for the operator
	Warnings []string
}

// DetectEnvironment probes the runtime to determine where the sensor is running.
func DetectEnvironment() Environment {
	env := Environment{
		OS:   runtime.GOOS,
		Arch: runtime.GOARCH,
	}

	switch runtime.GOOS {
	case "linux":
		env.detectLinux()
	case "windows":
		// Windows detection is handled in platform_windows.go
	}

	return env
}

func (e *Environment) detectLinux() {
	// ── WSL2 detection ──────────────────────────────────────────────
	if data, err := os.ReadFile("/proc/version"); err == nil {
		ver := strings.ToLower(string(data))
		if strings.Contains(ver, "microsoft") || strings.Contains(ver, "wsl") {
			e.IsWSL = true
			if distro := os.Getenv("WSL_DISTRO_NAME"); distro != "" {
				e.WSLDistro = distro
			}
			e.Warnings = append(e.Warnings,
				"WSL2 detected: systemd PrivateTmp=yes may isolate socket namespaces. "+
					"Ensure RuntimeDirectory=phantex is set in the systemd unit "+
					"or use the WSL override at /etc/systemd/system/phantex-sensor.service.d/wsl-override.conf")
		}
	}

	// ── Container detection ─────────────────────────────────────────
	// Method 1: /.dockerenv marker file
	if _, err := os.Stat("/.dockerenv"); err == nil {
		e.IsContainer = true
	}

	// Method 2: cgroup v2 with container runtime refs
	if !e.IsContainer {
		if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
			content := string(data)
			if strings.Contains(content, "docker") ||
				strings.Contains(content, "containerd") ||
				strings.Contains(content, "kubepods") ||
				strings.Contains(content, "podman") ||
				strings.Contains(content, "lxc") {
				e.IsContainer = true
			}
		}
	}

	// Method 3: container env hint
	if !e.IsContainer {
		if os.Getenv("container") != "" {
			e.IsContainer = true
		}
	}

	if e.IsContainer {
		e.Warnings = append(e.Warnings,
			"Container environment detected: eBPF probes require privileged mode or CAP_BPF+CAP_PERFMON. "+
				"Ensure the container has the required capabilities.")
	}

	// ── Kubernetes detection ────────────────────────────────────────
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		e.IsK8s = true
	}

	// ── BTF support check ───────────────────────────────────────────
	if !e.IsContainer {
		if _, err := os.Stat("/sys/kernel/btf/vmlinux"); os.IsNotExist(err) {
			e.Warnings = append(e.Warnings,
				"BTF vmlinux not found: eBPF CO-RE probes may fail. "+
					"Ensure CONFIG_DEBUG_INFO_BTF=y in kernel config.")
		}
	}
}
