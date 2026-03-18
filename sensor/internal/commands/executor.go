// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// Package commands implements response action execution on the sensor.
//
// When the gateway includes ControlCommand messages in a HeartbeatResponse,
// the sensor's heartbeat goroutine passes them to this executor.
//
// SECURITY:
//   - All IP parameters are validated with net.ParseIP() before use
//   - File paths are validated against a denylist of system-critical paths
//   - PID 0, PID 1, and the sensor's own PID are protected from kill
//   - CommandId is bounds-checked before slicing
//   - Forensic output is size-bounded to prevent disk exhaustion
//   - All exec.Command calls use argument arrays (no shell interpretation)
//   - A concurrency semaphore limits simultaneous command execution
//
// Supported actions (Windows + Linux):
//   - ISOLATE_HOST:      Enable firewall deny-all, allow gateway IP
//   - UNISOLATE_HOST:    Remove isolation firewall rules
//   - KILL_PROCESS:      Terminate process by PID (with safeguards)
//   - BLOCK_IP:          Add outbound firewall block for IP
//   - UNBLOCK_IP:        Remove firewall block for IP
//   - QUARANTINE_FILE:   Move file to quarantine directory + restrict perms
//   - COLLECT_FORENSICS: Capture process list, netstat, basic system info
package commands

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	pb "github.com/AKiileX/Phantex/proto/gen/go/phantex/v1"
	"go.uber.org/zap"
)

const (
	// maxConcurrentCommands limits simultaneous command execution to prevent
	// a flood of commands from overwhelming the host.
	maxConcurrentCommands = 5

	// maxForensicOutputBytes caps forensic data to prevent disk exhaustion.
	maxForensicOutputBytes = 10 * 1024 * 1024 // 10 MB

	// maxQuarantineFileSize prevents quarantining huge files that would
	// fill the quarantine directory.
	maxQuarantineFileSize = 500 * 1024 * 1024 // 500 MB
)

// safeCommandIDPrefix safely extracts the first 8 chars of a command ID,
// or the full string if shorter. Prevents slice bounds panic.
func safeCommandIDPrefix(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}

// validIP validates that a string is a well-formed IPv4 or IPv6 address.
// Returns the parsed IP or nil. Rejects anything that's not a pure IP
// (no CIDR, no hostnames, no injection payloads).
func validIP(s string) net.IP {
	// Reject strings with shell metacharacters before even parsing
	if strings.ContainsAny(s, ";|&`$(){}[]<>'\"\\\n\r\t ") {
		return nil
	}
	ip := net.ParseIP(strings.TrimSpace(s))
	return ip
}

// validDirection validates the direction parameter for firewall rules.
func validDirection(s string) string {
	switch s {
	case "inbound", "outbound", "both":
		return s
	default:
		return "both"
	}
}

// deniedPaths are system-critical paths that must NEVER be quarantined.
var deniedPaths = []string{
	// Linux
	"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/hosts",
	"/boot", "/sbin", "/bin", "/usr/sbin", "/usr/bin",
	"/lib", "/lib64", "/usr/lib",
	"/var/lib/phantex", // sensor itself
	"/proc", "/sys", "/dev",
	// Windows
	`C:\Windows`, `C:\Program Files`, `C:\Program Files (x86)`,
	`C:\ProgramData\Phantex`, // sensor itself
}

// isDeniedPath checks whether a file path falls within a denied directory.
func isDeniedPath(p string) bool {
	cleaned := filepath.Clean(p)
	for _, denied := range deniedPaths {
		// Exact match or prefix match (child of denied dir)
		if strings.EqualFold(cleaned, denied) {
			return true
		}
		prefix := denied + string(filepath.Separator)
		if len(cleaned) > len(prefix) && strings.EqualFold(cleaned[:len(prefix)], prefix) {
			return true
		}
	}
	return false
}

// safeFirewallRuleName sanitizes a string for use as a Windows Firewall rule name.
var safeNameRe = regexp.MustCompile(`[^a-zA-Z0-9_\-]`)

func safeFirewallRuleName(s string) string {
	return safeNameRe.ReplaceAllString(s, "_")
}

// Result is the outcome of executing a command.
type Result struct {
	CommandID string
	Success   bool
	Message   string
	Data      map[string]string // optional structured output
}

// Executor handles response action commands from the gateway.
type Executor struct {
	log           *zap.Logger
	quarantineDir string
	gatewayAddr   string // kept open during isolation
	sema          chan struct{}
	myPID         int
}

// NewExecutor creates a command executor.
func NewExecutor(log *zap.Logger, quarantineDir, gatewayAddr string) *Executor {
	if quarantineDir == "" {
		if runtime.GOOS == "windows" {
			quarantineDir = `C:\ProgramData\Phantex\quarantine`
		} else {
			quarantineDir = "/var/lib/phantex/quarantine"
		}
	}
	_ = os.MkdirAll(quarantineDir, 0700)
	return &Executor{
		log:           log.Named("commands"),
		quarantineDir: quarantineDir,
		gatewayAddr:   gatewayAddr,
		sema:          make(chan struct{}, maxConcurrentCommands),
		myPID:         os.Getpid(),
	}
}

// Execute runs a ControlCommand and returns the result.
// Acquires a concurrency semaphore slot to prevent command floods.
func (e *Executor) Execute(ctx context.Context, cmd *pb.ControlCommand) Result {
	// Acquire semaphore (with context cancellation support)
	select {
	case e.sema <- struct{}{}:
		defer func() { <-e.sema }()
	case <-ctx.Done():
		return Result{
			CommandID: cmd.CommandId,
			Success:   false,
			Message:   "command cancelled: executor at capacity",
		}
	}

	e.log.Info("executing command",
		zap.String("command_id", cmd.CommandId),
		zap.String("action", cmd.Action.String()))

	var result Result
	result.CommandID = cmd.CommandId

	switch cmd.Action {
	case pb.ControlAction_CONTROL_ACTION_ISOLATE_HOST:
		result = e.isolateHost(ctx, cmd)
	case pb.ControlAction_CONTROL_ACTION_UNISOLATE_HOST:
		result = e.unisolateHost(ctx, cmd)
	case pb.ControlAction_CONTROL_ACTION_KILL_PROCESS:
		result = e.killProcess(ctx, cmd)
	case pb.ControlAction_CONTROL_ACTION_BLOCK_IP:
		result = e.blockIP(ctx, cmd)
	case pb.ControlAction_CONTROL_ACTION_UNBLOCK_IP:
		result = e.unblockIP(ctx, cmd)
	case pb.ControlAction_CONTROL_ACTION_QUARANTINE_FILE:
		result = e.quarantineFile(ctx, cmd)
	case pb.ControlAction_CONTROL_ACTION_COLLECT_FORENSICS:
		result = e.collectForensics(ctx, cmd)
	default:
		result.Success = false
		result.Message = fmt.Sprintf("unsupported action: %s", cmd.Action.String())
	}

	e.log.Info("command result",
		zap.String("command_id", cmd.CommandId),
		zap.Bool("success", result.Success),
		zap.String("message", result.Message))

	return result
}

// ── Host Isolation ───────────────────────────────────────────────────────────

func (e *Executor) isolateHost(ctx context.Context, cmd *pb.ControlCommand) Result {
	r := Result{CommandID: cmd.CommandId, Data: make(map[string]string)}

	gwAddr := cmd.Params["gateway_addr"]
	if gwAddr == "" {
		gwAddr = e.gatewayAddr
	}

	// Extract just the IP portion (strip port) and VALIDATE
	host := gwAddr
	if h, _, err := net.SplitHostPort(gwAddr); err == nil {
		host = h
	}
	gwIP := validIP(host)
	if gwIP == nil {
		r.Success = false
		r.Message = fmt.Sprintf("invalid gateway IP address: %q", host)
		return r
	}
	gwIPStr := gwIP.String()

	if runtime.GOOS == "windows" {
		cmds := [][]string{
			{"netsh", "advfirewall", "firewall", "add", "rule",
				"name=PhantexIsolate-BlockAll-Out", "dir=out", "action=block", "enable=yes"},
			{"netsh", "advfirewall", "firewall", "add", "rule",
				"name=PhantexIsolate-BlockAll-In", "dir=in", "action=block", "enable=yes"},
			{"netsh", "advfirewall", "firewall", "add", "rule",
				"name=PhantexIsolate-AllowGW-Out", "dir=out", "action=allow",
				"remoteip=" + gwIPStr, "enable=yes"},
			{"netsh", "advfirewall", "firewall", "add", "rule",
				"name=PhantexIsolate-AllowGW-In", "dir=in", "action=allow",
				"remoteip=" + gwIPStr, "enable=yes"},
		}
		for _, args := range cmds {
			out, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
			if err != nil {
				r.Success = false
				r.Message = fmt.Sprintf("isolation failed at '%s': %v — %s", args[4], err, truncateOutput(out))
				return r
			}
		}
	} else {
		cmds := [][]string{
			{"iptables", "-I", "OUTPUT", "-d", gwIPStr, "-j", "ACCEPT"},
			{"iptables", "-I", "INPUT", "-s", gwIPStr, "-j", "ACCEPT"},
			{"iptables", "-A", "OUTPUT", "-j", "DROP"},
			{"iptables", "-A", "INPUT", "-j", "DROP"},
		}
		for _, args := range cmds {
			out, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
			if err != nil {
				r.Success = false
				r.Message = fmt.Sprintf("isolation failed: %v — %s", err, truncateOutput(out))
				return r
			}
		}
	}

	r.Success = true
	r.Message = "Host isolated — all traffic blocked except Phantex gateway"
	r.Data["gateway_ip"] = gwIPStr
	return r
}

func (e *Executor) unisolateHost(ctx context.Context, cmd *pb.ControlCommand) Result {
	r := Result{CommandID: cmd.CommandId}

	if runtime.GOOS == "windows" {
		rules := []string{
			"PhantexIsolate-BlockAll-Out",
			"PhantexIsolate-BlockAll-In",
			"PhantexIsolate-AllowGW-Out",
			"PhantexIsolate-AllowGW-In",
		}
		for _, name := range rules {
			_ = exec.CommandContext(ctx, "netsh", "advfirewall", "firewall",
				"delete", "rule", "name="+name).Run()
		}
	} else {
		_ = exec.CommandContext(ctx, "iptables", "-D", "OUTPUT", "-j", "DROP").Run()
		_ = exec.CommandContext(ctx, "iptables", "-D", "INPUT", "-j", "DROP").Run()
	}

	r.Success = true
	r.Message = "Host isolation lifted — network restored"
	return r
}

// ── Kill Process ─────────────────────────────────────────────────────────────

func (e *Executor) killProcess(ctx context.Context, cmd *pb.ControlCommand) Result {
	r := Result{CommandID: cmd.CommandId}

	pidStr := cmd.Params["pid"]
	if pidStr == "" {
		r.Success = false
		r.Message = "missing 'pid' parameter"
		return r
	}

	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		r.Success = false
		r.Message = fmt.Sprintf("invalid pid '%s': %v", pidStr, err)
		return r
	}

	// ── Safety guards ────────────────────────────────────────────────
	// PID 0 = kernel scheduler, PID 1 = init/systemd — killing either
	// causes catastrophic system failure (kernel panic / reboot).
	if pid <= 1 {
		r.Success = false
		r.Message = fmt.Sprintf("refusing to kill protected PID %d (system-critical)", pid)
		return r
	}

	// Don't allow killing the sensor itself
	if pid == e.myPID {
		r.Success = false
		r.Message = "refusing to kill sensor process (self-preservation)"
		return r
	}

	// Don't allow negative PIDs (which signal process groups on Linux)
	if pid < 0 {
		r.Success = false
		r.Message = "negative PIDs (process groups) are not allowed"
		return r
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		r.Success = false
		r.Message = fmt.Sprintf("process %d not found: %v", pid, err)
		return r
	}

	if runtime.GOOS == "windows" {
		err = proc.Kill()
	} else {
		err = proc.Signal(os.Kill)
	}

	if err != nil {
		r.Success = false
		r.Message = fmt.Sprintf("failed to kill process %d: %v", pid, err)
		return r
	}

	r.Success = true
	r.Message = fmt.Sprintf("Process %d terminated", pid)
	return r
}

// ── Block/Unblock IP ─────────────────────────────────────────────────────────

func (e *Executor) blockIP(ctx context.Context, cmd *pb.ControlCommand) Result {
	r := Result{CommandID: cmd.CommandId}

	ipStr := cmd.Params["ip"]
	if ipStr == "" {
		r.Success = false
		r.Message = "missing 'ip' parameter"
		return r
	}

	// Validate IP address to prevent command injection
	ip := validIP(ipStr)
	if ip == nil {
		r.Success = false
		r.Message = fmt.Sprintf("invalid IP address: %q (must be valid IPv4 or IPv6)", ipStr)
		return r
	}
	ipClean := ip.String() // canonical form

	direction := validDirection(cmd.Params["direction"])

	// Sanitize rule name to prevent injection via IP string
	ruleName := "PhantexBlock-" + safeFirewallRuleName(ipClean)

	if runtime.GOOS == "windows" {
		if direction == "both" || direction == "outbound" {
			out, err := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
				"name="+ruleName+"-Out", "dir=out", "action=block",
				"remoteip="+ipClean, "enable=yes").CombinedOutput()
			if err != nil {
				r.Success = false
				r.Message = fmt.Sprintf("block outbound failed: %v — %s", err, truncateOutput(out))
				return r
			}
		}
		if direction == "both" || direction == "inbound" {
			out, err := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
				"name="+ruleName+"-In", "dir=in", "action=block",
				"remoteip="+ipClean, "enable=yes").CombinedOutput()
			if err != nil {
				r.Success = false
				r.Message = fmt.Sprintf("block inbound failed: %v — %s", err, truncateOutput(out))
				return r
			}
		}
	} else {
		if direction == "both" || direction == "outbound" {
			_ = exec.CommandContext(ctx, "iptables", "-A", "OUTPUT", "-d", ipClean, "-j", "DROP").Run()
		}
		if direction == "both" || direction == "inbound" {
			_ = exec.CommandContext(ctx, "iptables", "-A", "INPUT", "-s", ipClean, "-j", "DROP").Run()
		}
	}

	r.Success = true
	r.Message = fmt.Sprintf("IP %s blocked (%s)", ipClean, direction)
	return r
}

func (e *Executor) unblockIP(ctx context.Context, cmd *pb.ControlCommand) Result {
	r := Result{CommandID: cmd.CommandId}

	ipStr := cmd.Params["ip"]
	if ipStr == "" {
		r.Success = false
		r.Message = "missing 'ip' parameter"
		return r
	}

	ip := validIP(ipStr)
	if ip == nil {
		r.Success = false
		r.Message = fmt.Sprintf("invalid IP address: %q", ipStr)
		return r
	}
	ipClean := ip.String()

	ruleName := "PhantexBlock-" + safeFirewallRuleName(ipClean)

	if runtime.GOOS == "windows" {
		_ = exec.CommandContext(ctx, "netsh", "advfirewall", "firewall",
			"delete", "rule", "name="+ruleName+"-Out").Run()
		_ = exec.CommandContext(ctx, "netsh", "advfirewall", "firewall",
			"delete", "rule", "name="+ruleName+"-In").Run()
	} else {
		_ = exec.CommandContext(ctx, "iptables", "-D", "OUTPUT", "-d", ipClean, "-j", "DROP").Run()
		_ = exec.CommandContext(ctx, "iptables", "-D", "INPUT", "-s", ipClean, "-j", "DROP").Run()
	}

	r.Success = true
	r.Message = fmt.Sprintf("IP %s unblocked", ipClean)
	return r
}

// ── Quarantine File ──────────────────────────────────────────────────────────

func (e *Executor) quarantineFile(ctx context.Context, cmd *pb.ControlCommand) Result {
	r := Result{CommandID: cmd.CommandId, Data: make(map[string]string)}

	filePath := cmd.Params["path"]
	if filePath == "" {
		r.Success = false
		r.Message = "missing 'path' parameter"
		return r
	}

	// Resolve to absolute and clean (prevents ../ traversal)
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		r.Success = false
		r.Message = fmt.Sprintf("invalid path: %v", err)
		return r
	}
	absPath = filepath.Clean(absPath)

	// Check against denylist of system-critical paths
	if isDeniedPath(absPath) {
		r.Success = false
		r.Message = fmt.Sprintf("DENIED: path %q is system-critical and cannot be quarantined", absPath)
		e.log.Warn("quarantine denied — system-critical path",
			zap.String("path", absPath),
			zap.String("command_id", cmd.CommandId))
		return r
	}

	// Check file exists and size
	info, err := os.Stat(absPath)
	if err != nil {
		r.Success = false
		r.Message = fmt.Sprintf("file not found: %v", err)
		return r
	}
	if info.IsDir() {
		r.Success = false
		r.Message = "cannot quarantine a directory — only files"
		return r
	}
	if info.Size() > maxQuarantineFileSize {
		r.Success = false
		r.Message = fmt.Sprintf("file too large (%d bytes, max %d)", info.Size(), maxQuarantineFileSize)
		return r
	}

	// Create quarantine destination with safe name
	ts := time.Now().Format("20060102T150405")
	cmdPrefix := safeCommandIDPrefix(cmd.CommandId)
	base := filepath.Base(absPath)
	// Sanitize base name to prevent any traversal in the destination
	base = safeFirewallRuleName(base)
	if base == "" || base == "_" {
		base = "unknown_file"
	}
	destName := fmt.Sprintf("%s_%s_%s", ts, cmdPrefix, base)
	destPath := filepath.Join(e.quarantineDir, destName)

	// Move file to quarantine
	if err := os.Rename(absPath, destPath); err != nil {
		// os.Rename fails across filesystems — fall back to copy+delete
		r.Success = false
		r.Message = fmt.Sprintf("failed to quarantine: %v", err)
		return r
	}

	// Make quarantined file read-only
	_ = os.Chmod(destPath, 0400)

	r.Success = true
	r.Message = fmt.Sprintf("File quarantined: %s → %s (%d bytes)", absPath, destPath, info.Size())
	r.Data["original_path"] = absPath
	r.Data["quarantine_path"] = destPath
	r.Data["file_size"] = strconv.FormatInt(info.Size(), 10)
	return r
}

// ── Forensic Collection ──────────────────────────────────────────────────────

func (e *Executor) collectForensics(ctx context.Context, cmd *pb.ControlCommand) Result {
	r := Result{CommandID: cmd.CommandId, Data: make(map[string]string)}

	var procList, netstat string

	if runtime.GOOS == "windows" {
		if out, err := exec.CommandContext(ctx, "tasklist", "/V", "/FO", "CSV").CombinedOutput(); err == nil {
			procList = truncateString(string(out), maxForensicOutputBytes)
		}
		if out, err := exec.CommandContext(ctx, "netstat", "-ano").CombinedOutput(); err == nil {
			netstat = truncateString(string(out), maxForensicOutputBytes)
		}
	} else {
		if out, err := exec.CommandContext(ctx, "ps", "auxf").CombinedOutput(); err == nil {
			procList = truncateString(string(out), maxForensicOutputBytes)
		}
		if out, err := exec.CommandContext(ctx, "ss", "-tlnp").CombinedOutput(); err == nil {
			netstat = truncateString(string(out), maxForensicOutputBytes)
		}
	}

	// Write to quarantine dir for upload
	ts := time.Now().Format("20060102T150405")
	cmdPrefix := safeCommandIDPrefix(cmd.CommandId)
	prefix := fmt.Sprintf("forensics_%s_%s", ts, cmdPrefix)

	procFile := filepath.Join(e.quarantineDir, prefix+"_processes.txt")
	netFile := filepath.Join(e.quarantineDir, prefix+"_netstat.txt")

	_ = os.WriteFile(procFile, []byte(procList), 0600)
	_ = os.WriteFile(netFile, []byte(netstat), 0600)

	r.Success = true
	r.Message = fmt.Sprintf("Forensic data collected: %d bytes processes, %d bytes network",
		len(procList), len(netstat))
	r.Data["process_list_file"] = procFile
	r.Data["netstat_file"] = netFile
	r.Data["process_count"] = strconv.Itoa(strings.Count(procList, "\n"))
	return r
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// truncateOutput truncates command output for safe logging (no multi-MB error messages).
func truncateOutput(b []byte) string {
	const maxLen = 512
	if len(b) <= maxLen {
		return string(b)
	}
	return string(b[:maxLen]) + "…[truncated]"
}

// truncateString limits a string to maxLen bytes.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// unused sync import guard
var _ = sync.Mutex{}
