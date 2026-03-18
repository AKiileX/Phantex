// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// Command phantex-sensor is the userspace eBPF sensor agent.
//
// It loads eBPF probes into the kernel, reads events from the shared ring
// buffer, enriches them with process metadata, and sends them to the
// Phantex gateway (or stdout in stub mode).
//
// Usage:
//
//	sudo ./phantex-sensor [--config /path/to/sensor.yaml]
//
// Signal handling:
//
//	SIGTERM / SIGINT — graceful shutdown (drain events, detach probes)
package main

import (
	"context"
	crypto_tls "crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	pb "github.com/AKiileX/Phantex/proto/gen/go/phantex/v1"
	"github.com/AKiileX/Phantex/sensor/internal/commands"
	"github.com/AKiileX/Phantex/sensor/internal/config"
	"github.com/AKiileX/Phantex/sensor/internal/converter"
	"github.com/AKiileX/Phantex/sensor/internal/discovery"
	bpf "github.com/AKiileX/Phantex/sensor/internal/ebpf"
	"github.com/AKiileX/Phantex/sensor/internal/enricher"
	"github.com/AKiileX/Phantex/sensor/internal/metrics"
	"github.com/AKiileX/Phantex/sensor/internal/platform"
	"github.com/AKiileX/Phantex/sensor/internal/sdksocket"
	ptls "github.com/AKiileX/Phantex/sensor/internal/tls"
	"github.com/AKiileX/Phantex/sensor/internal/transport"
)

// version is set at build time via -ldflags.
var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	// ── Flags ────────────────────────────────────────────────────────────
	var (
		configPath  string
		showVersion bool
		initConfig  bool
	)
	flag.StringVar(&configPath, "config", "", "path to sensor.yaml config file")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.BoolVar(&initConfig, "init-config", false, "generate default sensor.yaml and exit")
	flag.Parse()

	if showVersion {
		fmt.Println("phantex-sensor", version)
		return 0
	}

	if initConfig {
		return doInitConfig(configPath)
	}

	// ── Config ───────────────────────────────────────────────────────────
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		return 1
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "config validation: %v\n", err)
		return 1
	}

	// ── Logger ───────────────────────────────────────────────────────────
	log, err := buildLogger(cfg.LogLevel, cfg.LogFormat)
	if err != nil {
		fmt.Fprintf(os.Stderr, "logger: %v\n", err)
		return 1
	}
	defer log.Sync() //nolint:errcheck

	log.Debug("phantex-sensor starting",
		zap.String("version", version),
		zap.String("log_level", cfg.LogLevel),
		zap.String("filter_mode", cfg.EBPF.FilterMode),
		zap.String("config_sha256", cfg.ConfigHash),
	)

	// ── Environment Detection ────────────────────────────────────────────
	env := platform.DetectEnvironment()
	log.Debug("environment detected",
		zap.String("os", env.OS),
		zap.String("arch", env.Arch),
		zap.Bool("wsl", env.IsWSL),
		zap.Bool("container", env.IsContainer),
		zap.Bool("k8s", env.IsK8s),
		zap.String("wsl_distro", env.WSLDistro),
	)
	for _, w := range env.Warnings {
		log.Warn(w)
	}

	// ── RLIMIT ───────────────────────────────────────────────────────────
	// Remove the memlock rlimit so eBPF maps can be created.
	// On kernels >= 5.11 this is a no-op (memcg accounting is used instead).
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Warn("failed to remove memlock rlimit (may need root)", zap.Error(err))
	}

	// ── Context + Signal Handling ────────────────────────────────────────
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		sig := <-sigCh
		log.Info("received signal, initiating shutdown", zap.String("signal", sig.String()))
		cancel()
	}()

	// ── Load eBPF Probes ─────────────────────────────────────────────────
	loader := bpf.NewLoader(log)
	loaded, total := loader.LoadAll()
	defer loader.Close()

	// ── Prometheus Metrics (A1 Task) ─────────────────────────────────────
	metrics.ProbesLoaded.Set(float64(loaded))
	metrics.ProbesTotal.Set(float64(total))
	mode := "normal"
	if loaded == 0 {
		log.Warn("no probes loaded — sensor entering DEGRADED mode (SDK-only)")
		mode = "degraded"
	}
	metrics.Info.WithLabelValues(version, mode).Set(1)

	// Log failed probes only (successes are summarised in the banner)
	for _, p := range loader.Probes() {
		if p.Error != nil {
			log.Warn("probe degraded", zap.String("probe", p.Name), zap.Error(p.Error))
		}
	}

	// ── Initialize Map Manager ───────────────────────────────────────────
	var mm *bpf.MapManager
	if loader.PidFilterMap != nil && loader.ConfigMap != nil {
		mm = bpf.NewMapManager(log, loader.PidFilterMap, loader.ConfigMap)

		// Apply configured filter mode
		if cfg.EBPF.FilterMode == "filtered" {
			if err := mm.EnablePIDFilter(); err != nil {
				log.Warn("failed to enable PID filter", zap.Error(err))
			}
		} else {
			if err := mm.DisablePIDFilter(); err != nil {
				log.Warn("failed to disable PID filter", zap.Error(err))
			}
		}
	}

	// ── Agent Discovery (A3) — before ring buffer so PID filter is seeded ──
	scannerCfg := discovery.ScannerConfig{
		ScanInterval: cfg.Discovery.ScanInterval,
		ProcPath:     "/proc",
		PAIDConfig: discovery.PAIDConfig{
			TenantSlug: cfg.Discovery.TenantSlug,
			EnvTag:     cfg.Discovery.EnvTag,
		},
		CheckEnviron:       cfg.Discovery.CheckEnviron,
		WatchBinaries:      cfg.Discovery.WatchBinaries,
		ExcludePatterns:    cfg.Discovery.ExcludePatterns,
		ExcludeSelf:        cfg.Discovery.ExcludeSelf,
		DeduplicateWorkers: cfg.Discovery.DeduplicateWorkers,
	}
	agentScanner := discovery.NewScanner(log, scannerCfg)

	// Run one synchronous scan to seed the PID filter before probes emit events.
	// This eliminates the startup race where events fire for non-agent processes
	// because the filter map is empty.
	agentScanner.SeedScan()
	if mm != nil && cfg.EBPF.FilterMode == "filtered" {
		for _, agent := range agentScanner.Agents() {
			if err := mm.TrackPID(agent.PID); err != nil {
				log.Warn("failed to seed PID filter", zap.Uint32("pid", agent.PID), zap.Error(err))
			}
		}
		log.Debug("PID filter seeded", zap.Int("tracked_pids", len(agentScanner.Agents())))
	}

	// Start the periodic scanner in background
	go agentScanner.Run(ctx)

	// Lifecycle tracker: fast agent discovery/termination via eBPF exec/exit events
	lifecycleTracker := discovery.NewLifecycleTracker(log, agentScanner)

	// ── Ring Buffer Reader ───────────────────────────────────────────────
	var reader *bpf.Reader
	if loader.EventsMap == nil {
		log.Warn("eBPF event ingestion disabled — running in SDK-only mode (root/CAP_BPF required for probes)")
	} else {
		ringReader, err := ringbuf.NewReader(loader.EventsMap)
		if err != nil {
			log.Error("failed to create ring buffer reader", zap.Error(err))
			return 1
		}
		defer ringReader.Close()

		reader = bpf.NewReader(log, ringReader, cfg.EBPF.RingBufChanSize)

		// Close the ring reader on context cancellation so the blocking Read() unblocks.
		go func() {
			<-ctx.Done()
			ringReader.Close()
		}()

		go reader.Run(ctx)
	}

	// ── Enricher ─────────────────────────────────────────────────────────
	enrich := enricher.New(log, cfg.Performance.EnricherCacheTTL)

	// ── Transport Client ─────────────────────────────────────────────────
	conv := converter.New(cfg.SensorID, cfg.TenantID)

	// TLS for gateway connection (mTLS when cert+key+CA are configured)
	var tlsCfg *crypto_tls.Config
	if cfg.Transport.TLSEnabled {
		tlsProvider, err := ptls.NewProvider(ptls.Config{
			CertFile: cfg.Transport.TLSCertFile,
			KeyFile:  cfg.Transport.TLSKeyFile,
			CAFile:   cfg.Transport.TLSCAFile,
		}, log)
		if err != nil {
			log.Error("failed to create TLS provider", zap.Error(err))
			return 1
		}
		tlsProvider.StartReloader()
		defer tlsProvider.Stop()
		tlsCfg = tlsProvider.ClientTLSConfig()
		log.Debug("mTLS enabled for gateway transport",
			zap.String("cert", cfg.Transport.TLSCertFile),
			zap.String("ca", cfg.Transport.TLSCAFile),
		)
	}

	tc := transport.NewClient(transport.ClientConfig{
		GatewayAddr: cfg.Transport.GatewayAddr,
		AuthToken:   cfg.Transport.AuthToken,
		SensorID:    cfg.SensorID,
		TenantID:    cfg.TenantID,
		BatchSize:   cfg.Transport.BatchSize,
		BufferSize:  cfg.Transport.BufferSize,
		TLSConfig:   tlsCfg,
		Version:     version,
	}, log)
	defer tc.Close() //nolint:errcheck

	// ── Response Action Executor ─────────────────────────────────────────
	cmdExecutor := commands.NewExecutor(log, "", cfg.Transport.GatewayAddr)
	tc.SetCommandHandler(func(cmd *pb.ControlCommand) {
		result := cmdExecutor.Execute(ctx, cmd)
		log.Info("command executed",
			zap.String("command_id", cmd.CommandId),
			zap.Bool("success", result.Success),
			zap.String("message", result.Message))
	})

	// ── Wire metrics provider for heartbeats ─────────────────────────────
	startTime := time.Now()
	tc.SetMetricsProvider(func() *pb.SensorMetrics {
		m := &pb.SensorMetrics{
			EventsSent:    uint64(tc.EventsSent.Load()),
			EventsDropped: uint64(tc.GetStats().Dropped),
			UptimeSeconds: uint64(time.Since(startTime).Seconds()),
		}
		pl, pt := loader.LoadedCount()
		m.ProbesLoaded = uint32(pl)
		m.ProbesTotal = uint32(pt)
		// Approximate agents tracked from scanner
		if agentScanner != nil {
			m.AgentsTracked = uint32(len(agentScanner.Agents()))
		}
		// Reader stats (ring buffer)
		if reader != nil {
			rs := reader.Stats()
			m.EventsRead = rs.EventsRead
			m.ParseErrors = rs.ParseErrors
			m.BufferUsed = rs.RingDrops
		}
		// Runtime memory
		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)
		m.MemoryBytes = memStats.Sys
		return m
	})

	// Start connection loop + periodic flush in background
	go tc.Run(ctx, cfg.Transport.BatchTimeout)
	go tc.RunHeartbeat(ctx, 30*time.Second)

	// ── SDK Socket Listener (D2) ────────────────────────────────────────
	var sdkEvtCh <-chan *pb.PhantexEvent
	if cfg.SDKSocket.Enabled {
		sdkListener := sdksocket.New(sdksocket.Config{
			SocketPath:  cfg.SDKSocket.SocketPath,
			MaxConns:    cfg.SDKSocket.MaxConns,
			MaxLineSize: cfg.SDKSocket.MaxLineSize,
			RateLimit:   cfg.SDKSocket.RateLimit,
			SensorID:    cfg.SensorID,
			TenantID:    cfg.TenantID,
		}, log)

		sdkEvtCh = sdkListener.Events()

		go func() {
			if err := sdkListener.Run(ctx); err != nil {
				log.Warn("SDK socket listener unavailable — SDK integrations disabled",
					zap.String("hint", "run with sudo or grant write access to "+cfg.SDKSocket.SocketPath),
				)
			}
		}()
		log.Debug("SDK socket listener started",
			zap.String("path", cfg.SDKSocket.SocketPath),
		)
	} else {
		log.Debug("SDK socket listener disabled")
	}

	// ── Health Check Server (A1 Acceptance #6) ─────────────────────────
	if cfg.Health.Enabled {
		mux := http.NewServeMux()
		degraded := loaded == 0
		// Prometheus metrics endpoint
		mux.Handle("/metrics", metrics.Handler())
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			status := "ok"
			if degraded {
				status = "degraded"
			}
			fmt.Fprintf(w, //nolint:errcheck
				`{"status":%q,"version":%q,"probes_loaded":%d,"probes_total":%d,"degraded":%v}`,
				status, version, loaded, total, degraded,
			)
		})
		srv := &http.Server{
			Addr:         cfg.Health.Addr,
			Handler:      mux,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  30 * time.Second,
		}
		go func() {
			log.Debug("health check server listening", zap.String("addr", cfg.Health.Addr))
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Error("health check server failed", zap.Error(err))
			}
		}()
		go func() {
			<-ctx.Done()
			_ = srv.Close()
		}()
	}

	// ── Startup Banner ───────────────────────────────────────────────────
	log.Info(fmt.Sprintf("phantex-sensor v%s | %s/%s | kernel %s | probes %d/%d | %s mode",
		version, env.OS, env.Arch, kernelVersion(), loaded, total, cfg.EBPF.FilterMode))
	if len(agentScanner.Agents()) > 0 {
		for _, a := range agentScanner.Agents() {
			exeInfo := a.ExePath
			if exeInfo == "" {
				exeInfo = "exe unknown"
			}
			log.Info(fmt.Sprintf("  agent: %s (pid %d) — %s", a.Framework, a.PID, exeInfo))
		}
	}
	log.Info(fmt.Sprintf("gateway %s | sensor ready", cfg.Transport.GatewayAddr))

	// ── Event Loop ───────────────────────────────────────────────────────

	// Snapshot the eBPF event channel once. A nil channel (degraded/SDK-only
	// mode) is safe in a select — the case simply never fires.
	var ebpfEvtCh <-chan bpf.Event
	if reader != nil {
		ebpfEvtCh = reader.Events()
	}

	// Process agent discovery events in background
	go func() {
		for agentEvt := range agentScanner.Events() {
			// Update PID filter map so BPF probes emit/drop events for this PID
			if mm != nil && cfg.EBPF.FilterMode == "filtered" {
				switch agentEvt.Type {
				case discovery.AgentDiscovered:
					if err := mm.TrackPID(agentEvt.Agent.PID); err != nil {
						log.Warn("failed to track PID in BPF filter",
							zap.Uint32("pid", agentEvt.Agent.PID), zap.Error(err))
					}
				case discovery.AgentTerminated:
					if err := mm.UntrackPID(agentEvt.Agent.PID); err != nil {
						log.Warn("failed to untrack PID in BPF filter",
							zap.Uint32("pid", agentEvt.Agent.PID), zap.Error(err))
					}
				}
			}

			pbEvt := conv.ToAgentLifecycle(
				agentEvt.Type.String(),
				agentEvt.Agent.PID,
				agentEvt.Agent.PAID,
				string(agentEvt.Agent.Framework),
				"",
				agentEvt.Agent.ExePath,
				"",
				agentEvt.Agent.ContainerID,
			)
			if pbEvt != nil {
				tc.Send(pbEvt)
			}
		}
	}()

	eventsProcessed := uint64(0)
	sdkEventsProcessed := uint64(0)
	for {
		select {
		case <-ctx.Done():
			log.Info("shutting down event loop",
				zap.Uint64("events_processed", eventsProcessed),
				zap.Uint64("sdk_events_processed", sdkEventsProcessed),
			)
			return 0

		case sdkEvt, ok := <-sdkEvtCh:
			if !ok {
				sdkEvtCh = nil // Channel closed — stop selecting on it
				continue
			}
			sdkEventsProcessed++
			metrics.SDKEventsProcessed.Inc()
			metrics.EventsSent.Inc()
			tc.Send(sdkEvt)

		case evt, ok := <-ebpfEvtCh:
			if !ok {
				log.Info("eBPF event channel closed, shutting down")
				return 0
			}

			eventsProcessed++
			metrics.EventsProcessed.WithLabelValues(evt.Type.String()).Inc()

			// Feed exec/exit events to the lifecycle tracker for fast agent detection
			if evt.Type == bpf.EventProcessExec || evt.Type == bpf.EventProcessExit {
				lifecycleTracker.HandleEvent(evt)
			}

			// Enrich with /proc metadata
			info := enrich.Enrich(evt.Header.PID)

			// Evict cache on process exit events
			if evt.Type == bpf.EventProcessExit {
				enrich.Evict(evt.Header.PID)
			}

			// Look up agent PAID — check direct PID first, then walk
			// up to the parent (PPID) so child processes spawned by
			// an agent (e.g. curl, bash) inherit the agent attribution.
			var agentPAID string
			if agent := agentScanner.AgentByPID(evt.Header.PID); agent != nil {
				agentPAID = agent.PAID
			} else if evt.Header.PPID > 1 {
				if parent := agentScanner.AgentByPID(evt.Header.PPID); parent != nil {
					agentPAID = parent.PAID
				}
			}

			// Convert eBPF event → protobuf and send
			pbEvt := conv.ToProto(evt, info, agentPAID)
			if pbEvt != nil {
				metrics.EventsSent.Inc()
				tc.Send(pbEvt)
			}
		}
	}
}

// doInitConfig generates a default sensor.yaml config file.
func doInitConfig(outPath string) int {
	if outPath == "" {
		outPath = "/etc/phantex/sensor.yaml"
	}

	// Don't overwrite existing config
	if _, err := os.Stat(outPath); err == nil {
		fmt.Fprintf(os.Stderr, "config already exists: %s\n", outPath)
		fmt.Fprintln(os.Stderr, "remove it first or use --config <path> to write elsewhere")
		return 1
	}

	// Ensure parent directory exists
	dir := filepath.Dir(outPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create directory %s: %v\n", dir, err)
		return 1
	}

	cfg := config.DefaultConfig()
	// Generate a unique sensor ID for this installation
	loadedCfg, _ := config.Load("")
	if loadedCfg != nil && loadedCfg.SensorID != "" {
		cfg.SensorID = loadedCfg.SensorID
	}
	configYAML := fmt.Sprintf(`# Phantex Sensor Configuration
# Generated by: phantex-sensor --init-config
# Docs: https://github.com/AKiileX/Phantex

# Sensor identity (auto-generated UUID if left empty)
sensor_id: "%s"

# Tenant ID — set to your organization's tenant UUID
tenant_id: "your-tenant-id"

# Logging
log_level: "%s"
log_format: "json"

# eBPF settings
ebpf:
  filter_mode: "%s"
  ringbuf_chan_size: %d

# Transport (gRPC to Phantex gateway)
transport:
  gateway_addr: "%s"
  # auth_token: set PHANTEX_AUTH_TOKEN env var instead of config file
  tls_enabled: %t
  batch_size: %d
  batch_timeout: "%s"
  buffer_size: %d

# Health check endpoint
health:
  enabled: %t
  addr: "%s"

# Agent discovery
discovery:
  scan_interval: "%s"
  check_environ: %t

# SDK socket (receives events from Python/Node.js SDK)
sdk_socket:
  enabled: %t
  socket_path: "%s"
  max_conns: %d
  rate_limit: %d
`,
		cfg.SensorID,
		cfg.LogLevel,
		cfg.EBPF.FilterMode,
		cfg.EBPF.RingBufChanSize,
		cfg.Transport.GatewayAddr,
		cfg.Transport.TLSEnabled,
		cfg.Transport.BatchSize,
		cfg.Transport.BatchTimeout,
		cfg.Transport.BufferSize,
		cfg.Health.Enabled,
		cfg.Health.Addr,
		cfg.Discovery.ScanInterval,
		cfg.Discovery.CheckEnviron,
		cfg.SDKSocket.Enabled,
		cfg.SDKSocket.SocketPath,
		cfg.SDKSocket.MaxConns,
		cfg.SDKSocket.RateLimit,
	)

	if err := os.WriteFile(outPath, []byte(configYAML), 0640); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write config: %v\n", err)
		return 1
	}

	fmt.Printf("Config created: %s\n", outPath)
	fmt.Println("")
	fmt.Println("Next steps:")
	fmt.Println("  1. Edit the config and set your tenant_id and gateway_addr")
	fmt.Println("  2. Set PHANTEX_AUTH_TOKEN environment variable")
	fmt.Println("  3. Start the sensor: sudo phantex-sensor --config " + outPath)
	return 0
}

// buildLogger creates a zap logger from config values.
func buildLogger(level, format string) (*zap.Logger, error) {
	var lvl zapcore.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("invalid log level %q: %w", level, err)
	}

	var zapCfg zap.Config
	if format == "console" {
		zapCfg = zap.NewDevelopmentConfig()
	} else {
		zapCfg = zap.NewProductionConfig()
	}
	zapCfg.Level = zap.NewAtomicLevelAt(lvl)

	return zapCfg.Build()
}

// kernelVersion returns the running kernel version string.
func kernelVersion() string {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return "unknown"
	}
	// Convert [65]int8 → string (stop at first null byte)
	buf := make([]byte, 0, len(uname.Release))
	for _, b := range uname.Release {
		if b == 0 {
			break
		}
		buf = append(buf, byte(b))
	}
	return string(buf)
}
