// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

//go:build windows

// Command phantex-sensor (Windows) is the ETW-based sensor agent.
//
// It starts ETW trace sessions for process/file/registry events,
// polls TCP/DNS tables for network visibility, enriches events with
// Win32 process metadata, and sends them to the Phantex gateway via gRPC.
//
// Usage:
//
//	phantex-sensor.exe [--config C:\ProgramData\Phantex\sensor.yaml]
//
// Must run as Administrator (ETW requires elevated privileges).
//
// Signal handling:
//
//	Ctrl+C / SIGTERM → graceful shutdown (stop ETW sessions, drain events)
package main

import (
	"context"
	crypto_tls "crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	pb "github.com/AKiileX/Phantex/proto/gen/go/phantex/v1"
	"github.com/AKiileX/Phantex/sensor/internal/commands"
	"github.com/AKiileX/Phantex/sensor/internal/discovery"
	"github.com/AKiileX/Phantex/sensor/internal/metrics"
	"github.com/AKiileX/Phantex/sensor/internal/platform"
	configwin "github.com/AKiileX/Phantex/sensor/internal/platform/config_win"
	convwin "github.com/AKiileX/Phantex/sensor/internal/platform/converter_win"
	discwin "github.com/AKiileX/Phantex/sensor/internal/platform/discovery_win"
	enrichwin "github.com/AKiileX/Phantex/sensor/internal/platform/enricher_win"
	"github.com/AKiileX/Phantex/sensor/internal/platform/etw"
	"github.com/AKiileX/Phantex/sensor/internal/platform/namedpipe"
	"github.com/AKiileX/Phantex/sensor/internal/platform/wfp"
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
	)
	flag.StringVar(&configPath, "config", "", "path to sensor.yaml config file")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Println("phantex-sensor (windows)", version)
		return 0
	}

	// ── Config ───────────────────────────────────────────────────────────
	cfg, err := configwin.LoadWindows(configPath)
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

	log.Info("phantex-sensor (windows) starting",
		zap.String("version", version),
		zap.String("log_level", cfg.LogLevel),
		zap.Bool("etw_process", cfg.ETW.EnableProcess),
		zap.Bool("etw_file", cfg.ETW.EnableFile),
		zap.Bool("etw_registry", cfg.ETW.EnableRegistry),
	)

	// ── Admin Check ──────────────────────────────────────────────────────
	if !isRunningAsAdmin() {
		log.Error("phantex-sensor must run as Administrator for ETW access")
		fmt.Fprintln(os.Stderr, "ERROR: phantex-sensor requires Administrator privileges")
		return 1
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

	// ── Prometheus Metrics ───────────────────────────────────────────────
	metrics.Info.WithLabelValues(version, "normal").Set(1)

	// ── Start ETW Provider ───────────────────────────────────────────────
	etwCfg := etw.Config{
		EnableProcess:  cfg.ETW.EnableProcess,
		EnableFile:     cfg.ETW.EnableFile,
		EnableRegistry: cfg.ETW.EnableRegistry,
		EventChanSize:  cfg.ETW.EventChanSize,
	}
	etwProvider, err := etw.NewProvider(etwCfg, log)
	if err != nil {
		log.Error("failed to create ETW provider", zap.Error(err))
		return 1
	}

	providersStarted := 0
	go func() {
		if err := etwProvider.Start(ctx); err != nil {
			log.Error("ETW provider failed", zap.Error(err))
		}
	}()
	providersStarted++

	metrics.ProbesLoaded.Set(float64(providersStarted))
	metrics.ProbesTotal.Set(float64(3)) // process + file + registry

	// ── Start Network Provider (WFP) ─────────────────────────────────────
	netCfg := wfp.Config{
		TCPPollInterval: cfg.Network.TCPPollInterval,
		DNSPollInterval: cfg.Network.DNSPollInterval,
		DNSRateLimit:    cfg.Network.DNSRateLimit,
		ExtractSNI:      cfg.Network.ExtractSNI,
	}
	netProvider, err := wfp.NewNetworkProvider(netCfg, log)
	if err != nil {
		log.Warn("network provider creation failed — degraded mode", zap.Error(err))
	} else {
		go func() {
			if err := netProvider.Start(ctx); err != nil {
				log.Error("network provider failed", zap.Error(err))
			}
		}()
		providersStarted++
	}

	// ── Process Enricher ─────────────────────────────────────────────────
	enrich := enrichwin.New(log, cfg.Performance.EnricherCacheTTL)

	// ── Agent Discovery ──────────────────────────────────────────────────
	scannerCfg := discwin.ScannerConfig{
		ScanInterval: cfg.Discovery.ScanInterval,
		PAIDConfig: discovery.PAIDConfig{
			TenantSlug: cfg.Discovery.TenantSlug,
			EnvTag:     cfg.Discovery.EnvTag,
		},
		WatchBinaries: cfg.Discovery.WatchBinaries,
	}
	agentScanner := discwin.NewScanner(log, scannerCfg)
	go agentScanner.Run(ctx)

	// ── Transport Client ─────────────────────────────────────────────────
	conv := convwin.New(cfg.SensorID, cfg.TenantID)

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
		log.Info("mTLS enabled for gateway transport",
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
			ProbesLoaded:  uint32(providersStarted),
			ProbesTotal:   uint32(3), // process + file + registry
		}
		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)
		m.MemoryBytes = memStats.Sys
		return m
	})

	go tc.Run(ctx, cfg.Transport.BatchTimeout)
	go tc.RunHeartbeat(ctx, 30*time.Second)

	// ── Named Pipe SDK Listener ──────────────────────────────────────────
	var sdkEvtCh <-chan *pb.PhantexEvent
	if cfg.NamedPipe.Enabled {
		pipeListener := namedpipe.New(namedpipe.Config{
			PipeName:    cfg.NamedPipe.PipeName,
			MaxConns:    cfg.NamedPipe.MaxConns,
			MaxLineSize: cfg.NamedPipe.MaxLineSize,
			RateLimit:   cfg.NamedPipe.RateLimit,
			SensorID:    cfg.SensorID,
			TenantID:    cfg.TenantID,
		}, log)

		sdkEvtCh = pipeListener.Events()

		go func() {
			if err := pipeListener.Run(ctx); err != nil {
				log.Error("named pipe listener failed", zap.Error(err))
			}
		}()

		log.Info("named pipe SDK listener started",
			zap.String("pipe", cfg.NamedPipe.PipeName),
		)
	}

	// ── Health Check Server ──────────────────────────────────────────────
	if cfg.Health.Enabled {
		mux := http.NewServeMux()
		mux.Handle("/metrics", metrics.Handler())
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w,
				`{"status":"ok","version":%q,"platform":"windows","providers_started":%d,"enricher_cache":%d}`,
				version, providersStarted, enrich.CacheSize(),
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
			log.Info("health check server listening", zap.String("addr", cfg.Health.Addr))
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Error("health check server failed", zap.Error(err))
			}
		}()
		go func() {
			<-ctx.Done()
			_ = srv.Close()
		}()
	}

	// ── Event Loop ───────────────────────────────────────────────────────
	log.Info("sensor running — processing events",
		zap.Int("providers", providersStarted),
	)

	// Collect event channels
	etwEvtCh := etwProvider.Events()
	var netEvtCh <-chan platform.Event
	if netProvider != nil {
		netEvtCh = netProvider.Events()
	}

	// Process agent discovery events in background
	go func() {
		for agentEvt := range agentScanner.Events() {
			pbEvt := conv.ToAgentLifecycle(
				agentEvt.Type.String(),
				agentEvt.Agent.PID,
				agentEvt.Agent.PAID,
				string(agentEvt.Agent.Framework),
				"",
				agentEvt.Agent.ExePath,
				agentEvt.Agent.Cmdline,
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
				sdkEvtCh = nil
				continue
			}
			sdkEventsProcessed++
			metrics.SDKEventsProcessed.Inc()
			metrics.EventsSent.Inc()
			tc.Send(sdkEvt)

		case evt, ok := <-etwEvtCh:
			if !ok {
				log.Info("ETW event channel closed")
				etwEvtCh = nil
				continue
			}
			eventsProcessed++
			metrics.EventsProcessed.WithLabelValues(fmt.Sprintf("%d", evt.Type)).Inc()

			// Feed exec/exit to discovery for fast agent detection
			if evt.Type == platform.EventProcessExec {
				if p, ok := evt.Payload.(*platform.ProcessExecPayload); ok {
					agentScanner.HandleExecEvent(evt.PID, evt.PPID, evt.Comm, p.Filename, p.Argv)
				}
			} else if evt.Type == platform.EventProcessExit {
				agentScanner.HandleExitEvent(evt.PID)
			}

			// Enrich with Windows process metadata
			info := enrich.Enrich(evt.PID)
			if evt.Type == platform.EventProcessExit {
				enrich.Evict(evt.PID)
			}

			// Look up agent PAID
			var agentPAID string
			if agent := agentScanner.AgentByPID(evt.PID); agent != nil {
				agentPAID = agent.PAID
			}

			// Convert platform event → protobuf and send
			pbEvt := conv.ToProto(evt, info, agentPAID)
			if pbEvt != nil {
				metrics.EventsSent.Inc()
				tc.Send(pbEvt)
			}

		case netEvt, ok := <-netEvtCh:
			if !ok {
				netEvtCh = nil
				continue
			}
			eventsProcessed++
			metrics.EventsProcessed.WithLabelValues(fmt.Sprintf("%d", netEvt.Type)).Inc()

			info := enrich.Enrich(netEvt.PID)
			var agentPAID string
			if agent := agentScanner.AgentByPID(netEvt.PID); agent != nil {
				agentPAID = agent.PAID
			}

			pbEvt := conv.ToProto(netEvt, info, agentPAID)
			if pbEvt != nil {
				metrics.EventsSent.Inc()
				tc.Send(pbEvt)
			}
		}
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// isRunningAsAdmin checks if the current process has admin privileges.
func isRunningAsAdmin() bool {
	var sid *syscall.SID
	err := syscall.AllocateAndInitializeSid(
		&syscall.SIDIdentifierAuthority{Value: [6]byte{0, 0, 0, 0, 0, 5}}, // SECURITY_NT_AUTHORITY
		2,
		0x20,  // SECURITY_BUILTIN_DOMAIN_RID
		0x220, // DOMAIN_ALIAS_RID_ADMINS
		0, 0, 0, 0, 0, 0,
		&sid,
	)
	if err != nil {
		return false
	}
	defer syscall.FreeSid(sid)

	member, err := checkTokenMembership(sid)
	if err != nil {
		return false
	}
	return member
}

// checkTokenMembership wraps CheckTokenMembership from advapi32.dll.
func checkTokenMembership(sid *syscall.SID) (bool, error) {
	advapi32 := syscall.NewLazyDLL("advapi32.dll")
	proc := advapi32.NewProc("CheckTokenMembership")

	var isMember int32
	r1, _, err := proc.Call(
		0, // use process token
		uintptr(unsafe.Pointer(sid)),
		uintptr(unsafe.Pointer(&isMember)),
	)
	if r1 == 0 {
		return false, err
	}
	return isMember != 0, nil
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
