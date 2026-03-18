// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// Command phantex-gateway is the event ingestion gateway.
//
// It receives gRPC event streams from Phantex sensors, validates
// authentication, enforces tenant isolation, and publishes events
// downstream (to Kafka in production, stdout in Phase 1).
//
// Usage:
//
//	./phantex-gateway [--config /path/to/gateway.yaml]
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"github.com/AKiileX/Phantex/gateway/internal/auth"
	"github.com/AKiileX/Phantex/gateway/internal/config"
	grpcserver "github.com/AKiileX/Phantex/gateway/internal/grpc"
	"github.com/AKiileX/Phantex/gateway/internal/kafka"
	ptls "github.com/AKiileX/Phantex/gateway/internal/tls"
	pb "github.com/AKiileX/Phantex/proto/gen/go/phantex/v1"
)

var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	var (
		configPath  string
		showVersion bool
	)
	flag.StringVar(&configPath, "config", "", "path to gateway.yaml config file")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Println("phantex-gateway", version)
		return 0
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

	log.Info("phantex-gateway starting",
		zap.String("version", version),
		zap.String("listen_addr", cfg.GRPC.ListenAddr),
		zap.Bool("tls", cfg.GRPC.TLSEnabled),
		zap.Int("auth_tokens", len(cfg.Auth.Tokens)),
	)

	// ── Signal handling ──────────────────────────────────────────────────
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	// ── Event Publisher ──────────────────────────────────────────────────
	// Publisher wraps EventPublisher with lifecycle and stats methods.
	type publisherWrapper struct {
		grpcserver.EventPublisher
		close    func() error
		getStats func() kafka.Stats
	}

	var pub publisherWrapper

	if cfg.Kafka.Enabled {
		log.Info("kafka publishing enabled",
			zap.Strings("brokers", cfg.Kafka.Brokers),
			zap.String("topic_prefix", cfg.Kafka.TopicPrefix))

		kafkaCfg := kafka.KafkaConfig{
			Brokers:      cfg.Kafka.Brokers,
			TopicPrefix:  cfg.Kafka.TopicPrefix,
			BatchSize:    cfg.Kafka.BatchSize,
			BatchTimeout: cfg.Kafka.BatchTimeout,
		}

		// Kafka TLS (SASL_SSL) — reuse gateway TLS provider for certs
		if cfg.Kafka.TLSEnabled {
			kafkaTLS, err := ptls.NewProvider(ptls.Config{
				CertFile: cfg.Kafka.TLSCertFile,
				KeyFile:  cfg.Kafka.TLSKeyFile,
				CAFile:   cfg.Kafka.TLSCAFile,
			}, log)
			if err != nil {
				log.Error("failed to create Kafka TLS provider", zap.Error(err))
				return 1
			}
			kafkaTLS.StartReloader()
			defer kafkaTLS.Stop()
			kafkaCfg.TLSConfig = kafkaTLS.ClientTLSConfig()
			log.Info("kafka TLS enabled",
				zap.String("cert", cfg.Kafka.TLSCertFile),
				zap.String("ca", cfg.Kafka.TLSCAFile))
		}

		kp := kafka.NewKafkaPublisher(log, kafkaCfg)
		pub = publisherWrapper{
			EventPublisher: kp,
			close:          kp.Close,
			getStats:       kp.GetStats,
		}
	} else {
		log.Info("kafka disabled — using log publisher (dev mode)")
		lp := kafka.NewLogPublisher(log)
		pub = publisherWrapper{
			EventPublisher: lp,
			close:          lp.Close,
			getStats:       lp.GetStats,
		}
	}
	defer pub.close() //nolint:errcheck

	// ── Auth Validator ───────────────────────────────────────────────────
	validator := auth.NewValidator(log, cfg.Auth.Tokens)

	// ── gRPC Server ──────────────────────────────────────────────────────
	grpcOpts := []grpc.ServerOption{
		// Auth interceptors
		grpc.ChainStreamInterceptor(validator.StreamInterceptor()),
		grpc.ChainUnaryInterceptor(validator.UnaryInterceptor()),

		// Keepalive
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:             cfg.GRPC.KeepaliveInterval,
			Timeout:          cfg.GRPC.KeepaliveTimeout,
			MaxConnectionAge: 1 * time.Hour, // Force periodic re-auth by reconnecting
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second,
			PermitWithoutStream: true,
		}),

		// Limit concurrent streams per connection (defense against stream flooding)
		grpc.MaxConcurrentStreams(200),

		// Max message size: 16MB (generous for large batches)
		grpc.MaxRecvMsgSize(16 * 1024 * 1024),
	}

	// TLS / mTLS configuration
	var tlsProvider *ptls.Provider
	if cfg.GRPC.TLSEnabled {
		var err error
		tlsProvider, err = ptls.NewProvider(ptls.Config{
			CertFile:          cfg.GRPC.TLSCertFile,
			KeyFile:           cfg.GRPC.TLSKeyFile,
			CAFile:            cfg.GRPC.TLSCAFile,
			RequireClientCert: cfg.GRPC.TLSCAFile != "", // mTLS when CA provided
			MinVersion:        0,                        // defaults to TLS 1.3
			ReloadInterval:    60 * time.Second,         // auto-reload every 60s
		}, log)
		if err != nil {
			log.Error("failed to load TLS credentials",
				zap.String("cert", cfg.GRPC.TLSCertFile),
				zap.String("key", cfg.GRPC.TLSKeyFile),
				zap.String("ca", cfg.GRPC.TLSCAFile),
				zap.Error(err))
			return 1
		}
		defer tlsProvider.Stop()
		tlsProvider.StartReloader()

		creds := credentials.NewTLS(tlsProvider.ServerTLSConfig())
		grpcOpts = append(grpcOpts, grpc.Creds(creds))
		log.Info("mTLS enabled",
			zap.String("cert", cfg.GRPC.TLSCertFile),
			zap.String("key", cfg.GRPC.TLSKeyFile),
			zap.String("ca", cfg.GRPC.TLSCAFile),
			zap.Bool("require_client_cert", cfg.GRPC.TLSCAFile != ""))
	}

	srv := grpc.NewServer(grpcOpts...)

	// Register our service
	gatewayServer := grpcserver.NewServer(log, pub.EventPublisher, cfg.GRPC.MaxEventsPerSec, cfg.Backend.URL, cfg.Backend.InternalToken)
	defer gatewayServer.Stop() // Stop background goroutines (cleanupStaleBuckets)
	pb.RegisterSensorServiceServer(srv, gatewayServer)

	// ── Listener ─────────────────────────────────────────────────────────
	lis, err := net.Listen("tcp", cfg.GRPC.ListenAddr)
	if err != nil {
		log.Error("failed to listen", zap.String("addr", cfg.GRPC.ListenAddr), zap.Error(err))
		return 1
	}

	log.Info("gateway listening",
		zap.String("addr", lis.Addr().String()),
		zap.Int64("max_events_per_sec", cfg.GRPC.MaxEventsPerSec))

	// ── Graceful shutdown ────────────────────────────────────────────────
	go func() {
		select {
		case sig := <-sigCh:
			log.Info("received signal, initiating shutdown", zap.String("signal", sig.String()))
			cancel()

			// Give in-flight RPCs 10 seconds to complete
			go func() {
				time.Sleep(10 * time.Second)
				log.Warn("graceful shutdown timeout — forcing stop")
				srv.Stop()
			}()
			srv.GracefulStop()

		case <-ctx.Done():
			srv.GracefulStop()
		}
	}()

	// ── Stats reporter ───────────────────────────────────────────────────
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				stats := gatewayServer.GetStats()
				pubStats := pub.getStats()
				log.Info("gateway stats",
					zap.Int("active_sensors", stats.ActiveSensors),
					zap.Int64("total_events", stats.TotalEvents),
					zap.Int64("total_batches", stats.TotalBatches),
					zap.Int64("rejected_batches", stats.RejectedBatches),
					zap.Int64("published_events", pubStats.EventsTotal),
				)
			}
		}
	}()

	// ── Serve ────────────────────────────────────────────────────────────
	if err := srv.Serve(lis); err != nil {
		log.Error("gRPC server error", zap.Error(err))
		return 1
	}

	log.Info("gateway stopped")
	return 0
}

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
