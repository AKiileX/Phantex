// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// Package metrics provides Prometheus metrics for the Phantex sensor.
//
// Metrics are registered with a custom registry so the default Go collector
// is included automatically. The registry is exposed via promhttp handler
// on the health check server's /metrics endpoint.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const namespace = "phantex_sensor"

var (
	// EventsProcessed counts total eBPF events processed, labeled by event type.
	EventsProcessed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "events_processed_total",
		Help:      "Total eBPF events processed by type.",
	}, []string{"event_type"})

	// SDKEventsProcessed counts total SDK (Python framework hook) events processed.
	SDKEventsProcessed = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "sdk_events_processed_total",
		Help:      "Total SDK events received via Unix socket.",
	})

	// ProbesLoaded is the number of eBPF probes successfully loaded.
	ProbesLoaded = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "probes_loaded",
		Help:      "Number of eBPF probes currently loaded.",
	})

	// ProbesTotal is the total number of eBPF probes attempted.
	ProbesTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "probes_total",
		Help:      "Total number of eBPF probes attempted.",
	})

	// EventsSent counts events successfully sent to the gateway.
	EventsSent = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "events_sent_total",
		Help:      "Total events sent to the gateway via gRPC.",
	})

	// Errors counts sensor errors by component.
	Errors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "errors_total",
		Help:      "Total errors by component.",
	}, []string{"component"})

	// AgentsDiscovered is the current count of discovered AI agents.
	AgentsDiscovered = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "agents_discovered",
		Help:      "Number of AI agents currently tracked.",
	})

	// Info is a constant gauge with version/mode labels for identification.
	Info = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "info",
		Help:      "Sensor build information.",
	}, []string{"version", "mode"})

	// registry holds all sensor-specific metrics plus default Go process metrics.
	registry = prometheus.NewRegistry()
)

func init() {
	// Register default collectors (go runtime, process stats)
	registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	registry.MustRegister(collectors.NewGoCollector())

	// Register sensor metrics
	registry.MustRegister(
		EventsProcessed,
		SDKEventsProcessed,
		ProbesLoaded,
		ProbesTotal,
		EventsSent,
		Errors,
		AgentsDiscovered,
		Info,
	)
}

// Handler returns an http.Handler that serves Prometheus metrics.
func Handler() http.Handler {
	return promhttp.HandlerFor(registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})
}
