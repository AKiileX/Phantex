// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

package phantex

import (
	"net/http"
	"time"
)

// HTTPHook intercepts outgoing HTTP requests to detect and capture AI API calls.
// It wraps http.DefaultTransport to capture all outgoing HTTP traffic,
// filtering for known AI endpoints.
type HTTPHook struct {
	transport       Transport
	config          *Config
	installed       bool
	originalDefault http.RoundTripper
}

func newHTTPHook(transport Transport, config *Config) Hook {
	return &HTTPHook{transport: transport, config: config}
}

func (h *HTTPHook) Name() string { return "http" }

func (h *HTTPHook) Install() bool {
	h.originalDefault = http.DefaultTransport
	http.DefaultTransport = &phantexRoundTripper{
		base:      h.originalDefault,
		transport: h.transport,
		config:    h.config,
	}
	h.installed = true
	return true
}

func (h *HTTPHook) Uninstall() {
	if h.originalDefault != nil {
		http.DefaultTransport = h.originalDefault
	}
	h.installed = false
}

type phantexRoundTripper struct {
	base      http.RoundTripper
	transport Transport
	config    *Config
}

func (rt *phantexRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Host

	// Only instrument known AI API hosts
	if !isAIAPIHost(host) {
		return rt.base.RoundTrip(req)
	}

	ctx := req.Context()
	sc := CurrentSpanContext(ctx)
	if sc.TraceID == "" {
		sc.TraceID = NewTraceID()
	}
	spanID := NewSpanID()

	callEvt := NewToolCallEvent()
	callEvt.TenantID = rt.config.TenantID
	callEvt.AgentPAID = AgentPAID(ctx)
	callEvt.ToolName = host + req.URL.Path
	callEvt.Protocol = "http"
	callEvt.Framework = "net/http"
	callEvt.TraceID = sc.TraceID
	callEvt.SpanID = spanID
	callEvt.ParentSpanID = sc.SpanID
	_ = rt.transport.Send(callEvt)

	start := time.Now()
	resp, err := rt.base.RoundTrip(req)
	duration := time.Since(start)

	respEvt := NewToolResponseEvent()
	respEvt.TenantID = rt.config.TenantID
	respEvt.AgentPAID = AgentPAID(ctx)
	respEvt.ToolName = host + req.URL.Path
	respEvt.Protocol = "http"
	respEvt.Framework = "net/http"
	respEvt.TraceID = sc.TraceID
	respEvt.SpanID = spanID
	respEvt.DurationNs = duration.Nanoseconds()
	if err != nil {
		respEvt.Success = false
		respEvt.ErrorMessage = err.Error()
	} else if resp != nil {
		respEvt.OutputSize = int(resp.ContentLength)
		if resp.StatusCode >= 400 {
			respEvt.Success = false
			respEvt.ErrorMessage = resp.Status
		}
	}
	_ = rt.transport.Send(respEvt)

	return resp, err
}
