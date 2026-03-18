// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

package phantex

import (
	"context"
	"net/http"
	"time"
)

// OpenAIHook intercepts calls to the go-openai client library.
// It wraps http.RoundTripper to capture outgoing requests to OpenAI-compatible APIs.
type OpenAIHook struct {
	transport Transport
	config    *Config
	installed bool
}

func newOpenAIHook(transport Transport, config *Config) Hook {
	return &OpenAIHook{transport: transport, config: config}
}

func (h *OpenAIHook) Name() string { return "openai" }

func (h *OpenAIHook) Install() bool {
	// The go-openai library uses http.DefaultTransport under the hood.
	// We wrap it to intercept calls to api.openai.com and compatible endpoints.
	h.installed = true
	return true
}

func (h *OpenAIHook) Uninstall() {
	h.installed = false
}

// WrapHTTPClient returns an http.Client with a RoundTripper that captures
// OpenAI-compatible API calls as Phantex events. Use this to instrument
// the go-openai client:
//
//	httpClient := phantexHook.WrapHTTPClient(http.DefaultClient)
//	openaiClient := openai.NewClientWithConfig(openai.ClientConfig{HTTPClient: httpClient})
func (h *OpenAIHook) WrapHTTPClient(base *http.Client) *http.Client {
	if base == nil {
		base = http.DefaultClient
	}
	rt := base.Transport
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &http.Client{
		Transport: &openAIRoundTripper{
			base:      rt,
			transport: h.transport,
			config:    h.config,
		},
		Timeout: base.Timeout,
	}
}

type openAIRoundTripper struct {
	base      http.RoundTripper
	transport Transport
	config    *Config
}

func (rt *openAIRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Only instrument known AI API hosts
	host := req.URL.Host
	if !isAIAPIHost(host) {
		return rt.base.RoundTrip(req)
	}

	ctx := req.Context()
	sc := CurrentSpanContext(ctx)
	if sc.TraceID == "" {
		sc.TraceID = NewTraceID()
	}
	spanID := NewSpanID()

	// Emit tool call event
	callEvt := NewToolCallEvent()
	callEvt.TenantID = rt.config.TenantID
	callEvt.AgentPAID = AgentPAID(ctx)
	callEvt.ToolName = req.URL.Path
	callEvt.Protocol = "openai_api"
	callEvt.Framework = "go-openai"
	callEvt.TraceID = sc.TraceID
	callEvt.SpanID = spanID
	callEvt.ParentSpanID = sc.SpanID
	_ = rt.transport.Send(callEvt)

	start := time.Now()
	resp, err := rt.base.RoundTrip(req)
	duration := time.Since(start)

	// Emit tool response event
	respEvt := NewToolResponseEvent()
	respEvt.TenantID = rt.config.TenantID
	respEvt.AgentPAID = AgentPAID(ctx)
	respEvt.ToolName = req.URL.Path
	respEvt.Protocol = "openai_api"
	respEvt.Framework = "go-openai"
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

// Middleware returns an HTTP middleware that captures all requests as Phantex events.
// Use with go-openai or any HTTP-based AI client:
//
//	handler := phantexHook.Middleware(yourHandler)
func (h *OpenAIHook) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		traceID := TraceID(ctx)
		spanID := NewSpanID()
		ctx = WithTraceID(ctx, traceID)
		ctx = WithSpanID(ctx, spanID)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

// isAIAPIHost checks if the host is a known AI API endpoint.
func isAIAPIHost(host string) bool {
	known := []string{
		"api.openai.com",
		"api.anthropic.com",
		"generativelanguage.googleapis.com",
		"api.cohere.ai",
		"api.mistral.ai",
	}
	for _, h := range known {
		if host == h {
			return true
		}
	}
	return false
}

// InstrumentContext adds Phantex trace context to a Go context for use with go-openai.
func InstrumentContext(ctx context.Context, agentID string) context.Context {
	ctx = WithTraceID(ctx, NewTraceID())
	ctx = WithSpanID(ctx, NewSpanID())
	ctx = WithAgentPAID(ctx, agentID)
	ctx = WithFramework(ctx, "go-openai")
	return ctx
}
