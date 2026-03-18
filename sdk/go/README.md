# Phantex Go SDK

Runtime security instrumentation for AI agent frameworks in Go.

## Quick Start

```go
import phantex "github.com/AKiileX/Phantex/sdk/go"

client := phantex.NewClient(nil) // reads PHANTEX_* env vars
defer client.Close()
client.Start()
```

## Configuration

All configuration via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PHANTEX_TOKEN` | — | Auth token for gateway |
| `PHANTEX_TENANT_ID` | — | Tenant UUID |
| `PHANTEX_AGENT_ID` | — | Agent PAID |
| `PHANTEX_TRANSPORT` | `auto` | `auto` / `grpc` / `http` / `buffer` |
| `PHANTEX_GATEWAY_ADDR` | `localhost:50051` | gRPC gateway address |
| `PHANTEX_HOOKS` | `auto` | `auto` / `openai,http` / `none` |
| `PHANTEX_BATCH_SIZE` | `50` | Events per batch |
| `PHANTEX_ENABLED` | `1` | Kill switch (`0` to disable) |
| `PHANTEX_DEBUG` | `0` | Debug logging |

## Framework Hooks

### go-openai

Wrap your HTTP client to capture OpenAI API calls:

```go
import (
    phantex "github.com/AKiileX/Phantex/sdk/go"
    openai "github.com/sashabaranov/go-openai"
)

client := phantex.NewClient(nil)
client.Start()
defer client.Close()

// Get the OpenAI hook and wrap the HTTP client
hook := &phantex.OpenAIHook{}
httpClient := hook.WrapHTTPClient(nil)

// Use with go-openai
config := openai.DefaultConfig("your-api-key")
config.HTTPClient = httpClient
aiClient := openai.NewClientWithConfig(config)
```

### HTTP (Generic)

The HTTP hook automatically intercepts `http.DefaultTransport` to capture
outgoing requests to known AI API endpoints (OpenAI, Anthropic, Google, Cohere, Mistral).

```go
client := phantex.NewClient(&phantex.Config{
    Hooks: "http",
    Transport: "buffer",
})
client.Start()

// All http.Get / http.Post calls to AI APIs are now captured
```

## Manual Event Emission

```go
ctx := phantex.InstrumentContext(context.Background(), "my-agent")

evt := phantex.NewToolCallEvent()
evt.TenantID = "tenant-uuid"
evt.AgentPAID = "agent-paid"
evt.ToolName = "my-custom-tool"
evt.Framework = "custom"
evt.TraceID = phantex.TraceID(ctx)
evt.SpanID = phantex.NewSpanID()

client.Transport().Send(evt)
```

## Transport

The SDK supports three transport modes:

- **gRPC** (default): Direct protobuf streaming to the Phantex gateway
- **HTTP**: JSON-L batches over HTTPS (fallback)
- **Buffer**: In-memory storage for testing

## License

Apache-2.0
