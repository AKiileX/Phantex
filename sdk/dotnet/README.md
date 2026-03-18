# Phantex .NET SDK

Runtime security instrumentation for AI agent frameworks in .NET.

## Quick Start

```csharp
using Phantex.SDK;

await using var client = new PhantexClient();
await client.StartAsync();
// ... your agent code ...
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
| `PHANTEX_HOOKS` | `auto` | `auto` / `semantickernel,http` / `none` |
| `PHANTEX_BATCH_SIZE` | `50` | Events per batch |
| `PHANTEX_ENABLED` | `1` | Kill switch (`0` to disable) |
| `PHANTEX_DEBUG` | `0` | Debug logging |

## Framework Hooks

### Semantic Kernel

Use the `SemanticKernelHook` as a function invocation filter:

```csharp
using Phantex.SDK;

await using var phantex = new PhantexClient();
await phantex.StartAsync();

var hook = phantex.Hooks.OfType<SemanticKernelHook>().First();

// In your IFunctionInvocationFilter:
public async Task OnFunctionInvocationAsync(
    FunctionInvocationContext context, Func<FunctionInvocationContext, Task> next)
{
    await hook.OnFunctionInvocationAsync(
        context.Function.Name,
        context.Function.PluginName,
        "gpt-4",
        () => next(context));
}
```

### HttpClient (Generic)

Intercept outgoing HTTP requests to AI API endpoints:

```csharp
var hook = phantex.Hooks.OfType<HttpClientHook>().First();
var handler = hook.CreateHandler();
var httpClient = new HttpClient(handler);

// All requests to api.openai.com, etc. are now captured
```

## Transport

- **gRPC** (default): Direct protobuf streaming to Phantex gateway
- **HTTP**: JSON-L batches over HTTPS (fallback)
- **Buffer**: In-memory storage for testing

## Install

```bash
dotnet add package Phantex.SDK
```

## License

Apache-2.0
