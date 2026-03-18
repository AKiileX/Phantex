# Phantex SDK for Java

Runtime security instrumentation for Java AI agent frameworks. Captures tool calls, LLM invocations, and chain executions — ships telemetry to the Phantex gateway for observability and threat detection.

## Quickstart

```java
import io.phantex.sdk.PhantexClient;

var client = PhantexClient.create(); // reads config from env
client.start();
// Your LangChain4j / Spring AI code runs — Phantex captures everything.
client.stop();
```

## Configuration

All configuration via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PHANTEX_TOKEN` | `""` | Auth token for gateway |
| `PHANTEX_TENANT_ID` | `""` | Tenant UUID |
| `PHANTEX_AGENT_ID` | `""` | Agent identifier |
| `PHANTEX_TRANSPORT` | `auto` | `auto`, `grpc`, `http`, or `buffer` |
| `PHANTEX_GATEWAY_ADDR` | `localhost:50051` | Gateway address |
| `PHANTEX_HOOKS` | `auto` | `auto`, `langchain4j,spring_ai`, or `none` |
| `PHANTEX_ENABLED` | `1` | Kill switch (`0` to disable) |
| `PHANTEX_DEBUG` | `0` | Debug logging |

## Framework Hooks

### LangChain4j
Wrap your models to capture all chat/tool calls:

```java
import io.phantex.sdk.PhantexClient;
import io.phantex.sdk.hooks.LangChain4jHook;

var client = PhantexClient.create();
client.start();

LangChain4jHook hook = client.hook(LangChain4jHook.class);
ChatLanguageModel wrapped = hook.wrap(originalModel);
wrapped.generate("Hello"); // Phantex captures this
```

### Spring AI
Wrap your ChatModel/EmbeddingModel:

```java
import io.phantex.sdk.PhantexClient;
import io.phantex.sdk.hooks.SpringAIHook;

var client = PhantexClient.create();
client.start();

SpringAIHook hook = client.hook(SpringAIHook.class);
ChatModel wrapped = hook.wrap(originalChatModel);
wrapped.call(prompt); // Phantex captures this
```

## Maven

```xml
<dependency>
    <groupId>io.phantex</groupId>
    <artifactId>phantex-sdk</artifactId>
    <version>0.1.0</version>
</dependency>
```

## Builder Pattern

```java
var config = PhantexConfig.builder()
    .authToken("my-token")
    .tenantId("my-tenant")
    .hooks("langchain4j")
    .build();

var client = PhantexClient.builder()
    .config(config)
    .build();

client.start();
```

## Testing

```bash
cd sdk/java
mvn test
```

## License

Apache-2.0
