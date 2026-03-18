# SDK Setup

## SDKs — 6 Languages

| Language | Install | Build / Test | Framework Hooks |
|----------|---------|-------------|----------------|
| **Python** | `pip install ./sdk/python/` | `pytest` / `ruff check .` | LangChain, AutoGen, CrewAI, MCP, HTTP |
| **Node.js** | `npm install ./sdk/node/` | `npm run build` / `npm test` | LangChain.js, Vercel AI, OpenAI, Anthropic, MCP |
| **Go** | `go get github.com/AKiileX/Phantex/sdk/go` | `go test ./...` | http.RoundTripper, go-openai |
| **.NET** | `dotnet add reference sdk/dotnet/` | `dotnet build` / `dotnet test` | Semantic Kernel, HttpClient handler |
| **Java** | Local Maven build from `sdk/java/` | `mvn package` / `mvn test` | LangChain4j, Spring AI |
| **Ruby** | `gem build sdk/ruby/phantex-sdk.gemspec` | `gem install phantex-sdk-*.gem` | ruby-openai, langchainrb |

---

## Python SDK

```bash
# Install with all framework hooks
pip install "./sdk/python/[all]"

# Or install with specific framework support
pip install "./sdk/python/[langchain]"
pip install "./sdk/python/[mcp]"
pip install "./sdk/python/[autogen,crewai]"
```

```python
from phantex_sdk import PhantexSDK

phantex = PhantexSDK(
    gateway_addr="localhost:50051",
    agent_id="my-agent",
    # transport="auto",     # auto|socket|http|buffer
    # batch_size=50,
)
phantex.auto_instrument()

# Or instrument specific frameworks
# phantex.instrument_langchain()
# phantex.instrument_mcp()
```

**Kill switch:** Set `PHANTEX_ENABLED=0` to disable the SDK without removing code.

---

## Node.js SDK

```bash
cd sdk/node && npm install && npm run build
# Or from your project:
npm install /path/to/Phantex/sdk/node
```

```typescript
import { PhantexSDK } from '@phantex/sdk';

const phantex = new PhantexSDK({
  gatewayAddr: 'localhost:50051',
  agentId: 'my-node-agent',
});
phantex.autoInstrument(); // hooks LangChain.js, Vercel AI, OpenAI, Anthropic, MCP
```

---

## Go SDK

```go
import phantex "github.com/AKiileX/Phantex/sdk/go"

client, _ := phantex.NewClient(phantex.Config{
    GatewayAddr: "localhost:50051",
    AgentID:     "my-go-agent",
})
// Wrap your HTTP client
httpClient := client.WrapHTTPClient(http.DefaultClient)
```

---

## Dockerfile Integration (No Source Changes)

```dockerfile
COPY sdk/python/ /tmp/phantex-sdk/
RUN pip install /tmp/phantex-sdk/ && rm -rf /tmp/phantex-sdk/
ENV PHANTEX_AGENT_ID=my-agent
ENV PHANTEX_GATEWAY=gateway:50051
ENV PHANTEX_AUTO_INSTRUMENT=1
```
