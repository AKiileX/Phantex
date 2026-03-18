# Phantex SDK for Ruby

Runtime security instrumentation for Ruby AI agent frameworks. Captures tool calls, LLM invocations, and chain executions — ships telemetry to the Phantex gateway for observability and threat detection.

## Quickstart

```ruby
# Gemfile
gem 'phantex-sdk'

# In your agent code:
require 'phantex'

Phantex.start!
# Your ruby-openai / langchainrb code runs normally — Phantex captures everything.
```

## Configuration

All configuration via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PHANTEX_TOKEN` | `""` | Auth token for gateway |
| `PHANTEX_TENANT_ID` | `""` | Tenant UUID |
| `PHANTEX_AGENT_ID` | `""` | Agent identifier |
| `PHANTEX_TRANSPORT` | `auto` | `auto`, `http`, or `buffer` |
| `PHANTEX_GATEWAY_ADDR` | `localhost:50051` | Gateway address |
| `PHANTEX_HOOKS` | `auto` | `auto`, `ruby_openai,langchainrb`, or `none` |
| `PHANTEX_ENABLED` | `1` | Kill switch (`0` to disable) |
| `PHANTEX_DEBUG` | `0` | Debug logging |

## Framework Hooks

### ruby-openai
Automatically patches `OpenAI::Client#chat`, `#completions`, and `#embeddings`.

```ruby
require 'phantex'
require 'openai'

Phantex.start!
client = OpenAI::Client.new(access_token: ENV['OPENAI_API_KEY'])
client.chat(parameters: { model: "gpt-4", messages: [{ role: "user", content: "Hello" }] })
# ^ Phantex captures this call automatically
```

### langchainrb
Automatically patches `Langchain::LLM::Base#chat`, `Tool::Base#execute`, and `Chain::Base#call`.

```ruby
require 'phantex'
require 'langchain'

Phantex.start!
llm = Langchain::LLM::OpenAI.new(api_key: ENV['OPENAI_API_KEY'])
llm.chat(messages: [{ role: "user", content: "Summarize this" }])
# ^ Phantex captures this call automatically
```

## Manual Client Usage

```ruby
config = Phantex::Config.new(
  auth_token: "my-token",
  tenant_id:  "my-tenant",
  hooks:      "ruby_openai",
)
client = Phantex::Client.new(config: config)
client.start

# ... your agent code ...

client.stop
```

## Testing

```bash
cd sdk/ruby
ruby tests/phantex_test.rb
```

## License

Apache-2.0
