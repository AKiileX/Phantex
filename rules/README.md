# Phantex Core Detection Rules

> PRL (Phantex Rule Language) rules that ship with Phantex out of the box.

## Rules

| # | File | Name | Severity | Attack Class | Description |
|---|------|------|----------|-------------|-------------|
| 1 | `dos_protection.prl` | `high_tool_call_rate` | high | dos | Tool calls > 100 in 60s |
| 2 | `suspicious_network_dest.prl` | `suspicious_network_dest` | high | exfiltration | Network connect to non-private IP |
| 3 | `prompt_injection.prl` | `prompt_injection_pattern` | critical | prompt_injection | Known injection patterns in tool args |
| 4 | `excessive_file_read.prl` | `excessive_file_read` | medium | exfiltration | File reads > 50 in 60s |
| 5 | `credential_theft.prl` | `credential_in_output` | critical | credential_theft | API keys/tokens in tool args |
| 6 | `mcp_supply_chain.prl` | `unknown_mcp_server` | high | supply_chain | MCP tool with exec capabilities |
| 7 | `lateral_movement.prl` | `unusual_process_spawn` | high | lateral_movement | Shell/attack tool process spawn |
| 8 | `large_outbound_transfer.prl` | `large_outbound_transfer` | high | exfiltration | > 200 network connects in 5m |
| 9 | `new_network_connection.prl` | `new_network_connection` | medium | behavioral_anomaly | DNS to C2/tunneling domains |
| 10 | `sensitive_file_access.prl` | `sensitive_file_access` | high | unauthorized_access | Open on sensitive system files |

## PRL Syntax Quick Reference

```prl
# Comments start with #
# Comparisons: ==, !=, >, <, >=, <=, IN
# Logic: AND, OR, NOT, parentheses ()
# Functions: count(), contains(), regex_match(), time_since()

event.type == "TOOL_CALL"
AND regex_match("(?i)pattern", event.raw_data.tool_input)
AND count("TOOL_CALL", "60s") > 100
```

## Event Context

Rules evaluate against an `event` object with these fields:

| Field | Type | Example |
|-------|------|---------|
| `event.type` | string | `TOOL_CALL`, `PROCESS_EXEC`, `FILE_OPEN`, `NETWORK_CONNECT`, `NETWORK_DNS` |
| `event.severity` | string | `info`, `low`, `medium`, `high`, `critical` |
| `event.agent_id` | string | UUID of the agent |
| `event.sensor_id` | string | Sensor identifier |
| `event.raw_data.*` | dict | Event-type-specific fields (see below) |

### raw_data by Event Type

**TOOL_CALL / TOOL_RESPONSE:**
- `event.raw_data.tool_name` — tool being called
- `event.raw_data.tool_input` — input/arguments to the tool
- `event.raw_data.protocol` — `langchain_tool`, `mcp`, `autogen`, etc.

**PROCESS_EXEC:**
- `event.raw_data.process_exec.pid`, `.ppid`, `.uid`, `.comm`, `.filename`, `.argv`

**FILE_OPEN / FILE_READ / FILE_WRITE:**
- `event.raw_data.file.filename`, `.pid`, `.uid`, `.comm`, `.operation`

**NETWORK_CONNECT:**
- `event.raw_data.network.dst_addr`, `.dst_port`, `.src_addr`, `.src_port`, `.pid`, `.comm`

**NETWORK_DNS:**
- `event.raw_data.dns.query_name`, `.query_type`, `.dst_addr`, `.pid`, `.comm`

## Built-in Functions

| Function | Args | Returns | Description |
|----------|------|---------|-------------|
| `count(event_type, window)` | string, duration | int | Events of type in sliding window |
| `contains(text, pattern)` | string, string | bool | Substring search |
| `regex_match(pattern, text)` | string, string | bool | Python regex search |
| `time_since(event_type)` | string | float | Seconds since last event of type |

Duration format: `60s`, `5m`, `1h`, `7d`

## Customization

1. **Adjust thresholds** — Edit the numbers in `count()` comparisons
2. **Add allowlists** — Use `NOT regex_match(allowlist_pattern, field)` to exclude known-good patterns
3. **Create custom rules** — Add a `.prl` file and update `manifest.json`

## Validation

```bash
cd backend && python -m rules.loader
```

This validates all rules parse correctly and reports any errors.
