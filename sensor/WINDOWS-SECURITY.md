# Windows Sensor Security Architecture

## Block R — Security Hardening & Defense-in-Depth

### 1. Privilege Model

| Component | Required Privilege | Reason |
|-----------|-------------------|--------|
| ETW Provider | Administrator | Kernel ETW sessions require `SeSystemProfilePrivilege` |
| Network Monitor | Administrator | `GetExtendedTcpTable` with `TCP_TABLE_OWNER_PID` |
| Process Enricher | Standard (PROCESS_QUERY_LIMITED_INFORMATION) | Minimal access right |
| Agent Discovery | Standard (PROCESS_QUERY_LIMITED_INFORMATION) | Toolhelp32 snapshots |
| Named Pipe | LOCAL_SYSTEM | DACL restricts to SY+BA |
| Windows Service | LOCAL_SYSTEM | Default SCM service account |

**Principle of Least Privilege:** The sensor runs as LOCAL_SYSTEM (required for ETW) but individual Win32 API calls use `PROCESS_QUERY_LIMITED_INFORMATION` — the weakest process access right that still permits metadata queries. The sensor **never** uses `PROCESS_ALL_ACCESS` or reads process memory.

### 2. Input Validation & Bounds Checking

Every data path from Win32 APIs to protobuf output is bounds-checked:

- **ETW event parsers** (`etw/provider.go`):
  - `readUTF16String()`: Bounds-validates offset + length before reading, null-terminator scanning capped at buffer size
  - All string fields truncated: `maxPathLen=1024`, `maxArgvLen=2048`, `maxValueData=1024`
  - Process Start/Stop/Image Load/File/Registry parsers all check minimum buffer size before field extraction

- **Network provider** (`wfp/network.go`):
  - TCP table allocation capped at 64MB (`maxTcpTableSize`)
  - DNS iteration safety limit: 10,000 entries per scan
  - DNS names sanitized via `sanitizeDNSName()`: only printable ASCII + dots allowed
  - TLS SNI extraction validates ClientHello structure before parsing

- **Process enricher** (`enricher_win/enricher.go`):
  - All `OpenProcess` calls use handles with `defer CloseHandle()` — no handle leaks
  - `NtQueryInformationProcess` buffer capped at 4KB
  - Token queries use `TOKEN_QUERY` only — never `TOKEN_ADJUST_PRIVILEGES`

- **Converter** (`converter_win/converter.go`):
  - All string fields truncated via `truncate()` before protobuf assignment
  - UUID v7 generation uses `crypto/rand` (never `math/rand`)

### 3. Anti-Tampering

- **ETW session names**: Random 8-char hex suffix prevents session name prediction/hijack
  ```
  "PhantexProcess-a1b2c3d4" (not predictable)
  ```

- **Admin check at startup**: Sensor refuses to run without Administrator privileges (prevents running in degraded state that could be exploited)

- **Config file ACL**: `%ProgramData%\Phantex\` directory has DACL:
  ```
  D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)
  ```
  Only LOCAL_SYSTEM and BUILTIN\Administrators can read/write.

- **Auth token from environment**: Token comes from `PHANTEX_AUTH_TOKEN` env var, not config file. Production validator rejects default dev token.

### 4. Named Pipe Security

The SDK named pipe (`\\.\pipe\phantex-sdk`) implements:

- **DACL restriction**: Only LOCAL_SYSTEM (SY) and BUILTIN\Administrators (BA) can connect
  ```
  D:(A;;GA;;;SY)(A;;GA;;;BA)
  ```
- **Client PID verification**: `GetNamedPipeClientProcessId` identifies the connecting process
- **Per-connection rate limiting**: Token bucket (default 1000 events/sec)
- **Max concurrent connections**: Configurable limit (default 50)
- **Max line size**: 64KB per NDJSON line — prevents memory exhaustion

### 5. Network Security

- **TLS 1.3 + mTLS**: Reuses the Linux sensor's TLS provider with cert hot-reloading
- **Loopback filtering**: Network monitor skips 127.0.0.1 and ::1 connections
- **DNS rate limiting**: Max 5000 DNS cache entries per scan (prevents cache flooding DoS)

### 6. Resource Limits

| Resource | Limit | Enforced In |
|----------|-------|-------------|
| ETW event queue | 8192 events | `etw/provider.go` |
| TCP table allocation | 64 MB | `wfp/network.go` |
| DNS entries per scan | 10,000 | `wfp/network.go` |
| Modules per process | 4,096 | `discovery_win/scanner.go` |
| Enricher cache | TTL-based (30s default) | `enricher_win/enricher.go` |
| Named pipe connections | 50 (configurable) | `namedpipe/listener.go` |
| NDJSON line size | 64 KB | `namedpipe/listener.go` |
| SDK events/sec/conn | 1,000 | `namedpipe/listener.go` |

### 7. Graceful Degradation

- ETW providers fail independently: if registry ETW fails, process + file still work
- Network provider failure → sensor runs without network visibility (logged as warning)
- Named pipe failure → sensor runs without SDK ingestion
- Any non-fatal error is logged, never causes sensor crash

### 8. Build Security

- **Build tags**: All Windows code uses `//go:build windows` — never compiled on Linux
- **Vendored deps**: `GOFLAGS=-mod=vendor` for hermetic builds
- **Static binary**: `CGO_ENABLED=0` — no dynamic linking
- **Stripped symbols**: `-ldflags "-s -w"` in production builds
- **Version stamped**: `-X main.version=$(VERSION)` via git tags

### 9. File Layout

```
sensor/
├── cmd/
│   ├── phantex-sensor/
│   │   ├── main.go              # Linux entry point (go:build !windows)
│   │   └── main_windows.go      # Windows entry point (go:build windows)
│   └── phantex-sensor-ctl/
│       └── main.go              # Windows service installer
├── internal/
│   ├── platform/
│   │   ├── platform.go          # Cross-platform event interface
│   │   ├── etw/
│   │   │   ├── provider.go      # ETW event provider
│   │   │   └── syscalls.go      # Win32 ETW syscall wrappers
│   │   ├── wfp/
│   │   │   └── network.go       # TCP/DNS network monitor
│   │   ├── enricher_win/
│   │   │   ├── enricher.go      # Win32 process enrichment
│   │   │   └── enricher_test.go
│   │   ├── converter_win/
│   │   │   ├── converter.go     # platform.Event → PhantexEvent
│   │   │   └── converter_test.go
│   │   ├── discovery_win/
│   │   │   ├── scanner.go       # Toolhelp32 agent discovery
│   │   │   └── scanner_test.go
│   │   ├── namedpipe/
│   │   │   └── listener.go      # SDK named pipe (replaces Unix socket)
│   │   ├── config_win/
│   │   │   └── config.go        # Windows config extensions
│   │   └── service/
│   │       └── service.go       # Windows Service (SCM) integration
│   ├── config/                   # Shared config (reused)
│   ├── transport/                # gRPC client (reused)
│   ├── tls/                      # TLS 1.3 + mTLS (reused)
│   ├── metrics/                  # Prometheus metrics (reused)
│   └── discovery/                # Shared types + PAID generation (reused)
```

### 10. Reused Components (Zero Changes)

These packages are platform-independent and shared with the Linux sensor:

- `internal/config/` — Base YAML config, env overrides, validation
- `internal/transport/grpc_client.go` — Batching, buffering, reconnect
- `internal/tls/provider.go` — TLS 1.3, mTLS, cert hot-reload
- `internal/metrics/metrics.go` — Prometheus counters/gauges
- `internal/discovery/paid.go` — PAID generation algorithm
- `internal/discovery/signatures.go` — Framework fingerprint definitions
