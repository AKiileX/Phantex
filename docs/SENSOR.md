# Sensor Setup

## Sensor vs SDK — Two Layers of Visibility

| | **Sensor** (kernel-level) | **SDK** (application-level) |
|---|---|---|
| **What it sees** | Syscalls: process spawns, file opens, network, DNS, memory maps | Tool calls, prompts, model, tokens, MCP/LangChain protocol |
| **How it works** | eBPF probes in the Linux kernel — passive, can't be bypassed | Library in your app — instruments AI framework internals |
| **App changes?** | **No** — works on any process including closed-source | **Yes** — `pip install` + 2 lines of init code |

Use **sensor only** when you can't modify the app. Use **sensor + SDK** when you control the app for high-confidence alerting with both OS-level and semantic-level signals.

---

## Building the Sensor

### Quick Start (Interactive)

```bash
sudo ./start-sensor.sh              # interactive — prompts for config
sudo ./start-sensor.sh --defaults   # non-interactive — dev defaults, foreground
sudo ./start-sensor.sh --status     # check running sensor
sudo ./start-sensor.sh --stop       # stop sensor
```

`start-sensor.sh` handles everything: installs build tools if missing (clang, llvm, bpftool, kernel headers), generates a per-deployment Ed25519 signing keypair, compiles eBPF probes from source, signs them, builds the Go binary, and launches.

On first run it will:
1. **Check toolchain** — prompts to install missing packages (`apt`/`dnf`)
2. **Generate signing key** — Ed25519 keypair unique to your deployment
3. **Compile + sign + build** — `make all` (probes → sign → binary)
4. **Prompt for config** — tenant ID, auth token, gateway, filter mode

> **Note:** `sudo` must see Go 1.23+. If it finds an older system Go, run: `sudo ln -sf $(which go) /usr/local/bin/go`

> **Note:** On subsequent runs, if `sensor/sensor.yaml` already exists from a previous setup, the script skips all interactive prompts and uses the saved config directly. To reconfigure, delete it first: `rm sensor/sensor.yaml`

### Manual Build — Linux (eBPF)

Each deployment compiles eBPF probes from source and signs them with a locally-generated Ed25519 key. No pre-compiled binaries are distributed.

```bash
cd sensor
make genkey             # generate Ed25519 keypair (first time only)
make all                # compile probes → sign with your key → build binary
```

**Build requirements:** Go 1.23+, clang ≥ 15, llvm, bpftool, linux-headers, kernel ≥ 5.8 with BTF.

Individual targets:

```bash
make probes             # compile eBPF .bpf.o probes
make sign-bpf           # sign .bpf.o probes with Ed25519 key
make build              # compile probes + sign + build Go binary
make audit              # security: govulncheck + go mod verify + go vet
```

### Windows (ETW)

```bash
cd sensor
make build-windows      # cross-compile from Linux/macOS
# produces: phantex-sensor.exe + phantex-sensor-ctl.exe
```

The Windows sensor uses **ETW** (Event Tracing for Windows) instead of eBPF, plus **WFP** for network capture. Runs as a Windows service, requires Administrator privileges.

### Docker

```bash
docker build -f sensor/Dockerfile -t phantex-sensor .
docker run --rm --privileged \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  -v /sys/fs/bpf:/sys/fs/bpf \
  phantex-sensor --config /etc/phantex/sensor.yaml
```

---

## Sensor Configuration

**Dev quick start** — copy-paste this to get running immediately with `./quickstart.sh`:

```yaml
# sensor-dev.yaml — works out of the box with quickstart.sh (dev mode)
log_level: info
log_format: console

ebpf:
  filter_mode: filtered       # only trace discovered AI agent processes

transport:
  gateway_addr: "localhost:50051"
  auth_token: "phantex-docker-compose-dev-token-2025"
  tls_enabled: false
  batch_size: 100
  batch_timeout: 1s

health:
  enabled: true
  addr: ":9090"

discovery:
  scan_interval: 30s
  tenant_slug: default
  env_tag: dev
  exclude_self: true
  deduplicate_workers: true
```

```bash
# Build (eBPF probes compiled from source and signed per-deployment):
cd sensor
make genkey             # generate Ed25519 keypair (first time only)
make all                # compile probes → sign → build binary

# Run with the dev config (requires root for eBPF):
sudo PHANTEX_TENANT_ID=a0000000-0000-0000-0000-000000000001 \
  ./phantex-sensor --config sensor-dev.yaml
```

> **`filter_mode` matters:**
> - **`filtered`** (recommended) — only traces processes the sensor discovers as AI agents (Ollama, LangChain apps, MCP servers, etc.). Clean alerts, low noise.
> - **`all`** — traces every process on the system. Generates massive event volume and false alerts from normal OS activity (bash, systemd, docker, etc.). Only use for debugging or forensics.

> **Production:** generate a real token (`python3 -c "import secrets; print(secrets.token_urlsafe(32))"`) and add it to both `gateway.yaml` and your sensor config. Use `PHANTEX_AUTH_TOKEN` env var instead of putting tokens in files.

Generate a starter config for customization:

```bash
sudo ./phantex-sensor --init-config    # writes /etc/phantex/sensor.yaml
```

### Full Config Reference

```yaml
# sensor_id: ""          # Auto-generated UUID if empty
# tenant_id: ""          # Required for multi-tenant deployments

log_level: info           # debug | info | warn | error
log_format: json          # json | console

ebpf:
  filter_mode: filtered   # filtered = only AI agents (recommended) | all = every process (noisy)
  ringbuf_chan_size: 4096

transport:
  gateway_addr: "localhost:50051"
  # auth_token: ""                     # Prefer PHANTEX_AUTH_TOKEN env var
  tls_enabled: false
  # tls_cert_file: /etc/phantex/tls/client.crt
  # tls_key_file:  /etc/phantex/tls/client.key
  # tls_ca_file:   /etc/phantex/tls/ca.crt
  batch_size: 100
  batch_timeout: 1s
  buffer_size: 10000       # offline buffer (events kept when gateway is down)
  max_retries: 5
  retry_interval: 2s

health:
  enabled: true
  addr: ":9090"            # GET /healthz

discovery:
  scan_interval: 30s       # how often to scan for new AI agent processes
  tenant_slug: default
  env_tag: dev
  exclude_self: true       # don't monitor the sensor's own process
  deduplicate_workers: true
  # watch_binaries: [my-custom-agent]
  # exclude_patterns: [my-internal-service]

sdk_socket:
  enabled: true
  socket_path: /var/run/phantex/sdk.sock
  max_conns: 50
  rate_limit: 1000         # events/sec per connection
```

**Env var overrides:** `PHANTEX_AUTH_TOKEN`, `PHANTEX_SENSOR_ID`, `PHANTEX_TENANT_ID`.

---

## Running the Sensor

```bash
# Linux — direct binary
sudo ./phantex-sensor --config /etc/phantex/sensor.yaml

# Linux — systemd (after installing .deb/.rpm)
sudo systemctl start phantex-sensor
sudo systemctl status phantex-sensor

# Windows
.\phantex-sensor.exe --config C:\ProgramData\Phantex\sensor.yaml
```
