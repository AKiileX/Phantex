# Load Testing — Phantex Pipeline

End-to-end load tests using [k6](https://k6.io/) to verify the full Phantex
pipeline sustains target throughput under pressure.

## Prerequisites

```bash
# Install k6
# macOS
brew install k6
# Linux
sudo gpg -k
sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg \
  --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D68
echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" | \
  sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update && sudo apt-get install k6
# Docker (no install needed)
docker run --rm -i grafana/k6 version
```

## Running

### Quick smoke test
```bash
k6 run --duration 30s --vus 5 tests/load/k6-pipeline.js
```

### Full pipeline test (default stages)
```bash
k6 run tests/load/k6-pipeline.js
```

### Custom target
```bash
k6 run tests/load/k6-pipeline.js \
  --env BASE_URL=http://backend:8000 \
  --env TEST_EMAIL=admin@phantex.local \
  --env TEST_PASSWORD=secret
```

### Docker (against local compose)
```bash
docker run --rm -i --network phantex_default \
  -e BASE_URL=http://backend:8000 \
  grafana/k6 run - < tests/load/k6-pipeline.js
```

## Scenarios

| Scenario           | Pattern                 | Target             |
|--------------------|-------------------------|--------------------|
| `api_smoke`        | Ramping VUs (0→100)     | Health + readiness |
| `event_ingest`     | 1000 req/s constant     | Event submission   |
| `dashboard_queries`| Ramping VUs (0→20)      | Alert/MCP/Trust    |

## Thresholds

| Metric                 | Target           |
|------------------------|------------------|
| `http_req_duration p95` | < 500ms         |
| `http_req_duration p99` | < 2000ms        |
| `api_errors`            | < 5% error rate |
| `login_duration p95`    | < 1000ms        |
| `alert_query_duration p95` | < 800ms     |

## CI Integration

Add to your pipeline:
```yaml
- name: Load Test
  run: |
    k6 run --out json=k6-results.json tests/load/k6-pipeline.js
    # Fail pipeline if thresholds breached (k6 exits non-zero)
```
