# Metrics Abstraction Migration Guide

This guide helps you migrate from the legacy Telegraf-specific metrics implementation to the new vendor-agnostic metrics abstraction layer that supports OpenTelemetry, Telegraf/StatsD, and no-op backends.

## Overview

The metrics abstraction layer provides:
- **Vendor Agnostic**: Switch between OTEL, Telegraf, or disabled metrics via configuration
- **Backward Compatible**: Existing Telegraf configurations continue to work unchanged
- **Future Proof**: Easy to add new metrics backends
- **Performance**: Minimal overhead with lazy instrument creation

## Quick Migration

### For Existing Deployments (No Changes Required)

If you're using Telegraf/StatsD, **no changes are required**. The system defaults to `telegraf` backend and maintains full compatibility:

```bash
# Your existing configuration continues to work
TELEGRAF_HOST=metrics.example.com
TELEGRAF_PORT=8125
STATSD_PREFIX=aip
```

### To Enable OpenTelemetry

1. **Install OTEL dependencies** (optional):
   ```bash
   pip install opentelemetry-api opentelemetry-sdk opentelemetry-exporter-otlp opentelemetry-exporter-prometheus
   ```

2. **Update environment configuration**:
   ```bash
   METRICS_BACKEND=otel
   OTEL_EXPORTER_ENDPOINT=http://your-otel-collector:4317
   OTEL_SERVICE_NAME=aip
   OTEL_SERVICE_VERSION=1.0.0
   ```

3. **Restart the service** - metrics will now be exported via OTEL

### To Disable Metrics

```bash
METRICS_BACKEND=none
```

## Configuration Reference

### Environment Variables

| Variable | Legacy Equivalent | Default | Description |
|----------|------------------|---------|-------------|
| `METRICS_BACKEND` | N/A | `telegraf` | Backend type: `otel`, `telegraf`, `none` |
| `METRICS_HOST` | `TELEGRAF_HOST` | `telegraf` | Host for Telegraf/StatsD backend |
| `METRICS_PORT` | `TELEGRAF_PORT` | `8125` | Port for Telegraf/StatsD backend |
| `METRICS_PREFIX` | `STATSD_PREFIX` | `aip` | Metric name prefix |
| `OTEL_EXPORTER_ENDPOINT` | N/A | `null` | OTLP gRPC endpoint |
| `OTEL_SERVICE_NAME` | N/A | `aip` | Service name for OTEL attribution |
| `OTEL_SERVICE_VERSION` | N/A | `1.0.0` | Service version for OTEL attribution |
| `OTEL_EXPORT_INTERVAL_SECONDS` | N/A | `30` | How often to export OTEL metrics |
| `OTEL_ENABLE_PROMETHEUS` | N/A | `false` | Enable Prometheus scrape endpoint |

### Backward Compatibility Matrix

| Legacy Variable | New Variable | Status |
|----------------|--------------|--------|
| `TELEGRAF_HOST` | `METRICS_HOST` | ✅ Both supported |
| `TELEGRAF_PORT` | `METRICS_PORT` | ✅ Both supported |
| `STATSD_PREFIX` | `METRICS_PREFIX` | ✅ Both supported |

## Code Migration

### For Application Code

If you have custom code using metrics, update imports:

```python
# Before
from aio_statsd import TelegrafStatsdClient

# After  
from social.graze.aip.app.metrics import MetricsClient
from social.graze.aip.app.config import MetricsClientAppKey

# Usage (unchanged)
def my_handler(request):
    metrics_client = request.app[MetricsClientAppKey]
    metrics_client.increment("my.custom.metric", 1, {"tag": "value"})
```

### For New Components

Use the factory function for creating metrics clients:

```python
from social.graze.aip.app.metrics import create_metrics_client

# Create client based on configuration
metrics_client = create_metrics_client(
    backend="otel",
    service_name="my-service",
    otel_endpoint="http://localhost:4317"
)

# Use the client
metrics_client.increment("custom.counter", 1, {"method": "POST"})
await metrics_client.close()  # Don't forget to close
```

## Testing Migration

### Verify Telegraf Backend Still Works

```bash
# Set legacy configuration
export TELEGRAF_HOST=localhost
export TELEGRAF_PORT=8125
export METRICS_BACKEND=telegraf

# Start service and verify metrics are sent to StatsD/Telegraf
pdm run aipserver
```

### Test OpenTelemetry Backend

```bash
# Start OTEL collector (example with Docker)
docker run -p 4317:4317 -p 8889:8888 otel/opentelemetry-collector:latest

# Configure AIP for OTEL
export METRICS_BACKEND=otel
export OTEL_EXPORTER_ENDPOINT=http://localhost:4317
export OTEL_SERVICE_NAME=aip-test

# Start service and verify metrics in OTEL collector
pdm run aipserver
```

### Test Disabled Metrics

```bash
export METRICS_BACKEND=none
pdm run aipserver
# Service should start normally with no metrics collection
```

## Monitoring Migration

### Dashboards and Alerts

Metric names and tags remain unchanged across backends:

- **Telegraf/StatsD**: `aip.server.request.count{method=GET,status=200}`
- **OpenTelemetry**: `aip.server.request.count{method="GET",status="200"}`

Your existing Grafana dashboards and alerts should continue working with minor adjustments for tag syntax differences.

### OpenTelemetry Integration

With OTEL backend, you can:

1. **Export to multiple backends simultaneously**:
   ```bash
   OTEL_EXPORTER_ENDPOINT=http://jaeger:14250  # Tracing
   OTEL_ENABLE_PROMETHEUS=true                 # Prometheus scraping
   ```

2. **Use OTEL Collector for routing**:
   ```yaml
   # otel-collector.yaml
   receivers:
     otlp:
       protocols:
         grpc:
           endpoint: 0.0.0.0:4317
   
   exporters:
     prometheus:
       endpoint: "0.0.0.0:8889"
     jaeger:
       endpoint: jaeger:14250
   
   service:
     pipelines:
       metrics:
         receivers: [otlp]
         exporters: [prometheus, jaeger]
   ```

## Troubleshooting

### Common Issues

1. **Service won't start with OTEL backend**:
   ```bash
   # Install missing dependencies
   pip install opentelemetry-api opentelemetry-sdk opentelemetry-exporter-otlp
   ```

2. **Metrics not appearing in OTEL collector**:
   - Verify `OTEL_EXPORTER_ENDPOINT` is correct
   - Check collector is running and accessible
   - Enable debug logging: `DEBUG=true`

3. **Legacy environment variables not working**:
   - Ensure you're using the correct variable names (check table above)
   - Verify no typos in variable names
   - Check environment variable precedence

### Debug Mode

Enable debug logging to troubleshoot metrics issues:

```bash
export DEBUG=true
export METRICS_BACKEND=otel
pdm run aipserver
# Check logs for metrics client creation and operation details
```

### Validation

Use the included unit tests to validate your setup:

```bash
# Run metrics abstraction tests
pytest tests/test_metrics_abstraction.py -v

# Run integration tests
pytest tests/ -k metrics -v
```

## Performance Considerations

### Backend Performance

| Backend | Overhead | Latency | Scalability |
|---------|----------|---------|-------------|
| **None** | Minimal | None | Unlimited |
| **Telegraf** | Low | UDP fire-and-forget | Very high |
| **OTEL** | Medium | Batched exports | High |

### Optimization Tips

1. **Adjust export intervals** for OTEL:
   ```bash
   OTEL_EXPORT_INTERVAL_SECONDS=60  # Reduce export frequency
   ```

2. **Use sampling** for high-volume metrics:
   ```python
   # Custom sampling logic
   if random.random() < 0.1:  # 10% sampling
       metrics_client.increment("high.volume.metric")
   ```

3. **Batch operations** where possible:
   ```python
   # Better than multiple individual calls
   for item in batch:
       metrics_client.increment("batch.processed", len(batch))
   ```

## Support

For issues or questions:

1. Check the unit tests in `tests/test_metrics_abstraction.py`
2. Review the implementation in `src/social/graze/aip/app/metrics.py`
3. File issues at the project repository

## Summary

The metrics abstraction migration provides:
- ✅ **Zero-downtime migration** - existing setups continue working
- ✅ **Future-proof architecture** - easy to add new backends
- ✅ **Improved observability** - OpenTelemetry standard compliance
- ✅ **Performance flexibility** - choose the right backend for your needs

Choose your migration path based on your requirements:
- **Stay with Telegraf**: No action required
- **Modern observability**: Migrate to OpenTelemetry
- **Development/testing**: Use disabled metrics for faster startup