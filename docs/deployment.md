# rbscope Deployment Guide

## Prerequisites

- Kubernetes cluster with kernel ≥5.8 (BTF + BPF ring buffer support)
- Ruby processes with `rbscope` gem loaded
- At least one backend: Pyroscope, Jaeger v2, or Datadog

## Gem Installation (Tier 1)

Add to your Gemfile:
```ruby
gem 'rbscope'
```

Enable via environment variable:
```bash
RBSCOPE_ENABLED=1
```

### Rails Application Integration

```ruby
# config/initializers/rbscope.rb
if ENV['RBSCOPE_ENABLED']
  require 'rbscope'
  Rbscope.start(frequency: 19)

  # Add OTel span exporter (alongside existing exporters)
  require 'rbscope/otel'
  if defined?(OpenTelemetry::SDK)
    OpenTelemetry.tracer_provider.add_span_processor(
      OpenTelemetry::SDK::Trace::Export::SimpleSpanProcessor.new(
        Rbscope::OTelExporter.new
      )
    )
  end
end
```

## Collector Deployment (Tier 2)

### Kubernetes DaemonSet

```bash
# Create namespace and RBAC
kubectl apply -f collector/deploy/k8s/namespace.yaml
kubectl apply -f collector/deploy/k8s/rbac.yaml

# Configure
kubectl apply -f collector/deploy/k8s/configmap.yaml

# Deploy collector
kubectl apply -f collector/deploy/k8s/daemonset.yaml

# Verify
kubectl -n rbscope get ds rbscope-collector
kubectl -n rbscope logs -l app=rbscope-collector --tail=20
```

### ConfigMap Options

```yaml
data:
  frequency: "19"              # Sampling Hz (19=always-on, 99=standard, 999=deep)
  export: "pyroscope"          # Comma-separated: pyroscope,datadog,otlp,file
  pyroscope_url: "http://pyroscope:4040"
  otlp_endpoint: "otel-collector:4317"
  discovery_interval: "5s"     # How often to scan for new Ruby processes
  deep_capture_enabled: "false"
```

### Required Capabilities

The collector needs these Linux capabilities:
- `CAP_BPF` — Load and manage BPF programs
- `CAP_PERFMON` — Attach BPF programs to perf events (uprobes, tracepoints)
- `CAP_SYS_PTRACE` — Read /proc/<pid>/fd for fd→socket resolution

On older kernels (< 5.8), `CAP_SYS_ADMIN` may be needed instead.

## Backend Setup (Tier 3)

### Option A: Full Stack with OTel Collector

```bash
# From repo root — starts OTel Collector + Pyroscope + Jaeger
docker-compose up -d
```

The OTel Collector acts as a router:
- Receives OTLP profiles/traces from rbscope-collector
- Fans out to Pyroscope (profiles) and Jaeger (traces + profile correlation)

### Option B: Direct Pyroscope

Set collector export to `pyroscope` and point `pyroscope_url` at your Pyroscope instance.

### Option C: Direct Datadog

Set collector export to `datadog` and configure `datadog_url`. Correlates with existing OTel traces via `runtime-id` tag.

## On-Demand Deep Capture

Trigger a deep capture for investigation:

```bash
# From the collector pod or CLI
rbscope-collector capture --pid <RUBY_PID> --duration 10s --output /tmp/capture.rbscope
```

View the capture:
1. Convert to Firefox Profiler format (Gecko JSON)
2. Open https://profiler.firefox.com/ and load the file

## Rollout Strategy

1. **Dev** — Run collector locally against `bin/rails server`
2. **Staging** — DaemonSet on staging cluster, gem on subset of web workers
3. **Canary** — Enable on a small node pool, compare overhead metrics
4. **Production** — Gradual rollout, always-on at 19Hz across all web workers

## Monitoring the Collector

The collector exposes Prometheus metrics on `:8080/metrics`:

| Metric | Description |
|--------|-------------|
| `rbscope_samples_total` | Total stack samples captured |
| `rbscope_drops_total` | Ring buffer drops (should be 0) |
| `rbscope_export_latency_seconds` | Export operation latency histogram |
| `rbscope_attached_pids` | Number of currently attached Ruby processes |
