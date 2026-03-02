# rbscope — Ruby X-ray Profiling

> A modern, always-on Ruby profiler combining USDT probes, eBPF collection, and OpenTelemetry integration.

## Attribution

This project is a clean-sheet successor to the **[tracecap](https://github.com/tracecap)** profiling system, originally designed and built by **[Theo Julienne](https://github.com/theojulienne)** (~2021). Theo's architecture — thin in-process USDT probes collected by an external eBPF daemon — was ahead of its time and remains the core architectural insight behind rbscope.

The original tracecap repositories:

- [`tracecap/tracecap-ruby-profiler`](https://github.com/tracecap/tracecap-ruby-profiler) — C extension with USDT probes
- [`tracecap/tracecap-ruby-opentelemetry`](https://github.com/tracecap/tracecap-ruby-opentelemetry) — OTel SpanExporter via USDT
- [`tracecap/tracecap`](https://github.com/tracecap/tracecap) — Go/eBPF collector
- [`tracecap/tracecap-ui`](https://github.com/tracecap/tracecap-ui) — Django + TypeScript viewer

rbscope modernizes this vision for Ruby 4.0, CO-RE eBPF, OTLP profiling, and Kubernetes.

## Architecture

```
┌──────────────────────────────────┐
│  Tier 1: In-Process (Rust gem)   │   rbscope-ruby
│  USDT probes + OTel exporter     │   ~0 overhead when no collector attached
└──────────────┬───────────────────┘
               │ USDT (uprobe attachment)
               ▼
┌──────────────────────────────────┐
│  Tier 2: External Collector (Go) │   rbscope-collector
│  eBPF + I/O correlation + export │   K8s DaemonSet, CAP_BPF
└──────────────┬───────────────────┘
               │ pprof / OTLP / .rbscope
               ▼
┌──────────────────────────────────┐
│  Tier 3: Backends                │   Pyroscope, Datadog, Jaeger v2
│  OTel Collector fan-out          │   Firefox Profiler for deep captures
└──────────────────────────────────┘
```

## Status

🚧 Early development — the core components work end-to-end:

- ✅ Rust gem builds and passes all tests (32 Ruby + 4 Rust)
- ✅ Go collector builds and passes all tests (12 tests, race-clean)
- ✅ Standalone capture → speedscope flame graph
- ✅ OTel traces → Jaeger with rich child spans
- ✅ Demo mode: simulated profiles → Pyroscope (no BPF needed)

## Quick Start

**Prerequisites:** Docker and Docker Compose.

```bash
# Start the full demo stack
make demo-up

# Run smoke tests (waits for services, then verifies all paths)
make smoke-test

# Open the UIs:
#   Test app:   http://localhost:3000/slow
#   Jaeger UI:  http://localhost:16686
#   Pyroscope:  http://localhost:4040

# Tear down
make demo-down
```

No Codespace, no special Linux capabilities, no Ruby or Go install needed — everything runs in containers.

### Unit Tests (no Docker)

```bash
make test-gem        # needs Ruby + Rust
make test-collector  # needs Go
make test-all        # both
```

### Codespace / Dev Container

Open this repo in any [GitHub Codespace](https://github.com/features/codespaces) or VS Code dev container — the `.devcontainer/devcontainer.json` installs Ruby, Rust, Go, and Docker automatically.

## License

MIT

