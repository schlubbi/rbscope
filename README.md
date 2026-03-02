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

🚧 Planning phase — see docs/ for the full implementation plan.

## License

MIT

