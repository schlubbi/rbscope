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

## How It Works

Most Ruby observability starts with **tracing** — instrumenting known operations (HTTP handlers, DB queries, cache calls) to produce a request waterfall. This is the security-camera approach: great for what you point it at, blind everywhere else. If something slow happens *between* instrumented spans, you'll never know.

rbscope takes a fundamentally different approach: **statistical profiling** combined with **kernel-level observation**.

### Tier 1 — The Gem (Rust, in-process)

A background thread wakes up 99 times per second and photographs every Ruby thread's call stack via `rb_profile_frames`. It doesn't care what's instrumented — if Ruby is stuck in `JSON.parse` for 200ms, ~20 samples land in that function. If GC is running, you see that too. The result is a flame graph of where CPU time *actually* went, with no blind spots.

The gem also plants invisible **USDT probes** — essentially `nop` instructions that do nothing until the eBPF collector decides to listen. Zero overhead when unobserved.

### Tier 2 — The Collector (Go + eBPF, out-of-process)

Runs alongside your Ruby processes (typically as a Kubernetes DaemonSet). It attaches tiny eBPF programs to the Linux kernel:

- **I/O tracer** — fires on every `read()` / `write()` / `sendmsg()`, recording which file descriptor, how many bytes, and how long it blocked
- **Scheduler tracer** — fires on `sched_switch` to record why threads sleep (mutex? disk? network?) and for how long
- **Uprobe on USDT probes** — activates the gem's tripwires to capture raw instruction pointers from kernel-side, resolved to function names via `/proc/pid/maps`

All data flows through a BPF ring buffer into the Go collector, which stitches it into pprof profiles and pushes to your backend.

### Tier 3 — Backends

Pyroscope for continuous flame graphs, Jaeger for distributed traces, Datadog for APM integration. The OTel Collector acts as a router, fanning out to whichever backends you run.

### Trace ↔ Profile Linking

The OTel SDK assigns `trace_id` / `span_id` to every request. The gem's exporter fires a USDT probe with those IDs on span completion; the eBPF collector captures them as pprof labels. Click a slow trace in Jaeger → jump to the exact flame graph for that request in Pyroscope.

### Architecture

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

## Why Not Just Use Tracing?

Traditional OTel tracing and rbscope answer different questions:

| | OTel Tracing | rbscope |
|---|---|---|
| **Captures** | Events you instrumented | Everything Ruby does + kernel I/O |
| **Blind spots** | Anything between spans | None (statistical sampling) |
| **Answers "why slow?"** | "It was in the DB call" | "It was in `AR::Result#each` deserializing 10K rows, and the thread was off-CPU 23ms waiting on the GC lock" |
| **Overhead model** | Per-event (more spans = more cost) | Fixed (99 samples/sec regardless of traffic) |
| **Kernel visibility** | None | Full (I/O latency, scheduling, off-CPU) |
| **Setup** | Add gems, instrument code | Add gem + deploy collector DaemonSet |

They're complementary — rbscope integrates with OTel so you get both the structured request waterfall *and* the statistical "where did the CPU actually go" answer.

## Overhead

rbscope is designed to run **always-on in production**, not sampled.

| | OTel spans | rbscope gem | rbscope eBPF collector |
|---|---|---|---|
| **CPU** | ~0.5–3% (traffic-dependent) | ~0.05–0.1% (fixed) | ~0.01–0.05% (fixed) |
| **Memory** | 10–100MB (span buffers, scales with throughput) | ~64KB (ring buffer) | ~256KB (BPF maps) |
| **Scales with** | Request volume × span count | Nothing (fixed 99Hz) | Syscall volume (~200ns each) |
| **Safe always-on?** | With sampling | Yes | Yes |

The key insight: OTel tracing makes you choose between **full visibility** (expensive under load) and **sampling** (cheap, but you miss the one request that matters). rbscope's fixed-cost model means the same overhead whether the box is idle or melting — so you can observe 100% of requests, all the time.

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

