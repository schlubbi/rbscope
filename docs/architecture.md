# rbscope Architecture

> Built on the shoulders of [tracecap](https://github.com/tracecap) by **Theo Julienne** (@theojulienne).

## Three-Tier Design

rbscope is a Ruby profiling system with three distinct tiers, each running at a different privilege level and with different performance constraints.

### Tier 1: In-Process Ruby Extension (`rbscope` gem)

A Rust-based Ruby C extension that emits USDT probes. This tier runs **inside** the Ruby process and must be as lightweight as possible.

**Components:**
- **Sampling engine** (`sampler.rs`) — Dedicated pthread timer thread (not SIGALRM) that triggers `rb_profile_thread_frames` via `rb_postponed_job_trigger`. Fork-safe with PID tracking.
- **USDT probes** (`probes.rs`) — Three probe points compiled as NOPs: `ruby_sample` (periodic stack), `ruby_span` (OTel span completion), `ruby_alloc` (allocation event). Zero overhead when no collector attached.
- **Stack serialization** (`stack.rs`) — Compact binary format using frame indices (not strings). ~10-50x smaller than tracecap's string serialization.
- **OTel exporter** (`otel.rb`) — Implements `SpanExporter` interface, fires `ruby_span` probe with trace context.
- **Allocation tracker** (`allocation_tracker.rb`) — TracePoint-based sampling at configurable intervals.

**Key constraint:** <1% CPU overhead when no collector is attached (USDT NOPs).

### Tier 2: External Collector (`rbscope-collector`)

A Go binary that runs as a Kubernetes DaemonSet. Uses eBPF to attach to Ruby processes and correlate with kernel events.

**Components:**
- **BPF programs** — CO-RE/BTF eBPF programs that attach as uprobes to USDT probe sites
  - `ruby_reader.c` — Reads Ruby stack samples from USDT probes
  - `io_tracer.c` — Attaches to syscall tracepoints for I/O correlation
  - `sched_tracer.c` — Attaches to sched_switch for off-CPU tracking
- **Event processing** — Ring buffer reader, stack deduplication, pprof builder
- **Export** — Pyroscope (pprof push), Datadog (profile upload), OTLP (OTel Collector), local files
- **Auto-discovery** — Watches /proc or K8s API for Ruby processes, auto-attaches

**Key design:** BPF ring buffers (not perf event arrays) for lower overhead and no lost samples.

### Tier 3: Backends

No custom backends — rbscope exports to standard tools:
- **Pyroscope** — Continuous flame graphs via pprof push
- **Jaeger v2** — Trace↔profile correlation via OTLP
- **Datadog** — APM integration via profile upload API
- **Firefox Profiler** — Deep capture viewer (Gecko format)
- **OTel Collector** — Fan-out router connecting all backends

## Data Flow

```
Ruby Process                    rbscope-collector              Backends
─────────────                   ──────────────────             ────────
rb_profile_thread_frames        
  → binary stack                
  → USDT ruby_sample  ───────→  BPF uprobe handler
                                  → ring buffer
                                  → stack dedup             → Pyroscope
                                  → pprof builder           → Datadog
                                                            → Jaeger v2

OTel span completion
  → ruby_span probe   ───────→  BPF uprobe handler
                                  → span + stack
                                  → OTLP export             → OTel Collector

Kernel syscalls        ───────→  BPF tracepoints
  read/write/connect              → io_tracer
  sched_switch                    → sched_tracer
                                  → TID correlation         → I/O labels in pprof
```

## Key Technical Decisions

| Decision | Choice | Why |
|----------|--------|-----|
| Tier 1 language | Rust (rb-sys/magnus) | Memory safety for C extension, USDT crate |
| Tier 2 language | Go | cilium/ebpf, strong K8s ecosystem |
| Sampling signal | pthread timer | Avoids SIGALRM conflict with Unicorn |
| Stack format | Binary frame indices | 10-50x smaller than strings |
| Ring buffer | BPF_MAP_TYPE_RINGBUF | Less overhead than perf arrays |
| Profile format | pprof (continuous) + rbscope proto (deep) | Universal + rich |
| Export path | OTLP primary, direct push fallback | Backend-agnostic |
