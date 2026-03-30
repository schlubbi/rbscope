# rbscope — Ruby Profiler for Linux

An always-on Ruby profiler using eBPF. Attaches to running Ruby processes externally — no gem, no code changes, no restart. Produces flame graphs with fully-qualified Ruby stack traces including C extension calls.

## How It Works

rbscope runs **outside** your Ruby process. A small eBPF program attached to the kernel's perf subsystem interrupts each CPU 99 times per second, reads the target process's Ruby VM state via `/proc/pid/mem`, and emits stack samples through a BPF ring buffer into the Go collector.

```
Your Ruby process                       rbscope-collector (Go)
──────────────────                       ──────────────────────
                                         perf_event @ 99 Hz
Ruby VM  ◄────── BPF reads CFP chain ──  BPF program (in-kernel)
  │                                        │
  │                                        ▼ ring buffer
  │                                      FrameResolver
  │                                        reads iseq structs
  │                                        resolves class names
  │                                        resolves cfunc names
  │                                        │
  │                                        ▼
  │                                      ┌─────────────────┐
  │                                      │ Firefox Profiler │
  │                                      │ Pyroscope        │
  │                                      │ Datadog          │
  │                                      │ pprof            │
  │                                      └─────────────────┘
  │
  ├── I/O syscalls ◄── BPF tracepoints ── io_tracer
  └── sched_switch ◄── BPF tracepoints ── sched_tracer
```

**Zero in-process overhead.** The Ruby process doesn't know it's being profiled. No signals, no callbacks, no monkey-patching.

## What You See

rbscope produces fully-qualified Ruby stack traces:

```
Rack::ContentLength#call
  ActionDispatch::Executor#call
    PostsController#index
      Post::ActiveRecord_Relation#records
        rb_trilogy_query          ← C extension frames visible
          trilogy_query_send
          _cb_raw_write
```

Plus kernel-level markers:
- **I/O operations** — which syscalls, how many bytes, how long they blocked
- **Scheduling events** — when threads were on/off CPU and why
- **Idle detection** — epoll_wait/select → thread marked idle

## Requirements

| Requirement | Details |
|---|---|
| **Linux kernel** | ≥ 5.8 (BTF + BPF ring buffer support) |
| **Ruby** | ≥ 3.3.0 with DWARF debug info in libruby.so |
| **Capabilities** | `CAP_BPF` + `CAP_PERFMON` + `CAP_SYS_PTRACE` (or root) |
| **Architecture** | x86_64 or arm64 |

### Ruby with Debug Info

rbscope reads Ruby's internal data structures (iseq, CFP, RClass) via DWARF debug info in `libruby.so`. Most distro-packaged Rubies include this — you may need the `-dbg` or `-debuginfo` package.

**Check if your Ruby has debug info:**

```bash
# Look for .debug_info section in libruby
file $(ruby -e 'puts RbConfig::CONFIG["libdir"]')/libruby.so* | grep -i debug

# Or check with readelf
readelf -S $(ruby -e 'puts RbConfig::CONFIG["libdir"]')/libruby.so* | grep debug
```

**Common distro packages:**

| Distro | Ruby package | Debug info package |
|---|---|---|
| Ubuntu/Debian | `ruby` | `libruby-dev` or `ruby-dbg` |
| Fedora/RHEL | `ruby` | `ruby-debuginfo` |
| Alpine | Not supported (musl + no DWARF) | — |
| rbenv/ruby-build | Built from source | Include `--enable-debug-env` or build with `-g` |
| Docker `ruby:*` | Official images | Has DWARF by default |

**Custom Ruby builds (rbenv, ruby-build, ruby-install):**

```bash
# Ensure DWARF debug info is included
RUBY_CONFIGURE_OPTS="--enable-debug-env" rbenv install 3.3.0

# Or with ruby-build directly
CONFIGURE_OPTS="debugflags=-g" ruby-build 3.3.0 ~/.rubies/ruby-3.3.0
```

rbscope auto-discovers `libruby.so` from `/proc/pid/maps` — no manual path configuration needed in most cases.

## Quick Start

### One-Shot Capture

Capture a 10-second profile of a running Ruby process:

```bash
# Find your Ruby PID
pgrep -f 'puma|unicorn|pitchfork|rails'

# Capture (auto-discovers libruby.so)
sudo rbscope-collector capture \
  --pid 12345 \
  --mode bpf \
  --duration 10s \
  --format gecko \
  --output profile.json

# View in Firefox Profiler
# Open https://profiler.firefox.com and load profile.json
```

If auto-discovery fails (e.g., non-standard Ruby install):

```bash
sudo rbscope-collector capture \
  --pid 12345 \
  --mode bpf \
  --ruby-path /opt/ruby/lib/libruby.so \
  --duration 10s \
  --format gecko \
  --output profile.json
```

### Always-On (Continuous Profiling)

Run the collector as a daemon, streaming profiles to Pyroscope:

```bash
sudo rbscope-collector run \
  --export pyroscope \
  --pyroscope-url http://pyroscope:4040 \
  --frequency 19
```

The collector auto-discovers Ruby processes and attaches/detaches as they start and stop.

### Kubernetes DaemonSet

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: rbscope-collector
  namespace: rbscope
spec:
  selector:
    matchLabels:
      app: rbscope-collector
  template:
    spec:
      hostPID: true
      containers:
      - name: collector
        image: ghcr.io/schlubbi/rbscope-collector:latest
        args:
          - run
          - --export=pyroscope
          - --pyroscope-url=http://pyroscope:4040
          - --frequency=19
        securityContext:
          capabilities:
            add: [BPF, PERFMON, SYS_PTRACE]
        volumeMounts:
        - name: proc
          mountPath: /proc
          readOnly: true
        - name: sys
          mountPath: /sys
          readOnly: true
      volumes:
      - name: proc
        hostPath:
          path: /proc
      - name: sys
        hostPath:
          path: /sys
```

Key points:
- `hostPID: true` — required to see host Ruby processes from the container
- `BPF` + `PERFMON` + `SYS_PTRACE` capabilities — minimum for eBPF attachment and `/proc/pid/mem` reading
- Mount `/proc` and `/sys` — needed for process discovery and BPF map access

## Output Formats

| Format | Flag | Use case |
|---|---|---|
| **Gecko JSON** | `--format gecko` | Open in [Firefox Profiler](https://profiler.firefox.com) for interactive flame graphs, call trees, markers |
| **pprof** | `--format pb` | Compatible with `go tool pprof`, Pyroscope, Datadog |
| **CSV** | `--format csv` | Load into DuckDB for SQL analysis |

### Firefox Profiler (Recommended for Investigation)

The Gecko JSON format produces rich profiles with:
- **Call Tree** — fully-qualified Ruby frames with source locations
- **Flame Graph** — interactive, zoomable
- **Markers** — I/O operations, scheduling events, idle periods
- **Thread view** — per-worker breakdown (e.g., pitchfork workers)

Open [profiler.firefox.com](https://profiler.firefox.com), drag and drop the `.json` file.

## Optional: Enhanced Profiling with the Gem

For deeper instrumentation, add the `rbscope` gem to your application. This enables:

| Feature | BPF only | BPF + gem |
|---|---|---|
| Stack sampling | ✓ | ✓ |
| C extension frames | ✓ | ✓ |
| I/O + scheduling markers | ✓ | ✓ |
| **GVL contention profiling** | ✗ | ✓ |
| **Allocation tracking** (type, size) | ✗ | ✓ |
| Requires app restart | no | yes |

### Installation

```ruby
# Gemfile
gem 'rbscope', require: false
```

```ruby
# config/initializers/rbscope.rb (Rails)
if ENV['RBSCOPE_ENABLE']
  require 'rbscope'
end
```

```bash
# Enable at runtime
RBSCOPE_ENABLE=1 bundle exec pitchfork -c config/pitchfork.rb
```

The gem loads USDT probes that the BPF collector hooks into via uprobes. When no collector is attached, the probes are NOPs — zero overhead.

### Capture with Gem Mode

```bash
sudo rbscope-collector capture \
  --pid 12345 \
  --mode gem \
  --duration 10s \
  --format gecko \
  --output profile.json
```

## Supported Application Servers

rbscope works with any Ruby process. Tested with:

| Server | Notes |
|---|---|
| **Pitchfork** | Auto-discovers and attaches to all forked workers |
| **Puma** | Attach to the main process; sees all threads |
| **Unicorn** | Same as Pitchfork (fork-based) |
| **Sidekiq** | Attach to the Sidekiq process PID |
| **Plain Ruby** | Any `ruby` process works |

For fork-based servers (Pitchfork, Unicorn), the collector auto-discovers sibling workers sharing the same parent PID and attaches to all of them.

## Overhead

| Component | CPU | Memory |
|---|---|---|
| BPF stack walker (in-kernel) | ~0.01% per CPU | ~256KB (BPF maps) |
| Collector process (Go) | ~0.05% | ~10-20MB |
| Gem (when loaded) | ~0.05% | ~64KB |
| **Total (BPF only)** | **< 0.1%** | **< 25MB** |

Overhead is **fixed** — independent of request volume. The same cost whether your app handles 10 req/s or 10,000 req/s.

## Comparison with Other Tools

| | rbscope | Vernier | rbspy | Datadog Profiler |
|---|---|---|---|---|
| In-process code required | no | yes | no | yes |
| C extension frames | ✓ | ✓ | ✗ | ✗ |
| GVL profiling | with gem | ✓ | ✗ | ✗ |
| Allocation tracking | with gem | ✓ | ✗ | ✓ |
| I/O + scheduling markers | ✓ | ✗ | ✗ | ✗ |
| Always-on production safe | ✓ | risky | ✓ | ✓ |
| Continuous export | ✓ | ✗ | ✓ | ✓ |
| Linux only | yes | no | no | no |

**When to use rbscope:** You run Ruby on Linux and want always-on profiling with kernel-level visibility and zero app changes.

**When to use Vernier:** You need a one-off diagnostic profile on macOS or don't have BPF capabilities.

## Building from Source

```bash
# Collector (Go, requires Linux for BPF)
cd collector
go generate ./pkg/bpf/    # compile BPF C → Go (needs clang, bpftool)
go build -o rbscope-collector ./cmd/rbscope-collector/

# Gem (Rust, any platform)
cd gem
bundle exec rake compile
```

### Development VM

For development on macOS, use the included Lima VM:

```bash
limactl start scripts/lima-bpf-test.yaml
limactl shell rbscope-bpf
```

## Attribution

This project is a clean-sheet successor to **[tracecap](https://github.com/tracecap)**, originally designed and built by **[Theo Julienne](https://github.com/theojulienne)** (~2021). Theo's architecture — thin in-process USDT probes collected by an external eBPF daemon — was ahead of its time and remains a core insight behind rbscope.

## License

MIT
