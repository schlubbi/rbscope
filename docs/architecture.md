# rbscope Architecture

## Overview

rbscope is an out-of-process Ruby profiler. The core profiling engine runs entirely in the Linux kernel (eBPF) and a Go collector — the Ruby process being profiled has zero awareness of the profiler.

```
┌─────────────────────────────────────────────────┐
│  Linux Kernel                                    │
│                                                  │
│  perf_event (99 Hz)  ─►  ruby_stack_walker.bpf  │  Reads EC → CFP chain
│  sys_enter_read      ─►  io_tracer.bpf          │  I/O latency + bytes
│  sched_switch        ─►  sched_tracer.bpf       │  On/off-CPU tracking
│                              │                   │
│                              ▼                   │
│                        ring buffer (16MB)        │
└──────────────────────────┬──────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────┐
│  rbscope-collector (Go)                          │
│                                                  │
│  Ring buffer reader                              │
│    → FrameResolver (iseq → method, class, cfunc) │
│    → Timeline builder (samples + markers)        │
│    → Export                                      │
│        ├── Gecko JSON (Firefox Profiler)          │
│        ├── Pyroscope (continuous flame graphs)    │
│        ├── Datadog (APM integration)             │
│        ├── pprof (go tool pprof compatible)      │
│        └── CSV (DuckDB analysis)                 │
└─────────────────────────────────────────────────┘
```

## BPF Stack Walker

The core innovation. A `perf_event`-triggered BPF program that walks Ruby's control frame stack from kernel space.

### How It Works

1. **Trigger**: Kernel fires a perf event on each CPU at 99 Hz
2. **EC lookup**: BPF reads the pre-resolved Execution Context address from a per-PID hash map
3. **CFP walk**: Starting from `ec->cfp`, walks upward through control frames (`cfp->iseq`, `cfp->ep`, `cfp->self`)
4. **Emit**: Writes a `stack_walker_event` (header + up to 128 Ruby frames + native stack) to the ring buffer

Each Ruby frame carries:
- `iseq_addr` — pointer to the instruction sequence (NULL for cfunc frames)
- `pc` — program counter (or `cfp->ep` for cfunc frames, used for method name resolution)
- `is_cfunc` — flag distinguishing Ruby methods from C functions
- `self_val` — receiver VALUE, used for class name resolution

### Frame Resolution (Go side)

The BPF program emits raw pointers. The Go `FrameResolver` reads process memory (`/proc/pid/mem`) to resolve them:

| Data | How resolved |
|---|---|
| Method name | `iseq → iseq.body → body.location → label` (Ruby string) |
| File path | `iseq → iseq.body → body.location → pathobj` |
| Line number | `iseq → iseq.body → body.location → first_lineno` |
| Class name | `self → RBasic.klass → classext.classpath` |
| Cfunc name | `ep[-2] → method_entry → called_id → global_symbols.ids[serial]` |

All resolved data is cached — iseq structs and class names are immutable once created.

### DWARF Offset Extraction

rbscope reads struct offsets from `libruby.so`'s DWARF debug info at startup. This means:
- **Custom Ruby builds work automatically** — no pre-computed offset tables needed
- **New Ruby releases** require no rbscope changes (unless struct layouts change fundamentally)
- Falls back to a pre-computed table if DWARF is unavailable

Key structures parsed:
- `rb_execution_context_t` — CFP pointer offset
- `rb_control_frame_t` — iseq, ep, self, sizeof
- `rb_iseq_t` / `rb_iseq_constant_body` — body, location, label, pathobj
- `rb_thread_t` — EC offset
- `rb_vm_t` — ractor (inline in Ruby 4.0+), main_thread
- `RString` — embed vs heap string layout
- `RClass_and_rb_classext_t` — classpath offset

## I/O Tracer

Attaches to syscall tracepoints (`sys_enter_read`, `sys_exit_read`, `sys_enter_write`, etc.) to capture:
- File descriptor number
- Byte count
- Duration (enter → exit delta)
- Thread ID correlation

The collector resolves file descriptors to socket addresses via `/proc/pid/fd` and `/proc/pid/net/tcp` for meaningful I/O labels (e.g., "MySQL read 4.2KB, 1.3ms").

## Scheduler Tracer

Attaches to `sched_switch` to record:
- When threads go off-CPU and why (voluntary sleep vs preemption)
- Duration of off-CPU periods
- Correlation with I/O events for idle detection

Heuristic: `VOLUNTARY_SLEEP` without a matching I/O event → thread is **idle** (blocked in epoll_wait/select waiting for work).

## Optional Gem (Enhanced Mode)

The `rbscope` gem provides two capabilities that can't be observed externally:

### GVL Contention Profiling
Uses `rb_internal_thread_event` API to hook READY/RESUMED/SUSPENDED state transitions. Fires USDT probes that the BPF collector captures via uprobes.

### Allocation Tracking
Uses `RUBY_INTERNAL_EVENT_NEWOBJ` callback with counter-based sampling (1:256). Captures allocation type (`T_STRING`, `T_ARRAY`, etc.), estimated size, and stack trace via USDT probe.

Both fire USDT probes — compiled as NOP instructions that have zero cost until the collector attaches uprobes to activate them.

## Supported Ruby Versions

Tested with Ruby 3.3+ and Ruby 4.0. The DWARF-based offset extraction adapts automatically to struct layout changes between versions.

Notable Ruby 4.0 change: `rb_vm_t.ractor` is an **inline struct** (not a pointer), and `main_thread` is at offset 40 within it. The DWARF parser handles this automatically.

## Key Design Decisions

| Decision | Choice | Why |
|---|---|---|
| Stack walking approach | BPF reads CFP chain | Zero in-process overhead; sees C extensions |
| Offset discovery | DWARF debug info | Custom builds work; no version-specific tables |
| Ring buffer | `BPF_MAP_TYPE_RINGBUF` (16MB) | Lower overhead than perf arrays; no lost events |
| Cfunc resolution | `called_id` via symbol table | Gets Ruby method names (`closed?`), not C symbols (`rb_io_closed`) |
| Class resolution | `self → klass → classpath` | Matches `rb_profile_frame_full_label` output |
| Sampling rate | 99 Hz (always-on) / 99 Hz (capture) | Standard profiling rate; avoids aliasing with 100 Hz timers |
| Frame cache | Per-iseq-addr + per-klass | Iseqs and class names are immutable once created |
