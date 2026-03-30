# Deployment Guide

## One-Shot Capture (Investigation)

For ad-hoc profiling of a running Ruby process. No app changes needed.

### Prerequisites

1. Linux kernel ≥ 5.8
2. Root access (or `CAP_BPF` + `CAP_PERFMON` + `CAP_SYS_PTRACE`)
3. Ruby with DWARF debug info in `libruby.so`

### Steps

```bash
# 1. Find the Ruby PID
pgrep -fa 'puma|unicorn|pitchfork|sidekiq'

# 2. Capture a 10-second profile
sudo rbscope-collector capture \
  --pid 12345 \
  --mode bpf \
  --duration 10s \
  --format gecko \
  --output profile.json

# 3. View the profile
# Open https://profiler.firefox.com and load profile.json
```

The collector auto-discovers `libruby.so` from `/proc/pid/maps`. If it fails:

```bash
# Specify the path manually
sudo rbscope-collector capture \
  --pid 12345 \
  --mode bpf \
  --ruby-path /usr/lib/libruby.so.3.3.0 \
  --duration 10s \
  --format gecko \
  --output profile.json
```

### Fork-Based Servers (Pitchfork/Unicorn)

Point `--pid` at **any worker**. The collector auto-discovers siblings with the same parent PID and attaches to all of them. Each worker gets its own thread in the Firefox Profiler output.

```bash
# Get any worker PID
PID=$(pgrep -f "pitchfork.*worker" | head -1)
sudo rbscope-collector capture --pid $PID --mode bpf --duration 30s --format gecko --output profile.json
```

### Generating Load During Capture

For meaningful profiles, generate traffic while capturing:

```bash
# In one terminal: start capture
sudo rbscope-collector capture --pid 12345 --mode bpf --duration 15s --format gecko --output profile.json

# In another terminal: generate load
hey -n 500 -c 10 http://localhost:3000/posts
```

## Always-On (Continuous Profiling)

Run the collector as a daemon that auto-discovers Ruby processes and streams profiles to a backend.

### Standalone

```bash
sudo rbscope-collector run \
  --export pyroscope \
  --pyroscope-url http://pyroscope:4040 \
  --frequency 19
```

The collector:
1. Scans `/proc` every 5 seconds for Ruby processes
2. Attaches BPF programs to discovered processes
3. Detaches when processes exit
4. Streams profiles to Pyroscope at 10-second intervals

### systemd Service

```ini
# /etc/systemd/system/rbscope-collector.service
[Unit]
Description=rbscope Ruby Profiler
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/rbscope-collector run \
  --export pyroscope \
  --pyroscope-url http://pyroscope:4040 \
  --frequency 19
Restart=always
RestartSec=5

# Minimum capabilities
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_SYS_PTRACE
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_PTRACE

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now rbscope-collector
```

### Kubernetes DaemonSet

See the [README](../README.md#kubernetes-daemonset) for the full DaemonSet spec.

Key requirements:
- `hostPID: true` — see host processes
- Capabilities: `BPF`, `PERFMON`, `SYS_PTRACE`
- Mount `/proc` and `/sys` read-only

### Docker Compose (Development)

```yaml
services:
  rbscope-collector:
    image: ghcr.io/schlubbi/rbscope-collector:latest
    command: >
      run
      --export pyroscope
      --pyroscope-url http://pyroscope:4040
      --frequency 19
    pid: host
    cap_add:
      - BPF
      - PERFMON
      - SYS_PTRACE
    volumes:
      - /proc:/proc:ro
      - /sys:/sys:ro

  pyroscope:
    image: grafana/pyroscope:latest
    ports:
      - "4040:4040"
```

## Enhanced Mode (with Gem)

For GVL contention and allocation profiling, deploy the gem alongside the BPF collector.

### Add the Gem

```ruby
# Gemfile
gem 'rbscope', require: false
```

```ruby
# config/initializers/rbscope.rb
if ENV['RBSCOPE_ENABLE']
  require 'rbscope'
end
```

### Deploy

```bash
# Start your app with the gem enabled
RBSCOPE_ENABLE=1 bundle exec pitchfork -c config/pitchfork.rb
```

### Capture with Gem Mode

```bash
sudo rbscope-collector capture \
  --pid 12345 \
  --mode gem \
  --duration 10s \
  --format gecko \
  --output profile.json
```

Gem mode captures:
- Stack samples (via USDT probes + `rb_profile_frames`)
- GVL contention intervals (READY → RUNNING transitions with wait duration)
- Allocation events (type, size, stack)
- I/O and scheduling markers (from BPF tracepoints)

## Export Backends

### Pyroscope

```bash
rbscope-collector run --export pyroscope --pyroscope-url http://pyroscope:4040
```

### Datadog

```bash
DD_API_KEY=your-key rbscope-collector run \
  --export datadog \
  --datadog-url https://intake.profile.datadoghq.com
```

### OTLP (OpenTelemetry Collector)

```bash
rbscope-collector run \
  --export otlp \
  --otlp-endpoint otel-collector:4317
```

### Multiple Backends

```bash
rbscope-collector run \
  --export pyroscope,datadog \
  --pyroscope-url http://pyroscope:4040 \
  --datadog-url https://intake.profile.datadoghq.com
```

## Sampling Frequency

| Frequency | Flag | Use case |
|---|---|---|
| 19 Hz | `--frequency 19` | Always-on production (minimal overhead) |
| 99 Hz | `--frequency 99` | Standard profiling / captures |
| 999 Hz | `--frequency 999` | High-resolution investigation |

The default for `run` is 19 Hz. The default for `capture` is 99 Hz.

## Health and Monitoring

The collector exposes HTTP endpoints on port 8080:

| Endpoint | Description |
|---|---|
| `/healthz` | Returns `ok` — use for liveness probes |
| `/metrics` | Prometheus metrics |

Key metrics:

| Metric | Description |
|---|---|
| `rbscope_samples_total` | Total stack samples captured |
| `rbscope_drops_total` | Ring buffer drops (should be 0) |
| `rbscope_export_latency_seconds` | Export operation latency |
| `rbscope_attached_pids` | Number of currently attached processes |

## Troubleshooting

### "No debug info found in libruby.so"

Install the debug info package for your Ruby:

```bash
# Ubuntu/Debian
sudo apt install libruby-dev

# Fedora/RHEL
sudo dnf debuginfo-install ruby

# Verify
readelf -S $(ruby -e 'puts RbConfig::CONFIG["libdir"]')/libruby.so* | grep debug_info
```

### "Permission denied" or "operation not permitted"

The collector needs BPF capabilities:

```bash
# Run as root
sudo rbscope-collector capture --pid 12345 --mode bpf ...

# Or grant capabilities to the binary
sudo setcap 'cap_bpf,cap_perfmon,cap_sys_ptrace=ep' /usr/local/bin/rbscope-collector
```

### "Could not find libruby.so"

Auto-discovery reads `/proc/pid/maps`. If it fails:

```bash
# Find libruby manually
cat /proc/12345/maps | grep libruby

# Pass the path explicitly
rbscope-collector capture --pid 12345 --mode bpf --ruby-path /path/to/libruby.so ...
```

### "Kernel too old for BPF ring buffer"

BPF ring buffers require Linux ≥ 5.8. Check:

```bash
uname -r
```

### Empty profiles (0 samples)

1. Verify the PID is correct and the process is running
2. Generate load — idle processes produce few samples
3. Check the collector log for errors
4. Verify `libruby.so` has DWARF debug info
