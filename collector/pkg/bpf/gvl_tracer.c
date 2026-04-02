//go:build ignore

// rbscope BPF program: GVL state change tracer
//
// Attaches as uprobe to __rbscope_probe_gvl_event in the target Ruby
// process. Emits raw state-change events for the Go-side state machine
// to compute continuous intervals (RUNNING/STALLED/SUSPENDED).
//
// The gem fires the probe with:
//   arg0: event_type (u8: 1=READY, 2=RESUMED, 3=SUSPENDED)
//   arg1: tid (u32: native thread ID)
//   arg2: timestamp_ns (u64: CLOCK_MONOTONIC)
//   arg3: thread_value (u64: Ruby thread VALUE)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// GVL event types from the gem (probes.rs)
#define GVL_EVENT_READY     1
#define GVL_EVENT_RESUMED   2
#define GVL_EVENT_SUSPENDED 3

// BPF event type for userspace (events.go)
#define EVENT_GVL_STATE 7

// GVL states (match proto GVLState enum)
#define GVL_STATE_RUNNING   1
#define GVL_STATE_STALLED   2
#define GVL_STATE_SUSPENDED 3

// Minimum state duration for hysteresis (100µs).
// github/github generates thousands of GVL transitions per second — every
// I/O syscall triggers SUSPENDED→STALLED→RUNNING. Most of these sub-100µs
// transitions are invisible at any practical zoom level in the profiler.
// Filtering them in BPF reduces ring buffer volume by ~10x.
#define MIN_STATE_DURATION_NS 100000

// Per-thread last state tracking for hysteresis
struct gvl_thread_key {
    u32 pid;
    u32 tid;
};

struct gvl_last_state {
    u32 state;
    u64 timestamp_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct gvl_thread_key);
    __type(value, struct gvl_last_state);
} gvl_thread_state SEC(".maps");

// Event sent to userspace (32 bytes)
struct gvl_state_event {
    u32 event_type;     // EVENT_GVL_STATE = 7
    u32 pid;
    u32 tid;
    u32 gvl_state;      // GVL_STATE_RUNNING/STALLED/SUSPENDED
    u64 timestamp_ns;
    u64 thread_value;
};

// Ring buffer for state change events (16MB).
// github/github workers generate thousands of GVL transitions per second
// (every I/O syscall triggers SUSPENDED→STALLED→RUNNING). The ring buffer
// must be large enough to absorb bursts while the collector drains events.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} gvl_events SEC(".maps");

// Separate ring buffer for GVL stack events (8MB).
// Stack events are large (~4KB each) and would be starved by the high
// volume of small state events (32 bytes) if sharing the same buffer.
// With 5+ threads in a Pitchfork worker (main + OTel batch processors),
// the state event volume causes bpf_ringbuf_reserve to fail for large
// stack events, silently dropping all SUSPENDED stacks.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 23); // 8MB — holds ~2000 stack events
} gvl_stack_events SEC(".maps");

// Drop counter — incremented when bpf_ringbuf_reserve fails
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} gvl_drop_count SEC(".maps");

static __always_inline void emit_state(u32 pid, u32 tid, u32 state,
                                       u64 timestamp_ns, u64 thread_value)
{
    struct gvl_state_event *event;
    event = bpf_ringbuf_reserve(&gvl_events, sizeof(*event), 0);
    if (!event) {
        // Ring buffer full — increment drop counter
        u32 zero = 0;
        u64 *count = bpf_map_lookup_elem(&gvl_drop_count, &zero);
        if (count)
            __sync_fetch_and_add(count, 1);
        return;
    }

    event->event_type = EVENT_GVL_STATE;
    event->pid = pid;
    event->tid = tid;
    event->gvl_state = state;
    event->timestamp_ns = timestamp_ns;
    event->thread_value = thread_value;

    bpf_ringbuf_submit(event, 0);
}

SEC("uprobe/gvl_event")
int handle_gvl_event(struct pt_regs *ctx) {
    u8  event_type   = (u8)PT_REGS_PARM1(ctx);
    // Use host-namespace TID from bpf_get_current_pid_tgid() so that
    // GVL events land on the same thread as ruby_reader samples.
    // The gem passes namespace-relative gettid() as arg2 but we ignore it.
    u64 pidtgid      = bpf_get_current_pid_tgid();
    u32 tid          = (u32)pidtgid;
    u64 timestamp_ns = (u64)PT_REGS_PARM3(ctx);
    u64 thread_value = (u64)PT_REGS_PARM4(ctx);

    u32 pid = pidtgid >> 32;

    // Map gem event types to GVL states
    u32 new_state;
    if (event_type == GVL_EVENT_READY)
        new_state = GVL_STATE_STALLED;
    else if (event_type == GVL_EVENT_RESUMED)
        new_state = GVL_STATE_RUNNING;
    else if (event_type == GVL_EVENT_SUSPENDED)
        new_state = GVL_STATE_SUSPENDED;
    else
        return 0;

    struct gvl_thread_key key = { .pid = pid, .tid = tid };

    // Hysteresis: suppress ANY state transition where the previous state
    // lasted less than MIN_STATE_DURATION_NS. This dramatically reduces
    // event volume for high-throughput Ruby apps where thousands of brief
    // GVL transitions happen per second.
    struct gvl_last_state *last = bpf_map_lookup_elem(&gvl_thread_state, &key);
    if (last) {
        // Skip duplicate consecutive states
        if (new_state == last->state)
            return 0;

        u64 prev_duration = 0;
        if (timestamp_ns > last->timestamp_ns)
            prev_duration = timestamp_ns - last->timestamp_ns;

        if (prev_duration < MIN_STATE_DURATION_NS) {
            // Previous state was too brief to be meaningful. Don't emit
            // the transition; just update the timestamp so the NEXT state
            // change can measure from the right baseline.
            last->state = new_state;
            last->timestamp_ns = timestamp_ns;
            return 0;
        }
    }

    // Emit state change
    emit_state(pid, tid, new_state, timestamp_ns, thread_value);

    // Update last state
    struct gvl_last_state new_last = {
        .state = new_state,
        .timestamp_ns = timestamp_ns,
    };
    bpf_map_update_elem(&gvl_thread_state, &key, &new_last, BPF_ANY);

    return 0;
}

// --- GVL stack capture ---
// Fired by __rbscope_probe_gvl_stack when a thread releases the GVL.
// Same argument layout as ruby_sample:
//   arg0: stack_ptr (pointer to serialized v2 inline stack)
//   arg1: stack_len (bytes)
//   arg2: thread_id (Ruby VALUE)
//   arg3: timestamp_ns (wall clock)
//   arg4: weight (unused, always 0)

#define EVENT_GVL_STACK 8
#define MAX_GVL_STACK_BYTES 16384

// GVL stack event: header + inline stack data
struct gvl_stack_event {
    u32 event_type;     // EVENT_GVL_STACK = 8
    u32 pid;
    u32 tid;
    u32 stack_len;
    u64 timestamp_ns;
    u8  stack_data[MAX_GVL_STACK_BYTES];
};

SEC("uprobe/gvl_stack")
int handle_gvl_stack(struct pt_regs *ctx) {
    u64 stack_ptr = PT_REGS_PARM1(ctx);
    u32 stack_len = (u32)PT_REGS_PARM2(ctx);
    u64 timestamp = PT_REGS_PARM4(ctx);

    if (stack_len == 0 || stack_len > MAX_GVL_STACK_BYTES)
        return 0;

    u64 pidtgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pidtgid;
    u32 pid = pidtgid >> 32;

    struct gvl_stack_event *event;
    event = bpf_ringbuf_reserve(&gvl_stack_events,
                                sizeof(struct gvl_stack_event), 0);
    if (!event)
        return 0;

    event->event_type = EVENT_GVL_STACK;
    event->pid = pid;
    event->tid = tid;
    event->stack_len = stack_len;
    event->timestamp_ns = timestamp;

    // Read the serialized stack from user space
    if (bpf_probe_read_user(event->stack_data, stack_len & (MAX_GVL_STACK_BYTES - 1),
                            (void *)stack_ptr) < 0) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
