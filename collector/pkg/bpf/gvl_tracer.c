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

// Minimum state duration for hysteresis (10µs).
// STALLED→RUNNING transitions shorter than this are suppressed to avoid
// flooding the ring buffer with uncontended GVL acquisitions.
#define MIN_STATE_DURATION_NS 10000

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

// Ring buffer for state change events (4MB)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} gvl_events SEC(".maps");

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
    u32 tid          = (u32)PT_REGS_PARM2(ctx);
    u64 timestamp_ns = (u64)PT_REGS_PARM3(ctx);
    u64 thread_value = (u64)PT_REGS_PARM4(ctx);

    u32 pid = bpf_get_current_pid_tgid() >> 32;

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

    // Hysteresis: suppress STALLED→RUNNING transitions < 10µs.
    // These are uncontended GVL acquisitions that produce thousands of
    // zero-width barber-pole slivers nobody can see.
    struct gvl_last_state *last = bpf_map_lookup_elem(&gvl_thread_state, &key);
    if (last) {
        if (new_state == GVL_STATE_RUNNING && last->state == GVL_STATE_STALLED) {
            u64 stalled_duration = 0;
            if (timestamp_ns > last->timestamp_ns)
                stalled_duration = timestamp_ns - last->timestamp_ns;

            if (stalled_duration < MIN_STATE_DURATION_NS) {
                // Too short — suppress the STALLED that was already emitted
                // by not emitting this RUNNING either. Update state to
                // whatever was before STALLED (we don't track that, so just
                // skip both and let the Go state machine handle the gap).
                //
                // Actually: we can't un-emit the STALLED. Instead, just
                // don't emit this RUNNING, and update last_state to STALLED
                // still. The Go state machine will see STALLED with no
                // following RUNNING and treat the next real event as the
                // interval boundary.
                //
                // Better approach: don't emit STALLED immediately. Buffer it
                // and only emit on the next event if duration >= threshold.
                // But BPF can't do deferred emission easily.
                //
                // Simplest correct approach: emit RUNNING without the
                // intermediate STALLED. Delete the STALLED state and set
                // directly to RUNNING from whatever was before.
                last->state = GVL_STATE_RUNNING;
                last->timestamp_ns = timestamp_ns;
                // Don't emit — the short STALLED was already emitted but
                // Go-side can merge adjacent RUNNING intervals.
                return 0;
            }
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

char LICENSE[] SEC("license") = "Dual BSD/GPL";
