//go:build ignore

// rbscope BPF program: GVL (Global VM Lock) event tracer
//
// Attaches as uprobe to __rbscope_probe_gvl_event in the target Ruby
// process. Tracks READY→RESUMED transitions to measure GVL wait time.
//
// The gem fires the probe with:
//   arg0: event_type (u8: 1=READY, 2=RESUMED, 3=SUSPENDED)
//   arg1: tid (u32: native thread ID)
//   arg2: timestamp_ns (u64: CLOCK_MONOTONIC)
//   arg3: thread_value (u64: Ruby thread VALUE)
//
// Build: generated via bpf2go (see collector Makefile)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// GVL event types (match gem-side constants in probes.rs)
#define GVL_EVENT_READY     1   // Thread wants GVL (starts waiting)
#define GVL_EVENT_RESUMED   2   // Thread acquired GVL (done waiting)
#define GVL_EVENT_SUSPENDED 3   // Thread released GVL

// BPF event type for userspace (must match events.go EventGVLWait = 6)
#define EVENT_GVL_WAIT 6

// Minimum wait duration to report (1ms) — filters noise from
// uncontended GVL acquisitions.
#define MIN_WAIT_NS 1000000

// Per-thread GVL wait start tracking
struct gvl_wait_key {
    u32 pid;
    u32 tid;
};

struct gvl_wait_val {
    u64 timestamp_ns;
    u64 thread_value;
};

// Hash map: track when each thread started waiting for the GVL
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct gvl_wait_key);
    __type(value, struct gvl_wait_val);
} gvl_wait_start SEC(".maps");

// Event sent to userspace
struct gvl_wait_event {
    u32 event_type;     // EVENT_GVL_WAIT = 6
    u32 pid;
    u32 tid;
    u32 _pad;
    u64 wait_ns;        // how long the thread waited for GVL
    u64 timestamp_ns;   // when it acquired the GVL
    u64 thread_value;   // Ruby thread VALUE for cross-referencing
};

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1MB ring buffer (GVL events are small)
} gvl_events SEC(".maps");

SEC("uprobe/gvl_event")
int handle_gvl_event(struct pt_regs *ctx) {
    // Read probe arguments from registers
    u8  event_type   = (u8)PT_REGS_PARM1(ctx);
    u32 tid          = (u32)PT_REGS_PARM2(ctx);
    u64 timestamp_ns = (u64)PT_REGS_PARM3(ctx);
    u64 thread_value = (u64)PT_REGS_PARM4(ctx);

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct gvl_wait_key key = {
        .pid = pid,
        .tid = tid,
    };

    if (event_type == GVL_EVENT_READY) {
        // Thread wants the GVL — record wait start
        struct gvl_wait_val val = {
            .timestamp_ns = timestamp_ns,
            .thread_value = thread_value,
        };
        bpf_map_update_elem(&gvl_wait_start, &key, &val, BPF_ANY);
    } else if (event_type == GVL_EVENT_RESUMED) {
        // Thread acquired the GVL — compute wait duration
        struct gvl_wait_val *start = bpf_map_lookup_elem(&gvl_wait_start, &key);
        if (!start) {
            return 0; // no matching READY event (startup race)
        }

        u64 wait_ns = 0;
        if (timestamp_ns > start->timestamp_ns) {
            wait_ns = timestamp_ns - start->timestamp_ns;
        }

        // Delete the entry regardless
        bpf_map_delete_elem(&gvl_wait_start, &key);

        // Only report significant waits (> 1ms)
        if (wait_ns < MIN_WAIT_NS) {
            return 0;
        }

        // Emit GVL wait event to ring buffer
        struct gvl_wait_event *event;
        event = bpf_ringbuf_reserve(&gvl_events, sizeof(*event), 0);
        if (!event) {
            return 0;
        }

        event->event_type = EVENT_GVL_WAIT;
        event->pid = pid;
        event->tid = tid;
        event->_pad = 0;
        event->wait_ns = wait_ns;
        event->timestamp_ns = timestamp_ns;
        event->thread_value = start->thread_value;

        bpf_ringbuf_submit(event, 0);
    }
    // SUSPENDED events are not tracked — we only care about wait duration

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
