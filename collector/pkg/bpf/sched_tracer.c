//go:build ignore

// rbscope BPF program: Off-CPU tracking via sched_switch tracepoint
//
// When a tracked thread goes off-CPU we record the timestamp. When it
// comes back on-CPU we compute off-cpu duration and emit an event to
// the ring buffer. Only PIDs present in the target_pids map (populated
// from userspace) are tracked.
//
// Build: generated via bpf2go (see collector Makefile)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EVENT_OFFCPU 20

// ---- maps ----------------------------------------------------------------

// Ring buffer for off-CPU events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB
} sched_events SEC(".maps");

// TID → timestamp when it went off-CPU
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, u32);   // TID
    __type(value, u64); // off-CPU timestamp (ns)
} offcpu_start SEC(".maps");

// Target PIDs populated from userspace — only track these processes
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);   // PID (tgid)
    __type(value, u8);  // 1 = tracked
} target_pids SEC(".maps");

// ---- event ---------------------------------------------------------------

struct offcpu_event {
    u8  event_type;
    u8  _pad[3];
    u32 pid;
    u32 tid;
    u32 _pad2;
    u64 off_cpu_ns;
    u64 timestamp_ns;
};

// ---- tracepoint ----------------------------------------------------------

SEC("tp/sched/sched_switch")
int tp_sched_switch(struct trace_event_raw_sched_switch *ctx) {
    u64 now = bpf_ktime_get_ns();

    // --- prev thread going off-CPU ---
    u32 prev_tid = (u32)ctx->prev_pid;
    // In kernel, tgid == userspace PID. We need the tgid of the prev
    // task. For the *current* task we can use bpf_get_current_pid_tgid,
    // but prev may differ. We use the TID itself for the hash lookup
    // and rely on the target_pids check when we see it come back.
    // Record unconditionally; filter on wake-up.
    if (prev_tid != 0) {
        bpf_map_update_elem(&offcpu_start, &prev_tid, &now, BPF_ANY);
    }

    // --- next thread coming on-CPU ---
    u32 next_tid = (u32)ctx->next_pid;
    u64 *start_ts = bpf_map_lookup_elem(&offcpu_start, &next_tid);
    if (!start_ts)
        return 0;

    u64 delta = now - *start_ts;
    bpf_map_delete_elem(&offcpu_start, &next_tid);

    // Filter: only emit for tracked PIDs.
    // bpf_get_current_pid_tgid() returns the *next* task's IDs because
    // we execute in the context of the task being switched in.
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!bpf_map_lookup_elem(&target_pids, &pid))
        return 0;

    struct offcpu_event *ev = bpf_ringbuf_reserve(&sched_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->event_type   = EVENT_OFFCPU;
    ev->pid          = pid;
    ev->tid          = next_tid;
    ev->off_cpu_ns   = delta;
    ev->timestamp_ns = now;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
