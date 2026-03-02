//go:build ignore

// rbscope BPF program: Kernel I/O correlation via syscall tracepoints
//
// Traces read/write/sendto/recvfrom/connect syscalls and correlates
// them with Ruby stack IDs from ruby_reader.c. On syscall entry we
// stash fd + timestamp keyed by TID; on exit we compute latency and
// byte count, then emit an io_event to the ring buffer.
//
// Build: generated via bpf2go (see collector Makefile)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EVENT_IO 10

// Syscall numbers (x86_64)
#define SYS_READ     0
#define SYS_WRITE    1
#define SYS_CONNECT  42
#define SYS_SENDTO   44
#define SYS_RECVFROM 45

// ---- maps ----------------------------------------------------------------

// Ring buffer shared with userspace consumer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB
} io_events SEC(".maps");

// In-flight syscall state, keyed by TID
struct syscall_enter {
    u64 timestamp_ns;
    u32 syscall_nr;
    u32 fd;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, u32);                  // TID
    __type(value, struct syscall_enter);
} inflight SEC(".maps");

// TID → most recent Ruby stack_id.
// Populated by ruby_reader.c's handler (shared via PIN or bpf2go map
// reuse). Userspace loader wires this to the same map object.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, u32);   // TID
    __type(value, u32); // stack_id
} tid_to_ruby_stack SEC(".maps");

// Target PIDs populated from userspace — only trace these processes
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);   // PID
    __type(value, u8);  // 1 = tracked
} target_pids SEC(".maps");

// ---- event ---------------------------------------------------------------

struct io_event {
    u8  event_type;
    u8  _pad[3];
    u32 pid;
    u32 tid;
    u32 syscall_nr;
    u32 fd;
    s64 bytes;
    u64 latency_ns;
    u64 timestamp_ns;
    u32 ruby_stack_id;
    u32 _pad2;
};

// ---- helpers --------------------------------------------------------------

static __always_inline int pid_allowed(void) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    return bpf_map_lookup_elem(&target_pids, &pid) != NULL;
}

static __always_inline void record_enter(u32 syscall_nr, u32 fd) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct syscall_enter entry = {
        .timestamp_ns = bpf_ktime_get_ns(),
        .syscall_nr   = syscall_nr,
        .fd           = fd,
    };
    bpf_map_update_elem(&inflight, &tid, &entry, BPF_ANY);
}

static __always_inline void record_exit(long ret) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct syscall_enter *entry = bpf_map_lookup_elem(&inflight, &tid);
    if (!entry)
        return;

    u64 now = bpf_ktime_get_ns();
    u64 latency = now - entry->timestamp_ns;

    struct io_event *ev = bpf_ringbuf_reserve(&io_events, sizeof(*ev), 0);
    if (!ev) {
        bpf_map_delete_elem(&inflight, &tid);
        return;
    }

    ev->event_type   = EVENT_IO;
    ev->pid          = bpf_get_current_pid_tgid() >> 32;
    ev->tid          = tid;
    ev->syscall_nr   = entry->syscall_nr;
    ev->fd           = entry->fd;
    ev->bytes        = ret;
    ev->latency_ns   = latency;
    ev->timestamp_ns = now;

    // Attach Ruby stack context if available
    u32 *stack_id = bpf_map_lookup_elem(&tid_to_ruby_stack, &tid);
    ev->ruby_stack_id = stack_id ? *stack_id : 0;

    bpf_ringbuf_submit(ev, 0);
    bpf_map_delete_elem(&inflight, &tid);
}

// ---- tracepoints: read ---------------------------------------------------

SEC("tp/syscalls/sys_enter_read")
int tp_sys_enter_read(struct trace_event_raw_sys_enter *ctx) {
    if (!pid_allowed()) return 0;
    record_enter(SYS_READ, (u32)ctx->args[0]);
    return 0;
}

SEC("tp/syscalls/sys_exit_read")
int tp_sys_exit_read(struct trace_event_raw_sys_exit *ctx) {
    if (!pid_allowed()) return 0;
    record_exit(ctx->ret);
    return 0;
}

// ---- tracepoints: write --------------------------------------------------

SEC("tp/syscalls/sys_enter_write")
int tp_sys_enter_write(struct trace_event_raw_sys_enter *ctx) {
    if (!pid_allowed()) return 0;
    record_enter(SYS_WRITE, (u32)ctx->args[0]);
    return 0;
}

SEC("tp/syscalls/sys_exit_write")
int tp_sys_exit_write(struct trace_event_raw_sys_exit *ctx) {
    if (!pid_allowed()) return 0;
    record_exit(ctx->ret);
    return 0;
}

// ---- tracepoints: sendto -------------------------------------------------

SEC("tp/syscalls/sys_enter_sendto")
int tp_sys_enter_sendto(struct trace_event_raw_sys_enter *ctx) {
    if (!pid_allowed()) return 0;
    record_enter(SYS_SENDTO, (u32)ctx->args[0]);
    return 0;
}

SEC("tp/syscalls/sys_exit_sendto")
int tp_sys_exit_sendto(struct trace_event_raw_sys_exit *ctx) {
    if (!pid_allowed()) return 0;
    record_exit(ctx->ret);
    return 0;
}

// ---- tracepoints: recvfrom -----------------------------------------------

SEC("tp/syscalls/sys_enter_recvfrom")
int tp_sys_enter_recvfrom(struct trace_event_raw_sys_enter *ctx) {
    if (!pid_allowed()) return 0;
    record_enter(SYS_RECVFROM, (u32)ctx->args[0]);
    return 0;
}

SEC("tp/syscalls/sys_exit_recvfrom")
int tp_sys_exit_recvfrom(struct trace_event_raw_sys_exit *ctx) {
    if (!pid_allowed()) return 0;
    record_exit(ctx->ret);
    return 0;
}

// ---- tracepoints: connect ------------------------------------------------

SEC("tp/syscalls/sys_enter_connect")
int tp_sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    if (!pid_allowed()) return 0;
    record_enter(SYS_CONNECT, (u32)ctx->args[0]);
    return 0;
}

SEC("tp/syscalls/sys_exit_connect")
int tp_sys_exit_connect(struct trace_event_raw_sys_exit *ctx) {
    if (!pid_allowed()) return 0;
    record_exit(ctx->ret);
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
