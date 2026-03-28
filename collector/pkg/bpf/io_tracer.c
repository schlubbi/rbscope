//go:build ignore

// rbscope BPF program: Kernel I/O correlation via syscall tracepoints
//
// Traces read/write/sendto/recvfrom/connect syscalls and correlates
// them with Ruby stack IDs from ruby_reader.c. On syscall exit we
// resolve the FD to a socket and capture TCP stats.
//
// Build: generated via bpf2go (see collector Makefile)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "fd_helpers.h"

// Event type matches Go EventIO = 4
#define EVENT_IO 4

// I/O operation types (matches Go IoOp* constants)
#define IO_OP_READ    1
#define IO_OP_WRITE   2
#define IO_OP_SENDTO  3
#define IO_OP_RECVFROM 4
#define IO_OP_CONNECT 5

// Syscall numbers (x86_64)
#define SYS_READ     0
#define SYS_WRITE    1
#define SYS_CONNECT  42
#define SYS_SENDTO   44
#define SYS_RECVFROM 45

// ---- maps ----------------------------------------------------------------

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB
} io_events SEC(".maps");

struct syscall_enter {
    u64 timestamp_ns;
    u32 syscall_nr;
    u32 fd;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, u32);
    __type(value, struct syscall_enter);
} inflight SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);   // PID
    __type(value, u8);
} target_pids SEC(".maps");

// ---- event ---------------------------------------------------------------

// rbscope_io_event is the enriched I/O event emitted to userspace.
// Layout must match Go IOEvent parsing in events.go.
struct rbscope_io_event {
    // Standard header (24 bytes)
    u32 event_type;       // EVENT_IO = 4
    u32 pid;
    u32 tid;
    u32 _pad0;            // alignment for u64
    u64 timestamp_ns;
    // I/O fields (24 bytes)
    u32 op;               // IO_OP_* enum
    s32 fd;
    s64 bytes;            // return value (bytes or error)
    u64 latency_ns;
    // Socket enrichment (16 bytes)
    u8  fd_type;          // FD_TYPE_* from fd_helpers.h
    u8  sock_state;       // TCP state
    u16 local_port;       // host byte order
    u16 remote_port;      // host byte order
    u16 _pad1;
    u32 local_addr;       // IPv4, network byte order
    u32 remote_addr;      // IPv4, network byte order
    // TCP stats (40 bytes, only meaningful when fd_type == FD_TYPE_TCP)
    u32 srtt_us;
    u32 snd_cwnd;
    u32 total_retrans;
    u32 packets_out;
    u32 retrans_out;
    u32 lost_out;
    u32 rcv_wnd;
    u32 _pad2;
    u64 bytes_sent;
    u64 bytes_received;
};

// ---- helpers --------------------------------------------------------------

static __always_inline int pid_allowed(void) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    return bpf_map_lookup_elem(&target_pids, &pid) != NULL;
}

static __always_inline u32 syscall_to_op(u32 nr) {
    switch (nr) {
    case SYS_READ:     return IO_OP_READ;
    case SYS_WRITE:    return IO_OP_WRITE;
    case SYS_SENDTO:   return IO_OP_SENDTO;
    case SYS_RECVFROM: return IO_OP_RECVFROM;
    case SYS_CONNECT:  return IO_OP_CONNECT;
    default:           return 0;
    }
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

    struct rbscope_io_event *ev = bpf_ringbuf_reserve(&io_events, sizeof(*ev), 0);
    if (!ev) {
        bpf_map_delete_elem(&inflight, &tid);
        return;
    }

    // Zero the entire event first (important for optional fields)
    __builtin_memset(ev, 0, sizeof(*ev));

    // Header
    ev->event_type   = EVENT_IO;
    ev->pid          = bpf_get_current_pid_tgid() >> 32;
    ev->tid          = tid;
    ev->timestamp_ns = now;

    // I/O fields
    ev->op           = syscall_to_op(entry->syscall_nr);
    ev->fd           = (s32)entry->fd;
    ev->bytes        = ret;
    ev->latency_ns   = latency;

    // FD resolution: resolve to socket info + TCP stats
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct rbscope_socket_info si;
    struct rbscope_tcp_stats tcp;
    __builtin_memset(&si, 0, sizeof(si));
    __builtin_memset(&tcp, 0, sizeof(tcp));

    if (resolve_fd_info(task, (int)entry->fd, &si, &tcp)) {
        ev->fd_type     = si.fd_type;
        ev->sock_state  = si.sock_state;
        ev->local_port  = si.local_port;
        ev->remote_port = si.remote_port;
        ev->local_addr  = si.local_addr;
        ev->remote_addr = si.remote_addr;

        // TCP stats (only meaningful for TCP sockets)
        ev->srtt_us        = tcp.srtt_us;
        ev->snd_cwnd       = tcp.snd_cwnd;
        ev->total_retrans  = tcp.total_retrans;
        ev->packets_out    = tcp.packets_out;
        ev->retrans_out    = tcp.retrans_out;
        ev->lost_out       = tcp.lost_out;
        ev->rcv_wnd        = tcp.rcv_wnd;
        ev->bytes_sent     = tcp.bytes_sent;
        ev->bytes_received = tcp.bytes_received;
    }

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
