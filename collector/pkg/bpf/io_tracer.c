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

// bpf_get_stack flag — capture user-space stack frames
#ifndef BPF_F_USER_STACK
#define BPF_F_USER_STACK (1ULL << 8)
#endif

// I/O operation types (matches Go IoOp* constants)
#define IO_OP_READ       1
#define IO_OP_WRITE      2
#define IO_OP_SENDTO     3
#define IO_OP_RECVFROM   4
#define IO_OP_CONNECT    5
#define IO_OP_POLL       6
#define IO_OP_PPOLL      7
#define IO_OP_EPOLL_WAIT 8
#define IO_OP_PSELECT6   9
#define IO_OP_ACCEPT4    10
#define IO_OP_FUTEX      11
#define IO_OP_CLONE      12
#define IO_OP_GETRANDOM       13
#define IO_OP_CLOCK_GETTIME   14

// Syscall tags — arbitrary identifiers used to distinguish syscalls
// in the inflight map. Not actual NR values.
#define SYS_READ       0
#define SYS_WRITE      1
#define SYS_CONNECT    42
#define SYS_SENDTO     44
#define SYS_RECVFROM   45
#define SYS_POLL       100
#define SYS_PPOLL      101
#define SYS_EPOLL_WAIT 102
#define SYS_PSELECT6   103
#define SYS_ACCEPT4    104
#define SYS_FUTEX      105
#define SYS_CLONE      106
#define SYS_GETRANDOM  107
#define SYS_CLOCK_GETTIME 108

// Minimum latency (in ns) to emit poll-family and filtered events.
// Polls/futex/getrandom shorter than this are suppressed.
#define MIN_LATENCY_FILTER_NS 1000000  // 1ms

// Futex op masks — only trace WAIT operations, not WAKE.
#define FUTEX_CMD_MASK   0x7f
#define FUTEX_WAIT       0
#define FUTEX_WAIT_PRIVATE 128

// Clone flag — only trace thread creation, not fork.
#define CLONE_THREAD 0x00010000

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

// Maximum number of native stack IPs to capture per I/O event.
// 16 frames is enough to see: read() ← trilogy_sock_read() ← trilogy_query()
#define MAX_IO_STACK_DEPTH 16

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
    // Native user-space stack (captured at syscall exit)
    u32 stack_len;        // number of valid IPs in stack[]
    u32 _pad3;
    u64 stack[MAX_IO_STACK_DEPTH]; // user-space instruction pointers
};

// ---- helpers --------------------------------------------------------------

static __always_inline int pid_allowed(void) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    return bpf_map_lookup_elem(&target_pids, &pid) != NULL;
}

static __always_inline u32 syscall_to_op(u32 nr) {
    switch (nr) {
    case SYS_READ:       return IO_OP_READ;
    case SYS_WRITE:      return IO_OP_WRITE;
    case SYS_SENDTO:     return IO_OP_SENDTO;
    case SYS_RECVFROM:   return IO_OP_RECVFROM;
    case SYS_CONNECT:    return IO_OP_CONNECT;
    case SYS_POLL:       return IO_OP_POLL;
    case SYS_PPOLL:      return IO_OP_PPOLL;
    case SYS_EPOLL_WAIT: return IO_OP_EPOLL_WAIT;
    case SYS_PSELECT6:   return IO_OP_PSELECT6;
    case SYS_ACCEPT4:    return IO_OP_ACCEPT4;
    case SYS_FUTEX:      return IO_OP_FUTEX;
    case SYS_CLONE:      return IO_OP_CLONE;
    case SYS_GETRANDOM:       return IO_OP_GETRANDOM;
    case SYS_CLOCK_GETTIME:   return IO_OP_CLOCK_GETTIME;
    default:             return 0;
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

static __always_inline void record_exit(void *ctx, long ret) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct syscall_enter *entry = bpf_map_lookup_elem(&inflight, &tid);
    if (!entry)
        return;

    u64 now = bpf_ktime_get_ns();
    u64 latency = now - entry->timestamp_ns;
    u32 syscall_nr = entry->syscall_nr;
    u32 fd = entry->fd;

    // Suppress short-duration events for poll-family, futex, and getrandom.
    // Zero-timeout polls are readiness checks; uncontended futexes and
    // fast getrandom calls are noise.
    // clock_gettime is NOT filtered — we want every call's native stack
    // to identify code paths with frequent CPU clock reads.
    if (((syscall_nr >= SYS_POLL && syscall_nr <= SYS_PSELECT6) ||
         syscall_nr == SYS_FUTEX || syscall_nr == SYS_GETRANDOM) &&
        latency < MIN_LATENCY_FILTER_NS) {
        bpf_map_delete_elem(&inflight, &tid);
        return;
    }

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
    ev->op           = syscall_to_op(syscall_nr);
    ev->fd           = (s32)fd;
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

    // Capture user-space native stack at syscall exit.
    // This gives us the C call chain: read() ← trilogy_sock_read() ← trilogy_query()
    // bpf_get_stack returns bytes written (negative on error).
    long stack_bytes = bpf_get_stack(ctx, ev->stack,
                                     MAX_IO_STACK_DEPTH * sizeof(u64),
                                     BPF_F_USER_STACK);
    if (stack_bytes > 0)
        ev->stack_len = (u32)(stack_bytes / sizeof(u64));

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
    record_exit(ctx, ctx->ret);
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
    record_exit(ctx, ctx->ret);
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
    record_exit(ctx, ctx->ret);
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
    record_exit(ctx, ctx->ret);
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
    record_exit(ctx, ctx->ret);
    return 0;
}

// ---- tracepoints: ppoll --------------------------------------------------
// ppoll(struct pollfd *fds, nfds_t nfds, ...)
// Read the first pollfd to get the primary fd being waited on.

SEC("tp/syscalls/sys_enter_ppoll")
int tp_sys_enter_ppoll(struct trace_event_raw_sys_enter *ctx) {
    if (!pid_allowed()) return 0;
    // Read first pollfd.fd from userspace (struct pollfd = {int fd; short events; short revents;})
    u32 fd = 0;
    void *fds_ptr = (void *)ctx->args[0];
    if (fds_ptr)
        bpf_probe_read_user(&fd, sizeof(u32), fds_ptr);
    record_enter(SYS_PPOLL, fd);
    return 0;
}

SEC("tp/syscalls/sys_exit_ppoll")
int tp_sys_exit_ppoll(struct trace_event_raw_sys_exit *ctx) {
    if (!pid_allowed()) return 0;
    record_exit(ctx, ctx->ret);
    return 0;
}

// ---- tracepoints: poll ---------------------------------------------------
// poll(struct pollfd *fds, nfds_t nfds, int timeout)

SEC("tp/syscalls/sys_enter_poll")
int tp_sys_enter_poll(struct trace_event_raw_sys_enter *ctx) {
    if (!pid_allowed()) return 0;
    u32 fd = 0;
    void *fds_ptr = (void *)ctx->args[0];
    if (fds_ptr)
        bpf_probe_read_user(&fd, sizeof(u32), fds_ptr);
    record_enter(SYS_POLL, fd);
    return 0;
}

SEC("tp/syscalls/sys_exit_poll")
int tp_sys_exit_poll(struct trace_event_raw_sys_exit *ctx) {
    if (!pid_allowed()) return 0;
    record_exit(ctx, ctx->ret);
    return 0;
}

// ---- tracepoints: epoll_wait ---------------------------------------------
// epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)

SEC("tp/syscalls/sys_enter_epoll_wait")
int tp_sys_enter_epoll_wait(struct trace_event_raw_sys_enter *ctx) {
    if (!pid_allowed()) return 0;
    record_enter(SYS_EPOLL_WAIT, (u32)ctx->args[0]);
    return 0;
}

SEC("tp/syscalls/sys_exit_epoll_wait")
int tp_sys_exit_epoll_wait(struct trace_event_raw_sys_exit *ctx) {
    if (!pid_allowed()) return 0;
    record_exit(ctx, ctx->ret);
    return 0;
}

// ---- tracepoints: pselect6 -----------------------------------------------
// pselect6(int nfds, fd_set *readfds, ...)
// nfds is highest fd+1, not a specific fd. Store it as the "fd" for context.

SEC("tp/syscalls/sys_enter_pselect6")
int tp_sys_enter_pselect6(struct trace_event_raw_sys_enter *ctx) {
    if (!pid_allowed()) return 0;
    record_enter(SYS_PSELECT6, (u32)ctx->args[0]);
    return 0;
}

SEC("tp/syscalls/sys_exit_pselect6")
int tp_sys_exit_pselect6(struct trace_event_raw_sys_exit *ctx) {
    if (!pid_allowed()) return 0;
    record_exit(ctx, ctx->ret);
    return 0;
}

// ---- tracepoints: accept4 ------------------------------------------------
// accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)

SEC("tp/syscalls/sys_enter_accept4")
int tp_sys_enter_accept4(struct trace_event_raw_sys_enter *ctx) {
    if (!pid_allowed()) return 0;
    record_enter(SYS_ACCEPT4, (u32)ctx->args[0]);
    return 0;
}

SEC("tp/syscalls/sys_exit_accept4")
int tp_sys_exit_accept4(struct trace_event_raw_sys_exit *ctx) {
    if (!pid_allowed()) return 0;
    record_exit(ctx, ctx->ret);
    return 0;
}

// ---- tracepoints: futex --------------------------------------------------
// futex(int *uaddr, int op, int val, ...)
// Only trace FUTEX_WAIT and FUTEX_WAIT_PRIVATE — skip WAKE (90% of calls).

SEC("tp/syscalls/sys_enter_futex")
int tp_sys_enter_futex(struct trace_event_raw_sys_enter *ctx) {
    if (!pid_allowed()) return 0;
    u32 op = (u32)ctx->args[1] & FUTEX_CMD_MASK;
    if (op != FUTEX_WAIT && op != (FUTEX_WAIT_PRIVATE & FUTEX_CMD_MASK))
        return 0;
    record_enter(SYS_FUTEX, 0);
    return 0;
}

SEC("tp/syscalls/sys_exit_futex")
int tp_sys_exit_futex(struct trace_event_raw_sys_exit *ctx) {
    if (!pid_allowed()) return 0;
    record_exit(ctx, ctx->ret);
    return 0;
}

// ---- tracepoints: clone --------------------------------------------------
// clone(unsigned long flags, ...)
// Only trace CLONE_THREAD — thread creation, not process fork.

SEC("tp/syscalls/sys_enter_clone")
int tp_sys_enter_clone(struct trace_event_raw_sys_enter *ctx) {
    if (!pid_allowed()) return 0;
    u64 flags = ctx->args[0];
    if (!(flags & CLONE_THREAD))
        return 0;
    record_enter(SYS_CLONE, 0);
    return 0;
}

SEC("tp/syscalls/sys_exit_clone")
int tp_sys_exit_clone(struct trace_event_raw_sys_exit *ctx) {
    if (!pid_allowed()) return 0;
    record_exit(ctx, ctx->ret);
    return 0;
}

// ---- tracepoints: getrandom ----------------------------------------------
// getrandom(void *buf, size_t buflen, unsigned int flags)

SEC("tp/syscalls/sys_enter_getrandom")
int tp_sys_enter_getrandom(struct trace_event_raw_sys_enter *ctx) {
    if (!pid_allowed()) return 0;
    record_enter(SYS_GETRANDOM, 0);
    return 0;
}

SEC("tp/syscalls/sys_exit_getrandom")
int tp_sys_exit_getrandom(struct trace_event_raw_sys_exit *ctx) {
    if (!pid_allowed()) return 0;
    record_exit(ctx, ctx->ret);
    return 0;
}

// ---- tracepoints: clock_gettime ------------------------------------------
// clock_gettime(clockid_t clock_id, struct timespec *tp)
// CLOCK_THREAD_CPUTIME_ID and CLOCK_PROCESS_CPUTIME_ID hit the real syscall
// (not vDSO). ~1K/sec per worker. 1ms filter keeps only slow calls.
// The clock_id is stored in the fd field for marker context.

SEC("tp/syscalls/sys_enter_clock_gettime")
int tp_sys_enter_clock_gettime(struct trace_event_raw_sys_enter *ctx) {
    if (!pid_allowed()) return 0;
    record_enter(SYS_CLOCK_GETTIME, (u32)ctx->args[0]);
    return 0;
}

SEC("tp/syscalls/sys_exit_clock_gettime")
int tp_sys_exit_clock_gettime(struct trace_event_raw_sys_exit *ctx) {
    if (!pid_allowed()) return 0;
    record_exit(ctx, ctx->ret);
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
