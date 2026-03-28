// rbscope BPF helper: File descriptor resolution and TCP stats
//
// Resolves FDs to socket info (TCP/UDP/Unix) and captures TCP
// performance stats. Inspired by 0xtools/xCapture's fd_helpers.h.

#ifndef __FD_HELPERS_H
#define __FD_HELPERS_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// FD type classification
#define FD_TYPE_UNKNOWN  0
#define FD_TYPE_FILE     1
#define FD_TYPE_TCP      2
#define FD_TYPE_UDP      3
#define FD_TYPE_UNIX     4
#define FD_TYPE_PIPE     5

// Socket info captured from the kernel
struct rbscope_socket_info {
    u8  fd_type;       // FD_TYPE_* enum
    u8  sock_state;    // TCP state (TCP_ESTABLISHED=1, TCP_LISTEN=10, etc.)
    u16 local_port;    // host byte order
    u16 remote_port;   // host byte order
    u16 _pad;
    u32 local_addr;    // IPv4 address (network byte order)
    u32 remote_addr;   // IPv4 address (network byte order)
};

// TCP performance stats captured from tcp_sock
struct rbscope_tcp_stats {
    u32 srtt_us;          // smoothed RTT (microseconds)
    u32 snd_cwnd;         // congestion window (packets)
    u32 total_retrans;    // total retransmits for this connection
    u32 packets_out;      // packets in flight
    u32 retrans_out;      // retransmitted packets outstanding
    u32 lost_out;         // lost packets
    u32 rcv_wnd;          // receive window
    u32 _pad;
    u64 bytes_sent;       // total bytes sent
    u64 bytes_received;   // total bytes received
};

// ---- File descriptor resolution ----

// get_file_from_fd resolves an FD number to a struct file pointer via the
// task's file descriptor table. Returns NULL on failure.
static __always_inline struct file *get_file_from_fd(struct task_struct *task, int fd) {
    if (fd < 0 || fd >= 1024)
        return NULL;

    struct files_struct *files = BPF_CORE_READ(task, files);
    if (!files)
        return NULL;

    struct fdtable *fdt = BPF_CORE_READ(files, fdt);
    if (!fdt)
        return NULL;

    unsigned int max_fds = BPF_CORE_READ(fdt, max_fds);
    if ((unsigned int)fd >= max_fds)
        return NULL;

    struct file **fd_array = BPF_CORE_READ(fdt, fd);
    if (!fd_array)
        return NULL;

    // Dynamic array access requires bpf_probe_read_kernel, NOT BPF_CORE_READ
    struct file *file = NULL;
    bpf_probe_read_kernel(&file, sizeof(file), &fd_array[fd]);
    return file;
}

// resolve_socket_info checks if a file backs a socket and extracts address info.
// Returns true if socket info was populated.
static bool __always_inline resolve_socket_info(struct file *file,
                                                struct rbscope_socket_info *si) {
    if (!file)
        return false;

    __builtin_memset(si, 0, sizeof(*si));

    // Check if file is a socket via inode mode
    struct inode *inode = BPF_CORE_READ(file, f_path.dentry, d_inode);
    if (!inode)
        return false;

    unsigned short i_mode = BPF_CORE_READ(inode, i_mode);
    if ((i_mode & S_IFMT) != S_IFSOCK) {
        si->fd_type = FD_TYPE_FILE;
        return true;
    }

    // It's a socket — get the sock struct
    struct socket *sock = BPF_CORE_READ(file, private_data);
    if (!sock)
        return false;

    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk)
        return false;

    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    u8 protocol = BPF_CORE_READ(sk, sk_protocol);

    if (family == AF_INET || family == AF_INET6) {
        if (protocol == IPPROTO_TCP) {
            si->fd_type = FD_TYPE_TCP;
            si->sock_state = BPF_CORE_READ(sk, __sk_common.skc_state);
        } else if (protocol == IPPROTO_UDP) {
            si->fd_type = FD_TYPE_UDP;
        } else {
            return false;
        }

        // Read addresses (IPv4 only for now; IPv6 extension later)
        if (family == AF_INET) {
            si->local_addr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
            si->remote_addr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        }

        // Read ports — inet_sock embeds sock, same pointer cast
        struct inet_sock *inet = (struct inet_sock *)sk;
        si->local_port = bpf_ntohs(BPF_CORE_READ(inet, inet_sport));
        si->remote_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

        return true;
    }

    if (family == AF_UNIX) {
        si->fd_type = FD_TYPE_UNIX;
        return true;
    }

    return false;
}

// get_tcp_stats reads TCP performance stats from a sock.
// Only call this when resolve_socket_info returned fd_type == FD_TYPE_TCP.
static bool __always_inline get_tcp_stats(struct sock *sk,
                                          struct rbscope_tcp_stats *stats) {
    if (!sk || !stats)
        return false;

    __builtin_memset(stats, 0, sizeof(*stats));

    // tcp_sock embeds inet_sock which embeds sock — same pointer, just cast
    struct tcp_sock *tp = (struct tcp_sock *)sk;

    stats->srtt_us       = BPF_CORE_READ(tp, srtt_us);
    stats->snd_cwnd      = BPF_CORE_READ(tp, snd_cwnd);
    stats->total_retrans = BPF_CORE_READ(tp, total_retrans);
    stats->packets_out   = BPF_CORE_READ(tp, packets_out);
    stats->retrans_out   = BPF_CORE_READ(tp, retrans_out);
    stats->lost_out      = BPF_CORE_READ(tp, lost_out);
    stats->rcv_wnd       = BPF_CORE_READ(tp, rcv_wnd);

    // Conditional fields (kernel version dependent)
    if (bpf_core_field_exists(tp->bytes_sent))
        stats->bytes_sent = BPF_CORE_READ(tp, bytes_sent);
    if (bpf_core_field_exists(tp->bytes_received))
        stats->bytes_received = BPF_CORE_READ(tp, bytes_received);

    return true;
}

// resolve_fd_info is the main entry point: resolves an FD to socket info
// and optionally TCP stats. Call with task from bpf_get_current_task_btf().
static bool __always_inline resolve_fd_info(struct task_struct *task,
                                            int fd,
                                            struct rbscope_socket_info *si,
                                            struct rbscope_tcp_stats *tcp) {
    struct file *file = get_file_from_fd(task, fd);
    if (!file)
        return false;

    if (!resolve_socket_info(file, si))
        return false;

    // Capture TCP stats for TCP sockets not in LISTEN state
    if (si->fd_type == FD_TYPE_TCP && si->sock_state != TCP_LISTEN) {
        struct socket *sock = BPF_CORE_READ(file, private_data);
        if (sock) {
            struct sock *sk = BPF_CORE_READ(sock, sk);
            get_tcp_stats(sk, tcp);
        }
    }

    return true;
}

#endif /* __FD_HELPERS_H */
