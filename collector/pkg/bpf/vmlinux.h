// Minimal vmlinux.h stub for CO-RE BPF programs.
//
// A real vmlinux.h is generated from kernel BTF at build time via:
//   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
//
// This stub provides just enough type definitions for the BPF source
// files to be syntactically complete and pass clang parsing.

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef unsigned char       u8;
typedef unsigned short      u16;
typedef unsigned int        u32;
typedef unsigned long long  u64;

typedef signed char         s8;
typedef signed short        s16;
typedef signed int          s32;
typedef signed long long    s64;

typedef u8  __u8;
typedef u16 __u16;
typedef u32 __u32;
typedef u64 __u64;

typedef s8  __s8;
typedef s16 __s16;
typedef s32 __s32;
typedef s64 __s64;

typedef _Bool bool;
#define true  1
#define false 0

// Network byte-order types used by bpf_helper_defs.h
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u16 __le16;
typedef __u32 __le32;
typedef __u64 __le64;
typedef __u32 __wsum;
typedef __u32 __sum16;

// BPF map types (subset needed by our programs)
enum bpf_map_type {
    BPF_MAP_TYPE_UNSPEC = 0,
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_PROG_ARRAY = 3,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
    BPF_MAP_TYPE_PERCPU_HASH = 5,
    BPF_MAP_TYPE_PERCPU_ARRAY = 6,
    BPF_MAP_TYPE_STACK_TRACE = 7,
    BPF_MAP_TYPE_LRU_HASH = 9,
    BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
    BPF_MAP_TYPE_RINGBUF = 27,
};

// BPF map update flags
#define BPF_ANY     0
#define BPF_NOEXIST 1
#define BPF_EXIST   2

// Minimal pt_regs — architecture-specific
#if defined(__TARGET_ARCH_x86)
struct pt_regs {
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long bp;
    unsigned long bx;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long ax;
    unsigned long cx;
    unsigned long dx;
    unsigned long si;
    unsigned long di;
    unsigned long orig_ax;
    unsigned long ip;
    unsigned long cs;
    unsigned long flags;
    unsigned long sp;
    unsigned long ss;
};
#elif defined(__TARGET_ARCH_arm64)
struct pt_regs {
    unsigned long long regs[31];
    unsigned long long sp;
    unsigned long long pc;
    unsigned long long pstate;
};
// libbpf's bpf_tracing.h uses user_pt_regs on aarch64
struct user_pt_regs {
    unsigned long long regs[31];
    unsigned long long sp;
    unsigned long long pc;
    unsigned long long pstate;
};
#else
#error "Unsupported target architecture"
#endif

// Tracepoint context passed to SEC("tp/...") programs
struct trace_event_raw_sys_enter {
    unsigned long long unused;
    long               id;
    unsigned long      args[6];
};

struct trace_event_raw_sys_exit {
    unsigned long long unused;
    long               id;
    long               ret;
};

struct trace_event_raw_sched_switch {
    unsigned long long unused;
    char               prev_comm[16];
    int                prev_pid;
    int                prev_prio;
    long               prev_state;
    char               next_comm[16];
    int                next_pid;
    int                next_prio;
};

// Task struct (minimal, for bpf_get_current_task helpers)
struct task_struct {
    int pid;
    int tgid;
} __attribute__((preserve_access_index));

#endif /* __VMLINUX_H__ */
