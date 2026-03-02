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

// Minimal pt_regs for x86_64
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
