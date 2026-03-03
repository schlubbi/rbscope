//go:build ignore

// rbscope BPF program: Ruby USDT probe reader
//
// Attaches as uprobe to rbscope's USDT probe sites in the target Ruby
// process. Reads probe arguments (serialized stack frames, thread ID,
// timestamp) and forwards them to userspace via BPF ring buffer.
//
// This replaces the original tracecap's bpf/ruby_reader.c which used
// perf event arrays and string-based stack parsing.
//
// Build: generated via bpf2go (see collector Makefile)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Maximum stack size we'll read from userspace (bytes).
// Our binary format: 2 bytes header + up to 256 frames × 12 bytes = 3074 bytes
#define MAX_STACK_SIZE 4096

// Event types sent to userspace
#define EVENT_RUBY_SAMPLE 1
#define EVENT_RUBY_SPAN   2
#define EVENT_RUBY_ALLOC  3

// Event sent to userspace via ring buffer.
// Stack data is appended inline after this header.
struct ruby_sample_event {
    u32 event_type;
    u32 pid;
    u32 tid;
    u32 _pad0;
    u64 timestamp_ns;
    u64 thread_id;
    u32 stack_data_len;  // bytes of inline stack data following this header
    u32 _pad1;
    // stack data follows inline (variable length, up to MAX_STACK_SIZE)
};

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB ring buffer
} events SEC(".maps");

// Per-CPU scratch space for building events with inline stack data
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u8[sizeof(struct ruby_sample_event) + MAX_STACK_SIZE]);
} scratch SEC(".maps");

// USDT probe handler: __rbscope_probe_ruby_sample
//
// Fired by rbscope gem's postponed job callback with real stack data
// serialized in format v2 (inline strings).
//
// Arguments (from function parameters, read via registers):
//   arg0: pointer to stack data (format v2 inline strings)
//   arg1: stack data length (bytes)
//   arg2: thread ID (Ruby VALUE)
//   arg3: timestamp (nanoseconds)
SEC("uprobe/ruby_sample")
int handle_ruby_sample(struct pt_regs *ctx) {
    u64 stack_ptr = PT_REGS_PARM1(ctx);
    u32 stack_len = (u32)PT_REGS_PARM2(ctx);
    u64 thread_id = PT_REGS_PARM3(ctx);
    u64 timestamp = PT_REGS_PARM4(ctx);

    if (stack_len == 0 || stack_len > MAX_STACK_SIZE)
        return 0;

    // Use per-CPU scratch to build the complete event (header + stack data)
    u32 zero = 0;
    u8 *scratch_buf = bpf_map_lookup_elem(&scratch, &zero);
    if (!scratch_buf) return 0;

    // Build the header in scratch
    struct ruby_sample_event *event = (struct ruby_sample_event *)scratch_buf;
    event->event_type = EVENT_RUBY_SAMPLE;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = (u32)bpf_get_current_pid_tgid();
    event->timestamp_ns = timestamp ? timestamp : bpf_ktime_get_ns();
    event->thread_id = thread_id;
    event->stack_data_len = stack_len;

    // Copy stack data from userspace right after the header
    u32 hdr_size = sizeof(struct ruby_sample_event);
    // Bound the read to satisfy the BPF verifier
    u32 bounded_len = stack_len & (MAX_STACK_SIZE - 1);
    if (bpf_probe_read_user(scratch_buf + hdr_size, bounded_len, (void *)stack_ptr) < 0)
        return 0;

    // Submit the complete event (header + inline stack data) to ring buffer
    u32 total_size = hdr_size + bounded_len;
    bpf_ringbuf_output(&events, scratch_buf, total_size, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
