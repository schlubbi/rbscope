//go:build ignore

// rbscope BPF program: Ruby USDT probe reader
//
// Attaches as uprobe to rbscope's USDT probe sites in the target Ruby
// process. Reads probe arguments (serialized stack frames, thread ID,
// timestamp) and forwards them to userspace via BPF ring buffer.
//
// Also captures the native user-space call stack via bpf_get_stack()
// so the collector can merge Ruby frames with C extension frames
// (e.g., Trilogy, Nokogiri) for a complete call path from Ruby
// through C down to syscalls.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Maximum stack size we'll read from userspace (bytes).
#define MAX_STACK_SIZE 16384

// Maximum native stack depth (IPs). bpf_get_stack supports up to 127.
// We use 64 to keep event size reasonable (~512 bytes for native stack).
#define MAX_NATIVE_STACK_DEPTH 64
#define MAX_NATIVE_STACK_SIZE  (MAX_NATIVE_STACK_DEPTH * 8)

// Flag for bpf_get_stack to capture user-space stack instead of kernel.
#ifndef BPF_F_USER_STACK
#define BPF_F_USER_STACK (1ULL << 8)
#endif

// Event types sent to userspace
#define EVENT_RUBY_SAMPLE 1
#define EVENT_RUBY_SPAN   2
#define EVENT_RUBY_ALLOC  3

// Event sent to userspace via ring buffer.
// Layout: [header 40 bytes] [Ruby stack data] [native stack IPs]
struct ruby_sample_event {
    u32 event_type;
    u32 pid;
    u32 tid;
    u32 weight;            // number of sample ticks this event represents
    u64 timestamp_ns;
    u64 thread_id;
    u32 stack_data_len;    // bytes of inline Ruby stack data after header
    u32 native_stack_len;  // bytes of native stack IPs after Ruby stack data
    // Ruby stack data follows inline (stack_data_len bytes)
    // Native stack IPs follow (native_stack_len bytes, each u64)
};

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB ring buffer
} events SEC(".maps");

// Per-CPU scratch space for building events with inline stack data.
// Sized for header + max Ruby stack + max native stack.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u8[sizeof(struct ruby_sample_event) + MAX_STACK_SIZE + MAX_NATIVE_STACK_SIZE]);
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
//   arg4: weight (number of sample ticks this event represents)
SEC("uprobe/ruby_sample")
int handle_ruby_sample(struct pt_regs *ctx) {
    u64 stack_ptr = PT_REGS_PARM1(ctx);
    u32 stack_len = (u32)PT_REGS_PARM2(ctx);
    u64 thread_id = PT_REGS_PARM3(ctx);
    u64 timestamp = PT_REGS_PARM4(ctx);
    u32 weight = (u32)PT_REGS_PARM5(ctx);

    if (stack_len == 0 || stack_len > MAX_STACK_SIZE)
        return 0;

    // Use per-CPU scratch to build the complete event (header + stacks)
    u32 zero = 0;
    u8 *scratch_buf = bpf_map_lookup_elem(&scratch, &zero);
    if (!scratch_buf) return 0;

    // Build the header in scratch
    struct ruby_sample_event *event = (struct ruby_sample_event *)scratch_buf;
    event->event_type = EVENT_RUBY_SAMPLE;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = (u32)bpf_get_current_pid_tgid();
    event->weight = weight > 0 ? weight : 1;
    event->timestamp_ns = timestamp ? timestamp : bpf_ktime_get_ns();
    event->thread_id = thread_id;
    event->stack_data_len = stack_len;
    event->native_stack_len = 0;

    // Copy Ruby stack data from userspace right after the header
    u32 hdr_size = sizeof(struct ruby_sample_event);
    // Bound the read to satisfy the BPF verifier
    u32 bounded_len = stack_len & (MAX_STACK_SIZE - 1);
    if (bpf_probe_read_user(scratch_buf + hdr_size, bounded_len, (void *)stack_ptr) < 0)
        return 0;

    // Capture native user-space call stack via bpf_get_stack.
    // This gives us the C-level call chain (libtrilogy, libruby, libc, etc.)
    // that we can merge with the Ruby-level frames from the gem.
    //
    // Write native IPs into a fixed offset after the max Ruby stack area
    // to avoid verifier issues with dynamic offsets.
    u32 native_offset = hdr_size + MAX_STACK_SIZE;
    long native_ret = bpf_get_stack(ctx, scratch_buf + native_offset,
                                    MAX_NATIVE_STACK_SIZE, BPF_F_USER_STACK);
    u32 native_len = 0;
    if (native_ret > 0)
        native_len = (u32)native_ret;
    event->native_stack_len = native_len;

    // Copy native IPs right after Ruby stack data (compact layout for output)
    // We wrote native IPs at fixed offset, now we need to emit them at
    // hdr_size + bounded_len. Use bpf_ringbuf_output with the full scratch
    // and let the Go parser know the layout via the header fields.
    //
    // Actually, for simplicity, emit at the fixed native_offset position.
    // The Go parser reads: header → Ruby stack (stack_data_len bytes from
    // offset 40) → native stack (native_stack_len bytes from offset
    // 40 + MAX_STACK_SIZE = 4136).
    u32 total_size = native_offset + native_len;
    bpf_ringbuf_output(&events, scratch_buf, total_size, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
