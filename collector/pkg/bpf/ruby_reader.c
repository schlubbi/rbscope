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

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB ring buffer
} events SEC(".maps");

// Per-CPU scratch space for stack data (avoid stack allocation limits)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u8[MAX_STACK_SIZE]);
} scratch SEC(".maps");

// Stack deduplication map: hash(stack_data) → stack_id
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, u64);   // FNV-1a hash of stack data
    __type(value, u32); // stack ID (monotonically increasing)
} stack_dedup SEC(".maps");

// Counter for stack IDs
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} stack_id_counter SEC(".maps");

// Event sent to userspace via ring buffer
struct ruby_sample_event {
    u8  event_type;
    u8  _pad[3];
    u32 pid;
    u32 tid;
    u64 timestamp_ns;
    u32 stack_id;
    u32 stack_len;    // bytes of stack data following this header
    // stack data follows inline (variable length)
};

// Span event (from ruby_span USDT probe)
struct ruby_span_event {
    u8  event_type;
    u8  _pad[3];
    u32 pid;
    u32 tid;
    u64 timestamp_ns;
    u64 duration_ns;
    u8  trace_id[16];
    u8  span_id[8];
    u32 stack_id;
    u32 operation_len;
    // operation string follows inline
};

// FNV-1a hash for stack deduplication
static __always_inline u64 fnv1a_hash(const u8 *data, u32 len) {
    u64 hash = 14695981039346656037ULL;
    for (u32 i = 0; i < len && i < MAX_STACK_SIZE; i++) {
        hash ^= data[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

// Get or create a stack ID for the given stack data
static __always_inline u32 get_stack_id(const u8 *stack_data, u32 stack_len) {
    u64 hash = fnv1a_hash(stack_data, stack_len);

    u32 *existing = bpf_map_lookup_elem(&stack_dedup, &hash);
    if (existing) {
        return *existing;
    }

    // Allocate new stack ID
    u32 zero = 0;
    u32 *counter = bpf_map_lookup_elem(&stack_id_counter, &zero);
    if (!counter) return 0;

    u32 new_id = __sync_fetch_and_add(counter, 1);
    bpf_map_update_elem(&stack_dedup, &hash, &new_id, BPF_ANY);
    return new_id;
}

// USDT probe handler: ruby_sample
//
// Fired by rbscope gem's sampling thread at configurable frequency.
// Arguments (from USDT probe):
//   arg0: pointer to stack data (binary format)
//   arg1: stack data length
//   arg2: thread ID
//   arg3: timestamp (nanoseconds)
SEC("uprobe/ruby_sample")
int handle_ruby_sample(struct pt_regs *ctx) {
    u64 stack_ptr = PT_REGS_PARM1(ctx);
    u32 stack_len = (u32)PT_REGS_PARM2(ctx);
    u64 thread_id = PT_REGS_PARM3(ctx);
    u64 timestamp = PT_REGS_PARM4(ctx);

    if (stack_len > MAX_STACK_SIZE)
        stack_len = MAX_STACK_SIZE;

    // Read stack data from userspace into per-CPU scratch buffer
    u32 zero = 0;
    u8 *scratch_buf = bpf_map_lookup_elem(&scratch, &zero);
    if (!scratch_buf) return 0;

    if (bpf_probe_read_user(scratch_buf, stack_len & (MAX_STACK_SIZE - 1), (void *)stack_ptr) < 0)
        return 0;

    // Deduplicate stack
    u32 stack_id = get_stack_id(scratch_buf, stack_len);

    // Reserve ring buffer space for event
    u32 event_size = sizeof(struct ruby_sample_event);
    struct ruby_sample_event *event = bpf_ringbuf_reserve(&events, event_size, 0);
    if (!event) return 0;

    event->event_type = EVENT_RUBY_SAMPLE;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = (u32)bpf_get_current_pid_tgid();
    event->timestamp_ns = timestamp ? timestamp : bpf_ktime_get_ns();
    event->stack_id = stack_id;
    event->stack_len = stack_len;

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
