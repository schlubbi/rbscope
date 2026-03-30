//go:build ignore

// rbscope BPF program: Ruby stack walker (zero-instrumentation mode)
//
// Walks the Ruby VM stack by reading process memory via bpf_probe_read.
// Triggered by perf_event (timer-based sampling). Does NOT require the
// rbscope gem — works with any Ruby process that has DWARF debug info.
//
// The walker reads: EC → CFP → walks frames upward to vm_stack end.
// For each frame with a non-NULL iseq, it emits the iseq address so
// Go-side can resolve method names and file paths from /proc/pid/mem.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Maximum Ruby frames we'll walk per sample.
#define MAX_RUBY_FRAMES 128

// Event types
#define EVENT_RUBY_SAMPLE 1
#define EVENT_STACK_WALK  9

// Flag for bpf_get_stack to capture user-space stack.
#ifndef BPF_F_USER_STACK
#define BPF_F_USER_STACK (1ULL << 8)
#endif

// Maximum native stack depth for bpf_get_stack.
#define MAX_NATIVE_STACK_DEPTH 64
#define MAX_NATIVE_STACK_SIZE  (MAX_NATIVE_STACK_DEPTH * 8)

// Ruby VM struct offsets, populated from DWARF debug info by Go-side.
struct ruby_offsets {
    u32 ec_vm_stack;         // rb_execution_context_struct.vm_stack
    u32 ec_vm_stack_size;    // rb_execution_context_struct.vm_stack_size
    u32 ec_cfp;              // rb_execution_context_struct.cfp
    u32 cfp_pc;              // rb_control_frame_struct.pc
    u32 cfp_sp;              // rb_control_frame_struct.sp
    u32 cfp_iseq;            // rb_control_frame_struct.iseq
    u32 cfp_self;            // rb_control_frame_struct.self
    u32 cfp_ep;              // rb_control_frame_struct.ep
    u32 cfp_sizeof;          // sizeof(rb_control_frame_struct)
    u32 iseq_body;           // rb_iseq_struct.body
    u32 body_location;       // rb_iseq_constant_body.location
    u32 body_iseq_encoded;   // rb_iseq_constant_body.iseq_encoded
    u32 loc_pathobj;         // rb_iseq_location_struct.pathobj
    u32 loc_base_label;      // rb_iseq_location_struct.base_label
    u32 loc_label;           // rb_iseq_location_struct.label
    u32 loc_first_lineno;    // rb_iseq_location_struct.first_lineno
    u32 thread_ec;           // rb_thread_struct.ec
    u32 vm_ractor_main_thread; // vm.ractor.main_thread (absolute offset from vm)
    u32 rstring_len;         // RString.len
    u32 rstring_heap_ptr;    // RString.as.heap.ptr
    u32 rstring_embed_start; // RString.as.embed.ary
    u32 _pad;                // alignment padding
    u64 rstring_noembed;     // RSTRING_NOEMBED flag
};

// Per-PID configuration: EC address and libruby base.
// Populated by Go-side after process discovery.
struct pid_config {
    u64 ec_addr;        // rb_execution_context_struct address
    u64 libruby_base;   // runtime base address of libruby.so
};

// A single Ruby stack frame as emitted by the BPF walker.
// Go-side resolves iseq_addr → method name, file path, line number
// by reading the iseq struct from /proc/pid/mem.
struct ruby_frame {
    u64 iseq_addr;      // pointer to rb_iseq_struct (0 = cfunc frame)
    u64 pc;             // program counter within iseq (for line number)
    u64 self_val;       // cfp->self (receiver VALUE, for class name resolution)
    u32 is_cfunc;       // 1 if this is a C function frame
    u32 _pad;
};

// Event sent to userspace: header + ruby frames + native IPs.
struct stack_walker_event {
    u32 event_type;          // EVENT_RUBY_SAMPLE
    u32 pid;
    u32 tid;
    u32 num_frames;          // number of valid ruby_frame entries
    u64 timestamp_ns;
    u64 thread_id;           // Ruby thread VALUE (== cfp.self for main thread)
    u32 native_stack_len;    // bytes of native IPs
    u32 _pad;
    struct ruby_frame frames[MAX_RUBY_FRAMES]; // Ruby stack (bottom to top)
    u8 native_stack[MAX_NATIVE_STACK_SIZE];     // native IPs from bpf_get_stack
};

// --- BPF Maps ---

// Ruby offsets, keyed by 0 (single entry — all target PIDs share Ruby version).
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct ruby_offsets);
} ruby_offsets_map SEC(".maps");

// Per-PID config, keyed by PID.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, u32);
    __type(value, struct pid_config);
} pid_configs SEC(".maps");

// Ring buffer for sending events to userspace.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} stack_walker_events SEC(".maps");

// Per-CPU scratch space for building events.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct stack_walker_event);
} scratch SEC(".maps");

// --- Stack Walking Logic ---

// walk_ruby_stack reads the Ruby VM stack for a given PID.
// Returns the number of frames captured.
static __always_inline int walk_ruby_stack(
    struct stack_walker_event *event,
    struct ruby_offsets *off,
    struct pid_config *cfg)
{
    u64 ec = cfg->ec_addr;
    int num_frames = 0;

    // Read cfp from EC
    u64 cfp_ptr = 0;
    if (bpf_probe_read(&cfp_ptr, sizeof(cfp_ptr), (void *)(ec + off->ec_cfp)) < 0)
        return 0;

    // Read vm_stack and vm_stack_size to compute end_cfp (stack boundary)
    u64 vm_stack = 0;
    u64 vm_stack_size = 0;
    bpf_probe_read(&vm_stack, sizeof(vm_stack), (void *)(ec + off->ec_vm_stack));
    bpf_probe_read(&vm_stack_size, sizeof(vm_stack_size), (void *)(ec + off->ec_vm_stack_size));

    // end_cfp is the sentinel CFP at the very bottom of the stack.
    // vm_stack_size is in VALUEs (8 bytes each). The CFPs grow downward
    // from the end of the vm_stack buffer.
    u64 end_cfp = vm_stack + vm_stack_size * sizeof(u64) - off->cfp_sizeof;

    // Walk frames: cfp starts at EC.cfp (top of stack, most recent frame)
    // and grows upward (toward end_cfp) to reach older frames.
    // We skip the first CFP (it's the dummy FINISH frame).
    #pragma unroll
    for (int i = 0; i < MAX_RUBY_FRAMES; i++) {
        if (cfp_ptr == 0 || cfp_ptr >= end_cfp)
            break;

        // Read iseq pointer from this CFP
        u64 iseq = 0;
        if (bpf_probe_read(&iseq, sizeof(iseq),
                (void *)(cfp_ptr + off->cfp_iseq)) < 0)
            break;

        // Store frame
        event->frames[i].iseq_addr = iseq;
        event->frames[i].is_cfunc = (iseq == 0) ? 1 : 0;

        // Read self (receiver) for class name resolution
        u64 self_val = 0;
        bpf_probe_read(&self_val, sizeof(self_val),
            (void *)(cfp_ptr + off->cfp_self));
        event->frames[i].self_val = self_val;

        // Read PC for line number resolution (only meaningful for iseq frames)
        if (iseq != 0) {
            u64 pc = 0;
            bpf_probe_read(&pc, sizeof(pc),
                (void *)(cfp_ptr + off->cfp_pc));
            event->frames[i].pc = pc;
        } else {
            // For cfunc frames, carry EP in the pc field so Go can
            // resolve ep[-2] → method entry → called_id → method name
            u64 ep = 0;
            bpf_probe_read(&ep, sizeof(ep),
                (void *)(cfp_ptr + off->cfp_ep));
            event->frames[i].pc = ep;
        }

        num_frames++;

        // Move to next (older) frame: CFP grows upward in memory
        cfp_ptr += off->cfp_sizeof;
    }

    return num_frames;
}

// perf_event handler: triggered by timer-based sampling.
SEC("perf_event")
int handle_ruby_sample(struct bpf_perf_event_data *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = (u32)bpf_get_current_pid_tgid();

    // Check if this PID is a target Ruby process
    struct pid_config *cfg = bpf_map_lookup_elem(&pid_configs, &pid);
    if (!cfg)
        return 0;

    // Get offsets
    u32 zero = 0;
    struct ruby_offsets *off = bpf_map_lookup_elem(&ruby_offsets_map, &zero);
    if (!off)
        return 0;

    // Get scratch space
    struct stack_walker_event *event = bpf_map_lookup_elem(&scratch, &zero);
    if (!event)
        return 0;

    // Fill header
    event->event_type = EVENT_STACK_WALK;
    event->pid = pid;
    event->tid = tid;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->thread_id = 0; // TODO: read from EC or thread struct
    event->native_stack_len = 0;
    event->_pad = 0;

    // Walk Ruby stack
    int nframes = walk_ruby_stack(event, off, cfg);
    if (nframes <= 0)
        return 0;

    event->num_frames = nframes;

    // Capture native stack via bpf_get_stack
    long native_len = bpf_get_stack(ctx, event->native_stack,
                                     MAX_NATIVE_STACK_SIZE,
                                     BPF_F_USER_STACK);
    if (native_len > 0)
        event->native_stack_len = (u32)native_len;

    // Submit to ring buffer — only send header + used frames + native stack
    u32 frame_bytes = nframes * sizeof(struct ruby_frame);
    // Bound for verifier
    if (frame_bytes > MAX_RUBY_FRAMES * sizeof(struct ruby_frame))
        frame_bytes = MAX_RUBY_FRAMES * sizeof(struct ruby_frame);

    u32 header_size = __builtin_offsetof(struct stack_walker_event, frames);
    u32 total = header_size + frame_bytes;

    // Add native stack if captured
    // Note: native stack is at a fixed offset in the struct (after all frames),
    // so we need to copy the full struct up to the native stack end.
    // For simplicity, just send the entire struct.
    // The ring buffer will accept up to max_entries.
    bpf_ringbuf_output(&stack_walker_events, event, sizeof(*event), 0);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
