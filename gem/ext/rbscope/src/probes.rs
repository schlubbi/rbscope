// USDT probe definitions for rbscope.
//
// On Linux with SystemTap SDT, these compile to NOPs that can be
// activated by uprobes (bpftrace, perf, rbscope-collector).
// When no tracer is attached, overhead is effectively zero.
//
// Three probes:
//   ruby_sample — periodic stack sample (fired by sampling thread)
//   ruby_span  — OTel span completion (fired by span exporter)
//   ruby_alloc — allocation event (fired by allocation tracker)
//
// Uses the `probe` macro which compiles to USDT/DTrace nops on
// supported platforms and plain no-ops elsewhere.

use std::sync::atomic::{AtomicBool, Ordering};

static PROBES_ENABLED: AtomicBool = AtomicBool::new(false);

/// Emit a USDT-style probe. On supported platforms this compiles to a
/// NOP sled that BPF uprobes or DTrace can intercept at zero cost when
/// not traced. On unsupported platforms it's a no-op.
///
/// We use inline assembly with a "hint nop" pattern. The key insight:
/// the BPF collector doesn't actually need the USDT `.note.stapsdt`
/// section — it locates the probe sites by scanning for a known symbol
/// (`__rbscope_probe_<name>`) and attaches uprobes at that address.
///
/// This avoids the heavy SystemTap SDT header dependency.
#[inline(never)]
#[no_mangle]
pub extern "C" fn __rbscope_probe_ruby_sample(
    stack_ptr: *const u8,
    stack_len: u32,
    thread_id: u64,
    timestamp_ns: u64,
    weight: u32,
) {
    // Unique constant prevents Identical Code Folding (ICF) from merging
    // this function with other probe stubs that share the same signature.
    // If merged, multiple BPF uprobes fire at the same address, corrupting data.
    std::hint::black_box(1u64);
    std::hint::black_box((stack_ptr, stack_len, thread_id, timestamp_ns, weight));
}

#[inline(never)]
#[no_mangle]
pub extern "C" fn __rbscope_probe_ruby_span(
    trace_id_ptr: *const u8,
    span_id_ptr: *const u8,
    operation_ptr: *const u8,
    operation_len: u32,
    duration_ns: u64,
    stack_ptr: *const u8,
    stack_len: u32,
) {
    std::hint::black_box(4u64);
    std::hint::black_box((
            trace_id_ptr,
            span_id_ptr,
            operation_ptr,
            operation_len,
            duration_ns,
            stack_ptr,
            stack_len,
        ));
}

#[inline(never)]
#[no_mangle]
pub extern "C" fn __rbscope_probe_ruby_alloc(
    object_type_ptr: *const u8,
    object_type_len: u32,
    size: u64,
    stack_ptr: *const u8,
    stack_len: u32,
) {
    std::hint::black_box(2u64);
    std::hint::black_box((
            object_type_ptr,
            object_type_len,
            size,
            stack_ptr,
            stack_len,
        ));
}

/// GVL stack capture probe — fired when a thread releases the GVL (SUSPENDED).
/// Carries the Ruby stack at the moment of GVL release, enabling correlation
/// with subsequent I/O events to produce unified Ruby + native call trees.
///
/// Same argument layout as ruby_sample for BPF reuse.
#[inline(never)]
#[no_mangle]
pub extern "C" fn __rbscope_probe_gvl_stack(
    stack_ptr: *const u8,
    stack_len: u32,
    thread_id: u64,
    timestamp_ns: u64,
    _weight: u32,
) {
    std::hint::black_box(3u64);
    std::hint::black_box((stack_ptr, stack_len, thread_id, timestamp_ns, _weight));
}

/// GVL event probe — fired by the thread event hook callback.
/// Arguments are minimal since the callback runs WITHOUT the GVL held
/// (for READY events) and must not call any Ruby API.
///
///   event_type: 1=READY (wants GVL), 2=RESUMED (got GVL), 3=SUSPENDED (released GVL)
///   tid: native thread ID (from gettid())
///   timestamp_ns: CLOCK_MONOTONIC nanoseconds
///   thread_value: Ruby thread VALUE (for cross-referencing)
#[inline(never)]
#[no_mangle]
pub extern "C" fn __rbscope_probe_gvl_event(
    event_type: u8,
    tid: u32,
    timestamp_ns: u64,
    thread_value: u64,
) {
    std::hint::black_box(5u64);
    std::hint::black_box((event_type, tid, timestamp_ns, thread_value));
}

/// Fire the ruby_sample probe with a serialized stack.
pub fn fire_ruby_sample(stack_data: &[u8], thread_id: u64, timestamp_ns: u64, weight: u32) {
    if !PROBES_ENABLED.load(Ordering::Relaxed) {
        return;
    }
    __rbscope_probe_ruby_sample(
        stack_data.as_ptr(),
        stack_data.len() as u32,
        thread_id,
        timestamp_ns,
        weight,
    );
}

/// Fire the ruby_span probe with span context and stack.
pub fn fire_ruby_span(
    trace_id: &[u8; 16],
    span_id: &[u8; 8],
    operation: &str,
    duration_ns: u64,
    stack_data: &[u8],
) {
    if !PROBES_ENABLED.load(Ordering::Relaxed) {
        return;
    }
    __rbscope_probe_ruby_span(
        trace_id.as_ptr(),
        span_id.as_ptr(),
        operation.as_ptr(),
        operation.len() as u32,
        duration_ns,
        stack_data.as_ptr(),
        stack_data.len() as u32,
    );
}

/// Fire the ruby_alloc probe with allocation info and stack.
pub fn fire_ruby_alloc(object_type: &str, size: u64, stack_data: &[u8]) {
    // No PROBES_ENABLED check — allocation tracking has its own
    // ALLOC_TRACKING_ENABLED gate. The alloc probe should fire
    // whenever allocation tracking is active, independent of the
    // CPU sampler's probe state.
    __rbscope_probe_ruby_alloc(
        object_type.as_ptr(),
        object_type.len() as u32,
        size,
        stack_data.as_ptr(),
        stack_data.len() as u32,
    );
}

/// GVL event types matching BPF-side constants.
pub const GVL_EVENT_READY: u8 = 1;     // Thread wants GVL (waiting)
pub const GVL_EVENT_RESUMED: u8 = 2;   // Thread acquired GVL
pub const GVL_EVENT_SUSPENDED: u8 = 3; // Thread released GVL

/// Fire the GVL event probe. This is called from the thread event hook
/// callback, which may run WITHOUT the GVL held. Only touches atomics
/// and fires the probe — no Ruby API calls, no allocations.
pub fn fire_gvl_event(event_type: u8, tid: u32, timestamp_ns: u64, thread_value: u64) {
    // No PROBES_ENABLED check here — the hook is only registered when
    // GVL profiling is enabled, so every callback should fire.
    __rbscope_probe_gvl_event(event_type, tid, timestamp_ns, thread_value);
}

/// Fire the GVL stack probe with a serialized Ruby stack captured at
/// GVL SUSPENDED time. This provides the Ruby call context for I/O
/// that happens while the GVL is released.
pub fn fire_gvl_stack(stack_data: &[u8], thread_id: u64, timestamp_ns: u64) {
    __rbscope_probe_gvl_stack(
        stack_data.as_ptr(),
        stack_data.len() as u32,
        thread_id,
        timestamp_ns,
        0, // weight unused for GVL stacks
    );
}

pub fn set_probes_enabled(enabled: bool) {
    PROBES_ENABLED.store(enabled, Ordering::Relaxed);
}

/// Ruby-callable: check if probes are enabled.
pub fn probes_enabled() -> bool {
    PROBES_ENABLED.load(Ordering::Relaxed)
}
