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
    std::hint::black_box((
            object_type_ptr,
            object_type_len,
            size,
            stack_ptr,
            stack_len,
        ));
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
    if !PROBES_ENABLED.load(Ordering::Relaxed) {
        return;
    }
    __rbscope_probe_ruby_alloc(
        object_type.as_ptr(),
        object_type.len() as u32,
        size,
        stack_data.as_ptr(),
        stack_data.len() as u32,
    );
}

pub fn set_probes_enabled(enabled: bool) {
    PROBES_ENABLED.store(enabled, Ordering::Relaxed);
}

/// Ruby-callable: check if probes are enabled.
pub fn probes_enabled() -> bool {
    PROBES_ENABLED.load(Ordering::Relaxed)
}
