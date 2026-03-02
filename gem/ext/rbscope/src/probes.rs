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
// TODO(phase1.2): Replace stub implementations with actual USDT probes

use std::sync::atomic::{AtomicBool, Ordering};

static PROBES_ENABLED: AtomicBool = AtomicBool::new(false);

/// Fire the ruby_sample probe with a serialized stack.
///
/// # Arguments
/// * `stack_data` - Binary-encoded stack frames (frame indices)
/// * `thread_id` - Ruby thread identifier
/// * `timestamp_ns` - Monotonic timestamp in nanoseconds
pub fn fire_ruby_sample(stack_data: &[u8], thread_id: u64, timestamp_ns: u64) {
    if !PROBES_ENABLED.load(Ordering::Relaxed) {
        return;
    }
    // TODO: actual USDT probe fire
    // For now, this is a no-op placeholder. The data flows through
    // to verify serialization works, but nothing is emitted.
    let _ = (stack_data, thread_id, timestamp_ns);
}

/// Fire the ruby_span probe with span context and stack.
///
/// # Arguments
/// * `trace_id` - 16-byte OTel trace ID
/// * `span_id` - 8-byte OTel span ID
/// * `operation` - Span operation name
/// * `duration_ns` - Span duration in nanoseconds
/// * `stack_data` - Binary-encoded stack frames
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
    let _ = (trace_id, span_id, operation, duration_ns, stack_data);
}

/// Fire the ruby_alloc probe with allocation info and stack.
///
/// # Arguments
/// * `object_type` - Ruby object type string (e.g., "String", "Array")
/// * `size` - Approximate size in bytes
/// * `stack_data` - Binary-encoded stack frames
pub fn fire_ruby_alloc(object_type: &str, size: u64, stack_data: &[u8]) {
    if !PROBES_ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let _ = (object_type, size, stack_data);
}

pub fn set_probes_enabled(enabled: bool) {
    PROBES_ENABLED.store(enabled, Ordering::Relaxed);
}

/// Ruby-callable: check if probes are enabled.
pub fn probes_enabled() -> bool {
    PROBES_ENABLED.load(Ordering::Relaxed)
}
