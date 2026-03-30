// Allow dead code in probe and stack modules — these are public APIs
// used by the collector (Phase 2) and future phases. Only the sampler
// is wired up in Phase 1.
mod allocation_tracker;
#[allow(dead_code)]
mod probes;
mod sampler;
#[allow(dead_code)]
mod stack;

use magnus::{function, prelude::*, Error, Ruby};

/// Bridge function called from Ruby: Rbscope::Native.fire_span(trace_id_hex, span_id_hex, operation, duration_ns)
/// Converts hex strings to bytes and fires the USDT probe.
fn fire_span_from_ruby(trace_id_hex: String, span_id_hex: String, operation: String, duration_ns: u64) {
    let trace_id = hex_to_bytes_16(&trace_id_hex);
    let span_id = hex_to_bytes_8(&span_id_hex);

    // Fire the span probe without stack data — the BPF collector gets
    // trace context which it can correlate with concurrent stack samples.
    probes::fire_ruby_span(&trace_id, &span_id, &operation, duration_ns, &[]);
}

fn hex_to_bytes_16(hex: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        let start = i * 2;
        if start + 2 <= hex.len() {
            *byte = u8::from_str_radix(&hex[start..start + 2], 16).unwrap_or(0);
        }
    }
    out
}

fn hex_to_bytes_8(hex: &str) -> [u8; 8] {
    let mut out = [0u8; 8];
    for (i, byte) in out.iter_mut().enumerate() {
        let start = i * 2;
        if start + 2 <= hex.len() {
            *byte = u8::from_str_radix(&hex[start..start + 2], 16).unwrap_or(0);
        }
    }
    out
}

/// Initialize the rbscope Ruby extension.
///
/// Defines the Rbscope module and its methods, registers the postponed
/// job for safe stack capture, and prepares the sampling infrastructure
/// (but does not start it).
#[magnus::init]
fn init(ruby: &Ruby) -> Result<(), Error> {
    let module = ruby.define_module("Rbscope")?;
    let native = module.define_module("Native")?;

    native.define_singleton_method("start_sampling", function!(sampler::start_sampling, 1))?;
    native.define_singleton_method("stop_sampling", function!(sampler::stop_sampling, 0))?;
    native.define_singleton_method("enabled?", function!(probes::probes_enabled, 0))?;
    native.define_singleton_method("sample_count", function!(sampler::sample_count, 0))?;
    native.define_singleton_method("fire_span", function!(fire_span_from_ruby, 4))?;
    native.define_singleton_method("set_overhead_target", function!(sampler::set_overhead_target, 1))?;
    native.define_singleton_method("set_dynamic_rate", function!(sampler::set_dynamic_rate, 1))?;
    native.define_singleton_method("sampling_stats", function!(sampler::sampling_stats, 0))?;
    native.define_singleton_method("enable_gvl_profiling", function!(sampler::enable_gvl_profiling, 0))?;
    native.define_singleton_method("gvl_profiling_enabled?", function!(sampler::gvl_profiling_enabled, 0))?;
    native.define_singleton_method("gvl_event_count", function!(sampler::gvl_event_count, 0))?;
    native.define_singleton_method("start_allocation_tracking", function!(allocation_tracker::start_allocation_tracking, 1))?;
    native.define_singleton_method("stop_allocation_tracking", function!(allocation_tracker::stop_allocation_tracking, 0))?;
    native.define_singleton_method("allocation_tracking_enabled?", function!(allocation_tracker::allocation_tracking_enabled, 0))?;
    native.define_singleton_method("allocation_stats", function!(allocation_tracker::allocation_stats, 0))?;

    // Register the postponed job with the Ruby VM. This must happen on
    // the main thread during init — the handle is used later by the
    // sampler thread to trigger safe-point stack capture.
    sampler::register_postponed_job();

    Ok(())
}
