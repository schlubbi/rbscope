// Allow dead code in probe and stack modules — these are public APIs
// used by the collector (Phase 2) and future phases. Only the sampler
// is wired up in Phase 1.
#[allow(dead_code)]
mod probes;
mod sampler;
#[allow(dead_code)]
mod stack;

use magnus::{function, prelude::*, Error, Ruby};

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

    // Register the postponed job with the Ruby VM. This must happen on
    // the main thread during init — the handle is used later by the
    // sampler thread to trigger safe-point stack capture.
    sampler::register_postponed_job();

    Ok(())
}
