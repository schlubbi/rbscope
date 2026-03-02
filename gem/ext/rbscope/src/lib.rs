// Allow dead code in probe and stack modules — these are public APIs
// used by the collector (Phase 2) and future phases. Only the sampler
// is wired up in Phase 1.
#[allow(dead_code)]
mod probes;
mod sampler;
#[allow(dead_code)]
mod stack;

use magnus::{define_module, function, prelude::*, Error};

/// Initialize the rbscope Ruby extension.
///
/// Defines the Rbscope module and its methods, wires up configuration,
/// and prepares the sampling infrastructure (but does not start it).
#[magnus::init]
fn init() -> Result<(), Error> {
    let module = define_module("Rbscope")?;
    let native = module.define_module("Native")?;

    native.define_singleton_method("start_sampling", function!(sampler::start_sampling, 1))?;
    native.define_singleton_method("stop_sampling", function!(sampler::stop_sampling, 0))?;
    native.define_singleton_method("enabled?", function!(probes::probes_enabled, 0))?;
    native.define_singleton_method("sample_count", function!(sampler::sample_count, 0))?;

    Ok(())
}
