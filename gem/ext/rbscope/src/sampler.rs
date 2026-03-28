// Sampling engine for rbscope.
//
// Runs a dedicated background thread (not SIGALRM) that periodically
// triggers Ruby stack capture via rb_postponed_job. This avoids the
// single-timer conflict with Unicorn/Pitchfork's worker lifecycle
// management which also uses SIGALRM.
//
// Architecture:
//   1. At init: rb_postponed_job_preregister() reserves a job slot
//   2. Timer thread: sleeps for 1/frequency, then calls rb_postponed_job_trigger()
//   3. Ruby VM: at next safe point, runs the postponed job callback
//   4. Callback: calls rb_profile_thread_frames() to capture stack, fires USDT probe
//
// Dynamic sampling rate:
//   The sampler measures the cost of each callback (EWMA) and adjusts
//   the sleep interval to keep total overhead within a configurable
//   CPU budget (default 2%). When samples are expensive (deep stacks,
//   GC pressure), the rate backs off. When cheap, it speeds up.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU32, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::probes;
use crate::stack::{InlineStack, InlineFrame};

// ---------------------------------------------------------------------------
// FFI declarations for Ruby C API
// ---------------------------------------------------------------------------
//
// These are not (yet) exported by rb-sys for Ruby 3.3+/4.0 APIs, so we
// declare them manually. All are safe to call per the Ruby C API contract:
//   - rb_postponed_job_preregister: must be called from Ruby main thread
//   - rb_postponed_job_trigger: safe from ANY thread (the whole point)
//   - rb_profile_thread_frames: must be called from Ruby thread (our callback)

extern "C" {
    fn rb_postponed_job_preregister(
        flags: std::os::raw::c_uint,
        func: unsafe extern "C" fn(*mut std::ffi::c_void),
        data: *mut std::ffi::c_void,
    ) -> std::os::raw::c_int;

    fn rb_postponed_job_trigger(
        handle: std::os::raw::c_int,
    );

    fn rb_profile_thread_frames(
        thread: rb_sys::VALUE,
        start: std::os::raw::c_int,
        limit: std::os::raw::c_int,
        buff: *mut rb_sys::VALUE,
        lines: *mut std::os::raw::c_int,
    ) -> std::os::raw::c_int;

    fn rb_thread_current() -> rb_sys::VALUE;

    fn rb_profile_frame_full_label(frame: rb_sys::VALUE) -> rb_sys::VALUE;
    fn rb_profile_frame_path(frame: rb_sys::VALUE) -> rb_sys::VALUE;

    // Use Ruby's own string accessor — bypasses rb-sys struct layout
    // which is broken on Ruby 4.0 (reads len field as embedded string data).
    fn rb_string_value_ptr(val_ptr: *mut rb_sys::VALUE) -> *const std::os::raw::c_char;
}

/// Maximum number of Ruby frames to capture per sample.
const MAX_FRAMES: usize = 512;

/// Maximum serialized stack size (must fit in BPF ring buffer event).
const MAX_STACK_BYTES: usize = 4096;

/// Minimum sleep interval (100µs = max ~10kHz).
const MIN_INTERVAL_NS: u64 = 100_000;
/// Maximum sleep interval (1s = min 1Hz).
const MAX_INTERVAL_NS: u64 = 1_000_000_000;

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

static RUNNING: AtomicBool = AtomicBool::new(false);
static SAMPLE_COUNT: AtomicU64 = AtomicU64::new(0);
// Track the PID that started the sampler. After fork, the child has a
// different PID and should consider the sampler as not running.
static OWNER_PID: AtomicU32 = AtomicU32::new(0);
/// Postponed job handle returned by rb_postponed_job_preregister.
/// -1 means not yet registered.
static POSTPONED_JOB_HANDLE: AtomicI32 = AtomicI32::new(-1);

// Dynamic sampling rate state
/// EWMA of sample callback duration in nanoseconds (1/8 smoothing).
static SAMPLE_DURATION_EWMA_NS: AtomicU64 = AtomicU64::new(0);
/// Overhead target × 10000 (e.g. 200 = 2.00%). Stored as integer to
/// avoid floating point atomics.
static OVERHEAD_TARGET_BPS: AtomicU32 = AtomicU32::new(200);
/// Whether dynamic rate adjustment is enabled.
static DYNAMIC_RATE_ENABLED: AtomicBool = AtomicBool::new(true);
/// Current sampling interval in nanoseconds (observable).
static CURRENT_INTERVAL_NS: AtomicU64 = AtomicU64::new(0);
/// Maximum frequency configured at start (Hz).
static MAX_FREQUENCY_HZ: AtomicU32 = AtomicU32::new(99);

struct SamplerState {
    thread_handle: Option<thread::JoinHandle<()>>,
}

static SAMPLER: Mutex<Option<SamplerState>> = Mutex::new(None);
/// Reentrancy guard — prevents the callback from running if a previous
/// invocation is still in progress (e.g. under GC stress where string
/// allocations in the callback trigger GC which could re-enter).
static IN_CALLBACK: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// Postponed job callback — runs on Ruby VM thread at safe point
// ---------------------------------------------------------------------------

/// # Safety
///
/// Called by the Ruby VM from the main thread at a safe point after
/// rb_postponed_job_trigger(). It is safe to call Ruby C API functions
/// including rb_profile_thread_frames and rb_profile_frame_* here.
unsafe extern "C" fn postponed_job_callback(_data: *mut std::ffi::c_void) {
    // Catch any panics to prevent aborting the host Ruby process.
    // IMPORTANT: reset IN_CALLBACK after catch_unwind — if the inner
    // function panics, the cleanup at the end of callback_inner won't
    // run, permanently locking out all future callbacks.
    let _ = std::panic::catch_unwind(|| {
        postponed_job_callback_inner();
    });
    IN_CALLBACK.store(false, Ordering::Release);
}

unsafe fn postponed_job_callback_inner() {
    if !RUNNING.load(Ordering::Relaxed) {
        return;
    }

    // Reentrancy guard: skip if already inside the callback. This
    // prevents cascading when rb_profile_frame_full_label allocations
    // trigger GC under GC.stress, which could re-enter the callback.
    if IN_CALLBACK.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        return;
    }

    // Measure callback duration for dynamic rate adjustment
    let start_ns = clock_gettime_ns();

    let thread = rb_thread_current();

    let mut frame_buf: [rb_sys::VALUE; MAX_FRAMES] = [0; MAX_FRAMES];
    let mut line_buf: [std::os::raw::c_int; MAX_FRAMES] = [0; MAX_FRAMES];

    let num_frames = rb_profile_thread_frames(
        thread,
        0,
        MAX_FRAMES as std::os::raw::c_int,
        frame_buf.as_mut_ptr(),
        line_buf.as_mut_ptr(),
    );

    if num_frames <= 0 {
        // No frames captured (idle thread or error) — still count it
        SAMPLE_COUNT.fetch_add(1, Ordering::Relaxed);
        update_sample_duration_ewma(start_ns);
        IN_CALLBACK.store(false, Ordering::Release);
        return;
    }

    // Build an InlineStack from the captured frames
    let mut stack = InlineStack::new();
    for i in 0..num_frames as usize {
        let label = ruby_value_to_string(rb_profile_frame_full_label(frame_buf[i]));
        let path = ruby_value_to_string(rb_profile_frame_path(frame_buf[i]));
        let line = if line_buf[i] > 0 { line_buf[i] as u32 } else { 0 };

        stack.frames.push(InlineFrame { label, path, line });
    }

    // Serialize and fire the USDT probe
    let mut buf = Vec::with_capacity(stack.serialized_size().min(MAX_STACK_BYTES));
    if stack.serialize(&mut buf).is_ok() && buf.len() <= MAX_STACK_BYTES {
        let thread_id = thread as u64;
        let timestamp_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        probes::fire_ruby_sample(&buf, thread_id, timestamp_ns);
    }

    SAMPLE_COUNT.fetch_add(1, Ordering::Relaxed);
    update_sample_duration_ewma(start_ns);
    IN_CALLBACK.store(false, Ordering::Release);
}

/// Convert a Ruby VALUE string to a Rust String.
/// Returns "(unknown)" for nil/non-string values.
///
/// # Safety
///
/// Caller must ensure `value` is a valid Ruby VALUE and that this is
/// called from a Ruby thread (not the sampler thread).
unsafe fn ruby_value_to_string(value: rb_sys::VALUE) -> String {
    // Filter nil, false, zero
    if value == rb_sys::Qnil as rb_sys::VALUE
        || value == rb_sys::Qfalse as rb_sys::VALUE
        || value == 0
    {
        return "(unknown)".to_string();
    }

    // Filter special constants (fixnum, symbol, flonum) — these are
    // immediate values encoded in the pointer, not heap objects.
    // On 64-bit Ruby: any of the low 3 bits set means immediate.
    if value & 0x07 != 0 {
        return "(unknown)".to_string();
    }

    // For heap objects, check the type tag in the RBasic flags field
    // (offset 0). rb_profile_frame_* can return T_IMEMO objects;
    // calling RSTRING_PTR on those triggers an assertion panic in rb-sys.
    // T_STRING = 0x05 in bits 0-4 of the flags word.
    let flags = *(value as *const usize);
    if flags & 0x1f != 0x05 {
        return "(unknown)".to_string();
    }

    // Use Ruby's own rb_string_value_ptr instead of rb-sys's RSTRING_PTR.
    // rb-sys uses the Ruby 2.7 struct layout where embedded string data
    // is at offset 16, but Ruby 4.0 moved `len` there and data to offset 24.
    // rb_string_value_ptr calls the Ruby binary's own RSTRING_PTR which
    // uses the correct layout for the running Ruby version.
    let mut val = value;
    let ptr = rb_string_value_ptr(&mut val as *mut rb_sys::VALUE);
    let len = rb_sys::RSTRING_LEN(value);

    if ptr.is_null() || !(0..=10_000).contains(&len) {
        return "(unknown)".to_string();
    }

    let bytes = std::slice::from_raw_parts(ptr as *const u8, len as usize);
    String::from_utf8_lossy(bytes).into_owned()
}

// ---------------------------------------------------------------------------
// Dynamic rate helpers
// ---------------------------------------------------------------------------

/// Update the EWMA of sample callback duration (1/8 smoothing factor).
fn update_sample_duration_ewma(start_ns: u64) {
    let end_ns = clock_gettime_ns();
    let duration = end_ns.saturating_sub(start_ns);
    let prev = SAMPLE_DURATION_EWMA_NS.load(Ordering::Relaxed);
    let new_ewma = if prev == 0 {
        duration
    } else {
        // EWMA with α=1/8: new = old*7/8 + sample*1/8
        (prev * 7 + duration) / 8
    };
    SAMPLE_DURATION_EWMA_NS.store(new_ewma, Ordering::Relaxed);
}

/// Monotonic clock in nanoseconds (CLOCK_MONOTONIC on Linux/macOS).
fn clock_gettime_ns() -> u64 {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        // Safety: clock_gettime with CLOCK_MONOTONIC is always safe.
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        // Fallback: std::time::Instant doesn't give raw ns easily,
        // use SystemTime (less precise but portable).
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64
    }
}

/// Adjust the sampling interval based on measured overhead.
/// Returns the new interval in nanoseconds.
fn adjust_interval(current_interval_ns: u64) -> u64 {
    if !DYNAMIC_RATE_ENABLED.load(Ordering::Relaxed) {
        return current_interval_ns;
    }

    let avg_sample_ns = SAMPLE_DURATION_EWMA_NS.load(Ordering::Relaxed);
    if avg_sample_ns == 0 {
        return current_interval_ns;
    }

    let target_bps = OVERHEAD_TARGET_BPS.load(Ordering::Relaxed) as u64;
    // overhead = sample_ns / (sample_ns + interval_ns)
    // target: overhead <= target_bps / 10000
    // => sample_ns * 10000 <= target_bps * (sample_ns + interval_ns)
    let overhead_x10000 = avg_sample_ns * 10000 / (avg_sample_ns + current_interval_ns);

    let new_interval = if overhead_x10000 > target_bps {
        // Over budget — back off 10% (fast)
        current_interval_ns * 11 / 10
    } else if overhead_x10000 < target_bps * 8 / 10 {
        // Under 80% of budget — speed up 5% (conservative)
        current_interval_ns * 95 / 100
    } else {
        // Within [80%, 100%] of target — hold steady
        current_interval_ns
    };

    new_interval.clamp(MIN_INTERVAL_NS, MAX_INTERVAL_NS)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Register the postponed job with the Ruby VM. Must be called from the
/// Ruby main thread during extension initialization.
///
/// # Safety
///
/// Must be called exactly once, from the Ruby main thread, during init.
pub fn register_postponed_job() {
    // Safety: called from init, which runs on the Ruby main thread.
    let handle = unsafe {
        rb_postponed_job_preregister(
            0, // flags (none defined yet)
            postponed_job_callback,
            std::ptr::null_mut(),
        )
    };
    POSTPONED_JOB_HANDLE.store(handle, Ordering::SeqCst);
}

/// Check if we're in a forked child that inherited stale state.
fn is_stale_after_fork() -> bool {
    let owner = OWNER_PID.load(Ordering::Relaxed);
    owner != 0 && owner != std::process::id()
}

/// Reset stale state inherited from a parent process after fork.
fn reset_after_fork() {
    RUNNING.store(false, Ordering::SeqCst);
    SAMPLE_COUNT.store(0, Ordering::Relaxed);
    OWNER_PID.store(0, Ordering::Relaxed);
    IN_CALLBACK.store(false, Ordering::Relaxed);
    probes::set_probes_enabled(false);

    let mut sampler = SAMPLER.lock().unwrap();
    // Drop the inherited thread handle — the thread doesn't exist in this process
    *sampler = None;
}

/// Start the sampling engine at the given frequency (Hz).
///
/// Called from Ruby: `Rbscope::Native.start_sampling(99)`
///
/// # Arguments
/// * `frequency` - Sampling rate in Hz (19 = always-on, 99 = standard, 999 = deep)
pub fn start_sampling(frequency: u32) -> Result<bool, magnus::Error> {
    if frequency == 0 || frequency > 10_000 {
        let ruby = unsafe { magnus::Ruby::get_unchecked() };
        return Err(magnus::Error::new(
            ruby.exception_arg_error(),
            format!("frequency must be 1-10000, got {}", frequency),
        ));
    }

    // Handle forked children that inherited stale parent state
    if is_stale_after_fork() {
        reset_after_fork();
    }

    if RUNNING.load(Ordering::SeqCst) {
        return Ok(false); // already running
    }

    if POSTPONED_JOB_HANDLE.load(Ordering::SeqCst) < 0 {
        let ruby = unsafe { magnus::Ruby::get_unchecked() };
        return Err(magnus::Error::new(
            ruby.exception_runtime_error(),
            "postponed job not registered — was Rbscope initialized?",
        ));
    }

    let interval = Duration::from_micros(1_000_000 / u64::from(frequency));
    let interval_ns = interval.as_nanos() as u64;

    RUNNING.store(true, Ordering::SeqCst);
    OWNER_PID.store(std::process::id(), Ordering::Relaxed);
    probes::set_probes_enabled(true);
    SAMPLE_COUNT.store(0, Ordering::Relaxed);
    SAMPLE_DURATION_EWMA_NS.store(0, Ordering::Relaxed);
    MAX_FREQUENCY_HZ.store(frequency, Ordering::Relaxed);
    CURRENT_INTERVAL_NS.store(interval_ns, Ordering::Relaxed);

    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_clone = stop_flag.clone();

    let handle = thread::Builder::new()
        .name("rbscope-sampler".to_string())
        .spawn(move || {
            sampler_loop(interval, stop_clone);
        })
        .map_err(|e| {
            RUNNING.store(false, Ordering::SeqCst);
            let ruby = unsafe { magnus::Ruby::get_unchecked() };
            magnus::Error::new(
                ruby.exception_runtime_error(),
                format!("failed to spawn sampler thread: {}", e),
            )
        })?;

    let mut sampler = SAMPLER.lock().unwrap();
    *sampler = Some(SamplerState {
        thread_handle: Some(handle),
    });

    Ok(true)
}

/// Stop the sampling engine and join the sampler thread.
///
/// Called from Ruby: `Rbscope::Native.stop_sampling`
pub fn stop_sampling() -> Result<u64, magnus::Error> {
    // Handle forked children
    if is_stale_after_fork() {
        reset_after_fork();
        return Ok(0);
    }

    if !RUNNING.load(Ordering::SeqCst) {
        return Ok(0);
    }

    RUNNING.store(false, Ordering::SeqCst);
    probes::set_probes_enabled(false);

    let count = SAMPLE_COUNT.load(Ordering::Relaxed);

    let mut sampler = SAMPLER.lock().unwrap();
    if let Some(mut state) = sampler.take() {
        if let Some(handle) = state.thread_handle.take() {
            // In a forked child, the sampler thread doesn't exist.
            // join() will fail with ESRCH — that's fine, just ignore it.
            let _ = handle.join();
        }
    }

    Ok(count)
}

/// Return the number of samples taken since last start.
pub fn sample_count() -> u64 {
    SAMPLE_COUNT.load(Ordering::Relaxed)
}

fn sampler_loop(interval: Duration, _stop: Arc<AtomicBool>) {
    let handle = POSTPONED_JOB_HANDLE.load(Ordering::SeqCst);
    let mut interval_ns = interval.as_nanos() as u64;

    while RUNNING.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_nanos(interval_ns));

        if !RUNNING.load(Ordering::SeqCst) {
            break;
        }

        // Trigger the postponed job — Ruby VM will call our callback
        // at the next safe point on the main thread.
        //
        // Safety: rb_postponed_job_trigger is explicitly documented as
        // safe to call from any thread (that's its entire purpose).
        if handle >= 0 {
            unsafe { rb_postponed_job_trigger(handle) };
        }

        // Adjust interval based on measured sample cost
        interval_ns = adjust_interval(interval_ns);
        CURRENT_INTERVAL_NS.store(interval_ns, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// Configuration API (called from Ruby)
// ---------------------------------------------------------------------------

/// Set the overhead target as a percentage (e.g. 0.02 = 2%).
/// Called from Ruby: Rbscope::Native.set_overhead_target(0.02)
pub fn set_overhead_target(target: f64) -> Result<bool, magnus::Error> {
    if !(0.001..=0.5).contains(&target) {
        let ruby = unsafe { magnus::Ruby::get_unchecked() };
        return Err(magnus::Error::new(
            ruby.exception_arg_error(),
            format!("overhead_target must be 0.001-0.5, got {}", target),
        ));
    }
    let bps = (target * 10000.0) as u32;
    OVERHEAD_TARGET_BPS.store(bps, Ordering::Relaxed);
    Ok(true)
}

/// Enable or disable dynamic sampling rate adjustment.
/// Called from Ruby: Rbscope::Native.set_dynamic_rate(true)
pub fn set_dynamic_rate(enabled: bool) -> bool {
    DYNAMIC_RATE_ENABLED.store(enabled, Ordering::Relaxed);
    enabled
}

/// Return current sampling stats as a hash.
/// Called from Ruby: Rbscope::Native.sampling_stats
pub fn sampling_stats() -> (u64, u64, u64, u32) {
    let interval_ns = CURRENT_INTERVAL_NS.load(Ordering::Relaxed);
    let frequency_hz = if interval_ns > 0 {
        1_000_000_000 / interval_ns
    } else {
        0
    };
    let avg_sample_ns = SAMPLE_DURATION_EWMA_NS.load(Ordering::Relaxed);
    let sample_count = SAMPLE_COUNT.load(Ordering::Relaxed);
    let max_freq = MAX_FREQUENCY_HZ.load(Ordering::Relaxed);

    (frequency_hz, avg_sample_ns, sample_count, max_freq)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adjust_interval_disabled() {
        DYNAMIC_RATE_ENABLED.store(false, Ordering::Relaxed);
        SAMPLE_DURATION_EWMA_NS.store(50_000, Ordering::Relaxed);
        let result = adjust_interval(10_000_000);
        assert_eq!(result, 10_000_000, "should not change when disabled");
        DYNAMIC_RATE_ENABLED.store(true, Ordering::Relaxed);
    }

    #[test]
    fn test_adjust_interval_no_data() {
        DYNAMIC_RATE_ENABLED.store(true, Ordering::Relaxed);
        SAMPLE_DURATION_EWMA_NS.store(0, Ordering::Relaxed);
        let result = adjust_interval(10_000_000);
        assert_eq!(result, 10_000_000, "should not change with no data");
    }

    #[test]
    fn test_adjust_interval_backs_off_when_over_budget() {
        DYNAMIC_RATE_ENABLED.store(true, Ordering::Relaxed);
        OVERHEAD_TARGET_BPS.store(200, Ordering::Relaxed); // 2%

        // avg_sample = 500µs, interval = 1ms
        // overhead = 500k / (500k + 1M) = 33% → way over 2%
        SAMPLE_DURATION_EWMA_NS.store(500_000, Ordering::Relaxed);
        let result = adjust_interval(1_000_000);
        assert!(result > 1_000_000, "should back off: got {}", result);
        assert_eq!(result, 1_100_000, "should back off by 10%");
    }

    #[test]
    fn test_adjust_interval_speeds_up_when_under_budget() {
        DYNAMIC_RATE_ENABLED.store(true, Ordering::Relaxed);
        OVERHEAD_TARGET_BPS.store(200, Ordering::Relaxed); // 2%

        // avg_sample = 1µs, interval = 100ms
        // overhead = 1k / (1k + 100M) ≈ 0.001% → way under 2%
        SAMPLE_DURATION_EWMA_NS.store(1_000, Ordering::Relaxed);
        let result = adjust_interval(100_000_000);
        assert!(result < 100_000_000, "should speed up: got {}", result);
        assert_eq!(result, 95_000_000, "should speed up by 5%");
    }

    #[test]
    fn test_adjust_interval_holds_when_near_target() {
        DYNAMIC_RATE_ENABLED.store(true, Ordering::Relaxed);
        OVERHEAD_TARGET_BPS.store(200, Ordering::Relaxed); // 2%

        // avg_sample = 200µs, interval = 10ms
        // overhead = 200k / (200k + 10M) ≈ 1.96% → within [1.6%, 2%]
        SAMPLE_DURATION_EWMA_NS.store(200_000, Ordering::Relaxed);
        let result = adjust_interval(10_000_000);
        assert_eq!(result, 10_000_000, "should hold steady near target");
    }

    #[test]
    fn test_adjust_interval_clamps_min() {
        DYNAMIC_RATE_ENABLED.store(true, Ordering::Relaxed);
        OVERHEAD_TARGET_BPS.store(5000, Ordering::Relaxed); // 50%

        // Very cheap samples, very high budget → wants to go below MIN
        SAMPLE_DURATION_EWMA_NS.store(1, Ordering::Relaxed);
        let mut interval = MIN_INTERVAL_NS + 1000;
        for _ in 0..100 {
            interval = adjust_interval(interval);
        }
        assert!(interval >= MIN_INTERVAL_NS, "should not go below MIN: got {}", interval);
    }

    #[test]
    fn test_adjust_interval_clamps_max() {
        DYNAMIC_RATE_ENABLED.store(true, Ordering::Relaxed);
        OVERHEAD_TARGET_BPS.store(1, Ordering::Relaxed); // 0.01%

        // Expensive samples, tiny budget → wants to go above MAX
        SAMPLE_DURATION_EWMA_NS.store(10_000_000, Ordering::Relaxed);
        let mut interval = MAX_INTERVAL_NS - 1000;
        for _ in 0..100 {
            interval = adjust_interval(interval);
        }
        assert!(interval <= MAX_INTERVAL_NS, "should not go above MAX: got {}", interval);
    }

    #[test]
    fn test_adjust_interval_converges() {
        DYNAMIC_RATE_ENABLED.store(true, Ordering::Relaxed);
        OVERHEAD_TARGET_BPS.store(200, Ordering::Relaxed); // 2%
        SAMPLE_DURATION_EWMA_NS.store(100_000, Ordering::Relaxed); // 100µs

        // Start at 10ms interval, should converge near target
        let mut interval: u64 = 10_000_000;
        for _ in 0..200 {
            interval = adjust_interval(interval);
        }

        // At convergence: overhead = 100k / (100k + interval) ≈ 2%
        // => interval ≈ 100k * (10000/200 - 1) = 100k * 49 = 4.9ms
        let overhead = 100_000.0 / (100_000.0 + interval as f64);
        assert!(
            overhead < 0.025 && overhead > 0.015,
            "should converge near 2%, got {:.4} (interval={})",
            overhead, interval
        );
    }

    #[test]
    fn test_update_ewma_first_sample() {
        SAMPLE_DURATION_EWMA_NS.store(0, Ordering::Relaxed);
        // Simulate: first sample takes the raw value
        let prev = 0u64;
        let duration = 50_000u64;
        let new_ewma = if prev == 0 { duration } else { (prev * 7 + duration) / 8 };
        assert_eq!(new_ewma, 50_000);
    }

    #[test]
    fn test_update_ewma_smoothing() {
        // EWMA with α=1/8: heavily smoothed
        let prev = 100_000u64;
        let duration = 20_000u64;
        let new_ewma = (prev * 7 + duration) / 8;
        assert_eq!(new_ewma, 90_000); // 100k * 7/8 + 20k * 1/8 = 87.5k + 2.5k = 90k
    }
}
