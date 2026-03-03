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

    if ptr.is_null() || len < 0 || len > 10_000 {
        return "(unknown)".to_string();
    }

    let bytes = std::slice::from_raw_parts(ptr as *const u8, len as usize);
    String::from_utf8_lossy(bytes).into_owned()
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

    RUNNING.store(true, Ordering::SeqCst);
    OWNER_PID.store(std::process::id(), Ordering::Relaxed);
    probes::set_probes_enabled(true);
    SAMPLE_COUNT.store(0, Ordering::Relaxed);

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

    while RUNNING.load(Ordering::SeqCst) {
        thread::sleep(interval);

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
    }
}
