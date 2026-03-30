// Native allocation tracker for rbscope.
//
// Hooks into Ruby's internal NEWOBJ event via rb_add_event_hook2 to
// capture allocation sites with full Ruby call stacks. Uses counter-based
// sampling (default 1:256) to keep overhead under budget.
//
// Architecture:
//   1. rb_add_event_hook2(RUBY_INTERNAL_EVENT_NEWOBJ, callback, ...)
//   2. On every Nth allocation: capture stack via rb_profile_frames()
//   3. Get object type from RBasic flags (builtin_type)
//   4. Serialize raw frame VALUE pointers + line numbers (format v3)
//   5. Fire __rbscope_probe_ruby_alloc USDT probe
//
// Frame labels are NOT resolved in the gem — the collector resolves
// them via /proc/pid/mem using the same FrameResolver as BPF mode.
// This follows the pattern used by Vernier and StackProf: store raw
// VALUE pointers during NEWOBJ, resolve labels elsewhere.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU32, Ordering};

use crate::probes;

// ---------------------------------------------------------------------------
// FFI declarations
// ---------------------------------------------------------------------------

// Event flag for RUBY_INTERNAL_EVENT_NEWOBJ
// In Ruby source: include/ruby/internal/event.h
// RUBY_INTERNAL_EVENT_NEWOBJ = 0x100000
const RUBY_INTERNAL_EVENT_NEWOBJ: rb_sys::rb_event_flag_t = 0x100000;

extern "C" {
    fn rb_add_event_hook2(
        func: unsafe extern "C" fn(
            data: rb_sys::VALUE,
            arg: *const std::ffi::c_void, // const rb_trace_arg_t *
        ),
        events: rb_sys::rb_event_flag_t,
        data: rb_sys::VALUE,
        flags: rb_sys::rb_event_hook_flag_t,
    );

    fn rb_remove_event_hook_with_data(
        func: unsafe extern "C" fn(
            data: rb_sys::VALUE,
            arg: *const std::ffi::c_void,
        ),
        data: rb_sys::VALUE,
    ) -> std::os::raw::c_int;

    fn rb_tracearg_object(arg: *const std::ffi::c_void) -> rb_sys::VALUE;

    fn rb_profile_frames(
        start: std::os::raw::c_int,
        limit: std::os::raw::c_int,
        buff: *mut rb_sys::VALUE,
        lines: *mut std::os::raw::c_int,
    ) -> std::os::raw::c_int;
}


/// Maximum number of Ruby frames to capture per allocation.
const MAX_FRAMES: usize = 128; // Allocation stacks tend to be shallower than CPU stacks.

/// Maximum serialized stack size.
const MAX_STACK_BYTES: usize = 16384;

/// Ruby type mask: lower 5 bits of RBasic::flags hold the builtin type.
/// Equivalent to RB_BUILTIN_TYPE(obj) = (flags & T_MASK).
const RUBY_T_MASK: usize = 0x1f;

/// Extract the builtin type from a heap-allocated Ruby VALUE.
/// Reads `((struct RBasic*)val)->flags & 0x1f`.
/// Caller must ensure val is a valid heap pointer (not immediate, not 0/nil/false).
#[inline]
unsafe fn builtin_type(val: rb_sys::VALUE) -> i32 {
    let flags = *(val as *const usize);
    (flags & RUBY_T_MASK) as i32
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

static ALLOC_TRACKING_ENABLED: AtomicBool = AtomicBool::new(false);
/// Total allocations seen (including unsampled).
static ALLOC_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Sampled allocations (probe fired).
static ALLOC_SAMPLED: AtomicU64 = AtomicU64::new(0);
/// Sample interval (fire probe every Nth allocation).
static SAMPLE_INTERVAL: AtomicU32 = AtomicU32::new(256);
/// Reentrancy guard — prevents recursive sampling when stack extraction
/// triggers allocations (e.g., rb_class_name creates a Ruby String).
static IN_ALLOC_CALLBACK: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// NEWOBJ callback
// ---------------------------------------------------------------------------

/// Safety: called by the Ruby VM on every object allocation.
/// With RUBY_EVENT_HOOK_FLAG_RAW_ARG, Ruby calls the function with the
/// signature `(VALUE data, const rb_trace_arg_t *arg)` — NOT the standard
/// 5-arg rb_event_hook_func_t. Use rb_tracearg_object(arg) to get the
/// newly allocated object.
unsafe extern "C" fn on_newobj_event(
    _data: rb_sys::VALUE,
    arg: *const std::ffi::c_void,
) {
    // Bail immediately if tracking is disabled — this check must come
    // first since the hook stays registered and fires on every allocation.
    if !ALLOC_TRACKING_ENABLED.load(Ordering::Relaxed) {
        return;
    }

    // Hot path: increment counter and skip if not our sampling tick.
    let total = ALLOC_TOTAL.fetch_add(1, Ordering::Relaxed);
    let interval = SAMPLE_INTERVAL.load(Ordering::Relaxed) as u64;
    if interval == 0 || !total.is_multiple_of(interval) {
        return;
    }

    // Reentrancy guard
    if IN_ALLOC_CALLBACK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return;
    }

    // Get the newly allocated object from the trace arg
    let val = rb_tracearg_object(arg);

    // Guard: rb_tracearg_object can return 0 (NULL) for internal allocations
    // in Ruby 4.0 where the object isn't fully registered yet.
    if val == 0 || val == rb_sys::Qfalse as rb_sys::VALUE {
        IN_ALLOC_CALLBACK.store(false, Ordering::Release);
        return;
    }

    let _ = std::panic::catch_unwind(|| {
        on_newobj_event_inner(val);
    });

    IN_ALLOC_CALLBACK.store(false, Ordering::Release);
}

/// Stack format version byte for raw frame addresses (format v3).
/// Layout: [u8: version=3][u16: num_frames][per frame: u64 value + i32 line]
const RAW_FORMAT_VERSION: u8 = 3;

unsafe fn on_newobj_event_inner(val: rb_sys::VALUE) {
    // Validate that val looks like a heap pointer before dereferencing.
    // Immediate VALUEs (Fixnum, Symbol, true/false/nil) have low bits set
    // and should never appear here, but guard anyway.
    if val & 0x07 != 0 || val < 0x1000 {
        return;
    }

    let obj_type = builtin_type(val);
    let object_type = ruby_type_name(obj_type);

    // Estimate object size based on type.
    let size: u64 = match obj_type {
        0x05 => 80,  // T_STRING
        0x07 => 72,  // T_ARRAY
        0x08 => 96,  // T_HASH
        _    => 40,  // RVALUE slot size
    };

    // Capture Ruby call stack — raw frame VALUEs + line numbers.
    // rb_profile_frames is cheap (~µs) — it just walks the CFP chain
    // without allocating any Ruby objects.
    let mut frame_buf: [rb_sys::VALUE; MAX_FRAMES] = [0; MAX_FRAMES];
    let mut line_buf: [std::os::raw::c_int; MAX_FRAMES] = [0; MAX_FRAMES];

    let num_frames = rb_profile_frames(
        0,
        MAX_FRAMES as std::os::raw::c_int,
        frame_buf.as_mut_ptr(),
        line_buf.as_mut_ptr(),
    );

    if num_frames <= 0 {
        return;
    }

    let nf = num_frames as usize;

    // Serialize raw frame addresses in format v3.
    // The collector resolves these via /proc/pid/mem using FrameResolver,
    // the same path BPF mode uses for iseq addresses.
    // Layout: [version:u8][num_frames:u16][frame_value:u64 + line:i32] × N
    let buf_size = 3 + nf * 12;
    if buf_size > MAX_STACK_BYTES {
        return;
    }
    let mut buf = Vec::with_capacity(buf_size);
    buf.push(RAW_FORMAT_VERSION);
    buf.extend_from_slice(&(nf as u16).to_le_bytes());
    for i in 0..nf {
        buf.extend_from_slice(&(frame_buf[i] as u64).to_le_bytes());
        buf.extend_from_slice(&(line_buf[i] as i32).to_le_bytes());
    }

    probes::fire_ruby_alloc(&object_type, size, &buf);
    ALLOC_SAMPLED.fetch_add(1, Ordering::Relaxed);
}

/// Map Ruby T_xxx type constants to human-readable names.
fn ruby_type_name(t: i32) -> String {
    match t {
        0x00 => "T_NONE",
        0x01 => "T_OBJECT",
        0x02 => "T_CLASS",
        0x03 => "T_MODULE",
        0x04 => "T_FLOAT",
        0x05 => "T_STRING",
        0x06 => "T_REGEXP",
        0x07 => "T_ARRAY",
        0x08 => "T_HASH",
        0x09 => "T_STRUCT",
        0x0a => "T_BIGNUM",
        0x0b => "T_FILE",
        0x0c => "T_DATA",
        0x0d => "T_MATCH",
        0x0e => "T_COMPLEX",
        0x0f => "T_RATIONAL",
        0x1a => "T_SYMBOL",
        0x1b => "T_IMEMO",
        0x1c => "T_ICLASS",
        _ => "(unknown)",
    }
    .to_string()
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Start allocation tracking with the given sample interval.
/// Fires __rbscope_probe_ruby_alloc for every Nth allocation.
///
/// Must be called from the Ruby main thread.
///
/// @param sample_interval [Integer] Track every Nth allocation (1=all, 256=default)
pub fn start_allocation_tracking(sample_interval: u32) -> Result<bool, magnus::Error> {
    if ALLOC_TRACKING_ENABLED.load(Ordering::Relaxed) {
        return Ok(false); // already running
    }

    let interval = if sample_interval == 0 { 256 } else { sample_interval };
    SAMPLE_INTERVAL.store(interval, Ordering::Relaxed);
    ALLOC_TOTAL.store(0, Ordering::Relaxed);
    ALLOC_SAMPLED.store(0, Ordering::Relaxed);
    IN_ALLOC_CALLBACK.store(false, Ordering::Relaxed);
    ALLOC_TRACKING_ENABLED.store(true, Ordering::Relaxed);

    // Register the internal event hook with SAFE | RAW_ARG flags.
    // RUBY_EVENT_HOOK_FLAG_RAW_ARG makes Ruby call with (VALUE data, const rb_trace_arg_t *)
    // RUBY_EVENT_HOOK_FLAG_SAFE marks this hook as safe to call during GC
    // Combined value: SAFE(1) | RAW_ARG(4) = 5
    unsafe {
        rb_add_event_hook2(
            on_newobj_event,
            RUBY_INTERNAL_EVENT_NEWOBJ,
            rb_sys::Qnil as rb_sys::VALUE,
            std::mem::transmute::<i32, rb_sys::rb_event_hook_flag_t>(5), // SAFE | RAW_ARG
        );
    }

    Ok(true)
}

/// Stop allocation tracking and return the number of sampled allocations.
pub fn stop_allocation_tracking() -> u64 {
    if !ALLOC_TRACKING_ENABLED.load(Ordering::Relaxed) {
        return 0;
    }

    ALLOC_TRACKING_ENABLED.store(false, Ordering::Relaxed);

    unsafe {
        rb_remove_event_hook_with_data(
            on_newobj_event,
            rb_sys::Qnil as rb_sys::VALUE,
        );
    }

    ALLOC_SAMPLED.load(Ordering::Relaxed)
}

/// Return allocation tracking statistics.
pub fn allocation_stats() -> (u64, u64, u32) {
    (
        ALLOC_TOTAL.load(Ordering::Relaxed),
        ALLOC_SAMPLED.load(Ordering::Relaxed),
        SAMPLE_INTERVAL.load(Ordering::Relaxed),
    )
}

/// Check if allocation tracking is active.
pub fn allocation_tracking_enabled() -> bool {
    ALLOC_TRACKING_ENABLED.load(Ordering::Relaxed)
}
