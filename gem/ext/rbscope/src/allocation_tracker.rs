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
//   4. Resolve frame labels via rb_profile_frame_full_label()
//   5. Fire __rbscope_probe_ruby_alloc USDT probe
//
// The collector receives these as typed RubyAllocEvent and builds
// AllocationSample entries in the Capture proto.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU32, Ordering};

use crate::probes;
use crate::stack::{InlineStack, InlineFrame};

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

    fn rb_profile_frame_full_label(frame: rb_sys::VALUE) -> rb_sys::VALUE;
    fn rb_profile_frame_path(frame: rb_sys::VALUE) -> rb_sys::VALUE;
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

    let _ = std::panic::catch_unwind(|| {
        on_newobj_event_inner(val);
    });

    IN_ALLOC_CALLBACK.store(false, Ordering::Release);
}

unsafe fn on_newobj_event_inner(val: rb_sys::VALUE) {
    let obj_type = builtin_type(val);
    let object_type = ruby_type_name(obj_type);

    // Estimate object size. We can't call rb_obj_memsize_of() during NEWOBJ
    // (it may trigger allocations). Use the RVALUE slot size (40 bytes on
    // 64-bit) as the baseline — every Ruby object occupies at least one slot.
    // For types that commonly have extra heap data, add a conservative estimate.
    let size: u64 = match obj_type {
        0x05 => 80,  // T_STRING — slot + typical small string heap buffer
        0x07 => 72,  // T_ARRAY — slot + embedded capacity (usually 3 elements)
        0x08 => 96,  // T_HASH — slot + st_table overhead
        _    => 40,  // RVALUE slot size (minimum for any object)
    };

    // Capture Ruby call stack — just the raw frame VALUEs + lines.
    // We CANNOT call rb_profile_frame_full_label here because it
    // allocates Ruby Strings which trigger re-entrant NEWOBJ events.
    // Instead, serialize frame IPs for the BPF collector to resolve.
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

    // Resolve frame labels ONE AT A TIME, checking the reentrancy guard
    // is still ours after each call (rb_profile_frame_full_label allocates).
    let mut stack = InlineStack::new();
    for i in 0..nf {
        // rb_profile_frame_full_label allocates a Ruby String, which fires
        // NEWOBJ → our callback → reentrancy guard blocks it → returns.
        // The returned VALUE is safe to read because it's fully initialized.
        let label_val = rb_profile_frame_full_label(frame_buf[i]);
        let label = ruby_value_to_string(label_val);

        let path_val = rb_profile_frame_path(frame_buf[i]);
        let path = ruby_value_to_string(path_val);

        let line = if line_buf[i] > 0 { line_buf[i] as u32 } else { 0 };
        stack.frames.push(InlineFrame { label, path, line });
    }

    // Serialize and fire the USDT probe
    let mut buf = Vec::with_capacity(stack.serialized_size().min(MAX_STACK_BYTES));
    if stack.serialize(&mut buf).is_ok() && buf.len() <= MAX_STACK_BYTES {
        probes::fire_ruby_alloc(&object_type, size, &buf);
        ALLOC_SAMPLED.fetch_add(1, Ordering::Relaxed);
    }
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

/// Convert a Ruby VALUE string to a Rust String.
/// Reads the RString struct directly to avoid calling any Ruby C API
/// functions that might trigger allocations during NEWOBJ events.
///
/// RString layout (64-bit): { RBasic(16), union { heap{len(8), ptr(8), ...}, embed{ary[]} } }
/// STR_NOEMBED flag (bit 13) indicates heap vs embedded string.
unsafe fn ruby_value_to_string(value: rb_sys::VALUE) -> String {
    if value == rb_sys::Qnil as rb_sys::VALUE
        || value == rb_sys::Qfalse as rb_sys::VALUE
        || value == 0
    {
        return "(unknown)".to_string();
    }

    if value & 0x07 != 0 {
        return "(unknown)".to_string();
    }

    let flags = *(value as *const usize);
    // Check T_STRING (type bits [4:0] == 0x05)
    if flags & 0x1f != 0x05 {
        return "(unknown)".to_string();
    }

    // RBasic is 16 bytes (flags + klass). RString union starts at offset 16.
    let base = value as *const u8;

    // STR_NOEMBED = FL_USER1 = (1 << 13). If set, string is on heap.
    const STR_NOEMBED: usize = 1 << 13;

    let (ptr, len): (*const u8, usize) = if flags & STR_NOEMBED != 0 {
        // Heap string: offset 16 = len (long), offset 24 = ptr (*char)
        let len = *(base.add(16) as *const isize) as usize;
        let ptr = *(base.add(24) as *const *const u8);
        (ptr, len)
    } else {
        // Embedded string: length is in flags bits [19:15] (Ruby 3.3+/4.0).
        // EMBED_LEN_SHIFT = 15, EMBED_LEN_MASK = 0x1F (5 bits)
        let len = (flags >> 15) & 0x1f;
        let ptr = base.add(16); // data starts right after RBasic
        (ptr, len)
    };

    if ptr.is_null() || len > 10_000 {
        return "(unknown)".to_string();
    }

    let bytes = std::slice::from_raw_parts(ptr, len);
    String::from_utf8_lossy(bytes).into_owned()
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
