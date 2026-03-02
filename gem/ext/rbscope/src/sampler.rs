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
// TODO(phase1.3): Wire up actual rb_postponed_job and rb_profile_thread_frames
// via rb-sys FFI. For now, this implements the threading/lifecycle management
// with stub stack capture.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::probes;

static RUNNING: AtomicBool = AtomicBool::new(false);
static SAMPLE_COUNT: AtomicU64 = AtomicU64::new(0);
// Track the PID that started the sampler. After fork, the child has a
// different PID and should consider the sampler as not running.
static OWNER_PID: AtomicU32 = AtomicU32::new(0);

struct SamplerState {
    thread_handle: Option<thread::JoinHandle<()>>,
}

static SAMPLER: Mutex<Option<SamplerState>> = Mutex::new(None);

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
        return Err(magnus::Error::new(
            magnus::exception::arg_error(),
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
            magnus::Error::new(
                magnus::exception::runtime_error(),
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
    while RUNNING.load(Ordering::SeqCst) {
        thread::sleep(interval);

        if !RUNNING.load(Ordering::SeqCst) {
            break;
        }

        // TODO(phase1.3): Replace with actual rb_postponed_job_trigger()
        // For now, simulate a sample capture:
        // 1. Trigger postponed job → Ruby VM calls our callback at safe point
        // 2. Callback calls rb_profile_thread_frames() for each thread
        // 3. Serialize stack frames to binary format
        // 4. Fire ruby_sample USDT probe with serialized data
        capture_sample_stub();
    }
}

fn capture_sample_stub() {
    // Stub: increment counter and fire probe with empty stack.
    // This validates the threading and lifecycle management works
    // before we wire up real rb_profile_thread_frames.
    SAMPLE_COUNT.fetch_add(1, Ordering::Relaxed);

    let empty_stack: &[u8] = &[];
    let thread_id: u64 = 0;
    let timestamp_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    probes::fire_ruby_sample(empty_stack, thread_id, timestamp_ns);
}
