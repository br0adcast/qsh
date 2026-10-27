//! Frame storage measurement for the client's presentation path.
//!
//! Drives a `Session` through fixed workloads and reports, per presented
//! step, heap allocations (calls, bytes and grid-sized ones), the live heap
//! retained between steps and its peak inside a step, and the elapsed and
//! thread CPU time of each step. It is a measurement procedure, not a test:
//! it sets no thresholds. The method and recorded results are in
//! docs/performance-baseline.md, under "Frame storage reuse".
//!
//!   cargo run --release -p qsh --example frame_storage -- [--time] [WORKLOAD...]
//!
//! Without `--time` every allocation is counted and steps are not timed.
//! With it, counting is off and only time per step is reported: elapsed
//! (monotonic clock, descheduled time included) and CPU time of the thread
//! running the session. Output is one JSON object per workload on stdout.
//! The `idle` workload presents nothing and measures the recorder itself.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use qsh::session::{Action, Chrome, Session, UiEvent};
use transport::channel_geometry::{ChannelInstance, GeometryOutcome, GeometryRecord};
use transport::shell_frame::{encode_record, REC_DATA};

struct Counting;

static COUNTING: AtomicBool = AtomicBool::new(false);
static CALLS: AtomicUsize = AtomicUsize::new(0);
static BYTES: AtomicUsize = AtomicUsize::new(0);
static GRID_CALLS: AtomicUsize = AtomicUsize::new(0);
static GRID_BYTES: AtomicUsize = AtomicUsize::new(usize::MAX);
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grew(size: usize) {
    if !COUNTING.load(Ordering::Relaxed) {
        return;
    }
    CALLS.fetch_add(1, Ordering::Relaxed);
    BYTES.fetch_add(size, Ordering::Relaxed);
    if size >= GRID_BYTES.load(Ordering::Relaxed) {
        GRID_CALLS.fetch_add(1, Ordering::Relaxed);
    }
}

fn live_add(size: usize) {
    if COUNTING.load(Ordering::Relaxed) {
        let live = LIVE.fetch_add(size, Ordering::Relaxed) + size;
        PEAK.fetch_max(live, Ordering::Relaxed);
    }
}

fn live_sub(size: usize) {
    if COUNTING.load(Ordering::Relaxed) {
        LIVE.fetch_sub(size, Ordering::Relaxed);
    }
}

// The live count is exact only for blocks allocated while counting; the
// counter is switched on once, before the session is built, and stays on.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            grew(layout.size());
            live_add(layout.size());
        }
        pointer
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            grew(layout.size());
            live_add(layout.size());
        }
        pointer
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(pointer, layout, size) };
        if !moved.is_null() {
            grew(size);
            live_sub(layout.size());
            live_add(size);
        }
        moved
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        live_sub(layout.size());
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// One workload: a session of a given physical size, a preparation, and the
/// event of each measured step.
struct Workload {
    name: &'static str,
    cols: u16,
    rows: u16,
    steps: usize,
    prepare: fn(&mut Bench),
    step: fn(&mut Bench, usize) -> Vec<Action>,
}

struct Bench {
    session: Session,
    now: i64,
    cols: u16,
    rows: u16,
    request: u64,
    instance: ChannelInstance,
}

impl Bench {
    fn new(cols: u16, rows: u16) -> Bench {
        let mut session = Session::new(
            cols,
            rows,
            render::TermCaps::truecolor(),
            qsh::args::PredictMode::Never,
            Chrome {
                prefix: qsh::escape::DEFAULT_PREFIX,
                line: true,
                glyphs: qsh::window::Glyphs {
                    utf8: true,
                    colour: true,
                },
            },
        );
        session.handle(UiEvent::Link(transport::LinkState::Live), 0);
        session.on_channel_ready(16, 0);
        let mut bench = Bench {
            session,
            now: 1,
            cols,
            rows,
            request: 0,
            instance: ChannelInstance::new(1).expect("instance"),
        };
        bench.geometry(cols, rows);
        bench
    }

    fn tick(&mut self) -> i64 {
        self.now += 1;
        self.now
    }

    /// Apply the shell size a `cols` x `rows` display with a status line gets.
    fn geometry(&mut self, cols: u16, rows: u16) -> Vec<Action> {
        let (shell_cols, shell_rows) = qsh::session::shell_size(cols, rows, true);
        let outcome = if self.request == 0 {
            GeometryOutcome::Established
        } else {
            GeometryOutcome::Applied
        };
        let record = GeometryRecord {
            instance: self.instance,
            request_id: self.request,
            outcome,
            cols: shell_cols,
            rows: shell_rows,
        };
        self.request += 1;
        let now = self.tick();
        self.session.on_geometry(record, now)
    }

    fn output(&mut self, bytes: &[u8]) -> Vec<Action> {
        let now = self.tick();
        self.session
            .handle(UiEvent::Stream0(encode_record(REC_DATA, bytes)), now)
    }

    fn keys(&mut self, bytes: &[u8]) -> Vec<Action> {
        let input = qsh::input_ingress::IngressBudget::default()
            .admit_slice(bytes)
            .expect("admitted input");
        let now = self.tick();
        self.session.handle(UiEvent::Stdin(input), now)
    }

    fn shell_cols(&self) -> usize {
        usize::from(qsh::session::shell_size(self.cols, self.rows, true).0)
    }

    fn shell_rows(&self) -> usize {
        usize::from(qsh::session::shell_size(self.cols, self.rows, true).1)
    }
}

fn line(n: usize, width: usize) -> String {
    let mut text = format!("{n:06} \x1b[3{}m", n % 8);
    while text.len() < width {
        text.push_str("lorem ipsum dolor sit amet ");
    }
    text.truncate(width.saturating_sub(1));
    text.push_str("\x1b[0m\r\n");
    text
}

/// A full-screen redraw, as a full-screen application sends one.
fn screen(bench: &Bench, step: usize, combining: bool) -> Vec<u8> {
    let (cols, rows) = (bench.shell_cols(), bench.shell_rows());
    let mut text = String::from("\x1b[H");
    for row in 0..rows {
        text.push_str(&format!(
            "\x1b[{};1H\x1b[38;5;{}m",
            row + 1,
            (row + step) % 256
        ));
        for col in 0..cols {
            let base = char::from(b'a' + ((row + col + step) % 26) as u8);
            text.push(base);
            if combining {
                // Four marks per cell, varied so every step changes them.
                for mark in 0..4 {
                    let offset = ((col + mark + step) % 0x30) as u32;
                    text.push(char::from_u32(0x0300 + offset).expect("combining mark"));
                }
            }
        }
    }
    text.push_str("\x1b[0m");
    text.into_bytes()
}

fn prepare_nothing(_: &mut Bench) {}

/// The bookkeeping control: a step that does no work, so every figure it
/// reports is the recorder's own.
fn step_idle(_: &mut Bench, _: usize) -> Vec<Action> {
    Vec::new()
}

/// Fill the screen, so every measured line scrolls it.
fn prepare_full(bench: &mut Bench) {
    let (width, rows) = (bench.shell_cols(), bench.shell_rows());
    let text: String = (0..rows).map(|n| line(1_000_000 + n, width)).collect();
    bench.output(text.as_bytes());
}

fn step_stream(bench: &mut Bench, step: usize) -> Vec<Action> {
    let width = bench.shell_cols();
    bench.output(line(step, width).as_bytes())
}

fn step_echo(bench: &mut Bench, step: usize) -> Vec<Action> {
    let byte = [b'a' + (step % 26) as u8];
    if step % 40 == 39 {
        bench.output(b"\r\n$ ")
    } else {
        bench.output(&byte)
    }
}

fn prepare_alternate(bench: &mut Bench) {
    bench.output(b"\x1b[?1049h");
}

fn step_alternate(bench: &mut Bench, step: usize) -> Vec<Action> {
    let bytes = screen(bench, step, false);
    bench.output(&bytes)
}

fn step_combining(bench: &mut Bench, step: usize) -> Vec<Action> {
    let bytes = screen(bench, step, true);
    bench.output(&bytes)
}

fn prepare_history(bench: &mut Bench) {
    let width = bench.shell_cols();
    for chunk in 0..20 {
        let text: String = (0..100).map(|n| line(chunk * 100 + n, width)).collect();
        bench.output(text.as_bytes());
    }
    bench.keys(b"\x1d[");
}

fn step_history(bench: &mut Bench, step: usize) -> Vec<Action> {
    // Page up four times, then down four times, within 2,000 lines.
    if step % 8 < 4 {
        bench.keys(b"\x1b[5~")
    } else {
        bench.keys(b"\x1b[6~")
    }
}

fn step_resize(bench: &mut Bench, step: usize) -> Vec<Action> {
    let (cols, rows) = if step.is_multiple_of(2) {
        (160, 40)
    } else {
        (200, 50)
    };
    bench.cols = cols;
    bench.rows = rows;
    let now = bench.tick();
    let mut actions = bench.session.handle(UiEvent::Resized { cols, rows }, now);
    actions.extend(bench.geometry(cols, rows));
    let width = bench.shell_cols();
    actions.extend(bench.output(line(step, width).as_bytes()));
    actions
}

const WORKLOADS: &[Workload] = &[
    Workload {
        name: "idle",
        cols: 200,
        rows: 50,
        steps: 400,
        prepare: prepare_nothing,
        step: step_idle,
    },
    Workload {
        name: "stream-80x24",
        cols: 80,
        rows: 24,
        steps: 400,
        prepare: prepare_full,
        step: step_stream,
    },
    Workload {
        name: "stream-200x50",
        cols: 200,
        rows: 50,
        steps: 400,
        prepare: prepare_full,
        step: step_stream,
    },
    Workload {
        name: "stream-512x257",
        cols: 512,
        rows: 257,
        steps: 100,
        prepare: prepare_full,
        step: step_stream,
    },
    Workload {
        name: "append-512x257",
        cols: 512,
        rows: 257,
        steps: 100,
        prepare: prepare_nothing,
        step: step_stream,
    },
    Workload {
        name: "echo-200x50",
        cols: 200,
        rows: 50,
        steps: 400,
        prepare: prepare_nothing,
        step: step_echo,
    },
    Workload {
        name: "alternate-200x50",
        cols: 200,
        rows: 50,
        steps: 200,
        prepare: prepare_alternate,
        step: step_alternate,
    },
    Workload {
        name: "alternate-512x257",
        cols: 512,
        rows: 257,
        steps: 40,
        prepare: prepare_alternate,
        step: step_alternate,
    },
    Workload {
        name: "combining-200x50",
        cols: 200,
        rows: 50,
        steps: 100,
        prepare: prepare_alternate,
        step: step_combining,
    },
    Workload {
        name: "history-200x50",
        cols: 200,
        rows: 50,
        steps: 200,
        prepare: prepare_history,
        step: step_history,
    },
    Workload {
        name: "resize-200x50",
        cols: 200,
        rows: 50,
        steps: 100,
        prepare: prepare_nothing,
        step: step_resize,
    },
];

/// Steps run before measuring, so caches and retained buffers settle.
const WARMUP: usize = 16;

/// FNV-1a over everything written to the terminal: equal hashes mean equal
/// output, so two builds can be checked for identical presentation.
fn fnv(hash: &mut u64, actions: &[Action]) -> (usize, usize) {
    let (mut writes, mut bytes) = (0, 0);
    for action in actions {
        if let Action::Write(data) = action {
            writes += 1;
            bytes += data.len();
            for byte in data {
                *hash ^= u64::from(*byte);
                *hash = hash.wrapping_mul(0x0100_0000_01b3);
            }
        }
    }
    (writes, bytes)
}

/// CPU time consumed by the calling thread, which runs the whole session.
fn thread_cpu() -> Duration {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `now` is a valid, writable timespec for the call.
    let status = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut now) };
    assert_eq!(status, 0, "thread CPU clock");
    Duration::new(now.tv_sec as u64, now.tv_nsec as u32)
}

/// `VmRSS` and `VmHWM` of this process in KiB, where `/proc` has them. Run
/// one workload per process for the high-water mark to be that workload's.
fn process_memory() -> (Option<u64>, Option<u64>) {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|rest| rest.trim().trim_end_matches("kB").trim().parse().ok())
    };
    (field("VmRSS:"), field("VmHWM:"))
}

/// What one measured step allocated and left live, read from the counters
/// as soon as the step returned.
#[derive(Clone, Copy)]
struct Sample {
    calls: usize,
    bytes: usize,
    grids: usize,
    peak_above: usize,
    retained: usize,
}

fn run(workload: &Workload, timed: bool) -> serde_json::Value {
    let cell = size_of::<terminal::Cell>();
    let (shell_cols, shell_rows) = qsh::session::shell_size(workload.cols, workload.rows, true);
    let smallest_grid = if workload.name.starts_with("resize") {
        let (cols, rows) = qsh::session::shell_size(160, 40, true);
        usize::from(cols) * usize::from(rows)
    } else {
        usize::from(shell_cols) * usize::from(shell_rows)
    };
    GRID_BYTES.store(smallest_grid * cell, Ordering::Relaxed);
    COUNTING.store(!timed, Ordering::Relaxed);
    // The recorder's storage exists before the baseline and never grows, so
    // no step's counts and no retained figure include it.
    let mut samples = Vec::with_capacity(workload.steps);
    let base = LIVE.load(Ordering::Relaxed);

    let mut bench = Bench::new(workload.cols, workload.rows);
    (workload.prepare)(&mut bench);
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for step in 0..WARMUP {
        let actions = (workload.step)(&mut bench, step);
        fnv(&mut hash, &actions);
    }

    let (mut writes, mut written) = (0usize, 0usize);
    let (mut elapsed, mut cpu) = (Duration::ZERO, Duration::ZERO);
    for step in WARMUP..WARMUP + workload.steps {
        CALLS.store(0, Ordering::Relaxed);
        BYTES.store(0, Ordering::Relaxed);
        GRID_CALLS.store(0, Ordering::Relaxed);
        let before = LIVE.load(Ordering::Relaxed);
        PEAK.store(before, Ordering::Relaxed);
        let (wall, thread) = (Instant::now(), thread_cpu());
        let actions = (workload.step)(&mut bench, step);
        let spent = thread_cpu() - thread;
        let passed = wall.elapsed();
        // Every counter is read before anything is recorded.
        let sample = Sample {
            calls: CALLS.load(Ordering::Relaxed),
            bytes: BYTES.load(Ordering::Relaxed),
            grids: GRID_CALLS.load(Ordering::Relaxed),
            peak_above: PEAK.load(Ordering::Relaxed).saturating_sub(before),
            retained: 0,
        };
        elapsed += passed;
        cpu += spent;
        let (w, b) = fnv(&mut hash, &actions);
        writes += w;
        written += b;
        drop(actions);
        let retained = LIVE.load(Ordering::Relaxed).saturating_sub(base);
        samples.push(Sample { retained, ..sample });
    }
    let (rss_kib, hwm_kib) = process_memory();
    drop(bench);
    COUNTING.store(false, Ordering::Relaxed);

    let steps = workload.steps as f64;
    let mean = |pick: fn(&Sample) -> usize| samples.iter().map(pick).sum::<usize>() as f64 / steps;
    let max = |pick: fn(&Sample) -> usize| samples.iter().map(pick).max().unwrap_or(0);
    let mut result = serde_json::json!({
        "workload": workload.name,
        "cols": workload.cols,
        "rows": workload.rows,
        "steps": workload.steps,
        "cell_bytes": cell,
        "grid_bytes": usize::from(shell_cols) * usize::from(shell_rows) * cell,
        "writes": writes,
        "written_bytes": written,
        "output_fnv1a": format!("{hash:016x}"),
        "vm_rss_kib": rss_kib,
        "vm_hwm_kib": hwm_kib,
    });
    let fields = result.as_object_mut().expect("object");
    if timed {
        fields.insert(
            "elapsed_us_per_step".into(),
            (elapsed.as_secs_f64() * 1e6 / steps).into(),
        );
        fields.insert(
            "thread_cpu_us_per_step".into(),
            (cpu.as_secs_f64() * 1e6 / steps).into(),
        );
    } else {
        fields.insert("alloc_calls_per_step".into(), mean(|s| s.calls).into());
        fields.insert("alloc_bytes_per_step".into(), mean(|s| s.bytes).into());
        fields.insert("grid_allocs_per_step".into(), mean(|s| s.grids).into());
        fields.insert("grid_allocs_max_step".into(), max(|s| s.grids).into());
        let last = samples.last().map_or(0, |s| s.retained);
        fields.insert("retained_bytes_last".into(), last.into());
        fields.insert("retained_bytes_max".into(), max(|s| s.retained).into());
        fields.insert(
            "step_peak_above_live_bytes".into(),
            max(|s| s.peak_above).into(),
        );
    }
    result
}

fn main() {
    let mut timed = false;
    let mut names = Vec::new();
    for arg in std::env::args().skip(1) {
        if arg == "--time" {
            timed = true;
        } else {
            names.push(arg);
        }
    }
    for workload in WORKLOADS {
        if names.is_empty() || names.iter().any(|name| name == workload.name) {
            println!("{}", run(workload, timed));
        }
    }
}
