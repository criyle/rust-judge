//! Go trace v2 writer for Rust server activity.
//!
//! Tokio's task-poll hooks provide the actual start and end of scheduled task
//! polls. HTTP and workload spans add request-level context. Tokio tasks are
//! not presented as Go goroutines. When enabled, Tokio's measured
//! runnable-queue delay is recorded, but this does not reconstruct all
//! scheduler state or wake relationships.

use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    sync::{
        Arc, LazyLock, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};

const EVENT_BATCH: u8 = 1;
const EVENT_STRINGS: u8 = 4;
const EVENT_STRING: u8 = 5;
const EVENT_FREQUENCY: u8 = 8;
const EVENT_PROC_START: u8 = 10;
const EVENT_PROC_STOP: u8 = 11;
const EVENT_PROC_STATUS: u8 = 13;
const EVENT_GO_START: u8 = 16;
const EVENT_GO_DESTROY: u8 = 17;
const EVENT_GO_STATUS: u8 = 25;
const EVENT_USER_TASK_BEGIN: u8 = 40;
const EVENT_USER_TASK_END: u8 = 41;
const EVENT_SYNC: u8 = 50;
const EVENT_CLOCK_SNAPSHOT: u8 = 51;
const EVENT_END_OF_GENERATION: u8 = 52;
const TRACE_FREQUENCY: u64 = 1_000_000_000;

static ACTIVE_CAPTURE: LazyLock<Mutex<Option<Arc<Mutex<Capture>>>>> =
    LazyLock::new(|| Mutex::new(None));
static CAPTURE_ENABLED: AtomicBool = AtomicBool::new(false);
static NEXT_SPAN_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_RUNTIME_ID: AtomicU64 = AtomicU64::new(1);
static ACTIVE_TASK_POLL_SPANS: AtomicU64 = AtomicU64::new(0);
static TRACK_SCHEDULE_LATENCY: AtomicBool = AtomicBool::new(false);

std::thread_local! {
    static TASK_POLL_SPAN: RefCell<Option<ActiveTaskPollSpan>> = const { RefCell::new(None) };
}

#[derive(Clone, Debug)]
struct Span {
    id: u64,
    parent_id: u64,
    name: String,
    start_ns: u64,
    end_ns: u64,
}

#[derive(Debug)]
struct Capture {
    started: Instant,
    wall_started: SystemTime,
    mono_started_ns: u64,
    spans: Vec<Span>,
    tokio_tasks: HashMap<String, TokioTaskSpan>,
}

#[derive(Debug)]
struct TokioTaskSpan {
    span_id: u64,
    active_polls: usize,
    terminated: bool,
}

pub struct CaptureGuard {
    capture: Arc<Mutex<Capture>>,
    active: bool,
}

pub struct SpanGuard {
    capture: Arc<Mutex<Capture>>,
    id: u64,
    start_ns: u64,
}

struct ActiveTaskPollSpan {
    span: Option<SpanGuard>,
    task_key: Option<String>,
}

impl Drop for ActiveTaskPollSpan {
    fn drop(&mut self) {
        drop(self.span.take());
        if let Some(task_key) = self.task_key.as_deref() {
            task_poll_finished(task_key);
        }
        ACTIVE_TASK_POLL_SPANS.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Install callbacks that record real Tokio task-poll intervals during an
/// active trace capture. Tokio exposes these callbacks behind its
/// `tokio_unstable` cfg, so callers outside this workspace retain the
/// request-level spans without the scheduler hooks.
pub fn install_task_poll_hooks(builder: &mut tokio::runtime::Builder) {
    install_task_poll_hooks_with_schedule_latency(
        builder,
        TRACK_SCHEDULE_LATENCY.load(Ordering::Acquire),
    );
}

/// Install task hooks without asking Tokio to measure runnable-queue delay.
/// This is used by the Criterion ablation to isolate that measurement cost.
#[doc(hidden)]
pub fn install_task_poll_hooks_without_schedule_latency(builder: &mut tokio::runtime::Builder) {
    install_task_poll_hooks_with_schedule_latency(builder, false);
}

/// Install task hooks and enable Tokio's measured runnable-queue delay.
/// Runtime construction pays the measurement cost even when no trace is active,
/// so production enables this only when debug profiling is requested.
#[doc(hidden)]
pub fn install_task_poll_hooks_with_schedule_latency(
    builder: &mut tokio::runtime::Builder,
    enabled: bool,
) {
    install_task_poll_hooks_mode(builder, enabled);
}

/// Enable or disable schedule-latency tracking for subsequently built runtimes.
pub fn set_schedule_latency_enabled(enabled: bool) {
    TRACK_SCHEDULE_LATENCY.store(enabled, Ordering::Release);
}

fn install_task_poll_hooks_mode(
    builder: &mut tokio::runtime::Builder,
    track_schedule_latency: bool,
) {
    #[cfg(tokio_unstable)]
    {
        #[cfg(target_pointer_width = "64")]
        if track_schedule_latency {
            builder.track_task_schedule_latency();
        }
        let runtime_id = NEXT_RUNTIME_ID.fetch_add(1, Ordering::Relaxed);
        builder
            .on_task_spawn(move |meta| {
                let location = meta.spawned_at();
                task_spawned(
                    runtime_id,
                    format!("{:?}", meta.id()),
                    format!("{}:{}", location.file(), location.line()),
                );
            })
            .on_before_task_poll(move |meta| {
                #[cfg(target_pointer_width = "64")]
                if track_schedule_latency && let Some(latency) = meta.schedule_latency() {
                    task_schedule_latency(runtime_id, format!("{:?}", meta.id()), latency);
                }
                task_poll_begin(runtime_id, format!("{:?}", meta.id()))
            })
            .on_after_task_poll(|_| task_poll_end())
            .on_task_terminate(move |meta| task_terminated(runtime_id, format!("{:?}", meta.id())));
    }
    #[cfg(not(tokio_unstable))]
    let _ = (builder, track_schedule_latency);
}

#[cfg(all(tokio_unstable, target_pointer_width = "64"))]
fn task_schedule_latency(runtime_id: u64, task_id: String, latency: std::time::Duration) {
    if !CAPTURE_ENABLED.load(Ordering::Acquire) || latency.is_zero() {
        return;
    }
    let Some(capture) = active_capture() else {
        return;
    };
    let mut capture = capture.lock().unwrap_or_else(|error| error.into_inner());
    let key = task_key(runtime_id, &task_id);
    let Some(parent_id) = capture.tokio_tasks.get(&key).map(|task| task.span_id) else {
        return;
    };
    let end_ns = capture.started.elapsed().as_nanos().min(u64::MAX as u128) as u64;
    let latency_ns = latency.as_nanos().min(u64::MAX as u128) as u64;
    let start_ns = end_ns.saturating_sub(latency_ns);
    let id = NEXT_SPAN_ID.fetch_add(1, Ordering::Relaxed);
    capture.spans.push(Span {
        id,
        parent_id,
        name: format!("Tokio task schedule latency {task_id}"),
        start_ns,
        end_ns,
    });
}

fn task_key(runtime_id: u64, task_id: &str) -> String {
    format!("{runtime_id}:{task_id}")
}

fn task_spawned(runtime_id: u64, task_id: String, location: String) {
    if !CAPTURE_ENABLED.load(Ordering::Acquire) {
        return;
    }
    let Some(capture) = active_capture() else {
        return;
    };
    let mut capture = capture.lock().unwrap_or_else(|error| error.into_inner());
    let start_ns = capture.started.elapsed().as_nanos().min(u64::MAX as u128) as u64;
    let id = NEXT_SPAN_ID.fetch_add(1, Ordering::Relaxed);
    capture.spans.push(Span {
        id,
        parent_id: 0,
        name: format!("Tokio task {task_id} ({location})"),
        start_ns,
        end_ns: 0,
    });
    capture.tokio_tasks.insert(
        task_key(runtime_id, &task_id),
        TokioTaskSpan {
            span_id: id,
            active_polls: 0,
            terminated: false,
        },
    );
}

fn task_terminated(runtime_id: u64, task_id: String) {
    if !CAPTURE_ENABLED.load(Ordering::Acquire) {
        return;
    }
    let Some(capture) = active_capture() else {
        return;
    };
    let mut capture = capture.lock().unwrap_or_else(|error| error.into_inner());
    let key = task_key(runtime_id, &task_id);
    let Some(task) = capture.tokio_tasks.get_mut(&key) else {
        return;
    };
    if task.active_polls > 0 {
        task.terminated = true;
        return;
    }
    let id = task.span_id;
    capture.tokio_tasks.remove(&key);
    let end_ns = capture.started.elapsed().as_nanos().min(u64::MAX as u128) as u64;
    if let Some(span) = capture.spans.iter_mut().find(|span| span.id == id) {
        span.end_ns = end_ns.max(span.start_ns);
    }
}

fn task_poll_begin(runtime_id: u64, task_id: String) {
    if !CAPTURE_ENABLED.load(Ordering::Acquire) {
        return;
    }
    let key = task_key(runtime_id, &task_id);
    let parent_id = active_capture().and_then(|capture| {
        let capture = capture.lock().unwrap_or_else(|error| error.into_inner());
        capture.tokio_tasks.get(&key).map(|task| task.span_id)
    });
    let span = SpanGuard::start_nested(
        format!("Tokio task poll {task_id}"),
        parent_id.unwrap_or_default(),
    )
    .map(|span| {
        if parent_id.is_some() {
            task_poll_started(&key);
        }
        ACTIVE_TASK_POLL_SPANS.fetch_add(1, Ordering::AcqRel);
        ActiveTaskPollSpan {
            span: Some(span),
            task_key: parent_id.map(|_| key),
        }
    });
    TASK_POLL_SPAN.with(|active| {
        let previous = active.replace(span);
        drop(previous);
    });
}

fn task_poll_started(task_key: &str) {
    let Some(capture) = active_capture() else {
        return;
    };
    if let Some(task) = capture
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .tokio_tasks
        .get_mut(task_key)
    {
        task.active_polls += 1;
    }
}

fn task_poll_finished(task_key: &str) {
    if !CAPTURE_ENABLED.load(Ordering::Acquire) {
        return;
    }
    let Some(capture) = active_capture() else {
        return;
    };
    let mut capture = capture.lock().unwrap_or_else(|error| error.into_inner());
    let Some(task) = capture.tokio_tasks.get_mut(task_key) else {
        return;
    };
    task.active_polls = task.active_polls.saturating_sub(1);
    if task.active_polls == 0 && task.terminated {
        let id = task.span_id;
        capture.tokio_tasks.remove(task_key);
        let end_ns = capture.started.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        if let Some(span) = capture.spans.iter_mut().find(|span| span.id == id) {
            span.end_ns = end_ns.max(span.start_ns);
        }
    }
}

fn task_poll_end() {
    if !CAPTURE_ENABLED.load(Ordering::Acquire)
        && ACTIVE_TASK_POLL_SPANS.load(Ordering::Acquire) == 0
    {
        return;
    }
    TASK_POLL_SPAN.with(|active| drop(active.replace(None)));
}

fn active_capture() -> Option<Arc<Mutex<Capture>>> {
    ACTIVE_CAPTURE
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .as_ref()
        .cloned()
}

impl CaptureGuard {
    pub fn start() -> Option<Self> {
        let mut active = ACTIVE_CAPTURE
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if active.is_some() {
            return None;
        }
        let capture = Arc::new(Mutex::new(Capture {
            started: Instant::now(),
            wall_started: SystemTime::now(),
            mono_started_ns: monotonic_ns(),
            spans: Vec::new(),
            tokio_tasks: HashMap::new(),
        }));
        *active = Some(capture.clone());
        CAPTURE_ENABLED.store(true, Ordering::Release);
        Some(Self {
            capture,
            active: true,
        })
    }

    pub fn finish(mut self) -> Vec<u8> {
        self.clear_active();
        let mut capture = self
            .capture
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let end_ns = capture.started.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        for span in &mut capture.spans {
            if span.end_ns == 0 {
                span.end_ns = end_ns.max(span.start_ns);
            }
        }
        encode_trace(&capture)
    }

    fn clear_active(&mut self) {
        if !self.active {
            return;
        }
        let mut active = ACTIVE_CAPTURE
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if active
            .as_ref()
            .is_some_and(|capture| Arc::ptr_eq(capture, &self.capture))
        {
            *active = None;
            CAPTURE_ENABLED.store(false, Ordering::Release);
        }
        self.active = false;
    }
}

impl Drop for CaptureGuard {
    fn drop(&mut self) {
        self.clear_active();
    }
}

impl SpanGuard {
    pub fn start(name: impl Into<String>) -> Option<Self> {
        Self::start_nested(name, 0)
    }

    fn start_nested(name: impl Into<String>, parent_id: u64) -> Option<Self> {
        if !CAPTURE_ENABLED.load(Ordering::Acquire) {
            return None;
        }
        let capture = ACTIVE_CAPTURE
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()?
            .clone();
        let capture_state = capture.lock().unwrap_or_else(|error| error.into_inner());
        let start_ns = capture_state
            .started
            .elapsed()
            .as_nanos()
            .min(u64::MAX as u128) as u64;
        drop(capture_state);
        let name = name.into();
        let id = NEXT_SPAN_ID.fetch_add(1, Ordering::Relaxed);
        capture
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .spans
            .push(Span {
                id,
                parent_id,
                name: name.clone(),
                start_ns,
                end_ns: 0,
            });
        Some(Self {
            capture,
            id,
            start_ns,
        })
    }
}

impl Drop for SpanGuard {
    fn drop(&mut self) {
        let mut capture = self
            .capture
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let end_ns = capture.started.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        if let Some(span) = capture.spans.iter_mut().find(|span| span.id == self.id) {
            span.end_ns = end_ns.max(self.start_ns);
        }
    }
}

fn encode_trace(capture: &Capture) -> Vec<u8> {
    let mut out = b"go 1.26 trace\0\0\0".to_vec();
    let wall = capture
        .wall_started
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let wall_secs = wall.as_secs();
    let wall_nanos = wall.subsec_nanos() as u64;
    let base_time = 1u64;

    let mut sync = vec![EVENT_SYNC];
    push_event(&mut sync, EVENT_FREQUENCY, &[TRACE_FREQUENCY]);
    push_event(
        &mut sync,
        EVENT_CLOCK_SNAPSHOT,
        &[1, capture.mono_started_ns.max(1), wall_secs, wall_nanos],
    );
    push_batch(&mut out, u64::MAX, base_time, &sync);

    let mut strings = BTreeMap::<String, u64>::new();
    for span in &capture.spans {
        let next_id = strings.len() as u64 + 1;
        strings.entry(span.name.clone()).or_insert(next_id);
    }
    if !strings.is_empty() {
        let mut table = vec![EVENT_STRINGS];
        for (name, id) in &strings {
            table.push(EVENT_STRING);
            put_varint(&mut table, *id);
            put_varint(&mut table, name.len() as u64);
            table.extend_from_slice(name.as_bytes());
        }
        push_batch(&mut out, u64::MAX, base_time + 1, &table);
    }

    let mut spans = capture.spans.clone();
    spans.sort_by_key(|span| (span.start_ns, span.id));
    let mut events = Vec::new();
    let mut last_time = base_time + 2;
    push_event(
        &mut events,
        EVENT_PROC_STATUS,
        &[next_delta(&mut last_time, 1), 0, 2],
    );
    push_event(
        &mut events,
        EVENT_PROC_START,
        &[next_delta(&mut last_time, 1), 0, 1],
    );
    push_event(
        &mut events,
        EVENT_GO_STATUS,
        &[next_delta(&mut last_time, 1), 1, 1, 1],
    );
    push_event(
        &mut events,
        EVENT_GO_START,
        &[next_delta(&mut last_time, 1), 1, 1],
    );

    let mut timeline = Vec::with_capacity(spans.len() * 2);
    for span in spans {
        timeline.push((span.start_ns, true, span.clone()));
        timeline.push((span.end_ns, false, span));
    }
    timeline.sort_by_key(|(time, is_start, span)| (*time, !*is_start, span.id));
    for (time, is_start, span) in timeline {
        let delta = next_delta(&mut last_time, base_time + 2 + time);
        if is_start {
            let name_id = strings.get(&span.name).copied().unwrap_or_default();
            push_event(
                &mut events,
                EVENT_USER_TASK_BEGIN,
                &[delta, span.id, span.parent_id, name_id, 0],
            );
        } else {
            // Go's UserTaskEnd carries a stack ID, while the corresponding
            // UserTaskBegin is the event that carries the parent task ID.
            push_event(&mut events, EVENT_USER_TASK_END, &[delta, span.id, 0]);
        }
    }

    let destroy_time = last_time.saturating_add(1);
    push_event(
        &mut events,
        EVENT_GO_DESTROY,
        &[next_delta(&mut last_time, destroy_time)],
    );
    let stop_time = last_time.saturating_add(1);
    push_event(
        &mut events,
        EVENT_PROC_STOP,
        &[next_delta(&mut last_time, stop_time)],
    );
    push_batch(&mut out, 1, base_time + 2, &events);
    out.push(EVENT_END_OF_GENERATION);
    out
}

fn next_delta(previous: &mut u64, timestamp: u64) -> u64 {
    let timestamp = timestamp.max(previous.saturating_add(1));
    let delta = timestamp - *previous;
    *previous = timestamp;
    delta
}

fn push_batch(out: &mut Vec<u8>, m: u64, time: u64, payload: &[u8]) {
    out.push(EVENT_BATCH);
    put_varint(out, 1); // generation
    put_varint(out, m);
    put_varint(out, time);
    put_varint(out, payload.len() as u64);
    out.extend_from_slice(payload);
}

fn push_event(out: &mut Vec<u8>, event: u8, args: &[u64]) {
    out.push(event);
    for arg in args {
        put_varint(out, *arg);
    }
}

fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn monotonic_ns() -> u64 {
    #[cfg(target_os = "linux")]
    {
        let mut timespec = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `timespec` points to writable storage and CLOCK_MONOTONIC
        // is a valid Linux clock identifier.
        if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut timespec) } == 0 {
            return (timespec.tv_sec as u64)
                .saturating_mul(1_000_000_000)
                .saturating_add(timespec.tv_nsec as u64);
        }
    }
    1
}

#[cfg(test)]
mod tests {
    use super::{
        Capture, CaptureGuard, EVENT_END_OF_GENERATION, Span, encode_trace,
        install_task_poll_hooks_with_schedule_latency,
    };
    use std::{
        collections::HashMap,
        time::{Instant, SystemTime},
    };

    #[test]
    fn emits_go_trace_v2_with_balanced_rust_task_spans() {
        let capture = Capture {
            started: Instant::now(),
            wall_started: SystemTime::now(),
            mono_started_ns: 1,
            spans: vec![Span {
                id: 7,
                parent_id: 0,
                name: "HTTP GET /version".into(),
                start_ns: 10,
                end_ns: 20,
            }],
            tokio_tasks: HashMap::new(),
        };
        let trace = encode_trace(&capture);
        assert!(trace.starts_with(b"go 1.26 trace\0\0\0"));
        assert!(
            trace
                .windows(b"HTTP GET /version".len())
                .any(|window| { window == b"HTTP GET /version" })
        );
        assert_eq!(trace.last(), Some(&EVENT_END_OF_GENERATION));
    }

    #[test]
    fn captures_actual_tokio_task_poll_intervals() {
        let mut builder = tokio::runtime::Builder::new_current_thread();
        builder.enable_all();
        install_task_poll_hooks_with_schedule_latency(&mut builder, true);
        let runtime = builder.build().unwrap();
        let capture = CaptureGuard::start().expect("trace capture should be available");

        let task_id = runtime.block_on(async {
            let task = tokio::spawn(async {
                tokio::task::yield_now().await;
            });
            let task_id = format!("{:?}", task.id());
            task.await.unwrap();
            task_id
        });

        {
            let capture = capture
                .capture
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let task = capture
                .spans
                .iter()
                .find(|span| span.name.starts_with(&format!("Tokio task {task_id} (")))
                .expect("spawn hook should record the Tokio task lifetime");
            let polls = capture
                .spans
                .iter()
                .filter(|span| span.name == format!("Tokio task poll {task_id}"))
                .collect::<Vec<_>>();
            assert!(polls.len() >= 2, "yielded task should be polled repeatedly");
            assert!(polls.iter().all(|poll| poll.parent_id == task.id));
            assert!(polls.iter().all(|poll| poll.end_ns <= task.end_ns));
            #[cfg(target_pointer_width = "64")]
            {
                let queue_waits = capture
                    .spans
                    .iter()
                    .filter(|span| span.name == format!("Tokio task schedule latency {task_id}"))
                    .collect::<Vec<_>>();
                assert!(
                    !queue_waits.is_empty(),
                    "Tokio should report runnable-queue latency for the yielded task"
                );
                assert!(queue_waits.iter().all(|wait| wait.parent_id == task.id));
                assert!(queue_waits.iter().all(|wait| wait.end_ns <= task.end_ns));
            }
        }

        let trace = capture.finish();
        assert!(
            trace
                .windows(b"Tokio task poll Id(".len())
                .any(|window| { window.starts_with(b"Tokio task poll Id(") })
        );
    }
}
