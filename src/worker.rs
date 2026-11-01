//! Core request and file descriptors from go-judge's `worker` package.
use crate::envexec::{self, File as ExecFile};
use crate::filestore::LocalFileStore;
use crate::runner::Size;
use std::fmt;
use std::fs::File;
use std::io::{self, Cursor, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc,
};
use std::time::Duration;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TerminalSize {
    pub rows: u16,
    pub cols: u16,
    pub x: u16,
    pub y: u16,
}

#[derive(Clone, Debug)]
pub enum CmdFile {
    Local(PathBuf),
    Memory(Vec<u8>),
    Null,
    Cached(String),
    Collector {
        name: String,
        max: Size,
        pipe: bool,
    },
    StreamIn(Arc<Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>>),
    StreamOut {
        index: u32,
        fd: u32,
        tx: tokio::sync::mpsc::Sender<StreamOutput>,
    },
}

#[derive(Clone, Debug)]
pub struct StreamOutput {
    pub index: u32,
    pub fd: u32,
    pub content: Vec<u8>,
}

impl CmdFile {
    pub fn open_input(&self, store: &LocalFileStore) -> io::Result<InputFile> {
        match self {
            Self::Local(p) => File::open(p).map(InputFile::File),
            Self::Memory(b) => Ok(InputFile::Memory(Cursor::new(b.clone()))),
            Self::Null => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "null command file",
            )),
            Self::Cached(id) => store
                .get(id)
                .map(|(_, f)| InputFile::File(f))
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("file does not exist with id {id:?}"),
                    )
                }),
            Self::Collector { name, max, pipe } => Ok(InputFile::Collector {
                name: name.clone(),
                max: *max,
                pipe: *pipe,
            }),
            Self::StreamIn(_) | Self::StreamOut { .. } => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "stream command files are only valid for execution",
            )),
        }
    }

    /// Convert a request file to the corresponding envexec file descriptor source.
    pub fn env_file(&self, store: &LocalFileStore) -> io::Result<ExecFile> {
        match self {
            Self::Local(path) => Ok(ExecFile::input(path)),
            Self::Memory(bytes) => Ok(ExecFile::reader(Cursor::new(bytes.clone()))),
            Self::Null => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "null command file",
            )),
            Self::Cached(id) => store
                .get(id)
                .map(|(_, file)| ExecFile::opened(file))
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("file does not exist with id {id:?}"),
                    )
                }),
            Self::Collector { name, max, pipe } => {
                Ok(ExecFile::collector(name.clone(), *max, *pipe))
            }
            Self::StreamIn(rx) => Ok(ExecFile::stream_reader(StreamInputReader {
                rx: rx.clone(),
                current: Cursor::new(Vec::new()),
            })),
            Self::StreamOut { index, fd, tx } => Ok(ExecFile::writer(
                StreamOutputWriter {
                    index: *index,
                    fd: *fd,
                    tx: tx.clone(),
                },
                Size(u64::MAX),
            )),
        }
    }
}
impl fmt::Display for CmdFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local(p) => write!(f, "local:{}", p.display()),
            Self::Memory(b) => write!(f, "memory:(len:{})", b.len()),
            Self::Null => write!(f, "<nil>"),
            Self::Cached(id) => write!(f, "cached:(fileId:{id})"),
            Self::Collector { name, max, pipe } => {
                write!(f, "collector:(name:{name},max:{},pipe:{pipe})", max.0)
            }
            Self::StreamIn(_) => f.write_str("stream-in"),
            Self::StreamOut { .. } => f.write_str("stream-out"),
        }
    }
}

struct StreamInputReader {
    rx: Arc<Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>>,
    current: Cursor<Vec<u8>>,
}
impl io::Read for StreamInputReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        loop {
            let n = self.current.read(output)?;
            if n > 0 {
                return Ok(n);
            }
            let next = self.rx.lock().unwrap().blocking_recv();
            match next {
                Some(bytes) => self.current = Cursor::new(bytes),
                None => return Ok(0),
            }
        }
    }
}
struct StreamOutputWriter {
    index: u32,
    fd: u32,
    tx: tokio::sync::mpsc::Sender<StreamOutput>,
}
impl io::Write for StreamOutputWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        self.tx
            .blocking_send(StreamOutput {
                index: self.index,
                fd: self.fd,
                content: bytes.to_vec(),
            })
            .map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "stream output receiver closed")
            })?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub enum InputFile {
    File(File),
    Memory(Cursor<Vec<u8>>),
    Collector { name: String, max: Size, pipe: bool },
}

#[derive(Clone, Debug, Default)]
pub struct Command {
    pub args: Vec<String>,
    pub env: Vec<String>,
    pub files: Vec<CmdFile>,
    pub cpu_limit: Duration,
    pub clock_limit: Duration,
    pub memory_limit: Size,
    pub stack_limit: Size,
    pub output_limit: Size,
    pub proc_limit: u64,
    pub open_file_limit: u64,
    pub cpu_rate_limit: u64,
    pub cpu_set_limit: String,
    pub copy_in: std::collections::HashMap<String, CmdFile>,
    pub symlinks: std::collections::HashMap<String, String>,
    pub copy_out: Vec<CopyOutFile>,
    pub copy_out_cached: Vec<CopyOutFile>,
    pub copy_out_max: u64,
    pub copy_out_truncate: bool,
    pub tty: bool,
    pub terminal_resize: Option<Arc<Mutex<mpsc::Receiver<TerminalSize>>>>,
    pub data_segment_limit: bool,
    pub address_space_limit: bool,
}

#[derive(Clone, Debug, Default)]
pub struct CopyOutFile {
    pub name: String,
    pub optional: bool,
}
#[derive(Clone, Debug, Default)]
pub struct PipeIndex {
    pub index: usize,
    pub fd: usize,
}
#[derive(Clone, Debug, Default)]
pub struct PipeMap {
    pub input: PipeIndex,
    pub output: PipeIndex,
    pub cpu_set: String,
    pub name: String,
    pub limit: Size,
    pub proxy: bool,
    pub disable_zero_copy: bool,
}
#[derive(Clone, Debug, Default)]
pub struct Request {
    pub request_id: String,
    pub commands: Vec<Command>,
    pub pipe_mapping: Vec<PipeMap>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(i32)]
pub enum JudgeStatus {
    #[default]
    Invalid,
    Accepted,
    WrongAnswer,
    PartiallyCorrect,
    MemoryLimitExceeded,
    TimeLimitExceeded,
    OutputLimitExceeded,
    FileError,
    NonzeroExitStatus,
    Signalled,
    DangerousSyscall,
    JudgementFailed,
    InvalidInteraction,
    InternalError,
}
impl JudgeStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Invalid => "Invalid",
            Self::Accepted => "Accepted",
            Self::WrongAnswer => "Wrong Answer",
            Self::PartiallyCorrect => "Partially Correct",
            Self::MemoryLimitExceeded => "Memory Limit Exceeded",
            Self::TimeLimitExceeded => "Time Limit Exceeded",
            Self::OutputLimitExceeded => "Output Limit Exceeded",
            Self::FileError => "File Error",
            Self::NonzeroExitStatus => "Nonzero Exit Status",
            Self::Signalled => "Signalled",
            Self::DangerousSyscall => "Dangerous Syscall",
            Self::JudgementFailed => "Judgement Failed",
            Self::InvalidInteraction => "Invalid Interaction",
            Self::InternalError => "Internal Error",
        }
    }
}
impl fmt::Display for JudgeStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Default)]
pub struct ResultInfo {
    pub status: JudgeStatus,
    pub exit_order: usize,
    pub exit_status: i32,
    pub error: String,
    pub time: Duration,
    pub run_time: Duration,
    pub memory: Size,
    pub proc_peak: u64,
    pub files: std::collections::HashMap<String, File>,
    pub file_ids: std::collections::HashMap<String, String>,
    pub file_errors: Vec<envexec::FileError>,
}
#[derive(Debug, Default)]
pub struct Response {
    pub request_id: String,
    pub results: Vec<ResultInfo>,
    pub error: Option<String>,
}

/// Defaults passed from the worker configuration into one environment command.
#[derive(Clone, Debug, Default)]
pub struct ExecDefaults {
    pub extra_memory_limit: Size,
    pub output_limit: Size,
    pub copy_out_limit: Size,
    pub open_file_limit: u64,
    pub cpu_set: String,
}

impl Command {
    /// Prepare file sources and effective limits using the same precedence as Go worker.prepareCmd.
    pub fn prepare_envexec(
        &self,
        environment: Arc<dyn envexec::Environment>,
        store: &LocalFileStore,
        defaults: &ExecDefaults,
        pipe_names: &std::collections::HashSet<String>,
    ) -> io::Result<envexec::Cmd> {
        let mut files = Vec::with_capacity(self.files.len());
        for file in &self.files {
            files.push(match file {
                CmdFile::Null => None,
                other => Some(other.env_file(store)?),
            });
        }
        let mut copy_in = std::collections::HashMap::with_capacity(self.copy_in.len());
        for (name, file) in &self.copy_in {
            copy_in.insert(name.clone(), file.env_file(store)?);
        }
        let mut copy_out = Vec::new();
        copy_out.extend(
            self.copy_out
                .iter()
                .filter(|f| !pipe_names.contains(&f.name))
                .map(|f| envexec::CmdCopyOutFile {
                    name: f.name.clone(),
                    optional: f.optional,
                }),
        );
        copy_out.extend(
            self.copy_out_cached
                .iter()
                .filter(|f| !pipe_names.contains(&f.name))
                .map(|f| envexec::CmdCopyOutFile {
                    name: f.name.clone(),
                    optional: f.optional,
                }),
        );
        let copy_out_max = if self.copy_out_max > 0 {
            Size(self.copy_out_max)
        } else {
            defaults.copy_out_limit
        };
        let output_limit = if self.output_limit.0 > 0 {
            self.output_limit
        } else {
            defaults.output_limit
        };
        let open_file_limit = if self.open_file_limit > 0 {
            self.open_file_limit
        } else {
            defaults.open_file_limit
        };
        let cpu_set_limit = if self.cpu_set_limit.is_empty() {
            defaults.cpu_set.clone()
        } else {
            self.cpu_set_limit.clone()
        };
        Ok(envexec::Cmd {
            environment,
            copy_in,
            symlinks: self.symlinks.clone(),
            args: self.args.clone(),
            env: self.env.clone(),
            files,
            tty: self.tty,
            terminal_resize: self.terminal_resize.clone(),
            time_limit: self.cpu_limit,
            clock_limit: self.clock_limit,
            memory_limit: self.memory_limit,
            stack_limit: self.stack_limit,
            extra_memory_limit: defaults.extra_memory_limit,
            output_limit,
            proc_limit: self.proc_limit,
            open_file_limit,
            cpu_rate_limit: self.cpu_rate_limit,
            cpu_set_limit,
            copy_out,
            copy_out_max,
            copy_out_truncate: self.copy_out_truncate,
            address_space_limit: self.address_space_limit,
            data_segment_limit: self.data_segment_limit,
        })
    }
}

/// Polls a running process like Go's worker waiter. Returns true only when a CPU or wall limit fires.
pub fn wait_for_limits(
    process: &dyn envexec::Process,
    cpu_limit: Duration,
    clock_limit: Duration,
    tick_interval: Duration,
    cancelled: impl Fn() -> bool,
) -> bool {
    let clock_limit = if clock_limit.is_zero() {
        cpu_limit
    } else {
        clock_limit
    };
    let tick = if tick_interval.is_zero() {
        Duration::from_millis(100)
    } else {
        tick_interval
    };
    let start = std::time::Instant::now();
    loop {
        if cancelled() || process.done() {
            return false;
        }
        process.wait_timeout(tick);
        if start.elapsed() > clock_limit || process.usage().time > cpu_limit {
            return true;
        }
    }
}

/// Convert an envexec result, storing requested cached outputs and closing their local handles.
pub fn convert_result(
    mut result: envexec::CmdResult,
    cmd: &Command,
    store: &LocalFileStore,
) -> ResultInfo {
    let mut out = ResultInfo {
        status: result.status.into(),
        exit_order: result.exit_order,
        exit_status: result.exit_status,
        error: result.error,
        time: result.time,
        run_time: result.run_time,
        memory: result.memory,
        proc_peak: result.proc_peak,
        files: std::mem::take(&mut result.files),
        file_ids: Default::default(),
        file_errors: result.file_errors,
    };
    // Go reclassifies context cancellation as a signal if observed CPU and wall time remain below limits.
    if out.status == JudgeStatus::TimeLimitExceeded
        && out.exit_status != 0
        && out.time < cmd.cpu_limit
        && out.run_time < cmd.clock_limit
    {
        out.status = JudgeStatus::Signalled;
    }
    for requested in &cmd.copy_out_cached {
        let Some(file) = out.files.remove(&requested.name) else {
            continue;
        };
        let added = file.try_clone().and_then(|mut source| {
            source.seek(SeekFrom::Start(0))?;
            store.add_reader(requested.name.clone(), source)
        });
        match added {
            Ok(id) => {
                out.file_ids.insert(requested.name.clone(), id);
                drop(file);
            }
            Err(e) => {
                out.status = JudgeStatus::FileError;
                out.error = e.to_string();
                drop(file);
                for (_, remaining) in out.files.drain() {
                    drop(remaining);
                }
                break;
            }
        }
    }
    out
}
impl From<envexec::Status> for JudgeStatus {
    fn from(s: envexec::Status) -> Self {
        match s {
            envexec::Status::Accepted => Self::Accepted,
            envexec::Status::WrongAnswer => Self::WrongAnswer,
            envexec::Status::PartiallyCorrect => Self::PartiallyCorrect,
            envexec::Status::MemoryLimitExceeded => Self::MemoryLimitExceeded,
            envexec::Status::TimeLimitExceeded => Self::TimeLimitExceeded,
            envexec::Status::OutputLimitExceeded => Self::OutputLimitExceeded,
            envexec::Status::FileError => Self::FileError,
            envexec::Status::NonzeroExitStatus => Self::NonzeroExitStatus,
            envexec::Status::Signalled => Self::Signalled,
            envexec::Status::DangerousSyscall => Self::DangerousSyscall,
            envexec::Status::JudgementFailed => Self::JudgementFailed,
            envexec::Status::InvalidInteraction => Self::InvalidInteraction,
            envexec::Status::InternalError => Self::InternalError,
            envexec::Status::Invalid => Self::Invalid,
        }
    }
}

/// Environment lifecycle used by queued worker requests.
pub trait EnvironmentPool: Send + Sync + 'static {
    fn get(&self) -> io::Result<Arc<dyn envexec::Environment>>;
    fn put(&self, environment: Arc<dyn envexec::Environment>);
    fn destroy(&self) {}
}

async fn get_tracked_environment(
    pool: Arc<dyn EnvironmentPool>,
) -> io::Result<Arc<dyn envexec::Environment>> {
    tokio::task::spawn_blocking(move || {
        let environment = pool.get()?;
        crate::runtime_metrics::environment_acquired();
        Ok(environment)
    })
    .await
    .map_err(|error| io::Error::other(format!("environment acquisition task failed: {error}")))?
}

async fn put_tracked_environment(
    pool: Arc<dyn EnvironmentPool>,
    environment: Arc<dyn envexec::Environment>,
) {
    let _ = tokio::task::spawn_blocking(move || {
        pool.put(environment);
        crate::runtime_metrics::environment_released();
    })
    .await;
}

#[derive(Clone)]
pub struct WorkerConfig {
    pub file_store: LocalFileStore,
    pub environments: Arc<dyn EnvironmentPool>,
    pub parallelism: usize,
    pub queue_capacity: usize,
    pub defaults: ExecDefaults,
    pub cpu_sets: Vec<String>,
    pub tick_interval: Duration,
    pub exec_observer: Option<Arc<dyn Fn(&Response) + Send + Sync>>,
}
impl WorkerConfig {
    pub fn new(file_store: LocalFileStore, environments: Arc<dyn EnvironmentPool>) -> Self {
        Self {
            file_store,
            environments,
            parallelism: 1,
            queue_capacity: 512,
            defaults: ExecDefaults::default(),
            cpu_sets: Vec::new(),
            tick_interval: Duration::from_millis(100),
            exec_observer: None,
        }
    }
}

#[derive(Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);
impl CancellationToken {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

struct QueuedRequest {
    request: Request,
    cancellation: CancellationToken,
    started: mpsc::Sender<()>,
    response: tokio::sync::oneshot::Sender<Response>,
}
struct WorkerInner {
    config: WorkerConfig,
    sender: Mutex<Option<tokio::sync::mpsc::Sender<QueuedRequest>>>,
    started: AtomicBool,
    stopped: AtomicBool,
    queued: AtomicUsize,
    running: AtomicUsize,
    completions: Mutex<Vec<mpsc::Receiver<()>>>,
}
/// Bounded asynchronous worker with bypass-queue `execute` for interactive requests.
#[derive(Clone)]
pub struct AsyncWorker {
    inner: Arc<WorkerInner>,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WorkerStat {
    pub queue: usize,
    pub running: usize,
}
impl AsyncWorker {
    pub fn new(config: WorkerConfig) -> Self {
        Self {
            inner: Arc::new(WorkerInner {
                config,
                sender: Mutex::new(None),
                started: AtomicBool::new(false),
                stopped: AtomicBool::new(false),
                queued: AtomicUsize::new(0),
                running: AtomicUsize::new(0),
                completions: Mutex::new(Vec::new()),
            }),
        }
    }
    pub fn start(&self) -> io::Result<()> {
        if self.inner.stopped.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "worker is shut down",
            ));
        }
        let mut sender = self.inner.sender.lock().unwrap();
        if self.inner.stopped.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "worker is shut down",
            ));
        }
        if self.inner.started.load(Ordering::Acquire) {
            return Ok(());
        }
        let capacity = self.inner.config.queue_capacity;
        let (tx, rx) = tokio::sync::mpsc::channel::<QueuedRequest>(capacity.max(1));
        *sender = Some(tx);
        self.inner.started.store(true, Ordering::Release);
        let count = if self.inner.config.cpu_sets.is_empty() {
            self.inner.config.parallelism
        } else {
            self.inner.config.cpu_sets.len()
        };
        let receiver = Arc::new(tokio::sync::Mutex::new(rx));
        for i in 0..count {
            let inner = self.inner.clone();
            let receiver = receiver.clone();
            let cpuset = self
                .inner
                .config
                .cpu_sets
                .get(i)
                .cloned()
                .unwrap_or_default();
            let (done_tx, done_rx) = mpsc::channel();
            crate::tokio_runtime::runtime().handle().spawn(async move {
                worker_loop(inner, receiver, cpuset).await;
                let _ = done_tx.send(());
            });
            self.inner.completions.lock().unwrap().push(done_rx);
        }
        Ok(())
    }
    pub fn submit(
        &self,
        request: Request,
        cancellation: CancellationToken,
    ) -> (tokio::sync::oneshot::Receiver<Response>, mpsc::Receiver<()>) {
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        let (started_tx, started_rx) = mpsc::channel();
        let sender = self.inner.sender.lock().unwrap();
        if !self.inner.started.load(Ordering::Acquire) {
            send_immediate(
                started_tx,
                response_tx,
                request.request_id,
                "worker is not started",
            );
            return (response_rx, started_rx);
        }
        if self.inner.stopped.load(Ordering::Acquire) {
            send_immediate(
                started_tx,
                response_tx,
                request.request_id,
                "worker is shutting down",
            );
            return (response_rx, started_rx);
        }
        let Some(tx) = sender.as_ref() else {
            send_immediate(
                started_tx,
                response_tx,
                request.request_id,
                "worker is shutting down",
            );
            return (response_rx, started_rx);
        };
        self.inner.queued.fetch_add(1, Ordering::AcqRel);
        let queued = QueuedRequest {
            request,
            cancellation,
            started: started_tx,
            response: response_tx,
        };
        if let Err(error) = tx.try_send(queued) {
            self.inner.queued.fetch_sub(1, Ordering::AcqRel);
            let queued = match error {
                tokio::sync::mpsc::error::TrySendError::Full(q)
                | tokio::sync::mpsc::error::TrySendError::Closed(q) => q,
            };
            let text = if self.inner.stopped.load(Ordering::Acquire) {
                "worker is shutting down"
            } else {
                "worker queue is full"
            };
            let _ = queued.started.send(());
            let _ = queued.response.send(Response {
                request_id: queued.request.request_id,
                results: vec![],
                error: Some(text.into()),
            });
        }
        (response_rx, started_rx)
    }
    /// Runs immediately as a Tokio task, bypassing queue saturation and
    /// configured worker parallelism for interactive requests.
    pub fn execute(
        &self,
        request: Request,
        cancellation: CancellationToken,
    ) -> tokio::sync::oneshot::Receiver<Response> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut completions = self.inner.completions.lock().unwrap();
        if self.inner.stopped.load(Ordering::Acquire) || !self.inner.started.load(Ordering::Acquire)
        {
            let _ = tx.send(Response {
                request_id: request.request_id,
                results: vec![],
                error: Some("worker is not available".into()),
            });
            return rx;
        }
        let inner = self.inner.clone();
        let (done_tx, done_rx) = mpsc::channel();
        let _task = crate::tokio_runtime::runtime().handle().spawn(async move {
            inner.running.fetch_add(1, Ordering::AcqRel);
            let response = work_do_running(&inner, request, cancellation, String::new()).await;
            let _ = tx.send(response);
            let _ = done_tx.send(());
        });
        completions.push(done_rx);
        rx
    }
    pub fn stat(&self) -> WorkerStat {
        WorkerStat {
            queue: self.inner.queued.load(Ordering::Acquire),
            running: self.inner.running.load(Ordering::Acquire),
        }
    }
    /// Stops accepting queued work, drains accepted work and Tokio blocking
    /// tasks, then destroys the environment pool.
    pub fn shutdown(&self) {
        if self.inner.stopped.swap(true, Ordering::AcqRel) {
            return;
        }
        self.inner.sender.lock().unwrap().take();
        let completions = std::mem::take(&mut *self.inner.completions.lock().unwrap());
        for done in completions {
            let _ = done.recv();
        }
        self.inner.config.environments.destroy();
    }
}

fn send_immediate(
    started: mpsc::Sender<()>,
    response: tokio::sync::oneshot::Sender<Response>,
    request_id: String,
    message: &str,
) {
    let _ = started.send(());
    let _ = response.send(Response {
        request_id,
        results: vec![],
        error: Some(message.to_owned()),
    });
}

async fn worker_loop(
    inner: Arc<WorkerInner>,
    receiver: Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<QueuedRequest>>>,
    cpuset: String,
) {
    loop {
        let work = receiver.lock().await.recv().await;
        let Some(work) = work else {
            break;
        };
        inner.queued.fetch_sub(1, Ordering::AcqRel);
        let QueuedRequest {
            request,
            cancellation,
            started,
            response: response_tx,
        } = work;
        let response = if cancellation.is_cancelled() {
            let _ = started.send(());
            Response {
                request_id: request.request_id,
                results: vec![],
                error: Some("cancelled before execute".into()),
            }
        } else {
            let inner = inner.clone();
            let worker_cpuset = cpuset.clone();
            inner.running.fetch_add(1, Ordering::AcqRel);
            let _ = started.send(());
            work_do_running(&inner, request, cancellation, worker_cpuset).await
        };
        let _ = response_tx.send(response);
    }
}
async fn work_do_running(
    inner: &Arc<WorkerInner>,
    request: Request,
    cancellation: CancellationToken,
    cpuset: String,
) -> Response {
    let _trace_span = crate::runtime_trace::SpanGuard::start("go-judge execute");
    let mut response = execute_request(inner, &request, cancellation, cpuset).await;
    response.request_id = request.request_id;
    if let Some(observer) = &inner.config.exec_observer {
        observer(&response);
    }
    inner.running.fetch_sub(1, Ordering::AcqRel);
    response
}
async fn execute_request(
    inner: &Arc<WorkerInner>,
    request: &Request,
    cancellation: CancellationToken,
    cpuset: String,
) -> Response {
    if cancellation.is_cancelled() {
        return Response {
            request_id: request.request_id.clone(),
            results: vec![],
            error: Some("cancelled before execute".into()),
        };
    }
    let mut commands = Vec::with_capacity(request.commands.len());
    let mut environments = Vec::new();
    let mut defaults = inner.config.defaults.clone();
    // Go's worker always supplies its assigned cpuset as the command default.
    // This keeps every command in a group aligned with its proxy relay; an
    // explicit per-command CPUSetLimit still takes precedence in
    // `prepare_envexec`.
    defaults.cpu_set = cpuset.clone();
    for command in &request.commands {
        let environment = match get_tracked_environment(inner.config.environments.clone()).await {
            Ok(e) => e,
            Err(e) => {
                for environment in environments.drain(..) {
                    put_tracked_environment(inner.config.environments.clone(), environment).await;
                }
                return Response {
                    request_id: request.request_id.clone(),
                    results: std::iter::repeat_with(|| ResultInfo {
                        status: JudgeStatus::InternalError,
                        error: format!("failed to get environment {e}"),
                        ..Default::default()
                    })
                    .take(request.commands.len())
                    .collect(),
                    error: None,
                };
            }
        };
        match command.prepare_envexec(
            environment.clone(),
            &inner.config.file_store,
            &defaults,
            &proxy_pipe_names(&request.pipe_mapping, request.commands.len()),
        ) {
            Ok(cmd) => {
                commands.push(cmd);
                environments.push(environment);
            }
            Err(e) => {
                put_tracked_environment(inner.config.environments.clone(), environment).await;
                for e in environments.drain(..) {
                    put_tracked_environment(inner.config.environments.clone(), e).await;
                }
                return Response {
                    request_id: request.request_id.clone(),
                    results: vec![],
                    error: Some(e.to_string()),
                };
            }
        }
    }
    let store = inner.config.file_store.clone();
    let new_store: envexec::NewStoreFile = Arc::new(move || store.new_file().map(|(_, f)| f));
    if commands.len() == 1 {
        let cmd = commands.pop().unwrap();
        let environment = environments.pop().unwrap();
        let token = cancellation.clone();
        let single = envexec::Single {
            cmd,
            new_store_file: new_store,
        };
        let output = if crate::tokio_runtime::sync_command_wait_ablation_enabled() {
            tokio::task::spawn_blocking(move || {
                single.run_with_cancel(move || token.is_cancelled())
            })
            .await
            .unwrap_or_else(|error| {
                Err(io::Error::other(format!(
                    "synchronous command worker failed: {error}"
                )))
            })
        } else {
            single
                .run_with_cancel_async(move || token.is_cancelled())
                .await
        };
        put_tracked_environment(inner.config.environments.clone(), environment).await;
        return match output {
            Ok(result) => Response {
                request_id: request.request_id.clone(),
                results: vec![convert_result(
                    result,
                    &request.commands[0],
                    &inner.config.file_store,
                )],
                error: None,
            },
            Err(e) => Response {
                request_id: request.request_id.clone(),
                results: vec![],
                error: Some(e.to_string()),
            },
        };
    }
    let pipes = request
        .pipe_mapping
        .iter()
        .map(|p| envexec::PipeMapping {
            input: envexec::PipeIndex {
                index: p.input.index,
                fd: p.input.fd,
            },
            output: envexec::PipeIndex {
                index: p.output.index,
                fd: p.output.fd,
            },
            // Go overwrites the pipe's affinity with the worker-assigned CPU
            // set for the whole request group.
            cpu_set: cpuset.clone(),
            proxy: p.proxy,
            name: p.name.clone(),
            max: p.limit,
            disable_zero_copy: p.disable_zero_copy,
        })
        .collect();
    let token = cancellation.clone();
    let group = envexec::Group {
        commands,
        pipes,
        new_store_file: new_store,
    };
    let output = if crate::tokio_runtime::sync_command_wait_ablation_enabled() {
        tokio::task::spawn_blocking(move || group.run_with_cancel(move || token.is_cancelled()))
            .await
            .unwrap_or_else(|error| {
                Err(io::Error::other(format!(
                    "group worker task failed: {error}"
                )))
            })
    } else {
        group
            .run_with_cancel_async(move || token.is_cancelled())
            .await
    };
    for e in environments {
        put_tracked_environment(inner.config.environments.clone(), e).await;
    }
    match output {
        Ok(results) => Response {
            request_id: request.request_id.clone(),
            results: results
                .into_iter()
                .zip(&request.commands)
                .map(|(r, c)| convert_result(r, c, &inner.config.file_store))
                .collect(),
            error: None,
        },
        Err(e) => Response {
            request_id: request.request_id.clone(),
            results: vec![],
            error: Some(e.to_string()),
        },
    }
}
fn proxy_pipe_names(pipes: &[PipeMap], count: usize) -> std::collections::HashSet<String> {
    pipes
        .iter()
        .filter(|p| p.proxy && p.input.index < count)
        .map(|p| p.name.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    struct GateProcess(Arc<std::sync::atomic::AtomicBool>);
    impl envexec::Process for GateProcess {
        fn done(&self) -> bool {
            self.0.load(Ordering::Acquire)
        }
        fn result(&self) -> crate::runner::ResultInfo {
            crate::runner::ResultInfo {
                status: crate::runner::Status::Normal,
                ..Default::default()
            }
        }
        fn usage(&self) -> envexec::Usage {
            envexec::Usage::default()
        }
        fn cancel(&self) {
            self.0.store(true, Ordering::Release)
        }
    }
    struct GateEnv(Arc<std::sync::atomic::AtomicBool>);
    impl envexec::Environment for GateEnv {
        fn execve(&self, _: envexec::ExecveParam) -> io::Result<Box<dyn envexec::Process>> {
            Ok(Box::new(GateProcess(self.0.clone())))
        }
        fn open(&self, _: &[envexec::OpenParam]) -> io::Result<Vec<envexec::OpenResult>> {
            Ok(vec![])
        }
        fn symlink(&self, _: &[envexec::SymlinkParam]) -> io::Result<Vec<Option<String>>> {
            Ok(vec![])
        }
    }
    struct CancelProbeEnv {
        gate: Arc<AtomicBool>,
        process_started: std::sync::mpsc::SyncSender<()>,
    }
    impl envexec::Environment for CancelProbeEnv {
        fn execve(&self, _: envexec::ExecveParam) -> io::Result<Box<dyn envexec::Process>> {
            let process: Box<dyn envexec::Process> = Box::new(GateProcess(self.gate.clone()));
            let _ = self.process_started.send(());
            Ok(process)
        }
        fn open(&self, _: &[envexec::OpenParam]) -> io::Result<Vec<envexec::OpenResult>> {
            Ok(vec![])
        }
        fn symlink(&self, _: &[envexec::SymlinkParam]) -> io::Result<Vec<Option<String>>> {
            Ok(vec![])
        }
    }
    struct GatePool {
        env: Arc<dyn envexec::Environment>,
        destroyed: Arc<AtomicBool>,
    }
    impl EnvironmentPool for GatePool {
        fn get(&self) -> io::Result<Arc<dyn envexec::Environment>> {
            Ok(self.env.clone())
        }
        fn put(&self, _: Arc<dyn envexec::Environment>) {}
        fn destroy(&self) {
            self.destroyed.store(true, Ordering::Release)
        }
    }
    fn request(id: &str) -> Request {
        Request {
            request_id: id.into(),
            commands: vec![Command::default()],
            pipe_mapping: vec![],
        }
    }

    #[test]
    fn async_worker_signals_start_enforces_queue_capacity_and_drains_on_shutdown() {
        let dir = std::env::temp_dir().join(format!("worker-queue-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let gate = Arc::new(AtomicBool::new(false));
        let destroyed = Arc::new(AtomicBool::new(false));
        let env: Arc<dyn envexec::Environment> = Arc::new(GateEnv(gate.clone()));
        let pool: Arc<dyn EnvironmentPool> = Arc::new(GatePool {
            env,
            destroyed: destroyed.clone(),
        });
        let mut cfg = WorkerConfig::new(LocalFileStore::new(&dir), pool);
        cfg.parallelism = 1;
        cfg.queue_capacity = 1;
        let worker = AsyncWorker::new(cfg);
        worker.start().unwrap();
        let (first, started) = worker.submit(request("first"), CancellationToken::default());
        started.recv_timeout(Duration::from_secs(1)).unwrap();
        let (second, second_started) =
            worker.submit(request("second"), CancellationToken::default());
        assert_eq!(worker.stat().queue, 1);
        assert_eq!(worker.stat().running, 1);
        let (full, full_started) = worker.submit(request("full"), CancellationToken::default());
        full_started.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(
            full.blocking_recv().unwrap().error.as_deref(),
            Some("worker queue is full")
        );
        gate.store(true, Ordering::Release);
        assert_eq!(first.blocking_recv().unwrap().request_id, "first");
        second_started.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(second.blocking_recv().unwrap().request_id, "second");
        worker.shutdown();
        assert!(destroyed.load(Ordering::Acquire));
        assert!(worker.start().is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
    #[test]
    fn async_worker_cancels_running_process_when_token_is_signaled() {
        let dir = std::env::temp_dir().join(format!("worker-cancel-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let gate = Arc::new(AtomicBool::new(false));
        let (process_started, process_started_rx) = std::sync::mpsc::sync_channel(1);
        let env: Arc<dyn envexec::Environment> = Arc::new(CancelProbeEnv {
            gate,
            process_started,
        });
        let pool: Arc<dyn EnvironmentPool> = Arc::new(GatePool {
            env,
            destroyed: Arc::new(AtomicBool::new(false)),
        });
        let worker = AsyncWorker::new(WorkerConfig::new(LocalFileStore::new(&dir), pool));
        worker.start().unwrap();
        let token = CancellationToken::default();
        let (response, started) = worker.submit(request("running-cancel"), token.clone());
        started.recv_timeout(Duration::from_secs(1)).unwrap();
        process_started_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        token.cancel();
        let result = response.blocking_recv().unwrap();
        assert_eq!(result.results[0].status, JudgeStatus::InternalError);
        assert_eq!(result.results[0].error, "cancelled");
        worker.shutdown();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn async_worker_rejects_unstarted_canceled_requests_and_runs_execute() {
        let dir = std::env::temp_dir().join(format!("worker-execute-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let gate = Arc::new(AtomicBool::new(true));
        let env: Arc<dyn envexec::Environment> = Arc::new(GateEnv(gate));
        let pool: Arc<dyn EnvironmentPool> = Arc::new(GatePool {
            env,
            destroyed: Arc::new(AtomicBool::new(false)),
        });
        let worker = AsyncWorker::new(WorkerConfig::new(LocalFileStore::new(&dir), pool));
        let (early, _) = worker.submit(request("early"), CancellationToken::default());
        assert_eq!(
            early.blocking_recv().unwrap().error.as_deref(),
            Some("worker is not started")
        );
        worker.start().unwrap();
        let token = CancellationToken::default();
        token.cancel();
        let (canceled, started) = worker.submit(request("cancelled"), token);
        started.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(
            canceled.blocking_recv().unwrap().error.as_deref(),
            Some("cancelled before execute")
        );
        let response = crate::tokio_runtime::runtime()
            .block_on(worker.execute(request("interactive"), CancellationToken::default()))
            .unwrap();
        assert_eq!(response.request_id, "interactive");
        assert_eq!(response.results[0].status, JudgeStatus::Accepted);
        worker.shutdown();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn go_judge_status_names_and_cmd_file_debug_strings() {
        assert_eq!(JudgeStatus::Accepted as i32, 1);
        assert_eq!(JudgeStatus::InternalError as i32, 13);
        assert_eq!(
            JudgeStatus::MemoryLimitExceeded.to_string(),
            "Memory Limit Exceeded"
        );
        assert_eq!(CmdFile::Memory(vec![1, 2]).to_string(), "memory:(len:2)");
        assert_eq!(
            CmdFile::Cached("abc".into()).to_string(),
            "cached:(fileId:abc)"
        );
    }
    struct DummyProcess {
        usage: envexec::Usage,
    }
    impl envexec::Process for DummyProcess {
        fn done(&self) -> bool {
            false
        }
        fn result(&self) -> crate::runner::ResultInfo {
            Default::default()
        }
        fn usage(&self) -> envexec::Usage {
            self.usage
        }
        fn cancel(&self) {}
    }
    #[test]
    fn waiter_detects_cpu_usage_and_treats_zero_clock_as_cpu_limit() {
        let p = DummyProcess {
            usage: envexec::Usage {
                time: Duration::from_millis(20),
                memory: Size(0),
            },
        };
        assert!(wait_for_limits(
            &p,
            Duration::from_millis(10),
            Duration::ZERO,
            Duration::from_millis(1),
            || false
        ));
        assert!(!wait_for_limits(
            &p,
            Duration::from_secs(1),
            Duration::ZERO,
            Duration::from_millis(1),
            || true
        ));
    }

    struct DummyEnv;
    impl envexec::Environment for DummyEnv {
        fn execve(&self, _: envexec::ExecveParam) -> io::Result<Box<dyn envexec::Process>> {
            Err(io::Error::other("unused"))
        }
        fn open(&self, _: &[envexec::OpenParam]) -> io::Result<Vec<envexec::OpenResult>> {
            Ok(vec![])
        }
        fn symlink(&self, _: &[envexec::SymlinkParam]) -> io::Result<Vec<Option<String>>> {
            Ok(vec![])
        }
    }
    #[test]
    fn prepare_command_applies_worker_defaults_and_pipe_output_filter() {
        let store = LocalFileStore::new("unused");
        let cmd = Command {
            cpu_limit: Duration::from_secs(2),
            memory_limit: Size(100),
            stack_limit: Size(200),
            output_limit: Size(0),
            open_file_limit: 0,
            cpu_set_limit: String::new(),
            copy_out: vec![
                CopyOutFile {
                    name: "ordinary".into(),
                    optional: false,
                },
                CopyOutFile {
                    name: "pipe".into(),
                    optional: true,
                },
            ],
            copy_out_cached: vec![],
            files: vec![CmdFile::Null, CmdFile::Memory(vec![1])],
            ..Default::default()
        };
        let defaults = ExecDefaults {
            extra_memory_limit: Size(50),
            output_limit: Size(7),
            copy_out_limit: Size(8),
            open_file_limit: 9,
            cpu_set: "2-3".into(),
        };
        let prepared = cmd
            .prepare_envexec(
                Arc::new(DummyEnv),
                &store,
                &defaults,
                &["pipe".to_string()].into_iter().collect(),
            )
            .unwrap();
        let p = prepared.execve_param(vec![]);
        assert_eq!(p.limit.memory, Size(150));
        assert_eq!(p.limit.stack, Size(150));
        assert_eq!(p.limit.output, Size(7));
        assert_eq!(p.limit.open_file, 9);
        assert_eq!(p.limit.cpu_set, "2-3");
        assert_eq!(prepared.copy_out.len(), 1);
        assert_eq!(prepared.copy_out[0].name, "ordinary");
        assert!(prepared.files[0].is_none());
        assert!(prepared.files[1].is_some());
    }

    #[test]
    fn cached_outputs_are_added_to_store_and_removed_from_inline_files() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("rust-sandbox-worker-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = LocalFileStore::new(&dir);
        let (_, mut f) = store.new_file().unwrap();
        f.write_all(b"cached").unwrap();
        let mut files = std::collections::HashMap::new();
        files.insert("out".to_string(), f);
        let result = envexec::CmdResult {
            status: envexec::Status::Accepted,
            files,
            ..Default::default()
        };
        let cmd = Command {
            copy_out_cached: vec![CopyOutFile {
                name: "out".into(),
                optional: false,
            }],
            ..Default::default()
        };
        let converted = convert_result(result, &cmd, &store);
        assert_eq!(converted.status, JudgeStatus::Accepted);
        assert!(converted.files.is_empty());
        let id = &converted.file_ids["out"];
        let (_, mut cached) = store.get(id).unwrap();
        let mut data = String::new();
        std::io::Read::read_to_string(&mut cached, &mut data).unwrap();
        assert_eq!(data, "cached");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn partial_copy_out_files_survive_other_file_errors() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!(
            "rust-sandbox-worker-partial-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = LocalFileStore::new(&dir);
        let (_, mut output) = store.new_file().unwrap();
        output.write_all(b"12345").unwrap();
        let result = envexec::CmdResult {
            status: envexec::Status::FileError,
            files: std::collections::HashMap::from([("stdout".to_owned(), output)]),
            ..Default::default()
        };
        let mut converted = convert_result(result, &Command::default(), &store);
        assert_eq!(converted.status, JudgeStatus::FileError);
        let mut stdout = converted.files.get_mut("stdout").unwrap();
        stdout.seek(SeekFrom::Start(0)).unwrap();
        let mut contents = String::new();
        std::io::Read::read_to_string(&mut stdout, &mut contents).unwrap();
        assert_eq!(contents, "12345");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn memory_command_file_opens_independent_reader() {
        let store = LocalFileStore::new("unused");
        let mut opened = CmdFile::Memory(b"abc".to_vec()).open_input(&store).unwrap();
        if let InputFile::Memory(ref mut c) = opened {
            use std::io::Read;
            let mut bytes = Vec::new();
            c.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, b"abc");
        } else {
            panic!("expected in-memory input");
        }
    }
}
