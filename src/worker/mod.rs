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
    pub exec_observer: Option<ExecObserver>,
}

/// Optional callback invoked when a command response becomes available.
pub type ExecObserver = Arc<dyn Fn(&Response) + Send + Sync>;

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

mod async_worker;
pub use async_worker::{AsyncWorker, WorkerStat};

#[cfg(test)]
mod tests;
