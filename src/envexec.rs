//! Execution request, file, and result types translated from `go-judge/envexec`.
use crate::runner::{ResultInfo as RunnerResult, Size};
use crate::worker::TerminalSize;
use std::collections::HashMap;
use std::fs::{self, File as HostFile, OpenOptions};
use std::future::Future;
use std::io::{self, Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::task::{Context, Poll};
use std::time::Duration;

pub const FILE_COPY_PARALLELISM: usize = 8;
pub type NewStoreFile = Arc<dyn Fn() -> io::Result<HostFile> + Send + Sync>;

pub(crate) fn monotonic_time_ns() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let mut ts = std::mem::MaybeUninit::<libc::timespec>::uninit();
        if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, ts.as_mut_ptr()) } == 0 {
            let ts = unsafe { ts.assume_init() };
            return Some(
                (ts.tv_sec as u64)
                    .saturating_mul(1_000_000_000)
                    .saturating_add(ts.tv_nsec as u64),
            );
        }
    }
    None
}

#[cfg(target_os = "linux")]
static READER_MEMFD_ENABLED: AtomicBool = AtomicBool::new(true);

#[cfg(target_os = "linux")]
fn reader_memfd_enabled() -> bool {
    READER_MEMFD_ENABLED.load(Ordering::Acquire)
}
#[cfg(not(target_os = "linux"))]
fn reader_memfd_enabled() -> bool {
    false
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Limit {
    pub time: Duration,
    pub memory: Size,
    pub proc: u64,
    pub stack: Size,
    pub output: Size,
    pub rate: u64,
    pub open_file: u64,
    pub cpu_set: String,
    pub data_segment: bool,
    pub address_space: bool,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Usage {
    pub time: Duration,
    pub memory: Size,
}
#[derive(Clone, Debug, Default)]
pub struct ExecveParam {
    pub args: Vec<String>,
    pub env: Vec<String>,
    /// Optional workload seccomp filter installed for this exec request.
    /// go-judge installs its shared container filter during PID 1 setup,
    /// while standalone runprog supplies an additional per-command filter.
    pub seccomp: Option<crate::container::seccomp::Filter>,
    pub files: Vec<u64>,
    pub exec_file: u64,
    pub tty: bool,
    pub limit: Limit,
}
pub trait Process: Send + Sync {
    fn done(&self) -> bool;
    fn result(&self) -> RunnerResult;
    /// Monotonic time at which completion was observed, when the backend can report it.
    fn finished_at(&self) -> Option<u64> {
        None
    }
    fn usage(&self) -> Usage;
    /// Wait until the process changes state or the monitoring interval elapses.
    /// Backends with eventable process handles should wake on exit.
    fn wait_timeout(&self, timeout: Duration) {
        std::thread::sleep(timeout);
    }
    /// Async wait for command completion or a resource-check interval. The
    /// default keeps legacy backends responsive without occupying an OS
    /// thread; event-driven backends should override this method.
    fn wait_timeout_async<'a>(
        &'a self,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(tokio::time::sleep(timeout))
    }
    /// Request cancellation after the worker waiter observes a resource limit.
    fn cancel(&self);
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenParam {
    pub path: String,
    pub flag: i32,
    pub perm: u32,
    pub mkdir_all: bool,
}
pub struct OpenResult {
    pub file: Option<HostFile>,
    pub error: Option<String>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SymlinkParam {
    pub link_path: String,
    pub target: String,
}
pub trait Environment: Send + Sync {
    fn execve(&self, param: ExecveParam) -> io::Result<Box<dyn Process>>;
    fn open(&self, params: &[OpenParam]) -> io::Result<Vec<OpenResult>>;
    fn symlink(&self, params: &[SymlinkParam]) -> io::Result<Vec<Option<String>>>;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(i32)]
pub enum Status {
    #[default]
    Invalid = 0,
    Accepted = 1,
    WrongAnswer = 2,
    PartiallyCorrect = 3,
    MemoryLimitExceeded = 4,
    TimeLimitExceeded = 5,
    OutputLimitExceeded = 6,
    FileError = 7,
    NonzeroExitStatus = 8,
    Signalled = 9,
    DangerousSyscall = 10,
    JudgementFailed = 11,
    InvalidInteraction = 12,
    InternalError = 13,
}
impl Status {
    pub fn as_str(self) -> &'static str {
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
    pub fn from_name(s: &str) -> io::Result<Self> {
        ALL_STATUSES
            .iter()
            .copied()
            .find(|v| v.as_str() == s)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid string converting: {s}"),
                )
            })
    }
}
const ALL_STATUSES: [Status; 14] = [
    Status::Invalid,
    Status::Accepted,
    Status::WrongAnswer,
    Status::PartiallyCorrect,
    Status::MemoryLimitExceeded,
    Status::TimeLimitExceeded,
    Status::OutputLimitExceeded,
    Status::FileError,
    Status::NonzeroExitStatus,
    Status::Signalled,
    Status::DangerousSyscall,
    Status::JudgementFailed,
    Status::InvalidInteraction,
    Status::InternalError,
];
impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum FileErrorType {
    CopyInOpenFile = 0,
    CopyInCreateDir = 1,
    CopyInCreateFile = 2,
    CopyInCopyContent = 3,
    CopyOutOpen = 4,
    CopyOutNotRegularFile = 5,
    CopyOutSizeExceeded = 6,
    CopyOutCreateFile = 7,
    CopyOutCopyContent = 8,
    CollectSizeExceeded = 9,
    Symlink = 10,
}
impl FileErrorType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CopyInOpenFile => "CopyInOpenFile",
            Self::CopyInCreateDir => "CopyInCreateDir",
            Self::CopyInCreateFile => "CopyInCreateFile",
            Self::CopyInCopyContent => "CopyInCopyContent",
            Self::CopyOutOpen => "CopyOutOpen",
            Self::CopyOutNotRegularFile => "CopyOutNotRegularFile",
            Self::CopyOutSizeExceeded => "CopyOutSizeExceeded",
            Self::CopyOutCreateFile => "CopyOutCreateFile",
            Self::CopyOutCopyContent => "CopyOutCopyContent",
            Self::CollectSizeExceeded => "CollectSizeExceeded",
            Self::Symlink => "Symlink",
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileError {
    pub name: String,
    pub kind: FileErrorType,
    pub message: String,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CmdCopyOutFile {
    pub name: String,
    pub optional: bool,
}
#[derive(Debug, Default)]
pub struct CmdResult {
    pub status: Status,
    /// 1-based completion order within a grouped run; zero means unknown.
    pub exit_order: usize,
    pub(crate) finished_at: Option<u64>,
    pub exit_status: i32,
    pub error: String,
    pub time: Duration,
    pub run_time: Duration,
    pub memory: Size,
    pub proc_peak: u64,
    pub files: HashMap<String, HostFile>,
    pub file_errors: Vec<FileError>,
}

/// Host-side file description. Opened files and reader/writer handles transfer ownership.
pub enum File {
    Reader(Box<dyn Read + Send>),
    StreamReader(Box<dyn Read + Send>),
    Input(PathBuf),
    Collector {
        name: String,
        limit: Size,
        pipe: bool,
    },
    Writer {
        writer: Box<dyn Write + Send>,
        limit: Size,
    },
    Opened(HostFile),
}
impl File {
    pub fn reader<R: Read + Send + 'static>(r: R) -> Self {
        Self::Reader(Box::new(r))
    }
    pub fn stream_reader<R: Read + Send + 'static>(r: R) -> Self {
        Self::StreamReader(Box::new(r))
    }
    pub fn input(path: impl Into<PathBuf>) -> Self {
        Self::Input(path.into())
    }
    pub fn collector(name: impl Into<String>, limit: Size, pipe: bool) -> Self {
        Self::Collector {
            name: name.into(),
            limit,
            pipe,
        }
    }
    pub fn writer<W: Write + Send + 'static>(w: W, limit: Size) -> Self {
        Self::Writer {
            writer: Box::new(w),
            limit,
        }
    }
    pub fn opened(f: HostFile) -> Self {
        Self::Opened(f)
    }
    fn into_reader(self) -> io::Result<Box<dyn Read + Send>> {
        match self {
            Self::Reader(r) | Self::StreamReader(r) => Ok(r),
            Self::Input(p) => Ok(Box::new(HostFile::open(p)?)),
            Self::Opened(f) => Ok(Box::new(f)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "file cannot open as reader",
            )),
        }
    }
}

pub struct Cmd {
    pub environment: Arc<dyn Environment>,
    pub copy_in: HashMap<String, File>,
    pub symlinks: HashMap<String, String>,
    pub args: Vec<String>,
    pub env: Vec<String>,
    pub files: Vec<Option<File>>,
    pub tty: bool,
    pub terminal_resize: Option<Arc<std::sync::Mutex<std::sync::mpsc::Receiver<TerminalSize>>>>,
    pub time_limit: Duration,
    pub clock_limit: Duration,
    pub memory_limit: Size,
    pub stack_limit: Size,
    pub extra_memory_limit: Size,
    pub output_limit: Size,
    pub proc_limit: u64,
    pub open_file_limit: u64,
    pub cpu_rate_limit: u64,
    pub cpu_set_limit: String,
    pub copy_out: Vec<CmdCopyOutFile>,
    pub copy_out_max: Size,
    pub copy_out_truncate: bool,
    pub address_space_limit: bool,
    pub data_segment_limit: bool,
}

impl Cmd {
    /// Build the exact process launch limits used by Go's runSingleExecve.
    pub fn execve_param(&self, files: Vec<u64>) -> ExecveParam {
        let extra = if self.extra_memory_limit.0 == 0 {
            16 << 10
        } else {
            self.extra_memory_limit.0
        };
        let memory = Size(self.memory_limit.0.saturating_add(extra));
        let stack = if self.stack_limit.0 == 0 {
            Size(0)
        } else {
            Size(self.stack_limit.0.min(memory.0))
        };
        ExecveParam {
            args: self.args.clone(),
            env: self.env.clone(),
            seccomp: None,
            files,
            exec_file: 0,
            tty: self.tty,
            limit: Limit {
                time: self.time_limit,
                memory,
                proc: self.proc_limit,
                stack,
                output: self.output_limit,
                rate: self.cpu_rate_limit,
                open_file: self.open_file_limit,
                cpu_set: self.cpu_set_limit.clone(),
                data_segment: self.data_segment_limit,
                address_space: self.address_space_limit,
            },
        }
    }
}

/// Batch copy-in with Go-compatible flags, permissions, per-file errors, and file diagnostics.
pub fn copy_in(
    env: &dyn Environment,
    sources: HashMap<String, File>,
) -> (Vec<FileError>, io::Result<()>) {
    if sources.is_empty() {
        return (Vec::new(), Ok(()));
    }
    let entries: Vec<_> = sources.into_iter().collect();
    let opens: Vec<_> = entries
        .iter()
        .map(|(name, _)| OpenParam {
            path: name.clone(),
            flag: 1 | 64 | 512,
            perm: 0o777,
            mkdir_all: true,
        })
        .collect();
    let results = match env.open(&opens) {
        Ok(r) => r,
        Err(e) => {
            return (
                entries
                    .iter()
                    .map(|(n, _)| FileError {
                        name: n.clone(),
                        kind: FileErrorType::CopyInCreateFile,
                        message: e.to_string(),
                    })
                    .collect(),
                Err(io::Error::new(
                    e.kind(),
                    format!("copyin: batch open failed: {e}"),
                )),
            );
        }
    };
    let mut jobs = entries
        .into_iter()
        .zip(results)
        .collect::<Vec<_>>()
        .into_iter();
    let mut errors = Vec::new();
    let mut first = None;
    loop {
        let batch: Vec<_> = jobs.by_ref().take(FILE_COPY_PARALLELISM).collect();
        if batch.is_empty() {
            break;
        }
        let joins: Vec<_> = batch
            .into_iter()
            .map(|((name, source), opened)| {
                crate::tokio_runtime::spawn_blocking(move || {
                    if let Some(message) = opened.error {
                        return Some((
                            FileError {
                                name,
                                kind: FileErrorType::CopyInCreateFile,
                                message,
                            },
                            None,
                        ));
                    }
                    let Some(mut destination) = opened.file else {
                        return Some((
                            FileError {
                                name,
                                kind: FileErrorType::CopyInCreateFile,
                                message: "open returned no file".into(),
                            },
                            None,
                        ));
                    };
                    let copied = match source.into_reader() {
                        Err(error) => Err((FileErrorType::CopyInOpenFile, error)),
                        Ok(mut source) => io::copy(&mut source, &mut destination)
                            .map(|_| ())
                            .map_err(|error| (FileErrorType::CopyInCopyContent, error)),
                    };
                    copied.err().map(|(kind, error)| {
                        (
                            FileError {
                                name,
                                kind,
                                message: error.to_string(),
                            },
                            Some(error),
                        )
                    })
                })
            })
            .collect();
        let outcomes: Vec<_> = joins
            .into_iter()
            .map(|join| {
                join.recv().unwrap_or_else(|_| {
                    Some((
                        FileError {
                            name: String::new(),
                            kind: FileErrorType::CopyInCopyContent,
                            message: "copy-in worker panicked".into(),
                        },
                        Some(io::Error::other("copy-in worker panicked")),
                    ))
                })
            })
            .collect();
        for outcome in outcomes.into_iter().flatten() {
            errors.push(outcome.0);
            if first.is_none() {
                first = outcome.1;
            }
        }
    }
    match first {
        Some(e) => (errors, Err(e)),
        None => (errors, Ok(())),
    }
}

/// A write end whose relay copies at most `limit` bytes to its sink, then drains the
/// remaining pipe bytes so the child cannot block after output collection stops.
pub struct PipeRelay {
    pub write_end: Option<HostFile>,
    completion: std::sync::mpsc::Receiver<io::Result<u64>>,
}
impl PipeRelay {
    pub fn wait(self) -> io::Result<u64> {
        drop(self.write_end);
        self.completion
            .recv()
            .map_err(|_| io::Error::other("pipe relay stopped"))?
    }
}
#[cfg(unix)]
pub fn new_pipe<W: Write + Send + 'static>(sink: W, limit: Size) -> io::Result<PipeRelay> {
    use std::os::fd::{FromRawFd, OwnedFd};
    let mut fds = [-1; 2];
    // SAFETY: `fds` points to two writable integers; on success each descriptor is owned below.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pipe2 returned two fresh descriptors, each transferred into exactly one OwnedFd.
    let read_end = HostFile::from(unsafe { OwnedFd::from_raw_fd(fds[0]) });
    let write_end = HostFile::from(unsafe { OwnedFd::from_raw_fd(fds[1]) });
    let (tx, rx) = std::sync::mpsc::channel();
    let _task = crate::tokio_runtime::spawn_blocking(move || {
        let mut read_end = read_end;
        let mut sink = sink;
        let copied = io::copy(&mut Read::by_ref(&mut read_end).take(limit.0), &mut sink);
        let _ = tx.send(copied);
        io::copy(&mut read_end, &mut io::sink()).ok();
    });
    Ok(PipeRelay {
        write_end: Some(write_end),
        completion: rx,
    })
}

/// Open a host file through the same semantics as Go's FileToReader.
pub fn file_to_reader(file: File) -> io::Result<Box<dyn Read + Send>> {
    file.into_reader()
}
/// Open a host file for container copy-out, optionally creating parent directories.
pub fn open_host(path: &str, flags: i32, perm: u32, mkdir_all: bool) -> io::Result<HostFile> {
    if mkdir_all {
        if let Some(parent) = PathBuf::from(path).parent() {
            fs::create_dir_all(parent)?;
        }
    }
    let mut o = OpenOptions::new();
    o.read(flags & 0x3 == 0 || flags & 0x3 == 2)
        .write(flags & 0x3 == 1 || flags & 0x3 == 2)
        .create(flags & 64 != 0)
        .truncate(flags & 512 != 0)
        .mode(perm);
    o.open(path)
}

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

/// Run one command, including descriptor preparation, copy-in, symlink setup, waiting,
/// and copy-out. A copy/file operation failure is returned in `CmdResult` as `FileError`.
pub struct Single {
    pub cmd: Cmd,
    pub new_store_file: NewStoreFile,
}
impl Single {
    pub fn run(self) -> io::Result<CmdResult> {
        self.run_with_cancel(|| false)
    }
    pub fn run_with_cancel(
        self,
        cancelled: impl Fn() -> bool + Send + Sync,
    ) -> io::Result<CmdResult> {
        run_command(self.cmd, &self.new_store_file, &cancelled)
    }

    pub async fn run_with_cancel_async(
        self,
        cancelled: impl Fn() -> bool + Send + Sync + 'static,
    ) -> io::Result<CmdResult> {
        run_command_async(self.cmd, self.new_store_file, Arc::new(cancelled)).await
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PipeIndex {
    pub index: usize,
    pub fd: usize,
}
#[derive(Clone, Debug, Default)]
pub struct PipeMapping {
    pub input: PipeIndex,
    pub output: PipeIndex,
    pub cpu_set: String,
    pub proxy: bool,
    pub name: String,
    pub max: Size,
    pub disable_zero_copy: bool,
}
pub struct Group {
    pub commands: Vec<Cmd>,
    pub pipes: Vec<PipeMapping>,
    pub new_store_file: NewStoreFile,
}

fn order_group_results(mut results: Vec<CmdResult>) -> Vec<CmdResult> {
    let mut completed: Vec<_> = results
        .iter()
        .enumerate()
        .filter_map(|(i, result)| result.finished_at.map(|at| (at, i)))
        .collect();
    completed.sort_by_key(|(at, i)| (*at, *i));
    for (order, (_, index)) in completed.into_iter().enumerate() {
        results[index].exit_order = order + 1;
    }
    results
}

impl Group {
    pub fn run(self) -> io::Result<Vec<CmdResult>> {
        self.run_with_cancel(|| false)
    }
    /// Run mapped commands concurrently, with direct or relayed proxy pipes.
    pub fn run_with_cancel(
        self,
        cancelled: impl Fn() -> bool + Send + Sync + 'static,
    ) -> io::Result<Vec<CmdResult>> {
        let group = prepare_group(self, Arc::new(cancelled))?;
        let mut slots: Vec<Option<io::Result<CmdResult>>> = std::iter::repeat_with(|| None)
            .take(group.commands.len())
            .collect();
        let joins: Vec<_> = group
            .commands
            .into_iter()
            .enumerate()
            .map(|(i, cmd)| {
                let factory = group.factory.clone();
                let cancelled = group.cancelled.clone();
                (
                    i,
                    crate::tokio_runtime::spawn_blocking(move || {
                        run_command(cmd, &factory, &*cancelled)
                    }),
                )
            })
            .collect();
        for (i, join) in joins {
            slots[i] = Some(
                join.recv()
                    .unwrap_or_else(|_| Err(io::Error::other("command worker thread panicked"))),
            );
        }
        for relay in group.relays {
            let _ = relay.recv();
        }
        Ok(order_group_results(
            slots
                .into_iter()
                .map(|value| value.unwrap())
                .collect::<io::Result<Vec<_>>>()?,
        ))
    }

    pub async fn run_with_cancel_async(
        self,
        cancelled: impl Fn() -> bool + Send + Sync + 'static,
    ) -> io::Result<Vec<CmdResult>> {
        let group = prepare_group(self, Arc::new(cancelled))?;
        let joins: Vec<_> = group
            .commands
            .into_iter()
            .map(|cmd| {
                let factory = group.factory.clone();
                let cancelled = group.cancelled.clone();
                tokio::spawn(async move { run_command_async(cmd, factory, cancelled).await })
            })
            .collect();
        let mut results = Vec::with_capacity(joins.len());
        for join in joins {
            results
                .push(join.await.map_err(|error| {
                    io::Error::other(format!("command task failed: {error}"))
                })??);
        }
        for relay in group.relays {
            let _ = tokio::task::spawn_blocking(move || relay.recv())
                .await
                .map_err(|error| io::Error::other(format!("proxy relay waiter failed: {error}")))?;
        }
        Ok(order_group_results(results))
    }
}

struct PreparedGroup {
    commands: Vec<Cmd>,
    relays: Vec<std::sync::mpsc::Receiver<()>>,
    factory: NewStoreFile,
    cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
}

fn prepare_group(
    mut group: Group,
    cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
) -> io::Result<PreparedGroup> {
    let mut relays = Vec::new();
    let mut fds: Vec<Vec<Option<File>>> = group
        .commands
        .iter_mut()
        .map(|cmd| std::mem::take(&mut cmd.files))
        .collect();
    for pipe in &group.pipes {
        if pipe.input.index >= fds.len() || pipe.output.index >= fds.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pipe: index out of range",
            ));
        }
        if pipe.input == pipe.output {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pipe: input and output must differ",
            ));
        }
        for endpoint in [pipe.output, pipe.input] {
            if endpoint.fd >= 1 << 20 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "pipe: descriptor index is too large",
                ));
            }
            if fds[endpoint.index].len() <= endpoint.fd {
                fds[endpoint.index].resize_with(endpoint.fd + 1, || None);
            }
            if fds[endpoint.index][endpoint.fd].is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "pipe: fd already occupied",
                ));
            }
        }
        if pipe.proxy {
            let (relay_source, child_output) = os_pipe()?;
            let (child_input, relay_destination) = os_pipe()?;
            fds[pipe.input.index][pipe.input.fd] = Some(File::opened(child_output));
            fds[pipe.output.index][pipe.output.fd] = Some(File::opened(child_input));
            let zero_copy = !pipe.disable_zero_copy;
            let cpu_set = pipe.cpu_set.clone();
            if crate::tokio_runtime::legacy_proxy_ablation_enabled() || zero_copy {
                relays.push(crate::tokio_runtime::spawn_blocking(move || {
                    with_cpu_affinity(&cpu_set, || {
                        if zero_copy {
                            relay_splice_or_copy(relay_source, relay_destination);
                        } else {
                            relay_copy_and_drain(relay_source, relay_destination);
                        }
                    });
                }));
            } else {
                let (done_tx, done_rx) = std::sync::mpsc::channel();
                crate::tokio_runtime::runtime().handle().spawn(async move {
                    let relay = async_relay(relay_source, relay_destination);
                    let _ = AffinityFuture {
                        cpu_set,
                        inner: relay,
                    }
                    .await;
                    let _ = done_tx.send(());
                });
                relays.push(done_rx);
            }
        } else {
            let (read, write) = os_pipe()?;
            fds[pipe.input.index][pipe.input.fd] = Some(File::opened(write));
            fds[pipe.output.index][pipe.output.fd] = Some(File::opened(read));
        }
    }
    for (cmd, files) in group.commands.iter_mut().zip(fds) {
        cmd.files = files;
    }
    Ok(PreparedGroup {
        commands: group.commands,
        relays,
        factory: group.new_store_file,
        cancelled,
    })
}

#[cfg(target_os = "linux")]
fn with_cpu_affinity<T>(cpu_set: &str, run: impl FnOnce() -> T) -> T {
    use nix::{sched, unistd::Pid};
    if cpu_set.is_empty() {
        return run();
    }
    let Some(requested) = parse_cpu_affinity(cpu_set) else {
        return run();
    };
    let pid = Pid::from_raw(0);
    let Ok(previous) = sched::sched_getaffinity(pid) else {
        return run();
    };
    if sched::sched_setaffinity(pid, &requested).is_err() {
        return run();
    }
    let result = run();
    let _ = sched::sched_setaffinity(pid, &previous);
    result
}

struct AffinityFuture<F> {
    cpu_set: String,
    inner: F,
}

impl<F: Future> Future for AffinityFuture<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // The future is never moved after pinning; only its poll is wrapped so
        // each Tokio worker thread is restricted while it performs relay work.
        let this = unsafe { self.get_unchecked_mut() };
        let mut inner = unsafe { Pin::new_unchecked(&mut this.inner) };
        let mut result = None;
        with_cpu_affinity(&this.cpu_set, || result = Some(inner.as_mut().poll(cx)));
        result.expect("affinity wrapper always polls its future")
    }
}

#[cfg(target_os = "linux")]
async fn async_relay(source: HostFile, destination: HostFile) -> io::Result<()> {
    use tokio::io::unix::AsyncFd;

    set_nonblocking(&source)?;
    set_nonblocking(&destination)?;
    // SAFETY: both files own stable pipe descriptors and no code changes their
    // registrations while the AsyncFd values are alive.
    let source = unsafe { AsyncFd::register(source)? };
    // SAFETY: same ownership and descriptor-stability guarantee as above.
    let destination = unsafe { AsyncFd::register(destination)? };
    async_copy_relay(source, destination).await
}

#[cfg(not(target_os = "linux"))]
async fn async_relay(source: HostFile, destination: HostFile) -> io::Result<()> {
    let mut source = tokio::fs::File::from_std(source);
    let mut destination = tokio::fs::File::from_std(destination);
    tokio::io::copy(&mut source, &mut destination).await?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_nonblocking(file: &HostFile) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let fd = file.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn async_copy_relay(
    source: tokio::io::unix::AsyncFd<HostFile>,
    destination: tokio::io::unix::AsyncFd<HostFile>,
) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let n = loop {
            let mut readable = source.readable().await?;
            let n = readable.try_io(|inner| {
                let n = unsafe {
                    libc::read(
                        inner.get_ref().as_raw_fd(),
                        buffer.as_mut_ptr().cast(),
                        buffer.len(),
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match n {
                Err(_) => continue,
                Ok(Err(error)) => return Err(error),
                Ok(Ok(0)) => return Ok(()),
                Ok(Ok(n)) => break n,
            }
        };
        let mut offset = 0;
        while offset < n {
            let mut writable = destination.writable().await?;
            let written = writable.try_io(|inner| {
                let written = unsafe {
                    libc::write(
                        inner.get_ref().as_raw_fd(),
                        buffer[offset..n].as_ptr().cast(),
                        n - offset,
                    )
                };
                if written < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(written as usize)
                }
            });
            match written {
                Err(_) => continue,
                Ok(Err(error)) if error.raw_os_error() == Some(libc::EPIPE) => {
                    async_drain_relay_source(&source).await?;
                    return Ok(());
                }
                Ok(Err(error)) => return Err(error),
                Ok(Ok(0)) => return Err(io::Error::new(io::ErrorKind::WriteZero, "pipe relay")),
                Ok(Ok(written)) => offset += written,
            }
        }
    }
}

#[cfg(target_os = "linux")]
async fn async_drain_relay_source(source: &tokio::io::unix::AsyncFd<HostFile>) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let mut readable = source.readable().await?;
        let n = readable.try_io(|inner| {
            let n = unsafe {
                libc::read(
                    inner.get_ref().as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                )
            };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        });
        match n {
            Err(_) => continue,
            Ok(Err(error)) => return Err(error),
            Ok(Ok(0)) => return Ok(()),
            Ok(Ok(_)) => {}
        }
    }
}

#[cfg(target_os = "linux")]
fn parse_cpu_affinity(value: &str) -> Option<nix::sched::CpuSet> {
    let mut set = nix::sched::CpuSet::new();
    for segment in value.split(',') {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        let (first, last) = match segment.split_once('-') {
            Some((first, last)) => (first.trim().parse().ok()?, last.trim().parse().ok()?),
            None => {
                let cpu = segment.parse().ok()?;
                (cpu, cpu)
            }
        };
        if first > last {
            return None;
        }
        for cpu in first..=last {
            set.set(cpu).ok()?;
        }
    }
    Some(set)
}

#[cfg(not(target_os = "linux"))]
fn with_cpu_affinity<T>(_: &str, run: impl FnOnce() -> T) -> T {
    run()
}

fn relay_copy_and_drain(source: HostFile, destination: HostFile) {
    // Go's `io.Copy` dispatches pipe-to-pipe `*os.File` transfers through
    // `os.File.ReadFrom`, which uses Linux splice when both endpoints support
    // it. Keep the Rust buffered fallback for filesystems/kernels where splice
    // is unavailable, but match that fast path for Go's DisableZeroCopy mode.
    #[cfg(target_os = "linux")]
    {
        relay_splice_or_copy(source, destination);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let mut source = source;
        let mut destination = destination;
        if io::copy(&mut source, &mut destination).is_err() {
            drop(destination);
            let _ = io::copy(&mut source, &mut io::sink());
        }
    }
}

fn reader_to_host_file(
    mut reader: Box<dyn Read + Send>,
    reader_threads: &mut Vec<std::sync::mpsc::Receiver<()>>,
    try_memfd: bool,
) -> io::Result<HostFile> {
    #[cfg(target_os = "linux")]
    if try_memfd && READER_MEMFD_ENABLED.load(Ordering::Acquire) {
        match crate::container::memfd::dup_to_memfd_ref("input", &mut *reader) {
            Ok(file) => return Ok(file),
            Err(_) => READER_MEMFD_ENABLED.store(false, Ordering::Release),
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = try_memfd;

    let (read, write) = os_pipe()?;
    reader_threads.push(crate::tokio_runtime::spawn_blocking(move || {
        let mut write = write;
        let _ = io::copy(&mut reader, &mut write);
    }));
    Ok(read)
}

#[cfg(target_os = "linux")]
fn relay_splice_or_copy(mut source: HostFile, mut destination: HostFile) {
    use nix::fcntl::{SpliceFFlags, splice};
    loop {
        match splice(
            &source,
            None,
            &destination,
            None,
            64 * 1024,
            SpliceFFlags::SPLICE_F_MOVE,
        ) {
            Ok(0) => return,
            Ok(_) => continue,
            Err(nix::errno::Errno::EPIPE) => {
                drop(destination);
                let _ = io::copy(&mut source, &mut io::sink());
                return;
            }
            Err(_) => {
                if io::copy(&mut source, &mut destination).is_err() {
                    drop(destination);
                    let _ = io::copy(&mut source, &mut io::sink());
                }
                return;
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn relay_splice_or_copy(source: HostFile, destination: HostFile) {
    relay_copy_and_drain(source, destination);
}

struct Prepared {
    fds: Vec<HostFile>,
    relays: Vec<PipeRelay>,
    collectors: Vec<CollectorJob>,
    reader_threads: Vec<std::sync::mpsc::Receiver<()>>,
    resize_stop: Option<Arc<AtomicBool>>,
}
impl Drop for Prepared {
    fn drop(&mut self) {
        if let Some(stop) = &self.resize_stop {
            stop.store(true, Ordering::Release);
        }
    }
}
struct CollectorJob {
    name: String,
    limit: Size,
    buffer: HostFile,
    relay: Option<PipeRelay>,
}
fn run_command(
    cmd: Cmd,
    store: &NewStoreFile,
    cancelled: &dyn Fn() -> bool,
) -> io::Result<CmdResult> {
    let running = match start_command(cmd, store) {
        CommandStart::Finished(result) => return Ok(result),
        CommandStart::Running(running) => running,
    };
    let mut limit_hit = None;
    let mut was_cancelled = false;
    while !running.process.done() {
        if cancelled() && !was_cancelled {
            was_cancelled = true;
            running.process.cancel();
        }
        update_limits(
            running.process.as_ref(),
            running.start,
            &running.cmd,
            &mut limit_hit,
        );
        if limit_hit.is_some() {
            running.process.cancel();
        }
        // Match Go's 100ms resource-check tick. Backends with an eventable
        // process handle wake early when the child exits.
        running.process.wait_timeout(Duration::from_millis(100));
    }
    if limit_hit.is_none()
        && running.cmd.clock_limit > Duration::ZERO
        && running.start.elapsed() > running.cmd.clock_limit
    {
        limit_hit = Some(Status::TimeLimitExceeded);
    }
    finish_command(running, limit_hit, was_cancelled)
}

struct RunningCommand {
    cmd: Cmd,
    store: NewStoreFile,
    prepared: Prepared,
    process: Box<dyn Process>,
    file_errors: Vec<FileError>,
    start: std::time::Instant,
}

enum CommandStart {
    Finished(CmdResult),
    Running(RunningCommand),
}

fn start_command(mut cmd: Cmd, store: &NewStoreFile) -> CommandStart {
    let prepared = match prepare_files(&mut cmd, store) {
        Ok(v) => v,
        Err(e) => {
            return CommandStart::Finished(CmdResult {
                status: Status::InternalError,
                error: e.to_string(),
                ..Default::default()
            });
        }
    };
    let (file_errors, copy_err) =
        copy_in(cmd.environment.as_ref(), std::mem::take(&mut cmd.copy_in));
    if let Err(e) = copy_err {
        drop(prepared);
        return CommandStart::Finished(CmdResult {
            status: Status::FileError,
            error: e.to_string(),
            file_errors,
            ..Default::default()
        });
    }
    if !cmd.symlinks.is_empty() {
        let batch: Vec<_> = cmd
            .symlinks
            .iter()
            .map(|(link, target)| SymlinkParam {
                link_path: link.clone(),
                target: target.clone(),
            })
            .collect();
        match cmd.environment.symlink(&batch) {
            Err(e) => {
                drop(prepared);
                return CommandStart::Finished(CmdResult {
                    status: Status::FileError,
                    error: e.to_string(),
                    file_errors,
                    ..Default::default()
                });
            }
            Ok(results) => {
                let errors: Vec<_> = results
                    .into_iter()
                    .enumerate()
                    .filter_map(|(i, e)| {
                        e.map(|message| FileError {
                            name: batch
                                .get(i)
                                .map(|v| v.link_path.clone())
                                .unwrap_or_default(),
                            kind: FileErrorType::Symlink,
                            message,
                        })
                    })
                    .collect();
                if !errors.is_empty() {
                    drop(prepared);
                    return CommandStart::Finished(CmdResult {
                        status: Status::FileError,
                        error: format!("symlink: {} operations failed", errors.len()),
                        file_errors: errors,
                        ..Default::default()
                    });
                }
            }
        }
    }
    let param = cmd.execve_param(prepared.fds.iter().map(|f| f.as_raw_fd() as u64).collect());
    let process = match cmd.environment.execve(param) {
        Ok(p) => p,
        Err(e) => {
            drop(prepared);
            return CommandStart::Finished(CmdResult {
                status: Status::InternalError,
                error: e.to_string(),
                file_errors,
                ..Default::default()
            });
        }
    };
    CommandStart::Running(RunningCommand {
        cmd,
        store: store.clone(),
        prepared,
        process,
        file_errors,
        start: std::time::Instant::now(),
    })
}

fn update_limits(
    process: &dyn Process,
    start: std::time::Instant,
    cmd: &Cmd,
    limit_hit: &mut Option<Status>,
) {
    let usage = process.usage();
    if (cmd.time_limit > Duration::ZERO && usage.time > cmd.time_limit)
        || (cmd.clock_limit > Duration::ZERO && start.elapsed() > cmd.clock_limit)
    {
        *limit_hit = Some(Status::TimeLimitExceeded);
    }
    if cmd.memory_limit.0 > 0 && usage.memory > cmd.memory_limit {
        *limit_hit = Some(Status::MemoryLimitExceeded);
    }
}

async fn run_command_async(
    cmd: Cmd,
    store: NewStoreFile,
    cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
) -> io::Result<CmdResult> {
    let running = tokio::task::spawn_blocking(move || start_command(cmd, &store))
        .await
        .map_err(|error| io::Error::other(format!("command setup task failed: {error}")))?;
    let running = match running {
        CommandStart::Finished(result) => return Ok(result),
        CommandStart::Running(running) => running,
    };
    let mut limit_hit = None;
    let mut was_cancelled = false;
    while !running.process.done() {
        if cancelled() && !was_cancelled {
            was_cancelled = true;
            running.process.cancel();
        }
        update_limits(
            running.process.as_ref(),
            running.start,
            &running.cmd,
            &mut limit_hit,
        );
        if limit_hit.is_some() {
            running.process.cancel();
        }
        running
            .process
            .wait_timeout_async(Duration::from_millis(100))
            .await;
    }
    if limit_hit.is_none()
        && running.cmd.clock_limit > Duration::ZERO
        && running.start.elapsed() > running.cmd.clock_limit
    {
        limit_hit = Some(Status::TimeLimitExceeded);
    }
    tokio::task::spawn_blocking(move || finish_command(running, limit_hit, was_cancelled))
        .await
        .map_err(|error| io::Error::other(format!("command cleanup task failed: {error}")))?
}

fn finish_command(
    running: RunningCommand,
    limit_hit: Option<Status>,
    was_cancelled: bool,
) -> io::Result<CmdResult> {
    let RunningCommand {
        cmd,
        store,
        mut prepared,
        process,
        file_errors,
        start,
    } = running;
    let runner = process.result();
    let mut result = CmdResult {
        status: map_status(runner.status),
        finished_at: process.finished_at().or_else(monotonic_time_ns),
        exit_status: runner.exit_status,
        error: runner.error,
        time: runner.time,
        run_time: start.elapsed(),
        memory: runner.memory,
        proc_peak: runner.proc_peak,
        files: HashMap::new(),
        file_errors,
        ..Default::default()
    };
    if let Some(status) = limit_hit {
        result.status = status;
    }
    if was_cancelled && result.status == Status::Accepted {
        result.status = Status::InternalError;
        result.error = "cancelled".into();
    }
    for fd in prepared.fds.drain(..) {
        drop(fd);
    }
    if let Some(stop) = &prepared.resize_stop {
        stop.store(true, Ordering::Release);
    }
    for t in prepared.reader_threads.drain(..) {
        let _ = t.recv();
    }
    for relay in prepared.relays.drain(..) {
        let _ = relay.wait();
    }
    if let Err(e) = collect_outputs(&cmd, &store, &mut prepared, &mut result) {
        if result.status == Status::Accepted && result.error.is_empty() {
            result.status = Status::FileError;
            result.error = e.to_string();
        }
    }
    Ok(result)
}
fn map_status(s: crate::runner::Status) -> Status {
    use crate::runner::Status as R;
    match s {
        R::Normal => Status::Accepted,
        R::TimeLimitExceeded => Status::TimeLimitExceeded,
        R::MemoryLimitExceeded => Status::MemoryLimitExceeded,
        R::OutputLimitExceeded => Status::OutputLimitExceeded,
        R::DisallowedSyscall => Status::DangerousSyscall,
        R::Signalled => Status::Signalled,
        R::NonzeroExitStatus => Status::NonzeroExitStatus,
        R::Invalid | R::RunnerError => Status::InternalError,
    }
}
fn prepare_files(cmd: &mut Cmd, store: &NewStoreFile) -> io::Result<Prepared> {
    if cmd.tty {
        return prepare_tty_files(cmd, store);
    }
    let mut fds = Vec::with_capacity(cmd.files.len());
    let mut relays = Vec::new();
    let mut collectors = Vec::new();
    let mut reader_threads = Vec::new();
    let mut named = HashMap::<String, HostFile>::new();
    let mut collector_names = Vec::new();
    let mut seen_collectors = std::collections::HashSet::new();
    for file in cmd.files.iter().flatten() {
        if let File::Collector {
            name, pipe: false, ..
        } = file
            && seen_collectors.insert(name.clone())
        {
            collector_names.push(name.clone());
        }
    }
    let mut batched_collectors = HashMap::<String, (HostFile, HostFile)>::new();
    if !collector_names.is_empty() {
        let params: Vec<_> = collector_names
            .iter()
            .flat_map(|name| {
                [
                    OpenParam {
                        path: name.clone(),
                        flag: 1 | 64 | 512,
                        perm: 0o777,
                        mkdir_all: false,
                    },
                    OpenParam {
                        path: name.clone(),
                        flag: 2,
                        perm: 0o777,
                        mkdir_all: false,
                    },
                ]
            })
            .collect();
        let opened = cmd.environment.open(&params)?;
        if opened.len() != params.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "collector batch open returned wrong number of files",
            ));
        }
        for (name, pair) in collector_names.into_iter().zip(opened.chunks_exact(2)) {
            if let Some(message) = pair.iter().find_map(|item| item.error.as_ref()) {
                return Err(io::Error::other(format!("container: {name}: {message}")));
            }
            let write = pair[0]
                .file
                .as_ref()
                .ok_or_else(|| io::Error::other("collector write open returned no file"))?
                .try_clone()?;
            let read = pair[1]
                .file
                .as_ref()
                .ok_or_else(|| io::Error::other("collector read open returned no file"))?
                .try_clone()?;
            batched_collectors.insert(name, (write, read));
        }
    }
    for slot in &mut cmd.files {
        let Some(file) = slot.take() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "null file descriptor",
            ));
        };
        let fd = match file {
            File::Opened(f) => f,
            File::Input(path) => HostFile::open(path)?,
            File::Reader(reader) => {
                reader_to_host_file(reader, &mut reader_threads, reader_memfd_enabled())?
            }
            File::StreamReader(mut reader) => {
                let (read, write) = os_pipe()?;
                reader_threads.push(crate::tokio_runtime::spawn_blocking(move || {
                    let mut write = write;
                    let _ = io::copy(&mut reader, &mut write);
                }));
                read
            }
            File::Writer { writer, limit } => {
                let mut relay = new_pipe(writer, limit)?;
                let w = relay.write_end.take().unwrap();
                relays.push(relay);
                w
            }
            File::Collector { name, limit, pipe } => {
                if let Some(existing) = named.get(&name) {
                    existing.try_clone()?
                } else if pipe {
                    let buffer = store()?;
                    let mut relay = new_pipe(buffer.try_clone()?, Size(limit.0.saturating_add(1)))?;
                    let w = relay.write_end.take().unwrap();
                    collectors.push(CollectorJob {
                        name: name.clone(),
                        limit,
                        buffer,
                        relay: Some(relay),
                    });
                    named.insert(name, w.try_clone()?);
                    w
                } else {
                    let (write, read) = batched_collectors.remove(&name).ok_or_else(|| {
                        io::Error::other("collector batch open did not include file")
                    })?;
                    collectors.push(CollectorJob {
                        name: name.clone(),
                        limit,
                        buffer: read,
                        relay: None,
                    });
                    named.insert(name, write.try_clone()?);
                    write
                }
            }
        };
        fds.push(fd);
    }
    Ok(Prepared {
        fds,
        relays,
        collectors,
        reader_threads,
        resize_stop: None,
    })
}

/// Prepare a shared PTY for the command's terminal-backed streams. This
/// mirrors go-judge's TTY behavior: all child descriptors use the slave, input
/// is written through the master, and the first output collector drains the
/// merged terminal stream.
fn prepare_tty_files(cmd: &mut Cmd, store: &NewStoreFile) -> io::Result<Prepared> {
    let pair = nix::pty::openpty(None, None).map_err(io::Error::other)?;
    let master = HostFile::from(pair.master);
    let slave = HostFile::from(pair.slave);
    let mut fds = Vec::with_capacity(cmd.files.len());
    let relays = Vec::new();
    let mut collectors = Vec::new();
    let mut reader_threads = Vec::new();
    let mut has_input = false;
    let mut has_output = false;
    let resize_stop = cmd
        .terminal_resize
        .as_ref()
        .map(|_| Arc::new(AtomicBool::new(false)));

    if let Some(resize) = cmd.terminal_resize.take() {
        let resize_master = master.try_clone()?;
        let stop = resize_stop.as_ref().unwrap().clone();
        reader_threads.push(crate::tokio_runtime::spawn_blocking(move || {
            loop {
                if stop.load(Ordering::Acquire) {
                    break;
                }
                let next = resize
                    .lock()
                    .ok()
                    .map(|rx| rx.recv_timeout(Duration::from_millis(50)));
                match next {
                    Some(Ok(size)) => {
                        let _ = set_pty_window_size(resize_master.as_raw_fd(), size);
                    }
                    Some(Err(std::sync::mpsc::RecvTimeoutError::Disconnected)) | None => break,
                    Some(Err(std::sync::mpsc::RecvTimeoutError::Timeout)) => {}
                }
            }
        }));
    }

    for slot in &mut cmd.files {
        let Some(file) = slot.take() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "null file descriptor",
            ));
        };
        let fd = match file {
            File::Opened(file) => file,
            File::Input(path) => HostFile::open(path)?,
            File::Reader(mut reader) | File::StreamReader(mut reader) => {
                if has_input {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "tty: multiple input streams are not allowed",
                    ));
                }
                has_input = true;
                let mut master_write = master.try_clone()?;
                reader_threads.push(crate::tokio_runtime::spawn_blocking(move || {
                    let _ = io::copy(&mut reader, &mut master_write);
                }));
                slave.try_clone()?
            }
            File::Writer { mut writer, .. } => {
                let child_fd = slave.try_clone()?;
                if !has_output {
                    has_output = true;
                    let master_read = master.try_clone()?;
                    reader_threads.push(crate::tokio_runtime::spawn_blocking(move || {
                        let mut master_read = master_read;
                        if let Err(error) = io::copy(&mut master_read, &mut writer) {
                            if error.raw_os_error() != Some(libc::EIO) {
                                return;
                            }
                        }
                    }));
                }
                child_fd
            }
            File::Collector { name, limit, .. } => {
                let child_fd = slave.try_clone()?;
                if !has_output {
                    has_output = true;
                    let buffer = store()?;
                    let master_read = master.try_clone()?;
                    let thread_buffer = buffer.try_clone()?;
                    reader_threads.push(crate::tokio_runtime::spawn_blocking(move || {
                        let mut master_read = master_read;
                        let mut thread_buffer = thread_buffer;
                        let copied = io::copy(
                            &mut io::Read::by_ref(&mut master_read).take(limit.0.saturating_add(1)),
                            &mut thread_buffer,
                        );
                        if copied.is_err_and(|error| error.raw_os_error() != Some(libc::EIO)) {
                            return;
                        }
                        let _ = io::copy(&mut master_read, &mut io::sink());
                    }));
                    collectors.push(CollectorJob {
                        name,
                        limit,
                        buffer,
                        relay: None,
                    });
                }
                child_fd
            }
        };
        fds.push(fd);
    }
    // The master must be owned only by the relay threads. Keeping an extra
    // copy open here would prevent their reads from reaching PTY EOF.
    drop(master);
    drop(slave);
    Ok(Prepared {
        fds,
        relays,
        collectors,
        reader_threads,
        resize_stop,
    })
}

fn set_pty_window_size(fd: std::os::fd::RawFd, size: TerminalSize) -> io::Result<()> {
    let winsize = libc::winsize {
        ws_row: size.rows,
        ws_col: size.cols,
        ws_xpixel: size.x,
        ws_ypixel: size.y,
    };
    if unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &winsize) } == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
fn collect_outputs(
    cmd: &Cmd,
    store: &NewStoreFile,
    prepared: &mut Prepared,
    result: &mut CmdResult,
) -> io::Result<()> {
    for job in prepared.collectors.drain(..) {
        if let Some(relay) = job.relay {
            let _ = relay.wait();
        }
        let mut buffer = job.buffer;
        let size = buffer.metadata()?.len();
        if size > job.limit.0 {
            if result.status == Status::Accepted && result.error.is_empty() {
                result.status = Status::OutputLimitExceeded;
                result.error = Status::OutputLimitExceeded.to_string();
            }
            result.file_errors.push(FileError {
                name: job.name.clone(),
                kind: FileErrorType::CollectSizeExceeded,
                message: Status::OutputLimitExceeded.to_string(),
            });
            let _ = buffer.set_len(job.limit.0.saturating_add(1));
        }
        std::io::Seek::seek(&mut buffer, std::io::SeekFrom::Start(0))?;
        result.files.insert(job.name, buffer);
    }
    if cmd.copy_out.is_empty() {
        return Ok(());
    }
    let params: Vec<_> = cmd
        .copy_out
        .iter()
        .map(|n| OpenParam {
            path: n.name.clone(),
            flag: 0,
            perm: 0o777,
            mkdir_all: false,
        })
        .collect();
    let opened = match cmd.environment.open(&params) {
        Ok(opened) => opened,
        Err(error) => {
            for spec in &cmd.copy_out {
                let message = format!("batch open failed {}: {error}", spec.name);
                result.file_errors.push(FileError {
                    name: spec.name.clone(),
                    kind: FileErrorType::CopyOutOpen,
                    message,
                });
            }
            return Err(io::Error::other(format!(
                "copyout: batch open failed: {error}"
            )));
        }
    };
    if opened.len() != cmd.copy_out.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "copyout batch open returned wrong number of files",
        ));
    }
    let mut jobs = Vec::new();
    for (spec, item) in cmd.copy_out.iter().cloned().zip(opened) {
        if let Some(message) = item.error {
            if !spec.optional {
                result.file_errors.push(FileError {
                    name: spec.name.clone(),
                    kind: FileErrorType::CopyOutOpen,
                    message: message.clone(),
                });
                if result.status == Status::Accepted && result.error.is_empty() {
                    result.status = Status::FileError;
                    result.error = message;
                }
            }
            continue;
        }
        let Some(source) = item.file else {
            if !spec.optional {
                let message = "open returned no file".to_string();
                result.file_errors.push(FileError {
                    name: spec.name.clone(),
                    kind: FileErrorType::CopyOutOpen,
                    message: message.clone(),
                });
                if result.status == Status::Accepted && result.error.is_empty() {
                    result.status = Status::FileError;
                    result.error = message;
                }
            }
            continue;
        };
        jobs.push((spec, source));
    }
    let mut pending = jobs.into_iter();
    loop {
        let batch: Vec<_> = pending.by_ref().take(FILE_COPY_PARALLELISM).collect();
        if batch.is_empty() {
            break;
        }
        let store = Arc::clone(store);
        let joins: Vec<_> = batch
            .into_iter()
            .map(|(spec, source)| {
                let store = Arc::clone(&store);
                let copy_out_max = cmd.copy_out_max;
                let copy_out_truncate = cmd.copy_out_truncate;
                crate::tokio_runtime::spawn_blocking(move || {
                    copy_out_one(spec, source, &store, copy_out_max, copy_out_truncate)
                })
            })
            .collect();
        let outcomes: Vec<_> = joins
            .into_iter()
            .map(|join| {
                join.recv().unwrap_or_else(|_| CopyOutOutcome {
                    name: String::new(),
                    file: None,
                    file_error: Some(FileError {
                        name: String::new(),
                        kind: FileErrorType::CopyOutCopyContent,
                        message: "copyout worker panicked".into(),
                    }),
                    error: Some(io::Error::other("copyout worker panicked")),
                })
            })
            .collect();
        for outcome in outcomes {
            if let Some(file_error) = outcome.file_error {
                if result.status == Status::Accepted && result.error.is_empty() {
                    result.status = Status::FileError;
                    result.error = file_error.message.clone();
                }
                result.file_errors.push(file_error);
            }
            if let Some(error) = outcome.error {
                if result.status == Status::Accepted && result.error.is_empty() {
                    result.status = Status::FileError;
                    result.error = error.to_string();
                }
            }
            if let Some(file) = outcome.file {
                // Match Go's last-writer behavior when a collector and
                // copy-out entry use the same name.
                result.files.insert(outcome.name, file);
            }
        }
    }
    Ok(())
}

struct CopyOutOutcome {
    name: String,
    file: Option<HostFile>,
    file_error: Option<FileError>,
    error: Option<io::Error>,
}

fn copy_out_one(
    spec: CmdCopyOutFile,
    mut source: HostFile,
    store: &NewStoreFile,
    max: Size,
    truncate: bool,
) -> CopyOutOutcome {
    let name = spec.name.clone();
    let failed = |kind, message: String| CopyOutOutcome {
        name: name.clone(),
        file: None,
        file_error: Some(FileError {
            name: name.clone(),
            kind,
            message: message.clone(),
        }),
        error: Some(io::Error::other(message)),
    };
    let metadata = match source.metadata() {
        Ok(metadata) => metadata,
        Err(error) => {
            return failed(
                FileErrorType::CopyOutOpen,
                format!("copyout: stat {:?}: {error}", spec.name),
            );
        }
    };
    if !metadata.is_file() {
        return failed(
            FileErrorType::CopyOutNotRegularFile,
            format!("copyout: {:?} is not a regular file", spec.name),
        );
    }
    let mut amount = metadata.len();
    let mut exceeded = false;
    if max.0 > 0 && amount > max.0 {
        if !truncate {
            return failed(
                FileErrorType::CopyOutSizeExceeded,
                format!(
                    "copyout: {:?} size ({amount}) exceeds limit ({})",
                    spec.name, max.0
                ),
            );
        }
        amount = max.0;
        exceeded = true;
    }
    let mut target = match store() {
        Ok(file) => file,
        Err(error) => {
            return failed(
                FileErrorType::CopyOutCreateFile,
                format!(
                    "copyout: failed to create store file for {:?}: {error}",
                    spec.name
                ),
            );
        }
    };
    let copied = match io::copy(&mut Read::by_ref(&mut source).take(amount), &mut target) {
        Ok(copied) => copied,
        Err(error) => {
            return failed(
                FileErrorType::CopyOutCopyContent,
                format!(
                    "copyout: failed to copy content for {:?}: {error}",
                    spec.name
                ),
            );
        }
    };
    if let Err(error) = target.seek(SeekFrom::Start(0)) {
        return failed(
            FileErrorType::CopyOutCopyContent,
            format!(
                "copyout: failed to copy content for {:?}: {error}",
                spec.name
            ),
        );
    }
    if exceeded || (max.0 > 0 && copied > max.0) {
        let message = format!("copyout: {:?} size exceeds limit ({})", spec.name, max.0);
        return CopyOutOutcome {
            name: spec.name.clone(),
            file: Some(target),
            file_error: Some(FileError {
                name: spec.name,
                kind: FileErrorType::CopyOutSizeExceeded,
                message: message.clone(),
            }),
            error: Some(io::Error::other(message)),
        };
    }
    CopyOutOutcome {
        name: spec.name,
        file: Some(target),
        file_error: None,
        error: None,
    }
}
#[cfg(unix)]
fn os_pipe() -> io::Result<(HostFile, HostFile)> {
    use std::os::fd::{FromRawFd, OwnedFd};
    let mut fds = [-1; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok((
        HostFile::from(unsafe { OwnedFd::from_raw_fd(fds[0]) }),
        HostFile::from(unsafe { OwnedFd::from_raw_fd(fds[1]) }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::Mutex;
    struct CompletedProcess;
    impl Process for CompletedProcess {
        fn done(&self) -> bool {
            true
        }
        fn result(&self) -> RunnerResult {
            RunnerResult {
                status: crate::runner::Status::Normal,
                ..Default::default()
            }
        }
        fn usage(&self) -> Usage {
            Usage::default()
        }
        fn cancel(&self) {}
    }
    #[derive(Default)]
    struct FakeEnv {
        root: PathBuf,
        launched: Mutex<Vec<ExecveParam>>,
        links: Mutex<Vec<SymlinkParam>>,
        opened_batches: Mutex<Vec<usize>>,
    }
    impl Environment for FakeEnv {
        fn execve(&self, p: ExecveParam) -> io::Result<Box<dyn Process>> {
            if matches!(
                p.args.first().map(String::as_str),
                Some("write_output" | "write_output_to_stdout")
            ) {
                use std::os::fd::RawFd;
                let index = usize::from(
                    p.args.first().map(String::as_str) == Some("write_output_to_stdout"),
                );
                let fd = *p
                    .files
                    .get(index)
                    .ok_or_else(|| io::Error::other("missing output fd"))?
                    as RawFd;
                // SAFETY: the raw fd belongs to the prepared output pipe for this command.
                if unsafe { libc::write(fd, b"hello".as_ptr().cast(), 5) } < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            self.launched.lock().unwrap().push(p);
            Ok(Box::new(CompletedProcess))
        }
        fn open(&self, params: &[OpenParam]) -> io::Result<Vec<OpenResult>> {
            self.opened_batches.lock().unwrap().push(params.len());
            params
                .iter()
                .map(|p| {
                    let path = self.root.join(&p.path);
                    if p.mkdir_all {
                        if let Some(parent) = path.parent() {
                            fs::create_dir_all(parent)?;
                        }
                    }
                    let f = open_host(path.to_str().unwrap(), p.flag, p.perm, p.mkdir_all)?;
                    Ok(OpenResult {
                        file: Some(f),
                        error: None,
                    })
                })
                .collect()
        }
        fn symlink(&self, params: &[SymlinkParam]) -> io::Result<Vec<Option<String>>> {
            self.links.lock().unwrap().extend_from_slice(params);
            Ok(vec![None; params.len()])
        }
    }
    fn test_store(dir: PathBuf) -> NewStoreFile {
        Arc::new(move || {
            let n = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(dir.join(format!("store-{n}")))
        })
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn proxy_cpu_affinity_pins_the_relay_thread_and_ignores_invalid_masks() {
        use nix::{sched, unistd::Pid};
        let allowed = sched::sched_getaffinity(Pid::from_raw(0)).unwrap();
        let cpu = (0..sched::CpuSet::count())
            .find(|cpu| allowed.is_set(*cpu).unwrap_or(false))
            .unwrap();
        std::thread::spawn(move || {
            with_cpu_affinity(&cpu.to_string(), || {
                let current = sched::sched_getaffinity(Pid::from_raw(0)).unwrap();
                assert!(current.is_set(cpu).unwrap());
                assert_eq!(
                    (0..sched::CpuSet::count())
                        .filter(|candidate| current.is_set(*candidate).unwrap_or(false))
                        .count(),
                    1
                );
            });
            with_cpu_affinity("not-a-cpu", || {
                let current = sched::sched_getaffinity(Pid::from_raw(0)).unwrap();
                assert!(current.is_set(cpu).unwrap());
            });
        })
        .join()
        .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reader_inputs_use_seekable_sealed_memfd_with_pipe_fallback() {
        use std::io::{Cursor, Read, Seek, SeekFrom};

        let mut threads = Vec::new();
        let mut memfd = reader_to_host_file(
            Box::new(Cursor::new(b"seekable input".to_vec())),
            &mut threads,
            true,
        )
        .unwrap();
        assert!(memfd.metadata().unwrap().file_type().is_file());
        memfd.seek(SeekFrom::Start(9)).unwrap();
        let mut tail = String::new();
        memfd.read_to_string(&mut tail).unwrap();
        assert_eq!(tail, "input");
        assert!(memfd.write_all(b"x").is_err());

        let mut pipe_threads = Vec::new();
        let mut pipe = reader_to_host_file(
            Box::new(Cursor::new(b"pipe fallback".to_vec())),
            &mut pipe_threads,
            false,
        )
        .unwrap();
        assert!(!pipe.metadata().unwrap().file_type().is_file());
        let mut content = Vec::new();
        pipe.read_to_end(&mut content).unwrap();
        for thread in pipe_threads {
            thread.recv().unwrap();
        }
        assert_eq!(content, b"pipe fallback");
    }

    #[cfg(unix)]
    #[test]
    fn non_pipe_collectors_use_one_batched_environment_open() {
        let root =
            std::env::temp_dir().join(format!("envexec-collector-batch-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let env = Arc::new(FakeEnv {
            root: root.clone(),
            ..Default::default()
        });
        let mut cmd = unsafe_cmd_defaults(env.clone());
        cmd.files = vec![
            Some(File::collector("stdout", Size(1024), false)),
            Some(File::collector("stderr", Size(1024), false)),
        ];
        let prepared = prepare_files(&mut cmd, &test_store(root.clone())).unwrap();
        assert_eq!(*env.opened_batches.lock().unwrap(), [4]);
        assert_eq!(prepared.fds.len(), 2);
        drop(prepared);
        fs::remove_dir_all(root).unwrap();
    }
    struct Env {
        root: PathBuf,
        fail: bool,
    }
    impl Environment for Env {
        fn execve(&self, _: ExecveParam) -> io::Result<Box<dyn Process>> {
            Err(io::Error::other("execve is unused by this collector test"))
        }
        fn open(&self, p: &[OpenParam]) -> io::Result<Vec<OpenResult>> {
            if self.fail {
                return Err(io::Error::other("open failed"));
            }
            assert!(
                p.iter()
                    .all(|x| x.flag == 577 && x.perm == 0o777 && x.mkdir_all)
            );
            p.iter()
                .map(|x| {
                    let path = self.root.join(&x.path);
                    fs::create_dir_all(path.parent().unwrap())?;
                    Ok(OpenResult {
                        file: Some(
                            OpenOptions::new()
                                .write(true)
                                .create(true)
                                .truncate(true)
                                .open(path)?,
                        ),
                        error: None,
                    })
                })
                .collect()
        }
        fn symlink(&self, _: &[SymlinkParam]) -> io::Result<Vec<Option<String>>> {
            Ok(vec![])
        }
    }
    #[tokio::test]
    async fn single_async_runs_copyin_symlink_exec_and_copyout() {
        let root = std::env::temp_dir().join(format!("envexec-single-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("output.txt"), b"captured").unwrap();
        let env = Arc::new(FakeEnv {
            root: root.clone(),
            ..Default::default()
        });
        let cmd = Cmd {
            environment: env.clone(),
            copy_in: HashMap::from([(
                "input.txt".into(),
                File::reader(Cursor::new(b"input".to_vec())),
            )]),
            symlinks: HashMap::from([("alias".into(), "input.txt".into())]),
            args: vec!["/bin/true".into()],
            files: vec![Some(File::opened(HostFile::open("/dev/null").unwrap()))],
            copy_out: vec![CmdCopyOutFile {
                name: "output.txt".into(),
                optional: false,
            }],
            ..unsafe_cmd_defaults(env.clone())
        };
        let store_dir = root.join("store");
        fs::create_dir_all(&store_dir).unwrap();
        let result = Single {
            cmd,
            new_store_file: test_store(store_dir.clone()),
        }
        .run_with_cancel_async(|| false)
        .await
        .unwrap();
        assert_eq!(result.status, Status::Accepted);
        assert_eq!(fs::read(root.join("input.txt")).unwrap(), b"input");
        assert!(result.files.contains_key("output.txt"));
        assert_eq!(env.launched.lock().unwrap()[0].args, ["/bin/true"]);
        assert_eq!(env.links.lock().unwrap().len(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn async_single_wait_does_not_block_tokio_worker() {
        struct DelayedProcess(Arc<AtomicBool>);
        impl Process for DelayedProcess {
            fn done(&self) -> bool {
                self.0.load(Ordering::Acquire)
            }
            fn result(&self) -> RunnerResult {
                RunnerResult {
                    status: crate::runner::Status::Normal,
                    ..Default::default()
                }
            }
            fn usage(&self) -> Usage {
                Usage::default()
            }
            fn wait_timeout_async<'a>(
                &'a self,
                _: Duration,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
                let done = self.0.clone();
                Box::pin(async move {
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    done.store(true, Ordering::Release);
                })
            }
            fn cancel(&self) {
                self.0.store(true, Ordering::Release);
            }
        }
        struct DelayedEnvironment(Arc<AtomicBool>);
        impl Environment for DelayedEnvironment {
            fn execve(&self, _: ExecveParam) -> io::Result<Box<dyn Process>> {
                Ok(Box::new(DelayedProcess(self.0.clone())))
            }
            fn open(&self, _: &[OpenParam]) -> io::Result<Vec<OpenResult>> {
                Ok(vec![])
            }
            fn symlink(&self, _: &[SymlinkParam]) -> io::Result<Vec<Option<String>>> {
                Ok(vec![])
            }
        }

        let root = std::env::temp_dir().join(format!(
            "envexec-async-wait-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let done = Arc::new(AtomicBool::new(false));
        let env: Arc<dyn Environment> = Arc::new(DelayedEnvironment(done.clone()));
        let mut cmd = unsafe_cmd_defaults(env.clone());
        cmd.args = vec!["/bin/true".into()];
        cmd.files = vec![Some(File::opened(HostFile::open("/dev/null").unwrap()))];
        let store = test_store(root.clone());

        let ticked = Arc::new(AtomicBool::new(false));
        let ticked_task = ticked.clone();
        let timer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(5)).await;
            ticked_task.store(true, Ordering::Release);
        });
        let result = Single {
            cmd,
            new_store_file: store,
        }
        .run_with_cancel_async(|| false)
        .await
        .unwrap();
        timer.await.unwrap();
        assert_eq!(result.status, Status::Accepted);
        assert!(ticked.load(Ordering::Acquire));
        assert!(done.load(Ordering::Acquire));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn copyout_truncate_returns_bytes_from_start_of_store_file() {
        let root =
            std::env::temp_dir().join(format!("envexec-copyout-truncate-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("output.txt"), b"1234567890").unwrap();
        let env = Arc::new(FakeEnv {
            root: root.clone(),
            ..Default::default()
        });
        let mut cmd = unsafe_cmd_defaults(env.clone());
        cmd.args = vec!["/bin/true".into()];
        cmd.copy_out = vec![CmdCopyOutFile {
            name: "output.txt".into(),
            optional: false,
        }];
        cmd.copy_out_max = Size(5);
        cmd.copy_out_truncate = true;
        cmd.files = vec![Some(File::opened(HostFile::open("/dev/null").unwrap()))];
        let store_dir = root.join("store");
        fs::create_dir_all(&store_dir).unwrap();
        let result = Single {
            cmd,
            new_store_file: test_store(store_dir.clone()),
        }
        .run()
        .unwrap();
        assert_eq!(result.status, Status::FileError);
        let mut output = result.files.get("output.txt").unwrap().try_clone().unwrap();
        output.seek(SeekFrom::Start(0)).unwrap();
        let mut contents = Vec::new();
        output.read_to_end(&mut contents).unwrap();
        assert_eq!(contents, b"12345");
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn tty_collects_merged_output_from_a_shared_pty() {
        let root = std::env::temp_dir().join(format!("envexec-tty-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let env = Arc::new(FakeEnv {
            root: root.clone(),
            ..Default::default()
        });
        let cmd = Cmd {
            environment: env.clone(),
            args: vec!["write_output_to_stdout".into()],
            tty: true,
            files: vec![
                Some(File::reader(Cursor::new(b"input".to_vec()))),
                Some(File::collector("stdout", Size(1024), false)),
            ],
            ..unsafe_cmd_defaults(env)
        };
        let store_dir = root.join("store");
        fs::create_dir_all(&store_dir).unwrap();
        let result = Single {
            cmd,
            new_store_file: test_store(store_dir.clone()),
        }
        .run()
        .unwrap();
        assert_eq!(result.status, Status::Accepted);
        let mut output_file = result.files.get("stdout").unwrap().try_clone().unwrap();
        std::io::Seek::seek(&mut output_file, std::io::SeekFrom::Start(0)).unwrap();
        let mut output = Vec::new();
        output_file.read_to_end(&mut output).unwrap();
        // PTY input is echoed concurrently with the fake workload's output,
        // so either ordering is valid while both streams must be captured.
        assert!(output.windows(5).any(|part| part == b"input"));
        assert!(output.windows(5).any(|part| part == b"hello"));
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn pty_resize_updates_window_size_with_tiocswinsz() {
        let pair = nix::pty::openpty(None, None).unwrap();
        let master = HostFile::from(pair.master);
        let slave = HostFile::from(pair.slave);
        set_pty_window_size(
            master.as_raw_fd(),
            TerminalSize {
                rows: 37,
                cols: 119,
                x: 951,
                y: 681,
            },
        )
        .unwrap();
        let mut actual = unsafe { std::mem::zeroed::<libc::winsize>() };
        assert_eq!(
            unsafe { libc::ioctl(slave.as_raw_fd(), libc::TIOCGWINSZ, &mut actual) },
            0
        );
        assert_eq!(
            (
                actual.ws_row,
                actual.ws_col,
                actual.ws_xpixel,
                actual.ws_ypixel
            ),
            (37, 119, 951, 681)
        );
    }

    #[cfg(unix)]
    #[test]
    fn tty_resize_listener_stops_when_command_finishes_with_sender_alive() {
        let root =
            std::env::temp_dir().join(format!("envexec-tty-resize-stop-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let env = Arc::new(FakeEnv {
            root: root.clone(),
            ..Default::default()
        });
        let (resize_tx, resize_rx) = std::sync::mpsc::channel();
        let mut cmd = unsafe_cmd_defaults(env.clone());
        cmd.args = vec!["write_output".into()];
        cmd.tty = true;
        cmd.terminal_resize = Some(Arc::new(Mutex::new(resize_rx)));
        cmd.files = vec![Some(File::collector("stdout", Size(1024), false))];
        let result = Single {
            cmd,
            new_store_file: test_store(root.clone()),
        }
        .run()
        .unwrap();
        assert_eq!(result.status, Status::Accepted, "{}", result.error);
        drop(resize_tx);
        fs::remove_dir_all(root).unwrap();
    }
    fn unsafe_cmd_defaults(env: Arc<dyn Environment>) -> Cmd {
        Cmd {
            environment: env,
            copy_in: HashMap::new(),
            symlinks: HashMap::new(),
            args: vec![],
            env: vec![],
            files: vec![],
            tty: false,
            terminal_resize: None,
            time_limit: Duration::ZERO,
            clock_limit: Duration::ZERO,
            memory_limit: Size(0),
            stack_limit: Size(0),
            extra_memory_limit: Size(0),
            output_limit: Size(0),
            proc_limit: 0,
            open_file_limit: 0,
            cpu_rate_limit: 0,
            cpu_set_limit: String::new(),
            copy_out: vec![],
            copy_out_max: Size(0),
            copy_out_truncate: false,
            address_space_limit: false,
            data_segment_limit: false,
        }
    }

    #[cfg(unix)]
    #[test]
    fn single_writer_pipe_finishes_after_command_fds_close() {
        struct SharedWriter(Arc<Mutex<Vec<u8>>>);
        impl Write for SharedWriter {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let root = std::env::temp_dir().join(format!("envexec-writer-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let output = Arc::new(Mutex::new(Vec::new()));
        let env = Arc::new(FakeEnv {
            root: root.clone(),
            ..Default::default()
        });
        let mut cmd = unsafe_cmd_defaults(env);
        cmd.args = vec!["write_output".into()];
        cmd.files = vec![Some(File::writer(SharedWriter(output.clone()), Size(5)))];
        let result = Single {
            cmd,
            new_store_file: test_store(root.clone()),
        }
        .run()
        .unwrap();
        assert_eq!(result.status, Status::Accepted);
        assert_eq!(*output.lock().unwrap(), b"hello");
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn async_group_connects_command_descriptors_with_a_direct_pipe() {
        use std::sync::Mutex;
        struct PipeEnv(Arc<Mutex<Vec<u8>>>);
        impl Environment for PipeEnv {
            fn execve(&self, p: ExecveParam) -> io::Result<Box<dyn Process>> {
                use std::os::fd::RawFd;
                let fd = *p
                    .files
                    .first()
                    .ok_or_else(|| io::Error::other("missing fd"))?
                    as RawFd;
                if p.args.first().map(String::as_str) == Some("write") {
                    let data = b"hello";
                    // SAFETY: fd is the held writer end supplied in ExecveParam and data is valid.
                    let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
                    if n < 0 {
                        return Err(io::Error::last_os_error());
                    }
                } else {
                    let mut data = [0u8; 5];
                    // SAFETY: fd is the held reader end supplied in ExecveParam and data is writable.
                    let n = unsafe { libc::read(fd, data.as_mut_ptr().cast(), data.len()) };
                    if n < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    self.0
                        .lock()
                        .unwrap()
                        .extend_from_slice(&data[..n as usize]);
                }
                Ok(Box::new(CompletedProcess))
            }
            fn open(&self, _: &[OpenParam]) -> io::Result<Vec<OpenResult>> {
                Ok(vec![])
            }
            fn symlink(&self, _: &[SymlinkParam]) -> io::Result<Vec<Option<String>>> {
                Ok(vec![])
            }
        }
        fn make_cmd(env: Arc<dyn Environment>, arg: &str) -> Cmd {
            let mut c = unsafe_cmd_defaults(env);
            c.args = vec![arg.into()];
            c.files = vec![None];
            c
        }
        let root = std::env::temp_dir().join(format!("envexec-group-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let observed = Arc::new(Mutex::new(Vec::new()));
        let env = Arc::new(PipeEnv(observed.clone()));
        let group = Group {
            commands: vec![make_cmd(env.clone(), "write"), make_cmd(env, "read")],
            pipes: vec![PipeMapping {
                input: PipeIndex { index: 0, fd: 0 },
                output: PipeIndex { index: 1, fd: 0 },
                ..Default::default()
            }],
            new_store_file: test_store(root.clone()),
        };
        let results = group.run_with_cancel_async(|| false).await.unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(*observed.lock().unwrap(), b"hello");
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn async_group_proxy_pipe_relays_data_in_copy_and_splice_modes() {
        use std::sync::Mutex;
        const DATA_LEN: usize = 256 * 1024;
        struct ProxyEnv(Arc<Mutex<Vec<u8>>>);
        impl Environment for ProxyEnv {
            fn execve(&self, p: ExecveParam) -> io::Result<Box<dyn Process>> {
                use std::os::fd::RawFd;
                let fd = *p
                    .files
                    .first()
                    .ok_or_else(|| io::Error::other("missing fd"))?
                    as RawFd;
                if p.args.first().map(String::as_str) == Some("write") {
                    let data = vec![b'x'; DATA_LEN];
                    let mut offset = 0;
                    while offset < data.len() {
                        let n = unsafe {
                            libc::write(fd, data[offset..].as_ptr().cast(), data.len() - offset)
                        };
                        if n < 0 {
                            return Err(io::Error::last_os_error());
                        }
                        offset += n as usize;
                    }
                } else {
                    let mut data = vec![0u8; 8192];
                    loop {
                        let n = unsafe { libc::read(fd, data.as_mut_ptr().cast(), data.len()) };
                        if n < 0 {
                            return Err(io::Error::last_os_error());
                        }
                        if n == 0 {
                            break;
                        }
                        self.0
                            .lock()
                            .unwrap()
                            .extend_from_slice(&data[..n as usize]);
                    }
                }
                Ok(Box::new(CompletedProcess))
            }
            fn open(&self, _: &[OpenParam]) -> io::Result<Vec<OpenResult>> {
                Ok(vec![])
            }
            fn symlink(&self, _: &[SymlinkParam]) -> io::Result<Vec<Option<String>>> {
                Ok(vec![])
            }
        }
        fn cmd(env: Arc<dyn Environment>, arg: &str) -> Cmd {
            let mut command = unsafe_cmd_defaults(env);
            command.args = vec![arg.into()];
            command.files = vec![None];
            command
        }
        let root = std::env::temp_dir().join(format!("envexec-proxy-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        for disable_zero_copy in [true, false] {
            let received = Arc::new(Mutex::new(Vec::new()));
            let env: Arc<dyn Environment> = Arc::new(ProxyEnv(received.clone()));
            let results = Group {
                commands: vec![cmd(env.clone(), "write"), cmd(env, "read")],
                pipes: vec![PipeMapping {
                    input: PipeIndex { index: 0, fd: 0 },
                    output: PipeIndex { index: 1, fd: 0 },
                    proxy: true,
                    disable_zero_copy,
                    ..Default::default()
                }],
                new_store_file: test_store(root.clone()),
            }
            .run_with_cancel_async(|| false)
            .await
            .unwrap();
            assert!(
                results
                    .iter()
                    .all(|result| result.status == Status::Accepted)
            );
            assert_eq!(received.lock().unwrap().len(), DATA_LEN);
            assert!(received.lock().unwrap().iter().all(|byte| *byte == b'x'));
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn output_pipe_limits_collection_and_drains_to_eof() {
        let relay = new_pipe(Vec::<u8>::new(), Size(3)).unwrap();
        let mut child = relay.write_end.as_ref().unwrap().try_clone().unwrap();
        child.write_all(b"abcde").unwrap();
        drop(child);
        assert_eq!(relay.wait().unwrap(), 3);
    }

    #[test]
    fn statuses_match_go_ordinals_and_names() {
        assert_eq!(Status::InternalError as i32, 13);
        assert_eq!(
            Status::from_name("Dangerous Syscall").unwrap(),
            Status::DangerousSyscall
        );
        assert!(Status::from_name("unknown").is_err());
    }
    #[test]
    fn file_errors_preserve_json_names() {
        assert_eq!(FileErrorType::Symlink.as_str(), "Symlink");
        assert_eq!(FileErrorType::CopyOutSizeExceeded as i32, 6);
    }
    #[test]
    fn copyin_copies_reader_content_into_container_file() {
        let root = std::env::temp_dir().join(format!("rust-sandbox-copyin-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let env = Env {
            root: root.clone(),
            fail: false,
        };
        let input = [(
            "nested/data.txt".to_string(),
            File::reader(Cursor::new(b"payload".to_vec())),
        )]
        .into_iter()
        .collect();
        let (errors, result) = copy_in(&env, input);
        assert!(result.is_ok());
        assert!(errors.is_empty());
        assert_eq!(fs::read(root.join("nested/data.txt")).unwrap(), b"payload");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn copyin_batch_failure_returns_one_error_per_path() {
        let e = Env {
            root: std::env::temp_dir(),
            fail: true,
        };
        let input = [
            ("a", File::reader(Cursor::new(b"a".to_vec()))),
            ("b", File::reader(Cursor::new(b"b".to_vec()))),
        ]
        .into_iter()
        .map(|(n, f)| (n.to_string(), f))
        .collect();
        let (errors, err) = copy_in(&e, input);
        assert!(err.is_err());
        assert_eq!(errors.len(), 2);
        assert!(
            errors
                .iter()
                .all(|x| x.kind == FileErrorType::CopyInCreateFile && x.message == "open failed")
        );
    }

    #[test]
    fn copyin_missing_source_is_classified_as_open_error() {
        let root = std::env::temp_dir().join(format!(
            "rust-sandbox-copyin-missing-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let env = Env {
            root: root.clone(),
            fail: false,
        };
        let input = [("missing".to_string(), File::input(root.join("not-present")))]
            .into_iter()
            .collect();
        let (errors, result) = copy_in(&env, input);
        assert!(result.is_err());
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].name, "missing");
        assert_eq!(errors[0].kind, FileErrorType::CopyInOpenFile);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn over_limit_collector_reports_collect_size_file_error() {
        let root = std::env::temp_dir().join(format!(
            "rust-sandbox-collector-limit-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let buffer_path = root.join("buffer");
        fs::write(&buffer_path, b"12345").unwrap();
        let buffer = OpenOptions::new()
            .read(true)
            .write(true)
            .open(buffer_path)
            .unwrap();
        let env: Arc<dyn Environment> = Arc::new(FakeEnv {
            root: root.clone(),
            ..Default::default()
        });
        let cmd = unsafe_cmd_defaults(env);
        let mut prepared = Prepared {
            fds: Vec::new(),
            relays: Vec::new(),
            collectors: vec![CollectorJob {
                name: "stdout".into(),
                limit: Size(3),
                buffer,
                relay: None,
            }],
            reader_threads: Vec::new(),
            resize_stop: None,
        };
        let mut result = CmdResult {
            status: Status::Accepted,
            ..Default::default()
        };
        collect_outputs(&cmd, &test_store(root.clone()), &mut prepared, &mut result).unwrap();
        assert_eq!(result.status, Status::OutputLimitExceeded);
        let error = result.file_errors.first().unwrap();
        assert_eq!(error.name, "stdout");
        assert_eq!(error.kind, FileErrorType::CollectSizeExceeded);
        assert_eq!(error.message, Status::OutputLimitExceeded.to_string());
        assert_eq!(result.files["stdout"].metadata().unwrap().len(), 4);
        fs::remove_dir_all(root).unwrap();
    }
}
