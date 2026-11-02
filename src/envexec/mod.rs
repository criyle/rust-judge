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

mod command;
mod copy_in;
mod group;

use command::*;
pub use copy_in::copy_in;
use group::*;
pub use group::{
    Group, PipeIndex, PipeMapping, PipeRelay, Single, file_to_reader, new_pipe, open_host,
};

#[cfg(test)]
mod tests;
