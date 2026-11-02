//! Linux cgroup and environment-builder abstractions.
//!
//! These interfaces mirror the Go backend. A concrete mount namespace/cgroup
//! implementation still has to connect them to `rust-sandbox`'s container and
//! fork-exec primitives.

use std::fmt;
use std::fs;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::{
    collections::VecDeque,
    sync::mpsc::{self, Receiver, SyncSender},
    thread::JoinHandle,
};

#[derive(Debug)]
pub enum EnvError {
    Io(std::io::Error),
    Unsupported(&'static str),
    Poisoned,
    Backend(String),
}
impl fmt::Display for EnvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => e.fmt(f),
            Self::Unsupported(m) => write!(f, "unsupported: {m}"),
            Self::Poisoned => f.write_str("environment pool lock poisoned"),
            Self::Backend(m) => f.write_str(m),
        }
    }
}
impl std::error::Error for EnvError {}
impl From<std::io::Error> for EnvError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

pub trait Cgroup: Send {
    fn set_cpuset(&mut self, cpus: &str) -> Result<(), EnvError>;
    fn set_memory_limit(&mut self, bytes: u64) -> Result<(), EnvError>;
    fn set_proc_limit(&mut self, count: u64) -> Result<(), EnvError>;
    /// Go expresses rate as 1000 = 1 CPU.
    fn set_cpu_rate(&mut self, rate: u64, period: Duration) -> Result<(), EnvError>;
    fn cpu_usage(&self) -> Result<Duration, EnvError>;
    fn current_memory(&self) -> Result<u64, EnvError>;
    fn max_memory(&self) -> Result<u64, EnvError>;
    fn proc_peak(&self) -> Result<u64, EnvError>;
    fn set_cpuacct_usage(&mut self, _value: u64) -> Result<(), EnvError> {
        Err(EnvError::Unsupported("cpuacct usage is unavailable"))
    }
    fn set_memory_max_usage(&mut self, _value: u64) -> Result<(), EnvError> {
        Err(EnvError::Unsupported(
            "memory max usage reset is unavailable",
        ))
    }
    fn memory_memsw_max_usage(&self) -> Result<u64, EnvError> {
        Err(EnvError::Unsupported("memory memsw is unavailable"))
    }
    fn set_memory_memsw_limit(&mut self, _value: u64) -> Result<(), EnvError> {
        Err(EnvError::Unsupported("memory memsw is unavailable"))
    }
    fn set_cpu_cfs_period(&mut self, _period_us: u64) -> Result<(), EnvError> {
        Err(EnvError::Unsupported(
            "cgroup v1 CPU controller is unavailable",
        ))
    }
    fn set_cpu_cfs_quota(&mut self, _quota_us: u64) -> Result<(), EnvError> {
        Err(EnvError::Unsupported(
            "cgroup v1 CPU controller is unavailable",
        ))
    }
    fn set_cpuset_mems(&mut self, _mems: &str) -> Result<(), EnvError> {
        Err(EnvError::Unsupported(
            "cgroup cpuset controller is unavailable",
        ))
    }
    fn memory_stat_property(&self, _property: &str) -> Result<u64, EnvError> {
        Err(EnvError::Unsupported(
            "cgroup v1 memory controller is unavailable",
        ))
    }
    fn add_process(&mut self, pid: u32) -> Result<(), EnvError>;
    /// List process IDs directly recorded in this cgroup.
    fn processes(&self) -> Result<Vec<u32>, EnvError>;
    /// Whether this handle refers to a group that already existed when opened.
    fn existing(&self) -> bool;
    /// Create or open a named child cgroup.
    fn new_child(&self, name: &str) -> Result<Box<dyn Cgroup>, EnvError>;
    /// Create a child, then move the processes currently in this cgroup into it.
    fn nest(&self, name: &str) -> Result<Box<dyn Cgroup>, EnvError>;
    fn reset(&mut self) -> Result<(), EnvError>;
    fn destroy(self: Box<Self>) -> Result<(), EnvError>;
    fn open(&self) -> Result<OwnedFd, EnvError>;
    /// Open membership files used to enroll a child before it execs.
    /// Unified cgroups open `cgroup.procs` relative to their directory fd;
    /// v1 returns one membership file per mounted controller.
    fn open_procs(&self) -> Result<Vec<OwnedFd>, EnvError> {
        let directory = self.open()?;
        let name = b"cgroup.procs\0";
        // SAFETY: `directory` is an open cgroup directory and `name` is a
        // static NUL-terminated relative path. The returned descriptor is
        // owned exactly once below.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr().cast(),
                libc::O_WRONLY | libc::O_CLOEXEC,
            )
        };
        if fd == -1 {
            Err(std::io::Error::last_os_error().into())
        } else {
            // SAFETY: `openat` returned a new owned file descriptor.
            Ok(vec![unsafe { OwnedFd::from_raw_fd(fd) }])
        }
    }
}

pub trait CgroupBuilder: Send + Sync {
    fn random(&self, prefix: &str) -> Result<Box<dyn Cgroup>, EnvError>;
    fn open_existing(&self, name: &str) -> Result<Box<dyn Cgroup>, EnvError>;
}

pub(crate) fn validate_cgroup_name(name: &str) -> Result<(), EnvError> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\0') {
        return Err(EnvError::Backend(format!("invalid cgroup name {name:?}")));
    }
    Ok(())
}
pub trait CgroupPool: Send + Sync {
    fn get(&self) -> Result<CgroupLease, EnvError>;
    fn put(&self, cgroup: CgroupLease);
    fn shutdown(&self) -> Result<(), EnvError>;
}

/// A cgroup checked out for one command. `slot` is set for a cgroup owned by
/// a bounded pool slot and absent for a one-off overflow allocation.
pub struct CgroupLease {
    cgroup: Option<Box<dyn Cgroup>>,
    slot: Option<usize>,
}

impl CgroupLease {
    /// Wrap a cgroup returned by a custom pool implementation.
    pub fn new(cgroup: Box<dyn Cgroup>) -> Self {
        Self::standalone(cgroup)
    }

    fn pooled(cgroup: Box<dyn Cgroup>, slot: usize) -> Self {
        Self {
            cgroup: Some(cgroup),
            slot: Some(slot),
        }
    }

    fn standalone(cgroup: Box<dyn Cgroup>) -> Self {
        Self {
            cgroup: Some(cgroup),
            slot: None,
        }
    }

    fn into_parts(mut self) -> (Box<dyn Cgroup>, Option<usize>) {
        (
            self.cgroup.take().expect("cgroup lease consumed once"),
            self.slot,
        )
    }
}

impl std::ops::Deref for CgroupLease {
    type Target = dyn Cgroup;

    fn deref(&self) -> &Self::Target {
        self.cgroup.as_deref().expect("live cgroup lease")
    }
}

impl std::ops::DerefMut for CgroupLease {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.cgroup.as_deref_mut().expect("live cgroup lease")
    }
}

mod cgroup_v2;
pub use cgroup_v2::{
    CgroupV2, CgroupV2Builder, prepare_cgroup_v2_hierarchy, prepare_cgroup_v2_systemd_scope,
};
pub(crate) use cgroup_v2::{read_processes, safe_cgroup_relative_path};

#[derive(Clone, Debug, Default)]
pub struct Config {
    pub work_dir: String,
    pub cpu_rate: bool,
    pub cgroup_fd: bool,
    pub seccomp_filter: Vec<libc::sock_filter>,
}

#[derive(Clone, Debug, Default)]
pub struct ExecutionLimits {
    pub time: Duration,
    pub memory_bytes: u64,
    pub process_count: u64,
    pub output_bytes: u64,
    pub stack_bytes: u64,
    pub open_files: u64,
    pub cpu_rate: u64,
    pub cpu_set: String,
    pub data_segment: bool,
    pub address_space: bool,
}

/// Translate Go's linuxcontainer `Execve` limits into fork-exec rlimits.
/// Cgroup memory enforcement replaces RLIMIT_DATA unless explicitly requested.
pub fn resource_limits(
    limits: &ExecutionLimits,
    cgroup_enabled: bool,
) -> crate::container::rlimit::RLimits {
    crate::container::rlimit::RLimits {
        cpu: limits.time.as_secs().saturating_add(1),
        data: if limits.data_segment || !cgroup_enabled {
            limits.memory_bytes
        } else {
            0
        },
        file_size: limits.output_bytes,
        stack: limits.stack_bytes,
        address_space: if limits.address_space {
            limits.memory_bytes
        } else {
            0
        },
        open_file: limits.open_files,
        disable_core: true,
        ..Default::default()
    }
}

/// Apply the cgroup controls that Go's linuxcontainer backend sets before exec.
/// Optional controller errors should be ignored by the concrete cgroup
/// implementation when that controller is unavailable, matching Go's
/// ErrNotInitialized/ENOENT behavior.
pub fn set_cgroup_limits(
    cgroup: &mut dyn Cgroup,
    limits: &ExecutionLimits,
    cpu_rate_enabled: bool,
    period: Duration,
) -> Result<(), EnvError> {
    if !limits.cpu_set.is_empty() {
        ignore_unavailable_controller(cgroup.set_cpuset(&limits.cpu_set))?;
    }
    if cpu_rate_enabled && limits.cpu_rate > 0 {
        ignore_unavailable_controller(cgroup.set_cpu_rate(limits.cpu_rate, period))?;
    }
    ignore_unavailable_controller(cgroup.set_memory_limit(limits.memory_bytes))?;
    ignore_unavailable_controller(cgroup.set_proc_limit(limits.process_count))?;
    Ok(())
}

fn ignore_unavailable_controller(result: Result<(), EnvError>) -> Result<(), EnvError> {
    match result {
        Err(EnvError::Unsupported(_)) => Ok(()),
        Err(EnvError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

/// Platform factory implemented by the mount/container layer.
pub trait ContainerFactory: Send + Sync {
    type Environment: Send;
    fn build_container(&self) -> Result<Self::Environment, EnvError>;
}

pub struct EnvironmentBuilder<F: ContainerFactory> {
    factory: F,
    config: Config,
}
impl<F: ContainerFactory> EnvironmentBuilder<F> {
    pub fn new(factory: F, config: Config) -> Self {
        Self { factory, config }
    }
    pub fn build(&self) -> Result<(F::Environment, Config), EnvError> {
        let env = self.factory.build_container()?;
        Ok((env, self.config.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::Size;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn maps_go_limits_to_rlimits_and_cgroup_ownership() {
        let limits = ExecutionLimits {
            time: Duration::from_millis(1500),
            memory_bytes: Size(64 << 20).byte(),
            output_bytes: 4096,
            stack_bytes: 8192,
            open_files: 32,
            ..Default::default()
        };
        let with_cgroup = resource_limits(&limits, true).prepare();
        let without_cgroup = resource_limits(&limits, false).prepare();
        assert_eq!(with_cgroup[0].soft, 2);
        assert!(
            !with_cgroup
                .iter()
                .any(|l| l.resource == nix::sys::resource::Resource::RLIMIT_DATA)
        );
        assert!(
            without_cgroup
                .iter()
                .any(|l| l.resource == nix::sys::resource::Resource::RLIMIT_DATA
                    && l.soft == 64 << 20)
        );
        assert!(
            with_cgroup
                .iter()
                .any(|l| l.resource == nix::sys::resource::Resource::RLIMIT_CORE)
        );
    }

    struct PartialControllerCgroup(AtomicUsize);

    impl Cgroup for PartialControllerCgroup {
        fn set_cpuset(&mut self, _: &str) -> Result<(), EnvError> {
            Err(EnvError::Unsupported("cpuset controller is not mounted"))
        }
        fn set_memory_limit(&mut self, _: u64) -> Result<(), EnvError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn set_proc_limit(&mut self, _: u64) -> Result<(), EnvError> {
            Err(EnvError::Io(std::io::Error::from(
                std::io::ErrorKind::NotFound,
            )))
        }
        fn set_cpu_rate(&mut self, _: u64, _: Duration) -> Result<(), EnvError> {
            Err(EnvError::Unsupported("cpu controller is not mounted"))
        }
        fn cpu_usage(&self) -> Result<Duration, EnvError> {
            unreachable!()
        }
        fn current_memory(&self) -> Result<u64, EnvError> {
            unreachable!()
        }
        fn max_memory(&self) -> Result<u64, EnvError> {
            unreachable!()
        }
        fn proc_peak(&self) -> Result<u64, EnvError> {
            unreachable!()
        }
        fn add_process(&mut self, _: u32) -> Result<(), EnvError> {
            unreachable!()
        }
        fn processes(&self) -> Result<Vec<u32>, EnvError> {
            unreachable!()
        }
        fn existing(&self) -> bool {
            unreachable!()
        }
        fn new_child(&self, _: &str) -> Result<Box<dyn Cgroup>, EnvError> {
            unreachable!()
        }
        fn nest(&self, _: &str) -> Result<Box<dyn Cgroup>, EnvError> {
            unreachable!()
        }
        fn reset(&mut self) -> Result<(), EnvError> {
            unreachable!()
        }
        fn destroy(self: Box<Self>) -> Result<(), EnvError> {
            unreachable!()
        }
        fn open(&self) -> Result<OwnedFd, EnvError> {
            unreachable!()
        }
    }

    #[test]
    fn unavailable_controllers_do_not_disable_available_cgroup_limits() {
        let mut cgroup = PartialControllerCgroup(AtomicUsize::new(0));
        set_cgroup_limits(
            &mut cgroup,
            &ExecutionLimits {
                cpu_set: "0-1".into(),
                cpu_rate: 500,
                memory_bytes: 1024,
                process_count: 4,
                ..Default::default()
            },
            true,
            Duration::from_millis(100),
        )
        .unwrap();
        assert_eq!(cgroup.0.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn real_cgroup_controller_errors_are_not_treated_as_optional() {
        let error = EnvError::Io(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        assert!(matches!(
            ignore_unavailable_controller(Err(error)),
            Err(EnvError::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied
        ));
    }
}

pub struct ListCgroupPool {
    builder: Box<dyn CgroupBuilder>,
    cfs_period: Duration,
    idle: std::sync::Mutex<Vec<Box<dyn Cgroup>>>,
}
impl ListCgroupPool {
    pub fn new(builder: Box<dyn CgroupBuilder>, cfs_period: Duration) -> Self {
        Self {
            builder,
            cfs_period,
            idle: std::sync::Mutex::new(Vec::new()),
        }
    }
    pub fn cfs_period(&self) -> Duration {
        self.cfs_period
    }
}
impl CgroupPool for ListCgroupPool {
    fn get(&self) -> Result<CgroupLease, EnvError> {
        if let Some(cg) = self.idle.lock().map_err(|_| EnvError::Poisoned)?.pop() {
            return Ok(CgroupLease::new(cg));
        }
        self.builder.random("").map(CgroupLease::new)
    }
    fn put(&self, cgroup: CgroupLease) {
        let (mut cgroup, _) = cgroup.into_parts();
        if cgroup.reset().is_err() {
            let _ = cgroup.destroy();
            return;
        }
        if let Ok(mut idle) = self.idle.lock() {
            idle.push(cgroup);
        } else {
            let _ = cgroup.destroy();
        }
    }
    fn shutdown(&self) -> Result<(), EnvError> {
        let idle = std::mem::take(&mut *self.idle.lock().map_err(|_| EnvError::Poisoned)?);
        let mut first_error = None;
        for cg in idle {
            if let Err(err) = cg.destroy() {
                first_error.get_or_insert(err);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

/// Creates a fresh execution cgroup for every request and destroys it when
/// the process finishes. go-judge's production Linux environment uses this
/// lifecycle so per-run CPU accounting starts at zero; v2 `cpu.stat` cannot be
/// reset on a reused cgroup.
pub struct FreshCgroupPool {
    builder: Box<dyn CgroupBuilder>,
}

impl FreshCgroupPool {
    pub fn new(builder: Box<dyn CgroupBuilder>) -> Self {
        Self { builder }
    }
}

impl CgroupPool for FreshCgroupPool {
    fn get(&self) -> Result<CgroupLease, EnvError> {
        self.builder.random("").map(CgroupLease::new)
    }

    fn put(&self, cgroup: CgroupLease) {
        let (cgroup, _) = cgroup.into_parts();
        let _ = cgroup.destroy();
    }

    fn shutdown(&self) -> Result<(), EnvError> {
        Ok(())
    }
}

struct AsyncCgroupState {
    idle: VecDeque<(usize, Box<dyn Cgroup>)>,
    slots: Vec<AsyncCgroupSlot>,
    stopped: bool,
    error: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AsyncCgroupSlot {
    Starting,
    Idle,
    Leased,
    Recycling,
    Failed,
    Stopped,
}

enum AsyncCgroupMessage {
    Returned(Box<dyn Cgroup>),
    Stop,
}

/// Keeps a bounded set of fresh cgroups ready and replaces returned cgroups
/// on background workers. If every warm slot is leased, `get` creates a
/// one-off cgroup synchronously so a multi-command request cannot wait for one
/// of its own processes to finish before it can start the rest.
pub struct AsyncFreshCgroupPool {
    builder: Arc<dyn CgroupBuilder>,
    state: Arc<Mutex<AsyncCgroupState>>,
    ready: Arc<std::sync::Condvar>,
    put_lock: Mutex<()>,
    releases: Vec<SyncSender<AsyncCgroupMessage>>,
    workers: Mutex<Vec<JoinHandle<()>>>,
}

impl AsyncFreshCgroupPool {
    pub fn new(builder: Box<dyn CgroupBuilder>, worker_count: usize) -> Self {
        let worker_count = worker_count.max(1);
        let builder: Arc<dyn CgroupBuilder> = Arc::from(builder);
        let pool = Self {
            builder: builder.clone(),
            state: Arc::new(Mutex::new(AsyncCgroupState {
                idle: VecDeque::with_capacity(worker_count),
                slots: vec![AsyncCgroupSlot::Starting; worker_count],
                stopped: false,
                error: None,
            })),
            ready: Arc::new(std::sync::Condvar::new()),
            put_lock: Mutex::new(()),
            releases: Vec::with_capacity(worker_count),
            workers: Mutex::new(Vec::with_capacity(worker_count)),
        };

        let mut releases = Vec::with_capacity(worker_count);
        let mut workers = Vec::with_capacity(worker_count);
        for slot in 0..worker_count {
            let (release_tx, release_rx) = mpsc::sync_channel(1);
            let builder = builder.clone();
            let state = pool.state.clone();
            let ready = pool.ready.clone();
            let worker = thread::spawn(move || {
                async_cgroup_worker(slot, builder, release_rx, state, ready);
            });
            releases.push(release_tx);
            workers.push(worker);
        }
        let mut pool = pool;
        pool.releases = releases;
        *pool.workers.lock().expect("new cgroup worker mutex") = workers;
        pool
    }

    fn shutdown_inner(&self) -> Result<(), EnvError> {
        let _put_guard = self.put_lock.lock().map_err(|_| EnvError::Poisoned)?;
        let idle = {
            let mut state = self.state.lock().map_err(|_| EnvError::Poisoned)?;
            state.stopped = true;
            self.ready.notify_all();
            for slot in &mut state.slots {
                if !matches!(*slot, AsyncCgroupSlot::Leased | AsyncCgroupSlot::Recycling) {
                    *slot = AsyncCgroupSlot::Stopped;
                }
            }
            std::mem::take(&mut state.idle)
        };
        let mut first_error = None;
        for (_, cgroup) in idle {
            if let Err(error) = cgroup.destroy() {
                first_error.get_or_insert(error);
            }
        }
        for sender in &self.releases {
            let _ = sender.send(AsyncCgroupMessage::Stop);
        }
        for worker in self
            .workers
            .lock()
            .map_err(|_| EnvError::Poisoned)?
            .drain(..)
        {
            if worker.join().is_err() && first_error.is_none() {
                first_error = Some(EnvError::Backend("cgroup worker panicked".into()));
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl CgroupPool for AsyncFreshCgroupPool {
    fn get(&self) -> Result<CgroupLease, EnvError> {
        let mut state = self.state.lock().map_err(|_| EnvError::Poisoned)?;
        loop {
            if let Some((slot, cgroup)) = state.idle.pop_front() {
                state.slots[slot] = AsyncCgroupSlot::Leased;
                // Other waiters may now observe that every warm slot is
                // leased and need to switch to one-off overflow creation.
                self.ready.notify_all();
                return Ok(CgroupLease::pooled(cgroup, slot));
            }
            if state.stopped {
                return Err(EnvError::Backend("cgroup pool is shut down".into()));
            }
            if let Some(error) = state.error.as_ref() {
                return Err(EnvError::Backend(error.clone()));
            }
            if state
                .slots
                .iter()
                .all(|slot| *slot == AsyncCgroupSlot::Leased)
            {
                // Every warm slot is held by a live command. Groups may
                // contain more commands than the server worker count, so
                // allocate an overflow cgroup instead of waiting for a
                // command in the same group to finish and deadlocking pipes.
                drop(state);
                return self.builder.random("").map(CgroupLease::new);
            }
            state = self.ready.wait(state).map_err(|_| EnvError::Poisoned)?;
        }
    }

    fn put(&self, cgroup: CgroupLease) {
        let (cgroup, slot) = cgroup.into_parts();
        let Ok(_put_guard) = self.put_lock.lock() else {
            let _ = cgroup.destroy();
            return;
        };
        let Some(slot) = slot else {
            // Overflow cgroups do not occupy a warm-pool slot and must not
            // trigger a replacement cgroup.
            let _ = cgroup.destroy();
            return;
        };
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => {
                let _ = cgroup.destroy();
                return;
            }
        };
        if state.stopped || state.slots.get(slot) != Some(&AsyncCgroupSlot::Leased) {
            drop(state);
            let _ = cgroup.destroy();
            return;
        }
        state.slots[slot] = AsyncCgroupSlot::Recycling;
        drop(state);

        let sender = &self.releases[slot];
        if let Err(error) = sender.try_send(AsyncCgroupMessage::Returned(cgroup)) {
            let cgroup = match error {
                mpsc::TrySendError::Full(AsyncCgroupMessage::Returned(cgroup))
                | mpsc::TrySendError::Disconnected(AsyncCgroupMessage::Returned(cgroup)) => cgroup,
                mpsc::TrySendError::Full(AsyncCgroupMessage::Stop)
                | mpsc::TrySendError::Disconnected(AsyncCgroupMessage::Stop) => return,
            };
            if let Ok(mut state) = self.state.lock() {
                state.slots[slot] = AsyncCgroupSlot::Failed;
                state
                    .error
                    .get_or_insert_with(|| "cgroup worker stopped".into());
                self.ready.notify_all();
            }
            let _ = cgroup.destroy();
        }
    }

    fn shutdown(&self) -> Result<(), EnvError> {
        self.shutdown_inner()
    }
}

impl Drop for AsyncFreshCgroupPool {
    fn drop(&mut self) {
        let _ = self.shutdown_inner();
    }
}

fn async_cgroup_worker(
    slot: usize,
    builder: Arc<dyn CgroupBuilder>,
    releases: Receiver<AsyncCgroupMessage>,
    state: Arc<Mutex<AsyncCgroupState>>,
    ready: Arc<std::sync::Condvar>,
) {
    loop {
        let cgroup = match builder.random("") {
            Ok(cgroup) => cgroup,
            Err(error) => {
                if let Ok(mut state) = state.lock() {
                    state.error.get_or_insert_with(|| error.to_string());
                    state.slots[slot] = AsyncCgroupSlot::Failed;
                    ready.notify_all();
                }
                drain_cgroup_releases(&releases);
                return;
            }
        };
        {
            let mut state = match state.lock() {
                Ok(state) => state,
                Err(_) => {
                    let _ = cgroup.destroy();
                    drain_cgroup_releases(&releases);
                    return;
                }
            };
            if state.stopped {
                drop(state);
                let _ = cgroup.destroy();
                drain_cgroup_releases(&releases);
                return;
            }
            state.slots[slot] = AsyncCgroupSlot::Idle;
            state.idle.push_back((slot, cgroup));
            ready.notify_one();
        }

        match releases.recv() {
            Ok(AsyncCgroupMessage::Returned(cgroup)) => {
                let _ = cgroup.destroy();
                let mut state = match state.lock() {
                    Ok(state) => state,
                    Err(_) => {
                        drain_cgroup_releases(&releases);
                        return;
                    }
                };
                if state.stopped {
                    state.slots[slot] = AsyncCgroupSlot::Stopped;
                    drop(state);
                    drain_cgroup_releases(&releases);
                    return;
                }
                state.slots[slot] = AsyncCgroupSlot::Starting;
                ready.notify_all();
            }
            Ok(AsyncCgroupMessage::Stop) | Err(_) => {
                if let Ok(mut state) = state.lock() {
                    state.slots[slot] = AsyncCgroupSlot::Stopped;
                    ready.notify_all();
                }
                drain_cgroup_releases(&releases);
                return;
            }
        }
    }
}

fn drain_cgroup_releases(releases: &Receiver<AsyncCgroupMessage>) {
    while let Ok(message) = releases.try_recv() {
        if let AsyncCgroupMessage::Returned(cgroup) = message {
            let _ = cgroup.destroy();
        }
    }
}

#[cfg(test)]
mod cgroup_pool_tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn list_pool_reuses_cgroup_and_shutdown_removes_it() {
        let root =
            std::env::temp_dir().join(format!("rust-sandbox-cgroup-pool-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let pool = ListCgroupPool::new(
            Box::new(CgroupV2Builder::new(&root)),
            Duration::from_millis(100),
        );

        let first = pool.get().unwrap();
        let first_fd = first.open().unwrap();
        let mut first_stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        assert_eq!(
            unsafe { libc::fstat(first_fd.as_raw_fd(), first_stat.as_mut_ptr()) },
            0
        );
        let first_stat = unsafe { first_stat.assume_init() };
        drop(first_fd);
        pool.put(first);

        let reused = pool.get().unwrap();
        let reused_fd = reused.open().unwrap();
        let mut reused_stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        assert_eq!(
            unsafe { libc::fstat(reused_fd.as_raw_fd(), reused_stat.as_mut_ptr()) },
            0
        );
        let reused_stat = unsafe { reused_stat.assume_init() };
        assert_eq!(first_stat.st_dev, reused_stat.st_dev);
        assert_eq!(first_stat.st_ino, reused_stat.st_ino);
        drop(reused_fd);
        pool.put(reused);

        pool.shutdown().unwrap();
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::remove_dir(root).unwrap();
    }
}

#[cfg(test)]
mod fresh_cgroup_pool_tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    #[test]
    fn destroys_each_execution_group_when_returned() {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "rust-sandbox-fresh-cgroup-pool-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let pool = FreshCgroupPool::new(Box::new(CgroupV2Builder::new(&root)));
        let cgroup = pool.get().unwrap();
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        pool.put(cgroup);
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        pool.shutdown().unwrap();
        fs::remove_dir(root).unwrap();
    }
}

#[cfg(test)]
mod async_fresh_cgroup_pool_tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::sync::atomic::AtomicU64;

    #[test]
    fn precreates_and_replaces_fresh_cgroups_on_background_worker() {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "rust-sandbox-async-cgroup-pool-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let pool = AsyncFreshCgroupPool::new(Box::new(CgroupV2Builder::new(&root)), 1);

        let first = pool.get().unwrap();
        let first_fd = first.open().unwrap();
        let first_path = fs::read_link(format!("/proc/self/fd/{}", first_fd.as_raw_fd())).unwrap();
        drop(first_fd);
        pool.put(first);

        let second = pool.get().unwrap();
        let second_fd = second.open().unwrap();
        let second_path =
            fs::read_link(format!("/proc/self/fd/{}", second_fd.as_raw_fd())).unwrap();
        assert_ne!(first_path, second_path);
        drop(second_fd);
        pool.put(second);

        pool.shutdown().unwrap();
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn allocates_overflow_cgroups_when_all_warm_slots_are_leased() {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "rust-sandbox-async-cgroup-overflow-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let pool = AsyncFreshCgroupPool::new(Box::new(CgroupV2Builder::new(&root)), 1);

        let pooled = pool.get().unwrap();
        let overflow = pool.get().unwrap();
        assert_eq!(fs::read_dir(&root).unwrap().count(), 2);

        // Overflow leases are one-shot: returning one removes it without
        // creating another warm slot.
        pool.put(overflow);
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);

        pool.put(pooled);
        let replacement = pool.get().unwrap();
        pool.put(replacement);
        pool.shutdown().unwrap();
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn concurrent_checkouts_do_not_sleep_after_the_last_warm_slot_is_leased() {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "rust-sandbox-async-cgroup-parallel-overflow-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let pool = Arc::new(AsyncFreshCgroupPool::new(
            Box::new(CgroupV2Builder::new(&root)),
            1,
        ));
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let (tx, rx) = std::sync::mpsc::channel();
        for _ in 0..2 {
            let pool = pool.clone();
            let barrier = barrier.clone();
            let tx = tx.clone();
            thread::spawn(move || {
                barrier.wait();
                tx.send(pool.get()).unwrap();
            });
        }
        drop(tx);
        barrier.wait();

        let first = rx.recv_timeout(Duration::from_secs(2)).unwrap().unwrap();
        let second = rx.recv_timeout(Duration::from_secs(2)).unwrap().unwrap();
        pool.put(first);
        pool.put(second);
        pool.shutdown().unwrap();
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::remove_dir(root).unwrap();
    }
}
