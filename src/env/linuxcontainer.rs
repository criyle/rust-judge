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
use std::time::Duration;

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
    fn get(&self) -> Result<Box<dyn Cgroup>, EnvError>;
    fn put(&self, cgroup: Box<dyn Cgroup>);
    fn shutdown(&self) -> Result<(), EnvError>;
}

/// Creates per-execution cgroups below a delegated cgroup v2 directory.
/// The caller must choose a subtree where the required controllers are enabled.
#[derive(Clone, Debug)]
pub struct CgroupV2Builder {
    root: PathBuf,
}

impl CgroupV2Builder {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn create(&self, prefix: &str) -> Result<CgroupV2, EnvError> {
        // Each execution gets its own child under `containers`. Enable the
        // available controllers at that parent before creating that child,
        // matching go-sandbox's `V2.New` behavior.
        if self.root.join("cgroup.controllers").exists() {
            enable_v2_controllers(&self.root)?;
        }
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let prefix = sanitize_cgroup_prefix(prefix);
        for _ in 0..32 {
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let path = self
                .root
                .join(format!("{prefix}{}-{id}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => {
                    return Ok(CgroupV2 {
                        path,
                        existing: false,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(EnvError::Backend(
            "could not allocate unique cgroup v2 directory".into(),
        ))
    }

    pub fn open_existing(&self, name: &str) -> Result<CgroupV2, EnvError> {
        let relative = safe_cgroup_relative_path(name)?;
        let path = self.root.join(relative);
        if !path.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("cgroup does not exist: {}", path.display()),
            )
            .into());
        }
        Ok(CgroupV2 {
            path,
            existing: true,
        })
    }
}

/// Prepare the caller's cgroup v2 subtree like go-sandbox's
/// `EnableV2NestingAt` followed by go-judge's `New(prefix)` and
/// `Nest("api").New("containers")`. Go creates `api` and `containers` as
/// siblings under the configured prefix; `api` is not an ancestor of the
/// execution cgroup. Existing processes are first moved to an `init` child so
/// controllers can be enabled on the parent. `root` is the `containers` leaf
/// and must be a descendant of `current`.
pub fn prepare_cgroup_v2_hierarchy(current: &Path, root: &Path) -> Result<(), EnvError> {
    validate_absolute_cgroup_path(current)?;
    validate_absolute_cgroup_path(root)?;
    let relative = root.strip_prefix(current).map_err(|_| {
        EnvError::Backend(format!(
            "cgroup v2 root {} is outside current cgroup {}",
            root.display(),
            current.display()
        ))
    })?;
    let components = relative
        .components()
        .map(|component| match component {
            Component::Normal(name) => Ok(name),
            _ => Err(EnvError::Backend(format!(
                "invalid cgroup v2 hierarchy suffix {}",
                relative.display()
            ))),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if components.is_empty() {
        return Err(EnvError::Backend(
            "cgroup v2 execution root must be below its current cgroup".into(),
        ));
    }

    migrate_processes_to_init(current)?;
    enable_v2_controllers(current)?;

    let mut parent = current.to_path_buf();
    for (index, component) in components.iter().enumerate() {
        if index + 1 == components.len() {
            let api = parent.join("api");
            match fs::create_dir(&api) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if !api.is_dir() {
                        return Err(EnvError::Backend(format!(
                            "cgroup hierarchy entry is not a directory: {}",
                            api.display()
                        )));
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
        let child = parent.join(component);
        match fs::create_dir(&child) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if !child.is_dir() {
                    return Err(EnvError::Backend(format!(
                        "cgroup hierarchy entry is not a directory: {}",
                        child.display()
                    )));
                }
            }
            Err(error) => return Err(error.into()),
        }
        parent = child;
        if index + 1 < components.len() {
            migrate_processes_to_init(&parent)?;
            enable_v2_controllers(&parent)?;
        }
    }

    // The API child is intentionally empty here: the server was already
    // migrated to `init` by EnableV2NestingAt before the prefix is prepared.
    Ok(())
}

/// Prepare the Go systemd-scope layout: move the server processes into the
/// `api` child, enable the scope's delegated controllers, then create the
/// sibling `containers` cgroup. Go uses the nested `init` child only in its
/// no-systemd fallback path.
pub fn prepare_cgroup_v2_systemd_scope(current: &Path, containers: &Path) -> Result<(), EnvError> {
    validate_absolute_cgroup_path(current)?;
    validate_absolute_cgroup_path(containers)?;
    if containers.parent() != Some(current) || containers.file_name().is_none() {
        return Err(EnvError::Backend(format!(
            "systemd cgroup containers root {} must be a direct child of {}",
            containers.display(),
            current.display()
        )));
    }

    let api = current.join("api");
    match fs::create_dir(&api) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && api.is_dir() => {}
        Err(error) => return Err(error.into()),
    }
    let pids = fs::read_to_string(current.join("cgroup.procs"))?;
    let mut membership = fs::OpenOptions::new()
        .write(true)
        .open(api.join("cgroup.procs"))?;
    for item in pids.split_whitespace() {
        let pid = item
            .parse::<u32>()
            .map_err(|error| EnvError::Backend(format!("invalid cgroup PID {item:?}: {error}")))?;
        let record = format!("{pid}\n");
        if let Err(error) = membership.write_all(record.as_bytes()) {
            if error.raw_os_error() == Some(libc::ESRCH) {
                continue;
            }
            return Err(error.into());
        }
    }
    enable_v2_controllers(current)?;

    match fs::create_dir(containers) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && containers.is_dir() => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn validate_absolute_cgroup_path(path: &Path) -> Result<(), EnvError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(EnvError::Backend(format!(
            "invalid absolute cgroup path {}",
            path.display()
        )));
    }
    Ok(())
}

fn migrate_processes_to_init(parent: &Path) -> Result<(), EnvError> {
    let content = fs::read_to_string(parent.join("cgroup.procs"))?;
    let mut pids = Vec::new();
    for item in content.split_whitespace() {
        let pid = item
            .parse::<u32>()
            .map_err(|error| EnvError::Backend(format!("invalid cgroup PID {item:?}: {error}")))?;
        pids.push(pid);
    }
    if pids.is_empty() {
        return Ok(());
    }

    let init = parent.join("init");
    match fs::create_dir(&init) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if !init.is_dir() {
                return Err(EnvError::Backend(format!(
                    "cgroup init entry is not a directory: {}",
                    init.display()
                )));
            }
        }
        Err(error) => return Err(error.into()),
    }
    let mut membership = fs::OpenOptions::new()
        .write(true)
        .open(init.join("cgroup.procs"))?;
    for pid in pids {
        let record = format!("{pid}\n");
        if let Err(error) = membership.write_all(record.as_bytes()) {
            // The process may exit between reading cgroup.procs and moving it.
            if error.raw_os_error() == Some(libc::ESRCH) {
                continue;
            }
            return Err(error.into());
        }
    }
    Ok(())
}

fn enable_v2_controllers(parent: &Path) -> Result<(), EnvError> {
    let available = fs::read_to_string(parent.join("cgroup.controllers"))?;
    let enabled = fs::read_to_string(parent.join("cgroup.subtree_control"))?;
    let enabled: std::collections::BTreeSet<_> = enabled.split_whitespace().collect();
    let mut enable = Vec::new();
    for controller in ["cpu", "cpuset", "memory", "pids"] {
        if available.split_whitespace().any(|item| item == controller)
            && !enabled.contains(controller)
        {
            enable.push(format!("+{controller}"));
        }
    }
    if !enable.is_empty() {
        fs::write(parent.join("cgroup.subtree_control"), enable.join(" "))?;
    }
    Ok(())
}

#[cfg(test)]
mod cgroup_v2_hierarchy_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_root() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "rust-sandbox-cgroup-v2-hierarchy-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn seed_cgroup(path: &Path, procs: &str) {
        fs::create_dir_all(path).unwrap();
        fs::write(path.join("cgroup.controllers"), "cpu cpuset memory pids\n").unwrap();
        fs::write(path.join("cgroup.subtree_control"), "").unwrap();
        fs::write(path.join("cgroup.procs"), procs).unwrap();
    }

    #[test]
    fn migrates_existing_tasks_enables_controllers_and_prepares_execution_root() {
        let root = temp_root();
        let current = root.join("session.scope");
        seed_cgroup(&current, "101\n202\n");
        seed_cgroup(&current.join("init"), "");
        let execution_root = current.join("containers");

        prepare_cgroup_v2_hierarchy(&current, &execution_root).unwrap();

        assert_eq!(
            fs::read_to_string(current.join("init/cgroup.procs")).unwrap(),
            "101\n202\n"
        );
        assert_eq!(
            fs::read_to_string(current.join("cgroup.subtree_control")).unwrap(),
            "+cpu +cpuset +memory +pids"
        );
        assert!(current.join("api").is_dir());
        assert!(execution_root.is_dir());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn systemd_scope_moves_server_to_api_and_creates_sibling_containers() {
        let root = temp_root();
        let current = root.join("gojudge.scope");
        let api = current.join("api");
        let containers = current.join("containers");
        seed_cgroup(&current, "301\n");
        seed_cgroup(&api, "");

        prepare_cgroup_v2_systemd_scope(&current, &containers).unwrap();

        assert_eq!(
            fs::read_to_string(api.join("cgroup.procs")).unwrap(),
            "301\n"
        );
        assert!(containers.is_dir());
        assert!(!current.join("init").exists());
        assert_eq!(
            fs::read_to_string(current.join("cgroup.subtree_control")).unwrap(),
            "+cpu +cpuset +memory +pids"
        );

        let outside = current.join("nested/containers");
        assert!(prepare_cgroup_v2_systemd_scope(&current, &outside).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_hierarchy_roots_outside_current_cgroup() {
        let root = temp_root();
        let current = root.join("current");
        seed_cgroup(&current, "");
        assert!(prepare_cgroup_v2_hierarchy(&current, &root.join("sibling")).is_err());
        assert!(prepare_cgroup_v2_hierarchy(&current, &current.join("../escape")).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}

impl CgroupBuilder for CgroupV2Builder {
    fn random(&self, prefix: &str) -> Result<Box<dyn Cgroup>, EnvError> {
        self.create(prefix)
            .map(|cgroup| Box::new(cgroup) as Box<dyn Cgroup>)
    }

    fn open_existing(&self, name: &str) -> Result<Box<dyn Cgroup>, EnvError> {
        self.open_existing(name)
            .map(|cgroup| Box::new(cgroup) as Box<dyn Cgroup>)
    }
}

pub(crate) fn safe_cgroup_relative_path(raw: &str) -> Result<PathBuf, EnvError> {
    let path = Path::new(raw);
    if raw.is_empty()
        || raw.contains('\0')
        || path.is_absolute()
        || raw
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(EnvError::Backend(format!("invalid cgroup path {raw:?}")));
    }
    Ok(path.to_path_buf())
}

/// A single cgroup v2 execution group.
#[derive(Debug)]
pub struct CgroupV2 {
    path: PathBuf,
    existing: bool,
}

impl CgroupV2 {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn open_procs(&self) -> std::io::Result<std::fs::File> {
        std::fs::OpenOptions::new()
            .write(true)
            .open(self.path.join("cgroup.procs"))
    }

    fn write_optional(&self, name: &str, value: &str) -> Result<(), EnvError> {
        let path = self.path.join(name);
        if !path.exists() {
            return Ok(());
        }
        match fs::write(path, value) {
            Ok(()) => Ok(()),
            // Controllers that are disabled or absent behave like Go's
            // ErrNotInitialized and are optional on different kernels.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn read_u64(&self, name: &str) -> Result<u64, EnvError> {
        let value = fs::read_to_string(self.path.join(name))?;
        value
            .trim()
            .parse()
            .map_err(|error| EnvError::Backend(format!("invalid cgroup {name} value: {error}")))
    }
}

impl Cgroup for CgroupV2 {
    fn set_cpuset(&mut self, cpus: &str) -> Result<(), EnvError> {
        if cpus.is_empty() {
            return Ok(());
        }
        self.write_optional("cpuset.cpus", cpus)
    }

    fn set_memory_limit(&mut self, bytes: u64) -> Result<(), EnvError> {
        self.write_optional("memory.max", &bytes.to_string())
    }

    fn set_proc_limit(&mut self, count: u64) -> Result<(), EnvError> {
        self.write_optional("pids.max", &count.to_string())
    }

    fn set_cpu_rate(&mut self, rate: u64, period: Duration) -> Result<(), EnvError> {
        if rate == 0 {
            return Ok(());
        }
        let period_us = period.as_micros().min(u64::MAX as u128) as u64;
        if period_us == 0 {
            return Err(EnvError::Backend(
                "cgroup CPU period must be nonzero".into(),
            ));
        }
        let quota_us = period_us.saturating_mul(rate) / 1000;
        self.write_optional("cpu.max", &format!("{quota_us} {period_us}"))
    }

    fn cpu_usage(&self) -> Result<Duration, EnvError> {
        let stats = fs::read_to_string(self.path.join("cpu.stat"))?;
        let micros = stats
            .lines()
            .filter_map(|line| {
                let mut fields = line.split_whitespace();
                (fields.next()? == "usage_usec")
                    .then(|| fields.next()?.parse::<u64>().ok())
                    .flatten()
            })
            .next()
            .ok_or_else(|| EnvError::Backend("cpu.stat lacks usage_usec".into()))?;
        Ok(Duration::from_micros(micros))
    }

    fn current_memory(&self) -> Result<u64, EnvError> {
        self.read_u64("memory.current")
    }

    fn max_memory(&self) -> Result<u64, EnvError> {
        self.read_u64("memory.peak")
    }

    fn proc_peak(&self) -> Result<u64, EnvError> {
        self.read_u64("pids.peak")
    }

    fn add_process(&mut self, pid: u32) -> Result<(), EnvError> {
        // Match Go's AddProcesses: opening cgroup.procs without O_TRUNC and
        // writing at offset zero. Truncation is ignored by the kernel's
        // pseudo-file but observably changes fixture-backed cgroups.
        fs::OpenOptions::new()
            .write(true)
            .open(self.path.join("cgroup.procs"))?
            .write_all(pid.to_string().as_bytes())?;
        Ok(())
    }

    fn processes(&self) -> Result<Vec<u32>, EnvError> {
        read_processes(&self.path.join("cgroup.procs"))
    }

    fn existing(&self) -> bool {
        self.existing
    }

    fn new_child(&self, name: &str) -> Result<Box<dyn Cgroup>, EnvError> {
        validate_cgroup_name(name)?;
        enable_v2_controllers(&self.path)?;
        let path = self.path.join(name);
        match fs::create_dir(&path) {
            Ok(()) => Ok(Box::new(CgroupV2 {
                path,
                existing: false,
            })),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if !path.is_dir() {
                    return Err(EnvError::Backend(format!(
                        "cgroup child is not a directory: {}",
                        path.display()
                    )));
                }
                Ok(Box::new(CgroupV2 {
                    path,
                    existing: true,
                }))
            }
            Err(error) => Err(error.into()),
        }
    }

    fn nest(&self, name: &str) -> Result<Box<dyn Cgroup>, EnvError> {
        validate_cgroup_name(name)?;
        let child = self.path.join(name);
        let existing = match fs::create_dir(&child) {
            Ok(()) => false,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if !child.is_dir() {
                    return Err(EnvError::Backend(format!(
                        "cgroup child is not a directory: {}",
                        child.display()
                    )));
                }
                true
            }
            Err(error) => return Err(error.into()),
        };
        let nested = CgroupV2 {
            path: child.clone(),
            existing,
        };
        let result = (|| {
            let pids = self.processes()?;
            for pid in pids {
                fs::write(child.join("cgroup.procs"), pid.to_string())?;
            }
            enable_v2_controllers(&self.path)
        })();
        if let Err(error) = result {
            if !existing {
                let _ = fs::remove_dir(&child);
            }
            return Err(error);
        }
        Ok(Box::new(nested))
    }

    fn reset(&mut self) -> Result<(), EnvError> {
        // go-judge's cgroup wrapper intentionally keeps configured limits;
        // each execution gets a fresh group from its pool.
        Ok(())
    }

    fn destroy(self: Box<Self>) -> Result<(), EnvError> {
        if self.existing {
            return Ok(());
        }
        // Match go-sandbox's Rmdir-based cleanup. Workload descendants are
        // reaped by container PID 1; a nonempty cgroup remains an error.
        fs::remove_dir(self.path)?;
        Ok(())
    }

    fn open(&self) -> Result<OwnedFd, EnvError> {
        Ok(fs::File::open(&self.path)?.into())
    }
}

pub(crate) fn read_processes(path: &Path) -> Result<Vec<u32>, EnvError> {
    fs::read_to_string(path)?
        .split_whitespace()
        .map(|item| {
            item.parse::<u32>()
                .map_err(|error| EnvError::Backend(format!("invalid cgroup PID {item:?}: {error}")))
        })
        .collect()
}

fn sanitize_cgroup_prefix(prefix: &str) -> String {
    let value = prefix
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "-_".contains(c) {
                c
            } else {
                '_'
            }
        })
        .take(48)
        .collect::<String>();
    if value.is_empty() {
        String::new()
    } else {
        format!("{value}-")
    }
}

#[cfg(test)]
mod cgroup_v2_tests {
    use super::*;
    use std::os::fd::AsRawFd;

    fn temp_root() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "rust-sandbox-cgroup-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn creates_configures_reads_and_removes_cgroup() {
        let root = temp_root();
        fs::create_dir(&root).unwrap();
        let cgroup = CgroupV2Builder::new(&root).create("judge/unsafe").unwrap();
        let dir = fs::read_dir(&root).unwrap().next().unwrap().unwrap().path();
        let path = cgroup.open().unwrap();
        assert!(path.as_raw_fd() >= 0);
        drop(path);
        let mut cgroup = cgroup;
        for name in [
            "cpuset.cpus",
            "memory.max",
            "pids.max",
            "cpu.max",
            "cpu.stat",
            "memory.current",
            "memory.peak",
            "pids.peak",
            "cgroup.procs",
        ] {
            fs::write(dir.join(name), "").unwrap();
        }
        fs::write(dir.join("cpu.stat"), "usage_usec 230\nuser_usec 100\n").unwrap();
        fs::write(dir.join("memory.current"), "4096\n").unwrap();
        fs::write(dir.join("memory.peak"), "8192\n").unwrap();
        fs::write(dir.join("pids.peak"), "3\n").unwrap();
        cgroup.set_cpuset("0-2").unwrap();
        cgroup.set_memory_limit(1 << 20).unwrap();
        cgroup.set_proc_limit(8).unwrap();
        cgroup
            .set_cpu_rate(500, Duration::from_millis(100))
            .unwrap();
        cgroup.add_process(1234).unwrap();
        use std::io::Write;
        cgroup.open_procs().unwrap().write_all(b"5678").unwrap();
        assert_eq!(fs::read_to_string(dir.join("cpuset.cpus")).unwrap(), "0-2");
        assert_eq!(
            fs::read_to_string(dir.join("memory.max")).unwrap(),
            "1048576"
        );
        assert_eq!(fs::read_to_string(dir.join("pids.max")).unwrap(), "8");
        assert_eq!(
            fs::read_to_string(dir.join("cpu.max")).unwrap(),
            "50000 100000"
        );
        assert_eq!(
            fs::read_to_string(dir.join("cgroup.procs")).unwrap(),
            "5678"
        );
        assert_eq!(cgroup.cpu_usage().unwrap(), Duration::from_micros(230));
        assert_eq!(cgroup.current_memory().unwrap(), 4096);
        assert_eq!(cgroup.max_memory().unwrap(), 8192);
        assert_eq!(cgroup.proc_peak().unwrap(), 3);
        for name in [
            "cpuset.cpus",
            "memory.max",
            "pids.max",
            "cpu.max",
            "cpu.stat",
            "memory.current",
            "memory.peak",
            "pids.peak",
            "cgroup.procs",
        ] {
            fs::remove_file(dir.join(name)).unwrap();
        }
        Box::new(cgroup).destroy().unwrap();
        fs::remove_dir(&root).unwrap();
    }

    #[test]
    fn add_process_does_not_truncate_cgroup_procs() {
        let root = temp_root();
        fs::create_dir(&root).unwrap();
        let mut cgroup = CgroupV2Builder::new(&root).create("judge").unwrap();
        let procs = cgroup.path().join("cgroup.procs");
        fs::write(&procs, "123456").unwrap();

        cgroup.add_process(7).unwrap();

        assert_eq!(fs::read_to_string(&procs).unwrap(), "723456");
        fs::remove_file(procs).unwrap();
        Box::new(cgroup).destroy().unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn absent_controllers_are_optional_and_zero_rate_is_noop() {
        let root = temp_root();
        fs::create_dir(&root).unwrap();
        let cgroup = CgroupV2Builder::new(&root).random("").unwrap();
        let mut cgroup = cgroup;
        cgroup.set_cpuset("0").unwrap();
        cgroup.set_memory_limit(0).unwrap();
        cgroup.set_proc_limit(0).unwrap();
        cgroup.set_cpu_rate(0, Duration::ZERO).unwrap();
        cgroup.destroy().unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn named_children_existing_handles_and_process_migration_match_cgroup_api() {
        let root = temp_root();
        let current = root.join("current");
        let nested = current.join("nested");
        fs::create_dir_all(&nested).unwrap();
        for (path, procs) in [(&current, "101\n202\n"), (&nested, "")] {
            fs::write(path.join("cgroup.controllers"), "cpu cpuset memory pids\n").unwrap();
            fs::write(path.join("cgroup.subtree_control"), "").unwrap();
            fs::write(path.join("cgroup.procs"), procs).unwrap();
        }

        let builder = CgroupV2Builder::new(&root);
        let current_cgroup = builder.open_existing("current").unwrap();
        assert!(current_cgroup.existing());
        assert_eq!(current_cgroup.processes().unwrap(), vec![101, 202]);
        let nested_cgroup = current_cgroup.nest("nested").unwrap();
        assert!(nested_cgroup.existing());
        assert_eq!(
            fs::read_to_string(nested.join("cgroup.procs")).unwrap(),
            "202"
        );
        nested_cgroup.destroy().unwrap();
        assert!(nested.is_dir(), "destroy must preserve an existing child");

        let created = current_cgroup.new_child("created").unwrap();
        assert!(!created.existing());
        let created_path = current.join("created");
        created.destroy().unwrap();
        assert!(!created_path.exists());

        assert!(builder.open_existing("../escape").is_err());
        assert!(current_cgroup.new_child("../escape").is_err());
        fs::remove_dir_all(root).unwrap();
    }
}

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
    fn get(&self) -> Result<Box<dyn Cgroup>, EnvError> {
        if let Some(cg) = self.idle.lock().map_err(|_| EnvError::Poisoned)?.pop() {
            return Ok(cg);
        }
        self.builder.random("")
    }
    fn put(&self, mut cgroup: Box<dyn Cgroup>) {
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
    fn get(&self) -> Result<Box<dyn Cgroup>, EnvError> {
        self.builder.random("")
    }

    fn put(&self, cgroup: Box<dyn Cgroup>) {
        let _ = cgroup.destroy();
    }

    fn shutdown(&self) -> Result<(), EnvError> {
        Ok(())
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
