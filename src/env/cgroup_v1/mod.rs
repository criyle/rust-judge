//! Cgroup v1 controller discovery and execution groups.
//!
//! Controller membership is split across one or more cgroup hierarchies on
//! v1. This module resolves each controller's mount and current membership,
//! then creates/removes one directory per available controller. Enrolling a
//! process must call [`CgroupV1::add_process`] because v1 has no single cgroup
//! directory descriptor that can atomically enroll it in all hierarchies.

use super::linuxcontainer::{Cgroup, CgroupBuilder, EnvError, validate_cgroup_name};
mod discovery;
#[cfg(test)]
use discovery::parse_memberships;
pub use discovery::{
    discover_controller_mount_paths, discover_current_controller_paths, prepare_go_judge_hierarchy,
};
use discovery::{
    discover_controller_paths, ensure_cgroup_root, initialize_cpuset, remove_dirs,
    safe_leaf_prefix, safe_relative_path,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    os::fd::OwnedFd,
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

const CONTROLLERS: [&str; 5] = ["cpu", "cpuset", "cpuacct", "memory", "pids"];

/// Maps each available controller to the current process's cgroup directory
/// for that controller.
pub type ControllerPaths = BTreeMap<String, PathBuf>;

/// Builder rooted at a per-controller parent directory. `root` commonly
/// comes from [`discover_controller_paths`] with the caller's cgroup prefix
/// appended.
#[derive(Clone, Debug)]
pub struct CgroupV1Builder {
    roots: ControllerPaths,
}

impl CgroupV1Builder {
    pub fn new(roots: ControllerPaths) -> Self {
        Self { roots }
    }

    /// Resolve this process's v1 controller directories from procfs fixture
    /// contents. The optional relative `prefix` is appended below each
    /// current membership directory.
    pub fn from_proc_data(
        proc_cgroup: &str,
        mountinfo: &str,
        prefix: &str,
    ) -> Result<Self, EnvError> {
        let roots = discover_controller_paths(proc_cgroup, mountinfo)?;
        let suffix = safe_relative_path(prefix)?;
        Ok(Self {
            roots: roots
                .into_iter()
                .map(|(controller, path)| (controller, path.join(&suffix)))
                .collect(),
        })
    }

    pub fn roots(&self) -> &ControllerPaths {
        &self.roots
    }

    /// Create a unique leaf group under every available controller root.
    pub fn create(&self, prefix: &str) -> Result<CgroupV1, EnvError> {
        let prefix = safe_leaf_prefix(prefix)?;
        for controller in CONTROLLERS {
            if let Some(root) = self.roots.get(controller) {
                ensure_cgroup_root(root, controller == "cpuset")?;
            }
        }
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        for _ in 0..64 {
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let name = format!("{prefix}{}-{id}", std::process::id());
            let mut paths = ControllerPaths::new();
            let mut created = Vec::new();
            let mut collision = false;
            for controller in CONTROLLERS {
                let Some(root) = self.roots.get(controller) else {
                    continue;
                };
                let path = root.join(&name);
                match fs::create_dir(&path) {
                    Ok(()) => {
                        created.push(path.clone());
                        paths.insert(controller.to_owned(), path);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        collision = true;
                        break;
                    }
                    Err(error) => {
                        remove_dirs(&created);
                        return Err(error.into());
                    }
                }
            }
            if collision {
                remove_dirs(&created);
                continue;
            }
            if paths.is_empty() {
                return Err(EnvError::Unsupported(
                    "no supported cgroup v1 controllers are mounted",
                ));
            }
            if let Some(path) = paths.get("cpuset")
                && let Err(error) = initialize_cpuset(path)
            {
                remove_dirs(&created);
                return Err(error);
            }
            return Ok(CgroupV1 {
                paths,
                created,
                existing: false,
            });
        }
        Err(EnvError::Backend(
            "could not allocate unique cgroup v1 directory".into(),
        ))
    }

    pub fn open_existing(&self, name: &str) -> Result<CgroupV1, EnvError> {
        let relative = super::linuxcontainer::safe_cgroup_relative_path(name)?;
        let mut paths = ControllerPaths::new();
        for controller in CONTROLLERS {
            let Some(root) = self.roots.get(controller) else {
                continue;
            };
            let path = root.join(&relative);
            if !path.is_dir() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("cgroup does not exist: {}", path.display()),
                )
                .into());
            }
            paths.insert(controller.to_owned(), path);
        }
        if paths.is_empty() {
            return Err(EnvError::Unsupported(
                "no supported cgroup v1 controllers are mounted",
            ));
        }
        if let Some(path) = paths.get("cpuset") {
            initialize_cpuset(path)?;
        }
        Ok(CgroupV1 {
            paths,
            created: Vec::new(),
            existing: true,
        })
    }
}

impl CgroupBuilder for CgroupV1Builder {
    fn random(&self, prefix: &str) -> Result<Box<dyn Cgroup>, EnvError> {
        self.create(prefix)
            .map(|cgroup| Box::new(cgroup) as Box<dyn Cgroup>)
    }

    fn open_existing(&self, name: &str) -> Result<Box<dyn Cgroup>, EnvError> {
        self.open_existing(name)
            .map(|cgroup| Box::new(cgroup) as Box<dyn Cgroup>)
    }
}

/// Find each v1 controller mount and resolve the current process membership
/// within that mount. Handles escaped mountinfo path fields and controllers
/// mounted together (for example `cpu,cpuacct`).
/// A single execution group spanning all available v1 controller hierarchies.
#[derive(Debug)]
pub struct CgroupV1 {
    paths: ControllerPaths,
    created: Vec<PathBuf>,
    existing: bool,
}

impl CgroupV1 {
    pub fn paths(&self) -> &ControllerPaths {
        &self.paths
    }

    fn controller(&self, name: &str) -> Option<&Path> {
        self.paths.get(name).map(PathBuf::as_path)
    }

    fn write_controller(&self, controller: &str, file: &str, value: &str) -> Result<(), EnvError> {
        if let Some(path) = self.controller(controller) {
            fs::write(path.join(file), value)?;
        }
        // Go's cgroup.ErrNotInitialized is ignored by go-judge for missing
        // optional controllers, so an absent controller is a no-op here.
        Ok(())
    }

    fn read_controller_u64(&self, controller: &str, file: &str) -> Result<u64, EnvError> {
        let path = self.controller(controller).ok_or(EnvError::Unsupported(
            "requested cgroup v1 controller is not mounted",
        ))?;
        fs::read_to_string(path.join(file))?
            .trim()
            .parse()
            .map_err(|error| EnvError::Backend(format!("invalid {file} value: {error}")))
    }
}

impl Cgroup for CgroupV1 {
    fn set_cpuset(&mut self, cpus: &str) -> Result<(), EnvError> {
        if !cpus.is_empty() {
            self.write_controller("cpuset", "cpuset.cpus", cpus)?;
        }
        Ok(())
    }

    fn set_memory_limit(&mut self, bytes: u64) -> Result<(), EnvError> {
        self.write_controller("memory", "memory.limit_in_bytes", &bytes.to_string())
    }

    fn check_memory_swap_limit(&self) -> Result<(), EnvError> {
        let path = self.controller("memory").ok_or(EnvError::Unsupported(
            "cgroup v1 memory controller is unavailable",
        ))?;
        fs::metadata(path.join("memory.memsw.limit_in_bytes"))?;
        Ok(())
    }

    fn set_memory_swap_limit(&mut self, memory_bytes: u64) -> Result<(), EnvError> {
        self.write_controller(
            "memory",
            "memory.memsw.limit_in_bytes",
            &memory_bytes.to_string(),
        )
    }

    fn set_proc_limit(&mut self, count: u64) -> Result<(), EnvError> {
        self.write_controller("pids", "pids.max", &count.to_string())
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
        self.write_controller("cpu", "cpu.cfs_quota_us", &quota_us.to_string())?;
        self.write_controller("cpu", "cpu.cfs_period_us", &period_us.to_string())
    }

    fn cpu_usage(&self) -> Result<Duration, EnvError> {
        self.read_controller_u64("cpuacct", "cpuacct.usage")
            .map(Duration::from_nanos)
    }

    fn current_memory(&self) -> Result<u64, EnvError> {
        self.read_controller_u64("memory", "memory.usage_in_bytes")
    }

    fn max_memory(&self) -> Result<u64, EnvError> {
        self.read_controller_u64("memory", "memory.max_usage_in_bytes")
    }

    fn proc_peak(&self) -> Result<u64, EnvError> {
        // The go-sandbox cgroup v1 backend reports ErrNotInitialized.
        Err(EnvError::Unsupported(
            "process peak is unavailable in cgroup v1",
        ))
    }

    fn add_process(&mut self, pid: u32) -> Result<(), EnvError> {
        for controller in CONTROLLERS {
            let Some(path) = self.paths.get(controller) else {
                continue;
            };
            // Do not truncate cgroup.procs: Go opens it without O_TRUNC.
            fs::OpenOptions::new()
                .write(true)
                .open(path.join("cgroup.procs"))?
                .write_all(pid.to_string().as_bytes())?;
        }
        Ok(())
    }

    fn processes(&self) -> Result<Vec<u32>, EnvError> {
        let path = CONTROLLERS
            .iter()
            .find_map(|controller| self.paths.get(*controller))
            .ok_or(EnvError::Unsupported(
                "no supported cgroup v1 controllers are mounted",
            ))?;
        super::linuxcontainer::read_processes(&path.join("cgroup.procs"))
    }

    fn existing(&self) -> bool {
        self.existing
    }

    fn new_child(&self, name: &str) -> Result<Box<dyn Cgroup>, EnvError> {
        validate_cgroup_name(name)?;
        let mut paths = ControllerPaths::new();
        let mut created = Vec::new();
        let mut was_existing = true;
        for controller in CONTROLLERS {
            let Some(parent) = self.paths.get(controller) else {
                continue;
            };
            let path = parent.join(name);
            match fs::create_dir(&path) {
                Ok(()) => {
                    was_existing = false;
                    created.push(path.clone());
                    paths.insert(controller.to_owned(), path);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if !path.is_dir() {
                        remove_dirs(&created);
                        return Err(EnvError::Backend(format!(
                            "cgroup child is not a directory: {}",
                            path.display()
                        )));
                    }
                    paths.insert(controller.to_owned(), path);
                }
                Err(error) => {
                    remove_dirs(&created);
                    return Err(error.into());
                }
            }
        }
        if paths.is_empty() {
            return Err(EnvError::Unsupported(
                "no supported cgroup v1 controllers are mounted",
            ));
        }
        if let Some(path) = paths.get("cpuset")
            && let Err(error) = initialize_cpuset(path)
        {
            remove_dirs(&created);
            return Err(error);
        }
        Ok(Box::new(CgroupV1 {
            paths,
            created,
            existing: was_existing,
        }))
    }

    fn nest(&self, name: &str) -> Result<Box<dyn Cgroup>, EnvError> {
        let mut child = self.new_child(name)?;
        let pids = match self.processes() {
            Ok(pids) => pids,
            Err(error) => {
                if !child.existing() {
                    let _ = child.destroy();
                }
                return Err(error);
            }
        };
        for pid in pids {
            if let Err(error) = child.add_process(pid) {
                if !child.existing() {
                    let _ = child.destroy();
                }
                return Err(error);
            }
        }
        Ok(child)
    }

    fn set_cpuacct_usage(&mut self, value: u64) -> Result<(), EnvError> {
        self.write_controller("cpuacct", "cpuacct.usage", &value.to_string())
    }

    fn set_memory_max_usage(&mut self, value: u64) -> Result<(), EnvError> {
        self.write_controller("memory", "memory.max_usage_in_bytes", &value.to_string())
    }

    fn memory_memsw_max_usage(&self) -> Result<u64, EnvError> {
        self.read_controller_u64("memory", "memory.memsw.max_usage_in_bytes")
    }

    fn set_memory_memsw_limit(&mut self, value: u64) -> Result<(), EnvError> {
        self.write_controller("memory", "memory.memsw.limit_in_bytes", &value.to_string())
    }

    fn set_cpu_cfs_period(&mut self, period_us: u64) -> Result<(), EnvError> {
        self.write_controller("cpu", "cpu.cfs_period_us", &period_us.to_string())
    }

    fn set_cpu_cfs_quota(&mut self, quota_us: u64) -> Result<(), EnvError> {
        self.write_controller("cpu", "cpu.cfs_quota_us", &quota_us.to_string())
    }

    fn set_cpuset_mems(&mut self, mems: &str) -> Result<(), EnvError> {
        self.write_controller("cpuset", "cpuset.mems", mems)
    }

    fn memory_stat_property(&self, property: &str) -> Result<u64, EnvError> {
        let path = self.controller("memory").ok_or(EnvError::Unsupported(
            "requested cgroup v1 memory controller is not mounted",
        ))?;
        let stats = fs::read_to_string(path.join("memory.stat"))?;
        stats
            .lines()
            .find_map(|line| {
                let mut fields = line.split_whitespace();
                (fields.next()? == property)
                    .then(|| fields.next()?.parse::<u64>().ok())
                    .flatten()
            })
            .ok_or_else(|| EnvError::Backend(format!("memory.stat lacks {property:?}")))
    }

    fn reset(&mut self) -> Result<(), EnvError> {
        // Go's linuxcontainer wrapper leaves configured limits in place and
        // uses a fresh cgroup for each execution.
        Ok(())
    }

    fn destroy(self: Box<Self>) -> Result<(), EnvError> {
        if self.existing {
            return Ok(());
        }
        let mut last_error = None;
        for path in &self.created {
            if let Err(error) = fs::remove_dir(path) {
                last_error = Some(error);
            }
        }
        last_error.map_or(Ok(()), |error| Err(error.into()))
    }

    fn open(&self) -> Result<OwnedFd, EnvError> {
        // CLONE_INTO_CGROUP accepts a unified hierarchy cgroup fd. A v1
        // process must instead be written to every controller's cgroup.procs.
        Err(EnvError::Unsupported(
            "cgroup v1 cannot be joined through a single cgroup fd",
        ))
    }

    fn open_procs(&self) -> Result<Vec<OwnedFd>, EnvError> {
        CONTROLLERS
            .iter()
            .filter_map(|controller| self.paths.get(*controller))
            .map(|path| {
                fs::OpenOptions::new()
                    .write(true)
                    .open(path.join("cgroup.procs"))
                    .map(Into::into)
                    .map_err(EnvError::from)
            })
            .collect()
    }
}

/// Read procfs and discover v1 controller roots for the current process.
#[cfg(test)]
mod tests;
