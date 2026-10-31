//! Cgroup v1 controller discovery and execution groups.
//!
//! Controller membership is split across one or more cgroup hierarchies on
//! v1. This module resolves each controller's mount and current membership,
//! then creates/removes one directory per available controller. Enrolling a
//! process must call [`CgroupV1::add_process`] because v1 has no single cgroup
//! directory descriptor that can atomically enroll it in all hierarchies.

use super::linuxcontainer::{Cgroup, CgroupBuilder, EnvError, validate_cgroup_name};
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
            if let Some(path) = paths.get("cpuset") {
                if let Err(error) = initialize_cpuset(path) {
                    remove_dirs(&created);
                    return Err(error);
                }
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
pub fn discover_controller_paths(
    proc_cgroup: &str,
    mountinfo: &str,
) -> Result<ControllerPaths, EnvError> {
    let memberships = parse_memberships(proc_cgroup)?;
    let mounts = parse_mountinfo(mountinfo)?;
    let mut result = ControllerPaths::new();
    for (controller, membership) in memberships {
        if !CONTROLLERS.contains(&controller.as_str()) {
            continue;
        }
        for mount in &mounts {
            if !mount.controllers.contains(&controller) {
                continue;
            }
            let relative = membership.strip_prefix(&mount.root).map_err(|_| {
                EnvError::Backend(format!(
                    "cgroup membership {} is outside mount root {} for {controller}",
                    membership.display(),
                    mount.root.display()
                ))
            })?;
            result.insert(controller.clone(), mount.mount_point.join(relative));
            break;
        }
    }
    Ok(result)
}

/// Resolve each mounted v1 controller to its mount point without appending
/// the current process membership. go-judge creates server cgroups at the
/// configured prefix directly below each controller mount.
pub fn discover_controller_mount_paths(mountinfo: &str) -> Result<ControllerPaths, EnvError> {
    let mounts = parse_mountinfo(mountinfo)?;
    let mut result = ControllerPaths::new();
    for mount in mounts {
        for controller in mount.controllers {
            if CONTROLLERS.contains(&controller.as_str()) {
                result.insert(controller, mount.mount_point.clone());
            }
        }
    }
    Ok(result)
}

/// Create go-judge's v1 prefix, move existing prefix processes to its `api`
/// sibling, and create the `containers` sibling used by execution groups.
pub fn prepare_go_judge_hierarchy(container_roots: &ControllerPaths) -> Result<(), EnvError> {
    let mut prefix_roots = ControllerPaths::new();
    for controller in CONTROLLERS {
        if let Some(containers) = container_roots.get(controller) {
            let prefix = containers.parent().ok_or_else(|| {
                EnvError::Backend(format!(
                    "container cgroup path has no prefix: {}",
                    containers.display()
                ))
            })?;
            ensure_cgroup_root(prefix, controller == "cpuset")?;
            if controller == "cpuset" {
                initialize_cpuset(prefix)?;
            }
            prefix_roots.insert(controller.to_owned(), prefix.to_path_buf());
        }
    }
    if prefix_roots.is_empty() {
        return Err(EnvError::Unsupported(
            "no supported cgroup v1 controllers are mounted",
        ));
    }

    let prefix = CgroupV1 {
        paths: prefix_roots,
        created: Vec::new(),
        existing: true,
    };
    let mut api = prefix.new_child("api")?;
    for pid in prefix.processes()? {
        api.add_process(pid)?;
    }
    // Go creates this child after nesting API processes and uses it as the
    // parent for each per-environment cgroup.
    let _containers = prefix.new_child("containers")?;
    Ok(())
}

#[derive(Debug)]
struct CgroupMount {
    root: PathBuf,
    mount_point: PathBuf,
    controllers: BTreeSet<String>,
}

fn parse_memberships(text: &str) -> Result<BTreeMap<String, PathBuf>, EnvError> {
    let mut memberships = BTreeMap::new();
    for line in text.lines().filter(|line| !line.is_empty()) {
        let mut fields = line.splitn(3, ':');
        let hierarchy = fields.next().unwrap_or_default();
        let controllers = fields
            .next()
            .ok_or_else(|| EnvError::Backend(format!("invalid /proc/self/cgroup entry: {line}")))?;
        let path = fields
            .next()
            .ok_or_else(|| EnvError::Backend(format!("invalid /proc/self/cgroup entry: {line}")))?;
        hierarchy.parse::<u32>().map_err(|_| {
            EnvError::Backend(format!("invalid cgroup hierarchy id in entry: {line}"))
        })?;
        if controllers.is_empty() {
            // Unified hierarchy (`0::/...`) is handled by the v2 backend.
            continue;
        }
        let path = safe_absolute_path(path)?;
        for controller in controllers.split(',') {
            if !controller.is_empty() {
                memberships.insert(controller.to_owned(), path.clone());
            }
        }
    }
    Ok(memberships)
}

fn parse_mountinfo(text: &str) -> Result<Vec<CgroupMount>, EnvError> {
    let mut mounts = Vec::new();
    for line in text.lines().filter(|line| !line.is_empty()) {
        let (left, right) = line.split_once(" - ").ok_or_else(|| {
            EnvError::Backend(format!("invalid /proc/self/mountinfo entry: {line}"))
        })?;
        let before: Vec<_> = left.split_whitespace().collect();
        let after: Vec<_> = right.split_whitespace().collect();
        if before.len() < 6 || after.len() < 3 {
            return Err(EnvError::Backend(format!(
                "incomplete /proc/self/mountinfo entry: {line}"
            )));
        }
        if after[0] != "cgroup" {
            continue;
        }
        let root = PathBuf::from(decode_mount_field(before[3])?);
        let mount_point = PathBuf::from(decode_mount_field(before[4])?);
        let mut controllers = BTreeSet::new();
        for option in before[5]
            .split(',')
            .chain(after[2].split(','))
            .chain(after[1].split(','))
        {
            if CONTROLLERS.contains(&option) {
                controllers.insert(option.to_owned());
            }
        }
        if !controllers.is_empty() {
            validate_absolute(&root)?;
            validate_absolute(&mount_point)?;
            mounts.push(CgroupMount {
                root,
                mount_point,
                controllers,
            });
        }
    }
    Ok(mounts)
}

fn decode_mount_field(field: &str) -> Result<String, EnvError> {
    let bytes = field.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            if index + 3 >= bytes.len()
                || !bytes[index + 1..index + 4]
                    .iter()
                    .all(|byte| (b'0'..=b'7').contains(byte))
            {
                return Err(EnvError::Backend(format!(
                    "invalid escape in mountinfo field {field:?}"
                )));
            }
            let value = (bytes[index + 1] - b'0') * 64
                + (bytes[index + 2] - b'0') * 8
                + (bytes[index + 3] - b'0');
            decoded.push(value);
            index += 4;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded)
        .map_err(|_| EnvError::Backend("non-UTF-8 cgroup path in mountinfo".into()))
}

fn safe_absolute_path(raw: &str) -> Result<PathBuf, EnvError> {
    let path = Path::new(raw);
    validate_absolute(path)?;
    Ok(path.to_path_buf())
}

fn validate_absolute(path: &Path) -> Result<(), EnvError> {
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

fn safe_relative_path(raw: &str) -> Result<PathBuf, EnvError> {
    if raw.is_empty() {
        return Ok(PathBuf::new());
    }
    let path = Path::new(raw);
    if raw.contains('\0')
        || path.is_absolute()
        || raw
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(EnvError::Backend(format!(
            "invalid relative cgroup path {raw:?}"
        )));
    }
    Ok(path.to_path_buf())
}

fn safe_leaf_prefix(prefix: &str) -> Result<String, EnvError> {
    if prefix.is_empty() {
        return Ok(String::new());
    }
    if prefix.contains('/') || prefix == "." || prefix == ".." {
        return Err(EnvError::Backend(format!(
            "invalid cgroup leaf prefix {prefix:?}"
        )));
    }
    Ok(prefix
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || "-_".contains(character) {
                character
            } else {
                '_'
            }
        })
        .take(48)
        .collect())
}

fn remove_dirs(paths: &[PathBuf]) {
    for path in paths.iter().rev() {
        let _ = fs::remove_dir(path);
    }
}

fn initialize_cpuset(child: &Path) -> Result<(), EnvError> {
    // The parent may itself be a newly-created intermediate cgroup with an
    // empty cpuset. Match go-sandbox's copyCgroupPropertyFromParent by
    // walking upward to the first populated value and filling each empty
    // ancestor while unwinding.
    for name in ["cpuset.cpus", "cpuset.mems"] {
        initialize_cpuset_property(child, name)?;
    }
    Ok(())
}

fn initialize_cpuset_property(path: &Path, name: &str) -> Result<(), EnvError> {
    let property = path.join(name);
    // The kernel creates these pseudo-files with the cgroup directory. Treat
    // absent files as empty as well so filesystem fixtures can model mkdir.
    let current = fs::read_to_string(&property).unwrap_or_default();
    if !current.trim().is_empty() {
        return Ok(());
    }

    let parent = path.parent().ok_or_else(|| {
        EnvError::Backend(format!("cpuset path has no parent: {}", path.display()))
    })?;
    let parent_property = parent.join(name);
    let inherited = fs::read_to_string(&parent_property)?;
    if inherited.trim().is_empty() {
        initialize_cpuset_property(parent, name)?;
    }
    let inherited = fs::read_to_string(parent_property)?;
    fs::write(property, inherited)?;
    Ok(())
}

fn ensure_cgroup_root(path: &Path, cpuset: bool) -> Result<(), EnvError> {
    validate_absolute(path)?;
    let mut missing = Vec::new();
    let mut current = path.to_path_buf();
    while !current.exists() {
        missing.push(current.clone());
        current = current.parent().map(Path::to_path_buf).ok_or_else(|| {
            EnvError::Backend(format!(
                "cgroup root has no existing ancestor: {}",
                path.display()
            ))
        })?;
    }
    if !current.is_dir() {
        return Err(EnvError::Backend(format!(
            "cgroup root ancestor is not a directory: {}",
            current.display()
        )));
    }
    for child in missing.into_iter().rev() {
        match fs::create_dir(&child) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        if cpuset {
            initialize_cpuset(&child)?;
        }
    }
    Ok(())
}

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
        if let Some(path) = paths.get("cpuset") {
            if let Err(error) = initialize_cpuset(path) {
                remove_dirs(&created);
                return Err(error);
            }
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
pub fn discover_current_controller_paths(prefix: &str) -> Result<ControllerPaths, EnvError> {
    let membership = fs::read_to_string("/proc/self/cgroup")?;
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
    Ok(CgroupV1Builder::from_proc_data(&membership, &mountinfo, prefix)?.roots)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    fn fixture_root() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "rust-sandbox-cgroup-v1-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn discovers_controller_membership_from_mountinfo() {
        let cgroup =
            "2:cpu,cpuacct:/users/alice\n3:memory:/users/alice\n4:pids:/users/alice\n0::/unified";
        let mountinfo = concat!(
            "30 20 0:26 /users /sys/fs/cgroup/cpu\\040acct rw,nosuid,nodev,noexec,relatime - cgroup cgroup rw,cpu,cpuacct\n",
            "31 20 0:27 / /sys/fs/cgroup/memory rw,nosuid,nodev,noexec,relatime - cgroup cgroup rw,memory\n",
            "33 20 0:29 / /sys/fs/cgroup/unified rw - cgroup2 cgroup rw"
        );
        let paths = discover_controller_paths(cgroup, mountinfo).unwrap();
        assert_eq!(
            paths.get("cpu").unwrap(),
            &PathBuf::from("/sys/fs/cgroup/cpu acct/alice")
        );
        assert_eq!(paths.get("cpuacct"), paths.get("cpu"));
        assert_eq!(
            paths.get("memory").unwrap(),
            &PathBuf::from("/sys/fs/cgroup/memory/users/alice")
        );
        assert!(!paths.contains_key("pids"));

        let mount_roots = discover_controller_mount_paths(mountinfo).unwrap();
        assert_eq!(
            mount_roots.get("cpu").unwrap(),
            &PathBuf::from("/sys/fs/cgroup/cpu acct")
        );
        assert_eq!(
            mount_roots.get("memory").unwrap(),
            &PathBuf::from("/sys/fs/cgroup/memory")
        );
    }

    #[test]
    fn rejects_membership_traversal_and_invalid_prefixes() {
        assert!(parse_memberships("1:memory:/../../escape").is_err());
        let builder = CgroupV1Builder::new(ControllerPaths::new());
        assert!(builder.create("../escape").is_err());
        assert!(CgroupV1Builder::from_proc_data("1:memory:/x", "", "/absolute").is_err());
    }

    #[test]
    fn initializes_cpuset_through_empty_intermediate_ancestors() {
        let root = fixture_root();
        let middle = root.join("middle");
        let leaf = middle.join("leaf");
        fs::create_dir_all(&leaf).unwrap();
        for name in ["cpuset.cpus", "cpuset.mems"] {
            fs::write(
                root.join(name),
                if name.ends_with("cpus") {
                    "0-3\n"
                } else {
                    "0\n"
                },
            )
            .unwrap();
            fs::write(middle.join(name), "\n").unwrap();
            fs::write(leaf.join(name), "\n").unwrap();
        }

        initialize_cpuset(&leaf).unwrap();

        for (name, expected) in [("cpuset.cpus", "0-3\n"), ("cpuset.mems", "0\n")] {
            assert_eq!(fs::read_to_string(root.join(name)).unwrap(), expected);
            assert_eq!(fs::read_to_string(middle.join(name)).unwrap(), expected);
            assert_eq!(fs::read_to_string(leaf.join(name)).unwrap(), expected);
        }
        fs::remove_dir_all(root).unwrap();
    }

    fn seed_controller_files(path: &Path, controller: &str) {
        let names: &[(&str, &str)] = match controller {
            "cpu" => &[("cpu.cfs_quota_us", "-1"), ("cpu.cfs_period_us", "100000")],
            "cpuset" => &[("cpuset.cpus", ""), ("cpuset.mems", "")],
            "cpuacct" => &[("cpuacct.usage", "234000")],
            "memory" => &[
                ("memory.limit_in_bytes", "-1"),
                ("memory.usage_in_bytes", "4096"),
                ("memory.max_usage_in_bytes", "8192"),
                ("memory.memsw.max_usage_in_bytes", "12288"),
                ("memory.memsw.limit_in_bytes", "-1"),
                ("memory.stat", "cache 512\nrss 1024\n"),
            ],
            "pids" => &[("pids.max", "max")],
            _ => unreachable!(),
        };
        for (name, contents) in names {
            fs::write(path.join(name), contents).unwrap();
        }
        fs::write(path.join("cgroup.procs"), "").unwrap();
    }

    #[test]
    fn prepares_go_judge_api_and_containers_as_v1_siblings() {
        let root = fixture_root();
        let prefix = PathBuf::from("gojudge");
        let mut container_roots = ControllerPaths::new();
        for controller in CONTROLLERS {
            let mount = root.join(controller);
            fs::create_dir_all(&mount).unwrap();
            seed_controller_files(&mount, controller);
            if controller == "cpuset" {
                fs::write(mount.join("cpuset.cpus"), "0-3\n").unwrap();
                fs::write(mount.join("cpuset.mems"), "0\n").unwrap();
            }
            let base = mount.join(&prefix);
            let api = base.join("api");
            let containers = base.join("containers");
            for path in [&base, &api, &containers] {
                fs::create_dir_all(path).unwrap();
                seed_controller_files(path, controller);
            }
            fs::write(base.join("cgroup.procs"), "101").unwrap();
            container_roots.insert(controller.to_owned(), containers);
        }

        prepare_go_judge_hierarchy(&container_roots).unwrap();

        for controller in CONTROLLERS {
            let containers = container_roots.get(controller).unwrap();
            assert!(containers.is_dir());
            assert!(containers.parent().unwrap().join("api").is_dir());
            assert_eq!(
                fs::read_to_string(containers.parent().unwrap().join("api/cgroup.procs")).unwrap(),
                "101"
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn enrolls_v1_controllers_in_go_order() {
        let root = fixture_root();
        let mut paths = ControllerPaths::new();
        for controller in ["cpu", "cpuset", "cpuacct"] {
            let path = root.join(controller);
            fs::create_dir_all(&path).unwrap();
            fs::write(path.join("cgroup.procs"), "").unwrap();
            paths.insert(controller.to_owned(), path);
        }
        fs::remove_file(root.join("cpuacct/cgroup.procs")).unwrap();
        std::os::unix::fs::symlink("/dev/full", root.join("cpuacct/cgroup.procs")).unwrap();
        let mut cgroup = CgroupV1 {
            paths,
            created: Vec::new(),
            existing: true,
        };

        let error = cgroup.add_process(73).unwrap_err();

        assert_eq!(error.to_string().contains("No space left on device"), true);
        assert_eq!(
            fs::read_to_string(root.join("cpu/cgroup.procs")).unwrap(),
            "73"
        );
        assert_eq!(
            fs::read_to_string(root.join("cpuset/cgroup.procs")).unwrap(),
            "73"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn creates_configures_samples_and_destroys_all_controller_groups() {
        let root = fixture_root();
        let _ = fs::remove_dir_all(&root);
        let mut roots = ControllerPaths::new();
        for controller in CONTROLLERS {
            let path = root.join(controller);
            fs::create_dir_all(&path).unwrap();
            seed_controller_files(&path, controller);
            roots.insert(controller.to_owned(), path.join("api/containers"));
        }
        fs::write(root.join("cpuset/cpuset.cpus"), "0-3\n").unwrap();
        fs::write(root.join("cpuset/cpuset.mems"), "0\n").unwrap();
        let builder = CgroupV1Builder::new(roots);
        let mut cgroup = builder.create("exec-").unwrap();
        let paths = cgroup.paths().clone();
        for (controller, path) in &paths {
            if controller != "cpuset" {
                seed_controller_files(path, controller);
            } else {
                fs::write(path.join("cgroup.procs"), "").unwrap();
            }
        }
        let membership_fds = cgroup.open_procs().unwrap();
        assert_eq!(membership_fds.len(), CONTROLLERS.len());
        for fd in membership_fds {
            fs::File::from(fd).write_all(b"99").unwrap();
        }
        for path in paths.values() {
            assert_eq!(fs::read_to_string(path.join("cgroup.procs")).unwrap(), "99");
        }
        assert_eq!(
            fs::read_to_string(paths["cpuset"].join("cpuset.cpus")).unwrap(),
            "0-3\n"
        );
        assert_eq!(
            fs::read_to_string(paths["cpuset"].join("cpuset.mems")).unwrap(),
            "0\n"
        );

        cgroup.set_cpuset("1-2").unwrap();
        cgroup.set_memory_limit(1 << 20).unwrap();
        cgroup.set_proc_limit(7).unwrap();
        cgroup
            .set_cpu_rate(500, Duration::from_millis(100))
            .unwrap();
        assert_eq!(
            fs::read_to_string(paths["cpuset"].join("cpuset.cpus")).unwrap(),
            "1-2"
        );
        assert_eq!(
            fs::read_to_string(paths["memory"].join("memory.limit_in_bytes")).unwrap(),
            "1048576"
        );
        assert_eq!(
            fs::read_to_string(paths["pids"].join("pids.max")).unwrap(),
            "7"
        );
        assert_eq!(
            fs::read_to_string(paths["cpu"].join("cpu.cfs_quota_us")).unwrap(),
            "50000"
        );
        assert_eq!(
            fs::read_to_string(paths["cpu"].join("cpu.cfs_period_us")).unwrap(),
            "100000"
        );
        assert_eq!(cgroup.cpu_usage().unwrap(), Duration::from_nanos(234000));
        assert_eq!(cgroup.current_memory().unwrap(), 4096);
        assert_eq!(cgroup.max_memory().unwrap(), 8192);
        assert!(cgroup.proc_peak().is_err());

        cgroup.set_cpuacct_usage(777).unwrap();
        cgroup.set_memory_max_usage(16384).unwrap();
        cgroup.set_memory_memsw_limit(32768).unwrap();
        cgroup.set_cpu_cfs_period(200000).unwrap();
        cgroup.set_cpu_cfs_quota(100000).unwrap();
        cgroup.set_cpuset_mems("0-1").unwrap();
        assert_eq!(cgroup.memory_memsw_max_usage().unwrap(), 12288);
        assert_eq!(cgroup.memory_stat_property("rss").unwrap(), 1024);
        assert_eq!(
            fs::read_to_string(paths["cpuacct"].join("cpuacct.usage")).unwrap(),
            "777"
        );
        assert_eq!(
            fs::read_to_string(paths["memory"].join("memory.max_usage_in_bytes")).unwrap(),
            "16384"
        );
        assert_eq!(
            fs::read_to_string(paths["memory"].join("memory.memsw.limit_in_bytes")).unwrap(),
            "32768"
        );
        assert_eq!(
            fs::read_to_string(paths["cpu"].join("cpu.cfs_period_us")).unwrap(),
            "200000"
        );
        assert_eq!(
            fs::read_to_string(paths["cpu"].join("cpu.cfs_quota_us")).unwrap(),
            "100000"
        );
        assert_eq!(
            fs::read_to_string(paths["cpuset"].join("cpuset.mems")).unwrap(),
            "0-1"
        );

        cgroup.add_process(1234).unwrap();
        for path in paths.values() {
            assert_eq!(
                fs::read_to_string(path.join("cgroup.procs")).unwrap(),
                "1234"
            );
        }
        for path in paths.values() {
            for entry in fs::read_dir(path).unwrap() {
                fs::remove_file(entry.unwrap().path()).unwrap();
            }
        }
        Box::new(cgroup).destroy().unwrap();
        for path in paths.values() {
            assert!(!path.exists());
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn supports_named_children_existing_handles_and_process_migration() {
        let root = fixture_root();
        let mut parent_paths = ControllerPaths::new();
        for controller in ["cpu", "memory"] {
            let parent_path = root.join(controller).join("parent");
            fs::create_dir_all(&parent_path).unwrap();
            seed_controller_files(&parent_path, controller);
            fs::write(parent_path.join("cgroup.procs"), "4321").unwrap();
            let child_path = parent_path.join("nested");
            fs::create_dir(&child_path).unwrap();
            seed_controller_files(&child_path, controller);
            parent_paths.insert(controller.to_owned(), parent_path);
        }

        let parent = CgroupV1 {
            paths: parent_paths.clone(),
            created: Vec::new(),
            existing: true,
        };
        let builder = CgroupV1Builder::new(parent_paths.clone());
        let opened = builder.open_existing("nested").unwrap();
        assert!(opened.existing());
        Box::new(opened).destroy().unwrap();
        assert_eq!(parent.processes().unwrap(), vec![4321]);
        let existing_child = parent.new_child("nested").unwrap();
        assert!(existing_child.existing());
        existing_child.destroy().unwrap();

        let nested = parent.nest("nested").unwrap();
        assert!(nested.existing());
        for path in parent_paths.values() {
            assert_eq!(
                fs::read_to_string(path.join("nested/cgroup.procs")).unwrap(),
                "4321"
            );
        }
        nested.destroy().unwrap();
        assert!(
            parent_paths
                .values()
                .all(|path| path.join("nested").is_dir())
        );

        let created = parent.new_child("created").unwrap();
        assert!(!created.existing());
        let created_paths: Vec<_> = parent_paths
            .values()
            .map(|path| path.join("created"))
            .collect();
        created.destroy().unwrap();
        assert!(created_paths.iter().all(|path| !path.exists()));
        assert!(parent.new_child("../escape").is_err());

        for path in parent_paths.values() {
            fs::remove_dir_all(path).unwrap();
        }
        fs::remove_dir_all(root).unwrap();
    }
}
