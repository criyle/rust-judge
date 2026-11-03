use super::*;

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

    fn check_memory_swap_limit(&self) -> Result<(), EnvError> {
        let path = self.path.join("memory.swap.max");
        fs::metadata(path)?;
        Ok(())
    }

    fn set_memory_swap_limit(&mut self, _memory_bytes: u64) -> Result<(), EnvError> {
        self.write_optional("memory.swap.max", "0")
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
            "memory.swap.max",
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
        cgroup.check_memory_swap_limit().unwrap();
        cgroup.set_memory_swap_limit(1 << 20).unwrap();
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
        assert_eq!(
            fs::read_to_string(dir.join("memory.swap.max")).unwrap(),
            "0"
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
            "memory.swap.max",
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
