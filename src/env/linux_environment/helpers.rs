use super::*;

pub(super) fn container_resolve_flags() -> ResolveFlag {
    // Match path resolution in the container's chroot: absolute symlinks are
    // rooted at this environment, and `..` cannot escape it. Procfs magic
    // links remain disabled for host-side opens through the namespace root.
    ResolveFlag::RESOLVE_IN_ROOT | ResolveFlag::RESOLVE_NO_MAGICLINKS
}

pub(super) fn open_directory_at(
    root: &fs::File,
    path: &Path,
    no_symlinks: bool,
) -> io::Result<fs::File> {
    if path.as_os_str().is_empty() || path == Path::new(".") {
        return root.try_clone();
    }
    let mut how = OpenHow::new()
        .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
        .resolve(container_resolve_flags());
    if no_symlinks {
        how = how.resolve(container_resolve_flags() | ResolveFlag::RESOLVE_NO_SYMLINKS);
    }
    openat2(root, path, how)
        .map(fs::File::from)
        .map_err(io::Error::from)
}

pub(super) fn check_open_target(root: &fs::File, path: &Path, requested: &str) -> io::Result<bool> {
    if path.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{requested} is not a regular file"),
        ));
    }
    let parent_path = path.parent().unwrap_or(Path::new(""));
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "open target has no file name"))?;
    let parent = open_directory_at(root, parent_path, false)?;
    match fstatat(&parent, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(metadata) if SFlag::from_bits_truncate(metadata.st_mode) != SFlag::S_IFREG => {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{requested} is not a regular file"),
            ))
        }
        Ok(_) => Ok(false),
        Err(nix::errno::Errno::ENOENT) => Ok(true),
        Err(error) => Err(io::Error::from(error)),
    }
}

pub(super) fn create_parent_directories(root: &fs::File, path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    let mut current = root.try_clone()?;
    let mut prefix = PathBuf::new();
    for component in parent.components() {
        match component {
            Component::Normal(name) => {
                prefix.push(name);
                match open_directory_at(root, &prefix, false) {
                    Ok(directory) => current = directory,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        let created = match mkdirat(&current, name, Mode::from_bits_truncate(0o777))
                        {
                            Ok(()) => true,
                            Err(nix::errno::Errno::EEXIST) => false,
                            Err(error) => return Err(io::Error::from(error)),
                        };
                        let directory = open_directory_at(root, &prefix, false)?;
                        if created {
                            // PID 1 has umask(0) in Go, while these mkdirs
                            // run in the host server process. Set the
                            // resulting mode explicitly to preserve MkdirAll
                            // semantics regardless of the service umask.
                            fchmod(&directory, Mode::from_bits_truncate(0o777))
                                .map_err(io::Error::from)?;
                        }
                        current = directory;
                    }
                    Err(error) => return Err(error),
                }
            }
            Component::ParentDir => {
                prefix.push("..");
                current = open_directory_at(root, &prefix, false)?;
            }
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "path is not relative to the container root",
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn clear_directory(path: &Path) -> io::Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() && !file_type.is_symlink() {
            fs::remove_dir_all(entry_path)?;
        } else {
            fs::remove_file(entry_path)?;
        }
    }
    Ok(())
}

pub(super) fn clear_open_directory(directory: &fs::File) -> io::Result<()> {
    let path = format!("/proc/self/fd/{}", directory.as_raw_fd());
    clear_directory(Path::new(&path))
}

pub(super) fn execution_rlimits(param: &ExecveParam, cgroup_enabled: bool) -> RLimits {
    let limits = &param.limit;
    RLimits {
        cpu: limits.time.as_secs().saturating_add(1),
        data: if limits.data_segment || !cgroup_enabled {
            limits.memory.0
        } else {
            0
        },
        file_size: limits.output.0,
        stack: limits.stack.0,
        address_space: if limits.address_space {
            limits.memory.0
        } else {
            0
        },
        open_file: limits.open_file,
        disable_core: true,
        ..Default::default()
    }
}

pub(super) fn rlimit_id(resource: nix::sys::resource::Resource) -> i32 {
    use nix::sys::resource::Resource;
    match resource {
        Resource::RLIMIT_CPU => libc::RLIMIT_CPU as i32,
        Resource::RLIMIT_DATA => libc::RLIMIT_DATA as i32,
        Resource::RLIMIT_FSIZE => libc::RLIMIT_FSIZE as i32,
        Resource::RLIMIT_STACK => libc::RLIMIT_STACK as i32,
        Resource::RLIMIT_AS => libc::RLIMIT_AS as i32,
        Resource::RLIMIT_NOFILE => libc::RLIMIT_NOFILE as i32,
        Resource::RLIMIT_CORE => libc::RLIMIT_CORE as i32,
        _ => -1,
    }
}

pub(super) fn cgroup_error_is_permanent(error: &crate::env::linuxcontainer::EnvError) -> bool {
    match error {
        crate::env::linuxcontainer::EnvError::Unsupported(_) => true,
        crate::env::linuxcontainer::EnvError::Io(error) => matches!(
            error.kind(),
            io::ErrorKind::NotFound
                | io::ErrorKind::PermissionDenied
                | io::ErrorKind::ReadOnlyFilesystem
        ),
        crate::env::linuxcontainer::EnvError::Backend(_) => false,
        crate::env::linuxcontainer::EnvError::Poisoned => false,
    }
}

pub(super) fn make_temp_root(parent: &Path) -> io::Result<PathBuf> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    fs::create_dir_all(parent)?;
    for _ in 0..64 {
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = parent.join(format!("rust-sandbox-{}-{id}", std::process::id()));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "temporary container root collisions",
    ))
}

pub(super) struct TempRootGuard(pub(super) Option<PathBuf>);
impl Drop for TempRootGuard {
    fn drop(&mut self) {
        if let Some(root) = self.0.take() {
            let _ = fs::remove_dir_all(root);
        }
    }
}

/// Resolve the Go-style cgroup prefix to the leaf directory used by per-run
/// groups. Empty prefixes use the caller's current cgroup subtree.
pub fn default_cgroup_v2_root(prefix: &str) -> io::Result<PathBuf> {
    let relative = if prefix.is_empty() {
        let membership = fs::read_to_string("/proc/self/cgroup")?;
        let current = membership
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .unwrap_or("/")
            .trim_start_matches('/');
        if current.is_empty() {
            PathBuf::from("go-judge/containers")
        } else {
            PathBuf::from(current).join("containers")
        }
    } else {
        let path = Path::new(prefix);
        if path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cgroup prefix must be a safe relative path",
            ));
        }
        path.join("containers")
    };
    Ok(Path::new("/sys/fs/cgroup").join(relative))
}

/// Resolve the current process's unified cgroup directory from procfs.
pub fn current_cgroup_v2_path() -> io::Result<PathBuf> {
    let membership = fs::read_to_string("/proc/self/cgroup")?;
    let raw = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "process is not in a unified cgroup v2 hierarchy",
            )
        })?;
    let relative = Path::new(raw.trim_start_matches('/'));
    if raw != "/"
        && relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid current cgroup v2 membership path",
        ));
    }
    Ok(Path::new("/sys/fs/cgroup").join(relative))
}

/// Resolve the per-controller v1 roots used by go-judge's `containers` child
/// hierarchy. Controller mount points are discovered from procfs; an empty
/// configured prefix uses Go's `go-judge` default.
pub fn default_cgroup_v1_roots(prefix: &str) -> io::Result<crate::env::cgroup_v1::ControllerPaths> {
    let root = if prefix.is_empty() {
        PathBuf::from("go-judge/containers")
    } else {
        let prefix_path = Path::new(prefix);
        if prefix_path.is_absolute()
            || prefix_path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cgroup prefix must be a safe relative path",
            ));
        }
        prefix_path.join("containers")
    };
    cgroup_v1_roots_at_mount_prefix(&root)
}

/// Resolve a relative v1 hierarchy below each controller's mount point. Go's
/// server and runprog use `cgroup.New(prefix)`, which is mount-root-relative.
pub fn cgroup_v1_roots_at_mount_prefix(
    relative_root: &Path,
) -> io::Result<crate::env::cgroup_v1::ControllerPaths> {
    if relative_root.as_os_str().is_empty()
        || relative_root.is_absolute()
        || relative_root
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cgroup root must be a safe relative path",
        ));
    }
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
    let mounts = crate::env::cgroup_v1::discover_controller_mount_paths(&mountinfo)
        .map_err(io::Error::other)?;
    Ok(mounts
        .into_iter()
        .map(|(controller, mount)| (controller, mount.join(relative_root)))
        .collect())
}

/// Resolve a relative v1 cgroup hierarchy below the current process's
/// controller memberships. Use this only when the caller intentionally wants
/// a delegated subtree rooted at its own memberships.
pub fn cgroup_v1_roots_at_current_membership(
    relative_root: &Path,
) -> io::Result<crate::env::cgroup_v1::ControllerPaths> {
    let builder = crate::env::cgroup_v1::CgroupV1Builder::from_proc_data(
        &fs::read_to_string("/proc/self/cgroup")?,
        &fs::read_to_string("/proc/self/mountinfo")?,
        relative_root.to_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "cgroup root is not UTF-8")
        })?,
    )
    .map_err(io::Error::other)?;
    Ok(builder.roots().clone())
}

pub(super) fn find_container_init() -> io::Result<PathBuf> {
    if let Some(path) = std::env::var_os("RUST_SANDBOX_CONTAINER_INIT") {
        return Ok(path.into());
    }
    let current = std::env::current_exe()?;
    #[cfg(test)]
    {
        find_test_container_init(&current).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "container-init test helper is missing; build binaries with `cargo build --bins` before running sandbox tests",
            )
        })
    }
    #[cfg(not(test))]
    Ok(resolve_container_init(&current))
}

/// Go's container.Builder defaults ExecFile to `/proc/self/exe`, which
/// re-executes the production server as the container PID 1. Rust cannot run
/// package init hooks, so the `rust-judge` binary dispatches `container_init`
/// before starting its server (see `src/bin/rust-judge.rs`). Keep this resolver
/// identical to Go's default; standalone helpers are explicit overrides only.
pub(super) fn resolve_container_init(current: &Path) -> PathBuf {
    current.to_owned()
}

#[cfg(test)]
pub(super) fn find_test_container_init(current: &Path) -> Option<PathBuf> {
    let direct = current.with_file_name("container-init");
    if direct.is_file() {
        return Some(direct);
    }
    if let Some(parent) = current.parent()
        && parent.file_name().is_some_and(|name| name == "deps")
    {
        let sibling = parent.parent().unwrap_or(parent).join("container-init");
        if sibling.is_file() {
            return Some(sibling);
        }
    }
    None
}

pub(super) fn container_init_source(
    config: &LinuxEnvironmentConfig,
) -> io::Result<Option<PathBuf>> {
    if let Some(path) = config.container_init_path.as_ref() {
        if path.is_file() {
            return Ok(Some(path.clone()));
        }
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("container-init helper not found: {}", path.display()),
        ));
    }
    Ok(find_container_init().ok())
}

pub(super) fn wait_namespace_child(parent_pid: i32, timeout: Duration) -> io::Result<i32> {
    let children_path = format!("/proc/{parent_pid}/task/{parent_pid}/children");
    let start = Instant::now();
    loop {
        match fs::read_to_string(&children_path) {
            Ok(children) => {
                if let Some(pid) = children
                    .split_whitespace()
                    .next()
                    .and_then(|value| value.parse::<i32>().ok())
                {
                    return Ok(pid);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        if start.elapsed() >= timeout {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "namespace keeper did not start in time",
            ));
        }
        thread::sleep(Duration::from_millis(2));
    }
}

pub(super) fn prepare_mount_target(source: &Path, target: &Path) -> io::Result<()> {
    if source.is_dir() {
        fs::create_dir_all(target)
    } else {
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(target)
            .map(|_| ())
    }
}

pub(super) fn create_symlinks(root: &Path, links: &[crate::env::Link]) -> io::Result<()> {
    for link in links {
        let path = root.join(normalize_container_path(&link.link_path)?.trim_start_matches('/'));
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let _ = fs::remove_file(&path);
        std::os::unix::fs::symlink(&link.target, path)?;
    }
    Ok(())
}

pub(super) fn normalize_container_path(path: &str) -> io::Result<String> {
    let path = Path::new(path);
    let mut clean = PathBuf::from("/");
    for part in path.components() {
        match part {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(value) => clean.push(value),
            Component::ParentDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "path escapes container root",
                ));
            }
        }
    }
    Ok(clean.to_string_lossy().into_owned())
}

pub(super) fn read_dotenv(path: &str) -> io::Result<Vec<String>> {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    content
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                None
            } else if line.contains('=') {
                Some(Ok(line.to_owned()))
            } else {
                Some(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("dotenv: invalid line {}", index + 1),
                )))
            }
        })
        .collect()
}

pub(super) fn lookup_container_executable(
    root: &fs::File,
    work_dir: &str,
    name: &str,
    environment: &[String],
) -> io::Result<String> {
    if Path::new(name).file_name().is_none_or(|base| base != name) {
        return Ok(name.to_owned());
    }

    let is_executable = |container_path: &Path| {
        let relative = if container_path.is_absolute() {
            container_path
                .strip_prefix("/")
                .unwrap_or(container_path)
                .to_path_buf()
        } else {
            Path::new(work_dir.trim_start_matches('/')).join(container_path)
        };
        let how = OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_IN_ROOT | ResolveFlag::RESOLVE_NO_MAGICLINKS);
        openat2(root, &relative, how)
            .ok()
            .and_then(|fd| fs::File::from(fd).metadata().ok())
            .is_some_and(|metadata| !metadata.is_dir() && metadata.mode() & 0o111 != 0)
    };
    let work_path = Path::new(work_dir).join(name);
    if is_executable(&work_path) {
        return Ok(format!("./{name}"));
    }

    let path = environment
        .iter()
        .rev()
        .find_map(|entry| entry.strip_prefix("PATH="))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "no PATH environment variable provided for look up",
            )
        })?;
    for directory in path.split(':') {
        let directory = if directory.is_empty() { "." } else { directory };
        let candidate = Path::new(directory).join(name);
        if is_executable(&candidate) {
            let candidate = if candidate.is_absolute() {
                candidate
            } else {
                Path::new(".").join(candidate)
            };
            return Ok(candidate.to_string_lossy().into_owned());
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "executable file not found in $PATH",
    ))
}

pub(super) fn cstring(value: &str) -> io::Result<CString> {
    CString::new(value).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in string"))
}
pub(super) fn cstring_path(value: &Path) -> io::Result<CString> {
    CString::new(value.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))
}

pub(super) fn chown_fd(fd: i32, uid: u32, gid: u32) -> io::Result<()> {
    if unsafe { libc::fchown(fd, uid as libc::uid_t, gid as libc::gid_t) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn is_anonymous_pipe(fd: i32) -> io::Result<bool> {
    let target = fs::read_link(format!("/proc/self/fd/{fd}"))?;
    Ok(target.to_string_lossy().starts_with("pipe:["))
}
