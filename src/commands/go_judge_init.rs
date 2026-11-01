//! Rust-native container control server used by the PID-1 helper.
//!
//! The control channel uses the repository's protobuf plus Unix seqpacket
//! transport. File descriptors are carried with `SCM_RIGHTS`; gob is not used.

use crate::container::{
    fork_exec::{Credential, Runner},
    protocol::{self, Command, CommandType, ErrorReply, ExecReply, Reply, WireCommand, WireReply},
    rlimit::RLimits,
    unix_socket::Socket,
};
use nix::sys::socket::{ControlMessage, UnixCredentials};
use std::os::unix::process::ExitStatusExt;
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
        unix::fs::OpenOptionsExt,
    },
    path::Path,
    process::Command as ProcessCommand,
    time::Duration,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitError(pub String);
impl std::fmt::Display for InitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for InitError {}

#[derive(Clone, Debug)]
struct InitConfig {
    work_dir: String,
    container_root: Option<CString>,
    default_env: Vec<String>,
    uid: Option<u32>,
    gid: Option<u32>,
    unshare_cgroup: bool,
    seccomp: crate::container::seccomp::Filter,
    reset_paths: Vec<String>,
}
impl Default for InitConfig {
    fn default() -> Self {
        Self {
            work_dir: "/w".into(),
            container_root: None,
            default_env: read_dotenv().unwrap_or_default(),
            uid: Some(1000),
            gid: Some(1000),
            unshare_cgroup: false,
            seccomp: Default::default(),
            reset_paths: Vec::new(),
        }
    }
}

/// Mirrors Go `container.Init`: outside its PID-1 invocation this is a no-op.
pub fn run() -> Result<(), InitError> {
    let args = std::env::args_os().collect::<Vec<_>>();
    if unsafe { libc::getpid() } != 1
        || args.get(1).and_then(|arg| arg.to_str()) != Some("container_init")
    {
        return Ok(());
    }
    // Match Go's container-init behavior for explicit file and directory
    // modes: do not inherit a restrictive service umask.
    unsafe { libc::umask(0) };
    ignore_container_signals();
    close_on_exec_all_fds().map_err(init_error)?;
    // The parent establishes the seqpacket socket at fd 3 before exec.
    let fd = unsafe { OwnedFd::from_raw_fd(3) };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(init_error)?;
    let socket = runtime
        .block_on(async { Socket::new(fd) })
        .map_err(init_error)?;
    runtime.block_on(serve(socket)).map_err(init_error)
}

fn ignore_container_signals() {
    for signal in [
        libc::SIGBUS,
        libc::SIGFPE,
        libc::SIGSEGV,
        libc::SIGHUP,
        libc::SIGINT,
        libc::SIGTERM,
        libc::SIGQUIT,
        libc::SIGILL,
        libc::SIGTRAP,
        libc::SIGABRT,
        libc::SIGSTKFLT,
        libc::SIGSYS,
    ] {
        // SAFETY: SIG_IGN is a valid disposition and the signal number is
        // from libc's Linux signal constants.
        unsafe { libc::signal(signal, libc::SIG_IGN) };
    }
}

fn close_on_exec_all_fds() -> io::Result<()> {
    for entry in fs::read_dir("/proc/self/fd")? {
        let entry = entry?;
        let fd = entry
            .file_name()
            .to_string_lossy()
            .parse::<i32>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid proc fd entry"))?;
        // SAFETY: fcntl operates on the descriptor enumerated from procfs.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags == -1 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EBADF) {
                continue;
            }
            return Err(error);
        }
        // SAFETY: flags were obtained for the same live descriptor above.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EBADF) {
                continue;
            }
            return Err(error);
        }
    }
    Ok(())
}

async fn serve(socket: Socket) -> io::Result<()> {
    let mut config = InitConfig::default();
    loop {
        let (wire, _frame) = protocol::recv_proto::<WireCommand>(&socket).await?;
        let command = Command::try_from(wire)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        match command.cmd {
            Some(CommandType::Ping) => {
                send_reply(&socket, &Reply::default(), &[], None).await?;
            }
            Some(CommandType::Configure) => {
                let result = configure(&mut config, command.conf_cmd);
                send_reply(&socket, &result.unwrap_or_else(error_reply), &[], None).await?;
            }
            Some(CommandType::Open) => {
                let (reply, files) = open_files(&command.open_cmd);
                send_reply_files(&socket, &reply, &files, None).await?;
            }
            Some(CommandType::Delete) => {
                let reply = delete_file(command.delete_cmd);
                send_reply(&socket, &reply, &[], None).await?;
            }
            Some(CommandType::Reset) => {
                let reply = reset(&config.reset_paths);
                send_reply(&socket, &reply, &[], None).await?;
            }
            Some(CommandType::Symlink) => {
                let reply = symlink_files(&command.symlink_cmd);
                send_reply(&socket, &reply, &[], None).await?;
            }
            Some(CommandType::Exec) => {
                let (_reply, frame) = (Reply::default(), _frame);
                let (reply, kill_received) =
                    execute(&socket, &config, command.exec_cmd, frame.fds).await?;
                let wait_for_kill = reply.exec_reply.is_some() && !kill_received;
                send_reply(&socket, &reply, &[], None).await?;
                if wait_for_kill {
                    // Go's container host sends this after receiving the
                    // wait result. Consume it before returning to the command
                    // loop so it cannot be mistaken for the next request.
                    let _ = protocol::recv_proto::<WireCommand>(&socket).await?;
                }
            }
            Some(CommandType::Ok | CommandType::Kill) | None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unknown command outside an active execution",
                ));
            }
        }
    }
}

fn configure(
    config: &mut InitConfig,
    command: Option<crate::container::protocol::ConfigureCommand>,
) -> Result<Reply, io::Error> {
    let Some(command) = command else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "configure: missing config",
        ));
    };
    let conf = command.conf;
    let filesystem = filesystem_plan(
        &conf.container_root,
        &conf.mounts,
        &conf.symbolic_links,
        &conf.mask_paths,
    )?;
    // The production Rust launcher prepares the namespace root before it
    // execs itself as PID 1. Go's launcher passes the host-side temporary root
    // here and lets container.Init perform the mount/pivot; `/` means that
    // setup has already happened in the namespace runner.
    if conf.container_root != "/" {
        setup_filesystem(&filesystem)?;
    } else {
        // The Rust namespace launcher already mounted the root and its bind
        // and tmpfs mounts. Finish the container setup that Go normally does
        // in container.Init: proc mounts, links, and masks.
        for mount in filesystem.mounts {
            mount
                .mount()
                .map_err(|error| io::Error::other(format!("init_fs: mount {mount}: {error}")))?;
        }
        for link in filesystem.links {
            let path = Path::new(&link.link_path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            std::os::unix::fs::symlink(&link.target, path)?;
        }
        for path in filesystem.mask_paths {
            mask_path(path)?;
        }
    }
    if !conf.container_root.is_empty() {
        config.container_root = Some(cstring(&conf.container_root)?);
    }
    config.work_dir = if conf.work_dir.is_empty() {
        "/w".into()
    } else {
        conf.work_dir
    };
    // Go's container.Init changes PID 1's working directory before running
    // the init command. This also defines how relative Open, Delete, and
    // Symlink control requests resolve while the container is alive.
    std::env::set_current_dir(&config.work_dir)?;
    config.default_env = read_dotenv()?;
    config.uid = if conf.cred {
        Some(if conf.container_uid == 0 {
            1000
        } else {
            conf.container_uid as u32
        })
    } else {
        None
    };
    config.gid = if conf.cred {
        Some(if conf.container_gid == 0 {
            1000
        } else {
            conf.container_gid as u32
        })
    } else {
        None
    };
    config.seccomp = conf.seccomp;
    config.unshare_cgroup = conf.unshare_cgroup;
    config.reset_paths = conf
        .mounts
        .into_iter()
        .filter(|mount| mount.is_tmpfs())
        .map(|mount| mount.target)
        .collect();
    if !conf.host_name.is_empty() {
        let name = cstring(&conf.host_name)?;
        if unsafe { libc::sethostname(name.as_ptr(), name.as_bytes().len()) } == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    if !conf.domain_name.is_empty() {
        let name = cstring(&conf.domain_name)?;
        if unsafe { libc::setdomainname(name.as_ptr(), name.as_bytes().len()) } == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    if !conf.init_command.is_empty() {
        let mut command = ProcessCommand::new(&conf.init_command[0]);
        command.args(&conf.init_command[1..]);
        command.current_dir(&config.work_dir);
        command.envs(
            config
                .default_env
                .iter()
                .filter_map(|item| item.split_once('=')),
        );
        let output = command.output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "init command failed: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )));
        }
    }
    // Go installs the container policy once, after filesystem and init-command
    // setup. PID 1 is the parent of every workload, so children inherit the
    // filter and the init server remains subject to the same policy. This
    // runtime is current-thread, hence each stacked BPF program can be applied
    // with TSYNC without needing a Go-style runtime-wide thread rendezvous.
    install_seccomp(&config.seccomp)?;
    Ok(Reply::default())
}

fn install_seccomp(filter: &crate::container::seccomp::Filter) -> io::Result<()> {
    for program in filter.programs() {
        if program.is_empty() {
            continue;
        }
        let program = program
            .iter()
            .map(|instruction| seccompiler::sock_filter {
                code: instruction.code,
                jt: instruction.jt,
                jf: instruction.jf,
                k: instruction.k,
            })
            .collect::<Vec<_>>();
        seccompiler::apply_filter_all_threads(&program).map_err(|error| {
            io::Error::other(format!("install seccomp in container init: {error}"))
        })?;
    }
    Ok(())
}

/// Validated, side-effect-free description of the filesystem setup performed
/// by Go's `initFileSystem`. Keeping planning separate makes ordering and
/// protocol validation testable without mount privileges.
#[derive(Debug)]
struct FileSystemPlan<'a> {
    root: CString,
    mounts: &'a [crate::container::mount::Mount],
    links: &'a [crate::container::protocol::SymbolicLink],
    mask_paths: &'a [String],
}

fn filesystem_plan<'a>(
    root: &str,
    mounts: &'a [crate::container::mount::Mount],
    links: &'a [crate::container::protocol::SymbolicLink],
    mask_paths: &'a [String],
) -> io::Result<FileSystemPlan<'a>> {
    if root.is_empty() || !Path::new(root).is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "init_fs: container root must be an absolute path",
        ));
    }
    let root = cstring(root)?;
    for mount in mounts {
        cstring(&mount.target)?;
        cstring(&mount.source)?;
        cstring(&mount.fs_type)?;
        cstring(&mount.data)?;
    }
    for link in links {
        cstring(&link.link_path)?;
        cstring(&link.target)?;
    }
    for path in mask_paths {
        cstring(path)?;
    }
    Ok(FileSystemPlan {
        root,
        mounts,
        links,
        mask_paths,
    })
}

fn setup_filesystem(plan: &FileSystemPlan<'_>) -> io::Result<()> {
    mount_fs(
        Some(c"tmpfs"),
        plan.root.as_c_str(),
        Some(c"tmpfs"),
        0,
        None,
    )
    .map_err(|error| io::Error::other(format!("init_fs: mount /: {error}")))?;
    std::env::set_current_dir(plan.root.to_string_lossy().as_ref())
        .map_err(|error| io::Error::other(format!("init_fs: chdir: {error}")))?;

    for mount in plan.mounts {
        mount
            .mount()
            .map_err(|error| io::Error::other(format!("init_fs: mount {mount}: {error}")))?;
    }

    fs::create_dir("old_root")
        .map_err(|error| io::Error::other(format!("init_fs: mkdir old_root: {error}")))?;
    let old_root = c"old_root";
    // SAFETY: root and old_root are NUL-terminated and remain alive for the
    // syscall. The process is expected to be privileged in a mount namespace.
    let result =
        unsafe { libc::syscall(libc::SYS_pivot_root, plan.root.as_ptr(), old_root.as_ptr()) };
    if result == -1 {
        return Err(io::Error::other(format!(
            "init_fs: pivot_root({}, old_root): {}",
            plan.root.to_string_lossy(),
            io::Error::last_os_error()
        )));
    }
    let old_root_path = c"old_root";
    // SAFETY: old_root_path is a valid NUL-terminated path.
    if unsafe { libc::umount2(old_root_path.as_ptr(), libc::MNT_DETACH) } == -1 {
        return Err(io::Error::other(format!(
            "init_fs: unmount old_root: {}",
            io::Error::last_os_error()
        )));
    }
    fs::remove_dir("old_root")
        .map_err(|error| io::Error::other(format!("init_fs: unlink old_root: {error}")))?;

    for link in plan.links {
        let path = Path::new(&link.link_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                io::Error::other(format!("init_fs: mkdir_all({}): {error}", parent.display()))
            })?;
        }
        std::os::unix::fs::symlink(&link.target, path)
            .map_err(|error| io::Error::other(format!("init_fs: symlink: {error}")))?;
    }
    for path in plan.mask_paths {
        mask_path(path)
            .map_err(|error| io::Error::other(format!("init_fs: mask path: {error}")))?;
    }

    let readonly_flags =
        libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOATIME | libc::MS_NOSUID;
    mount_fs(Some(c"tmpfs"), c"/", Some(c"tmpfs"), readonly_flags, None)
        .map_err(|error| io::Error::other(format!("init_fs: readonly remount /: {error}")))
}

fn mount_fs(
    source: Option<&std::ffi::CStr>,
    target: &std::ffi::CStr,
    fs_type: Option<&std::ffi::CStr>,
    flags: libc::c_ulong,
    data: Option<&std::ffi::CStr>,
) -> io::Result<()> {
    // SAFETY: every non-null pointer refers to a live NUL-terminated C string.
    let result = unsafe {
        libc::mount(
            source.map_or(std::ptr::null(), std::ffi::CStr::as_ptr),
            target.as_ptr(),
            fs_type.map_or(std::ptr::null(), std::ffi::CStr::as_ptr),
            flags,
            data.map_or(std::ptr::null(), |value| value.as_ptr().cast()),
        )
    };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn mask_path(path: &str) -> io::Result<()> {
    let dev_null = c"/dev/null";
    let target = cstring(path)?;
    // Go masks files by bind mounting /dev/null. A missing path is ignored;
    // when the target is beneath a non-directory, it falls back to readonly
    // tmpfs, matching the upstream behavior.
    match mount_fs(
        Some(dev_null),
        target.as_c_str(),
        Some(c""),
        libc::MS_BIND,
        Some(c""),
    ) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) if error.raw_os_error() == Some(libc::ENOTDIR) => mount_fs(
            Some(c"tmpfs"),
            target.as_c_str(),
            Some(c"tmpfs"),
            libc::MS_RDONLY as libc::c_ulong,
            Some(c""),
        ),
        Err(error) => Err(io::Error::other(format!("mask path: {error}"))),
    }
}

fn open_files(commands: &[crate::container::protocol::OpenCommand]) -> (Reply, Vec<File>) {
    if commands.is_empty() {
        return (
            error_reply(io::Error::new(
                io::ErrorKind::InvalidInput,
                "open: no open parameter received",
            )),
            Vec::new(),
        );
    }
    let mut errors = Vec::with_capacity(commands.len());
    let mut files = Vec::new();
    for command in commands {
        let result = open_one(command);
        match result {
            Ok(file) => {
                errors.push(String::new());
                files.push(file);
            }
            Err(error) => errors.push(error.to_string()),
        }
    }
    (
        Reply {
            batch_errors: errors,
            ..Default::default()
        },
        files,
    )
}

fn open_one(command: &crate::container::protocol::OpenCommand) -> io::Result<File> {
    let path = Path::new(&command.path);
    if command.mkdir_all {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "open target is not a regular file",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut options = OpenOptions::new();
    options
        .read(command.flag & libc::O_ACCMODE as i64 != libc::O_WRONLY as i64)
        .write(command.flag & libc::O_ACCMODE as i64 != libc::O_RDONLY as i64)
        .mode(command.perm)
        .custom_flags(command.flag as i32);
    options.open(path)
}

fn delete_file(command: Option<crate::container::protocol::DeleteCommand>) -> Reply {
    let Some(command) = command else {
        return error_reply(io::Error::new(
            io::ErrorKind::InvalidInput,
            "delete: no parameter provided",
        ));
    };
    match fs::remove_file(&command.path).or_else(|error| {
        if error.kind() == io::ErrorKind::IsADirectory {
            fs::remove_dir(&command.path)
        } else {
            Err(error)
        }
    }) {
        Ok(()) => Reply::default(),
        Err(error) => error_reply(io::Error::other(format!("delete: {error}"))),
    }
}

fn symlink_files(links: &[crate::container::protocol::SymbolicLink]) -> Reply {
    let errors = links
        .iter()
        .map(|link| {
            std::os::unix::fs::symlink(&link.target, &link.link_path)
                .err()
                .map_or_else(String::new, |e| e.to_string())
        })
        .collect();
    Reply {
        batch_errors: errors,
        ..Default::default()
    }
}

fn reset(paths: &[String]) -> Reply {
    for path in paths {
        if let Err(error) = remove_contents(Path::new(path)) {
            return error_reply(io::Error::other(format!("reset: {path}: {error}")));
        }
    }
    Reply::default()
}

fn remove_contents(path: &Path) -> io::Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let path = entry.path();
        let kind = entry.file_type()?;
        if kind.is_dir() && !kind.is_symlink() {
            fs::remove_dir_all(path)?;
        } else {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

async fn execute(
    socket: &Socket,
    config: &InitConfig,
    command: Option<crate::container::protocol::ExecCommand>,
    fds: Vec<OwnedFd>,
) -> io::Result<(Reply, bool)> {
    let Some(command) = command else {
        return Ok((
            error_reply(io::Error::new(
                io::ErrorKind::InvalidInput,
                "exec: no parameter provided",
            )),
            false,
        ));
    };
    let mut fds = fds;
    let exec_file = if command.fd_exec {
        if fds.is_empty() {
            return Ok((
                error_reply(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "exec: expected executable fd",
                )),
                false,
            ));
        }
        Some(fds.remove(0))
    } else {
        None
    };
    let cgroup_fds = if command.fd_cgroup {
        let count = command.cgroup_fd_count.max(1) as usize;
        if fds.len() < count {
            return Ok((
                error_reply(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "exec: expected cgroup fd",
                )),
                false,
            ));
        }
        fds.drain(0..count).collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    // The protocol supplies a cgroup directory descriptor (the Go fork-exec
    // path uses it with clone3). The std::process backend cannot pass that
    // descriptor to clone3, so open the directory's membership file and move
    // the child into the requested group in its pre_exec hook instead.
    let mut cgroup_procs_files = Vec::with_capacity(cgroup_fds.len());
    for directory in cgroup_fds {
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                c"cgroup.procs".as_ptr(),
                libc::O_WRONLY | libc::O_CLOEXEC,
            )
        };
        if fd == -1 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENOTDIR) {
                // Rust's environment can pass the already opened cgroup.procs
                // file instead of its parent directory.
                cgroup_procs_files.push(File::from(directory));
                continue;
            }
            return Ok((error_reply(error), false));
        }
        cgroup_procs_files.push(unsafe { File::from_raw_fd(fd) });
    }
    let args = command
        .argv
        .iter()
        .map(|arg| cstring(arg))
        .collect::<io::Result<Vec<_>>>()?;
    if args.is_empty() {
        return Ok((
            error_reply(io::Error::new(
                io::ErrorKind::InvalidInput,
                "exec: missing argv",
            )),
            false,
        ));
    }
    let mut env = config.default_env.clone();
    env.extend(command.env);
    let mut runner = Runner {
        args,
        env: env
            .iter()
            .map(|item| cstring(item))
            .collect::<io::Result<Vec<_>>>()?,
        work_dir: cstring(&config.work_dir)?,
        // PID 1 already pivoted into the configured container root during
        // Configure. Reapplying chroot in each workload is both redundant and
        // forbidden by the inherited Go-compatible seccomp policy.
        container_root: None,
        bind_mounts: Vec::new(),
        proc_mounts: Vec::new(),
        tmpfs_mounts: Vec::new(),
        rootfs_tmpfs: false,
        symlinks: Vec::new(),
        mask_paths: Vec::new(),
        fd_map: fds.iter().map(AsRawFd::as_raw_fd).collect(),
        exec_file: exec_file.as_ref().map(AsRawFd::as_raw_fd),
        pid_namespace_helper: None,
        helper_unshare_flags: 0,
        helper_args: None,
        cgroup_procs_fds: cgroup_procs_files.iter().map(AsRawFd::as_raw_fd).collect(),
        user_namespace_fd: None,
        rlimits: convert_rlimits(&command.rlimits)?,
        pivot_root: None,
        host_name: None,
        domain_name: None,
        sync_fn: None,
        clone_flags: 0,
        credential: config.uid.zip(config.gid).map(|(uid, gid)| Credential {
            uid,
            gid,
            groups: Vec::new(),
            no_set_groups: true,
        }),
        uid_map: None,
        gid_map: None,
        gid_map_enable_set_groups: false,
        no_new_privs: true,
        // Configure installs the persistent container filter on PID 1, so
        // forked workloads inherit it exactly once (Go's container behavior).
        seccomp: command.seccomp,
        drop_caps: true,
        unshare_cgroup_after_sync: config.unshare_cgroup,
        control_tty: command.ctty,
        cpu_set: if command.cpu_set.is_empty() {
            None
        } else {
            Some(cstring(&command.cpu_set)?)
        },
    };
    let mut child = match runner.start() {
        Ok(child) => child,
        Err(error) => return Ok((error_reply(error), false)),
    };
    let pid = child.id() as i32;
    // The Go protocol reports the started process through SCM_CREDENTIALS.
    // std::process::Command has completed its exec handshake at this point.
    let credentials = unsafe {
        UnixCredentials::from(libc::ucred {
            pid: if command.sync_after { 1 } else { pid },
            uid: libc::getuid(),
            gid: libc::getgid(),
        })
    };
    if let Err(error) = send_reply(socket, &Reply::default(), &[], Some(credentials)).await {
        stop_child_and_reap(&mut child, pid);
        return Err(error);
    }

    let mut usage = ProcessUsage::default();
    let mut kill_received = false;
    let mut pidfd = open_pidfd_async(pid);
    let status = loop {
        let event = tokio::select! {
            result = wait_pidfd_ready(pidfd.as_ref().expect("enabled pidfd branch")), if pidfd.is_some() => {
                ChildWaitEvent::Pidfd(result)
            }
            _ = tokio::time::sleep(Duration::from_millis(5)), if pidfd.is_none() => {
                ChildWaitEvent::Poll
            }
            received = protocol::recv_proto::<WireCommand>(socket) => {
                ChildWaitEvent::Control(received)
            }
        };
        match event {
            ChildWaitEvent::Pidfd(Ok(())) => {
                if let Some(status) = try_wait_process_usage(pid, &mut usage)? {
                    break status;
                }
                // Readiness on a live child should not occur. Fall back to
                // polling if a kernel or descriptor implementation reports a
                // spurious readiness event.
                pidfd = None;
            }
            ChildWaitEvent::Pidfd(Err(_)) => {
                // pidfd_open or epoll registration can be unavailable under
                // older kernels and restricted seccomp profiles.
                pidfd = None;
            }
            ChildWaitEvent::Poll => {
                sample_process_usage(pid, &mut usage);
                if let Some(status) = try_wait_process_usage(pid, &mut usage)? {
                    break status;
                }
            }
            ChildWaitEvent::Control(received) => {
                let (wire, _) = match received {
                    Ok(message) => message,
                    Err(error) => {
                        stop_child_and_reap(&mut child, pid);
                        return Err(error);
                    }
                };
                match Command::try_from(wire) {
                    Ok(message) if message.cmd == Some(CommandType::Kill) => {
                        kill_received = true;
                        let _ = unsafe { libc::kill(-pid, libc::SIGKILL) };
                    }
                    Ok(message) if message.cmd == Some(CommandType::Ok) => {}
                    Ok(_) => {
                        stop_child_and_reap(&mut child, pid);
                        return Ok((
                            error_reply(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "only kill/ok is valid while a command runs",
                            )),
                            false,
                        ));
                    }
                    Err(error) => {
                        stop_child_and_reap(&mut child, pid);
                        return Ok((error_reply(error), false));
                    }
                }
            }
        }
    };
    // PID 1 owns descendants orphaned by the payload. Stop the remaining
    // process group and reap those children before returning to the command
    // loop, matching go-sandbox's waitAll behavior.
    let _ = unsafe { libc::kill(-pid, libc::SIGKILL) };
    reap_children(pid);
    let exit_time_ns = crate::envexec::monotonic_time_ns().unwrap_or_default();
    let (status_code, exit_status) = if let Some(code) = status.code() {
        (if code == 0 { 0 } else { 7 }, code)
    } else if let Some(signal) = status.signal() {
        let code = match signal {
            libc::SIGXCPU | libc::SIGKILL => 2,
            libc::SIGXFSZ => 4,
            libc::SIGSYS => 5,
            _ => 6,
        };
        (code, signal)
    } else {
        (8, -1)
    };
    Ok((
        Reply {
            exec_reply: Some(ExecReply {
                exit_status,
                status: status_code,
                // The pidfd path supplies wait4's final usage. Procfs sampling
                // fills usage only on kernels where pidfd waiting is unavailable.
                time_ns: usage.user_time_ns.min(i64::MAX as u64) as i64,
                memory_bytes: usage.peak_memory_bytes,
                exit_time_ns,
            }),
            ..Default::default()
        },
        kill_received,
    ))
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ProcessUsage {
    user_time_ns: u64,
    peak_memory_bytes: u64,
}

enum ChildWaitEvent {
    Pidfd(io::Result<()>),
    Poll,
    Control(io::Result<(WireCommand, protocol::ReceivedFrame)>),
}

fn open_pidfd_async(pid: i32) -> Option<tokio::io::unix::AsyncFd<OwnedFd>> {
    // SAFETY: pidfd_open takes a PID and flags; the returned descriptor is
    // uniquely owned when the syscall succeeds.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if fd < 0 {
        return None;
    }
    // SAFETY: a successful pidfd_open returns a fresh owned descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    // SAFETY: the pidfd is owned here, and no other code polls or mutates it.
    unsafe { tokio::io::unix::AsyncFd::register(fd) }.ok()
}

async fn wait_pidfd_ready(pidfd: &tokio::io::unix::AsyncFd<OwnedFd>) -> io::Result<()> {
    let mut ready = pidfd.readable().await?;
    ready.clear_ready();
    Ok(())
}

fn sample_process_usage(pid: i32, usage: &mut ProcessUsage) {
    let proc_dir = Path::new("/proc").join(pid.to_string());
    if let Ok(stat) = fs::read_to_string(proc_dir.join("stat")) {
        if let Some(ticks) = process_user_ticks(&stat) {
            let ticks_per_second = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as u64;
            let ns = ticks.saturating_mul(1_000_000_000) / ticks_per_second;
            usage.user_time_ns = usage.user_time_ns.max(ns);
        }
    }
    if let Ok(status) = fs::read_to_string(proc_dir.join("status")) {
        if let Some(bytes) = process_vm_hwm_bytes(&status) {
            usage.peak_memory_bytes = usage.peak_memory_bytes.max(bytes);
        }
    }
}

/// Reap an exited child with wait4 so the final user CPU time and peak RSS
/// match Go's syscall.Wait4 result. waitid with WNOWAIT detects completion
/// without consuming the status, keeping the child available to std's
/// Child::kill cleanup path if the container control socket closes first.
fn try_wait_process_usage(
    pid: i32,
    usage: &mut ProcessUsage,
) -> io::Result<Option<std::process::ExitStatus>> {
    let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
    // SAFETY: waitid initializes siginfo_t on success. WNOWAIT leaves the
    // child waitable so wait4 below remains the single reaping operation.
    if unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            info.as_mut_ptr(),
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: waitid returned success and initialized the structure.
    let info = unsafe { info.assume_init() };
    // SAFETY: si_pid is valid for SIGCHLD waitid results.
    if unsafe { info.si_pid() } == 0 {
        return Ok(None);
    }

    let mut status = 0;
    let mut raw_usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    loop {
        // SAFETY: pid is the direct child launched by std::process::Command;
        // both output pointers remain valid for the duration of the syscall.
        let result = unsafe { libc::wait4(pid, &mut status, 0, raw_usage.as_mut_ptr()) };
        if result == pid {
            break;
        }
        if result == -1 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        return Err(io::Error::other("wait4 returned an unexpected child pid"));
    }
    // SAFETY: wait4 returned the requested pid and initialized rusage.
    let raw_usage = unsafe { raw_usage.assume_init() };
    let user_seconds = raw_usage.ru_utime.tv_sec.max(0) as u64;
    let user_micros = raw_usage.ru_utime.tv_usec.max(0) as u64;
    usage.user_time_ns = user_seconds
        .saturating_mul(1_000_000_000)
        .saturating_add(user_micros.saturating_mul(1_000));
    usage.peak_memory_bytes = (raw_usage.ru_maxrss.max(0) as u64).saturating_mul(1024);
    Ok(Some(std::os::unix::process::ExitStatusExt::from_raw(
        status,
    )))
}

fn process_user_ticks(stat: &str) -> Option<u64> {
    // comm is parenthesized and may itself contain spaces or `)`, so split
    // only after its final closing parenthesis as /proc/PID/stat requires.
    let end_comm = stat.rfind(") ")?;
    stat[end_comm + 2..]
        .split_whitespace()
        .nth(11)?
        .parse()
        .ok()
}

fn process_vm_hwm_bytes(status: &str) -> Option<u64> {
    let line = status.lines().find(|line| line.starts_with("VmHWM:"))?;
    let kib = line.split_whitespace().nth(1)?.parse::<u64>().ok()?;
    Some(kib.saturating_mul(1024))
}

fn reap_children(workload_pgid: i32) {
    // Container PID 1 owns every orphan in the PID namespace, matching Go's
    // waitAll behavior. Unit tests call execute() from the host test process,
    // where waitpid(-1) could steal children from other concurrently running
    // tests; there, constrain cleanup to this workload's process group.
    let child_selector = if unsafe { libc::getpid() } == 1 {
        -1
    } else {
        -workload_pgid
    };
    loop {
        let mut status = 0;
        let pid = unsafe { libc::waitpid(child_selector, &mut status, 0) };
        if pid > 0 {
            continue;
        }
        if pid == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        break;
    }
}

fn stop_child_and_reap(child: &mut std::process::Child, pid: i32) {
    let _ = unsafe { libc::kill(-pid, libc::SIGKILL) };
    let _ = child.wait();
    reap_children(pid);
}

fn convert_rlimits(limits: &[crate::container::protocol::ResourceLimit]) -> io::Result<RLimits> {
    let mut result = RLimits::default();
    for limit in limits {
        // The wire protocol accepts Go's complete []syscall.Rlimit shape.
        // Keep each entry verbatim: the convenience RLimits fields cannot
        // represent distinct soft/hard values for most resources (including
        // RLIMIT_CORE), and collapsing duplicate IDs would change Go's
        // sequential setrlimit behavior.
        result.raw.push(crate::container::rlimit::RawLimit {
            resource: limit.res as libc::__rlimit_resource_t,
            soft: limit.rlim.cur,
            hard: limit.rlim.max,
        });
    }
    Ok(result)
}

async fn send_reply(
    socket: &Socket,
    reply: &Reply,
    files: &[File],
    credentials: Option<UnixCredentials>,
) -> io::Result<()> {
    let fds = files
        .iter()
        .map(AsFd::as_fd)
        .collect::<Vec<BorrowedFd<'_>>>();
    let raw_fds = fds.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>();
    let mut controls = Vec::new();
    if !raw_fds.is_empty() {
        controls.push(ControlMessage::ScmRights(&raw_fds));
    }
    if let Some(credentials) = credentials.as_ref() {
        controls.push(ControlMessage::ScmCredentials(credentials));
    }
    protocol::send_proto(socket, &WireReply::from(reply), &controls).await
}

async fn send_reply_files(
    socket: &Socket,
    reply: &Reply,
    files: &[File],
    credentials: Option<UnixCredentials>,
) -> io::Result<()> {
    send_reply(socket, reply, files, credentials).await
}

fn error_reply(error: io::Error) -> Reply {
    Reply {
        error: Some(ErrorReply {
            errno: error.raw_os_error(),
            message: error.to_string(),
        }),
        ..Default::default()
    }
}

fn read_dotenv() -> io::Result<Vec<String>> {
    let content = match fs::read_to_string("/.env") {
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
                return None;
            }
            if line.contains('=') {
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

fn cstring(value: &str) -> io::Result<CString> {
    CString::new(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "argument contains NUL"))
}

fn init_error(error: impl std::fmt::Display) -> InitError {
    InitError(error.to_string())
}

pub const EXIT_CODE_AFTER_INIT: u8 = 2;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::protocol::{OpenCommand, WireCommand};

    #[test]
    fn rlimit_conversion_preserves_unknown_linux_resource_ids() {
        let resource = libc::RLIMIT_NPROC as i32;
        let limits = convert_rlimits(&[crate::container::protocol::ResourceLimit {
            res: resource,
            rlim: crate::container::protocol::ResourceLimitValues { cur: 7, max: 9 },
        }])
        .unwrap();
        assert_eq!(
            limits.raw,
            [crate::container::rlimit::RawLimit {
                resource: resource as libc::__rlimit_resource_t,
                soft: 7,
                hard: 9,
            }]
        );
    }

    #[test]
    fn rlimit_conversion_preserves_all_soft_hard_pairs_and_order() {
        let limits = convert_rlimits(&[
            crate::container::protocol::ResourceLimit {
                res: libc::RLIMIT_CORE as i32,
                rlim: crate::container::protocol::ResourceLimitValues { cur: 0, max: 4096 },
            },
            crate::container::protocol::ResourceLimit {
                res: libc::RLIMIT_DATA as i32,
                rlim: crate::container::protocol::ResourceLimitValues {
                    cur: 2048,
                    max: 8192,
                },
            },
        ])
        .unwrap();

        assert_eq!(
            limits.raw,
            [
                crate::container::rlimit::RawLimit {
                    resource: libc::RLIMIT_CORE as libc::__rlimit_resource_t,
                    soft: 0,
                    hard: 4096,
                },
                crate::container::rlimit::RawLimit {
                    resource: libc::RLIMIT_DATA as libc::__rlimit_resource_t,
                    soft: 2048,
                    hard: 8192,
                },
            ]
        );
        assert!(limits.prepare().is_empty());
    }

    #[test]
    fn init_is_noop_outside_pid_one_invocation() {
        assert_eq!(run(), Ok(()));
    }

    #[test]
    fn opens_files_with_batch_errors_and_returns_descriptors() {
        let root = std::env::temp_dir().join(format!("rust-init-open-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("file");
        let commands = [
            OpenCommand {
                path: path.to_string_lossy().into_owned(),
                flag: (libc::O_CREAT | libc::O_RDWR) as i64,
                perm: 0o600,
                mkdir_all: false,
            },
            OpenCommand {
                path: root.join("missing/file").to_string_lossy().into_owned(),
                flag: libc::O_RDONLY as i64,
                perm: 0,
                mkdir_all: false,
            },
        ];
        let (reply, files) = open_files(&commands);
        assert_eq!(files.len(), 1);
        assert_eq!(reply.batch_errors.len(), 2);
        assert_eq!(reply.batch_errors[0], "");
        assert!(!reply.batch_errors[1].is_empty());
        drop(files);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn protobuf_command_and_reply_roundtrip_for_init_control() {
        let command = WireCommand {
            cmd: CommandType::Ping as i32,
            ..Default::default()
        };
        let bytes = protocol::encode_message(&command);
        let decoded: WireCommand = protocol::decode_message(&bytes).unwrap();
        assert_eq!(decoded.cmd, CommandType::Ping as i32);
        let reply = WireReply::from(&Reply::default());
        assert!(reply.error.is_none());
        assert!(reply.exec_reply.is_none());
    }

    #[tokio::test]
    async fn seqpacket_open_command_returns_file_descriptor() {
        use crate::container::protocol::{WireOpenCommand, WireReply};

        let root = std::env::temp_dir().join(format!("rust-init-ipc-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("from-control");
        let (server, client) = Socket::pair().unwrap();
        let server_task = tokio::spawn(serve(server));
        let command = WireCommand {
            cmd: CommandType::Open as i32,
            open_cmd: vec![WireOpenCommand {
                path: path.to_string_lossy().into_owned(),
                flag: (libc::O_CREAT | libc::O_RDWR) as i64,
                perm: 0o600,
                mkdir_all: false,
            }],
            ..Default::default()
        };
        protocol::send_proto(&client, &command, &[]).await.unwrap();
        let (reply, frame) = protocol::recv_proto::<WireReply>(&client).await.unwrap();
        assert_eq!(reply.batch_errors, [""]);
        assert_eq!(frame.fds.len(), 1);
        assert!(path.exists());
        drop(client);
        assert!(server_task.await.unwrap().is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn idle_init_rejects_exec_sync_commands_like_go() {
        for command in [CommandType::Ok, CommandType::Kill] {
            let (server, client) = Socket::pair().unwrap();
            let server_task = tokio::spawn(serve(server));
            protocol::send_proto(
                &client,
                &WireCommand {
                    cmd: command as i32,
                    ..Default::default()
                },
                &[],
            )
            .await
            .unwrap();
            assert!(server_task.await.unwrap().is_err());
        }
    }

    #[test]
    fn wait4_captures_final_user_cpu_time_and_peak_rss() {
        let child = std::process::Command::new("/bin/sh")
            .args(["-c", "i=0; while [ $i -lt 100000 ]; do i=$((i+1)); done"])
            .spawn()
            .unwrap();
        let mut usage = ProcessUsage::default();
        let status = loop {
            if let Some(status) = try_wait_process_usage(child.id() as i32, &mut usage).unwrap() {
                break status;
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        assert!(status.success());
        assert!(usage.user_time_ns > 0, "{usage:?}");
        assert!(usage.peak_memory_bytes > 0, "{usage:?}");
    }

    #[test]
    fn non_pid_one_cleanup_does_not_reap_unrelated_children() {
        use std::os::unix::process::CommandExt;

        let mut workload = std::process::Command::new("/bin/sh")
            .args(["-c", "sleep 10"])
            .process_group(0)
            .spawn()
            .unwrap();
        let mut unrelated = std::process::Command::new("/bin/sh")
            .args(["-c", "sleep 0.1"])
            .spawn()
            .unwrap();
        let workload_pid = workload.id() as i32;
        let _ = unsafe { libc::kill(-workload_pid, libc::SIGKILL) };
        let _ = workload.wait();

        reap_children(workload_pid);
        assert!(unrelated.try_wait().is_ok());
        let _ = unrelated.wait();
    }

    #[tokio::test]
    async fn pidfd_wakes_when_child_exits() {
        let child = std::process::Command::new("/bin/true").spawn().unwrap();
        let Some(pidfd) = open_pidfd_async(child.id() as i32) else {
            return;
        };
        tokio::time::timeout(Duration::from_secs(2), wait_pidfd_ready(&pidfd))
            .await
            .expect("pidfd readiness timed out")
            .unwrap();
        let mut usage = ProcessUsage::default();
        assert!(
            try_wait_process_usage(child.id() as i32, &mut usage)
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn exec_command_can_launch_from_received_executable_fd() {
        use crate::container::protocol::{Command as InitCommand, ExecCommand, WireReply};
        use nix::sys::socket::ControlMessage;
        use std::os::fd::AsRawFd;

        let (server, client) = Socket::pair().unwrap();
        let executable = File::open("/bin/true").unwrap();
        let command = InitCommand {
            cmd: Some(CommandType::Exec),
            exec_cmd: Some(ExecCommand {
                argv: vec!["/bin/true".into()],
                fd_exec: true,
                ..ExecCommand::default()
            }),
            ..InitCommand::default()
        };
        let fds = [executable.as_raw_fd()];
        let controls = [ControlMessage::ScmRights(&fds)];
        let config = InitConfig {
            work_dir: "/".into(),
            uid: None,
            gid: None,
            ..InitConfig::default()
        };
        let server_task = server;
        let execute_task = tokio::spawn(async move {
            let (wire, frame) = protocol::recv_proto::<WireCommand>(&server_task).await?;
            let command = InitCommand::try_from(wire)?;
            let (reply, _) = execute(&server_task, &config, command.exec_cmd, frame.fds).await?;
            send_reply(&server_task, &reply, &[], None).await
        });
        protocol::send_proto(&client, &WireCommand::from(&command), &controls)
            .await
            .unwrap();

        let (started, frame) = protocol::recv_proto::<WireReply>(&client).await.unwrap();
        assert!(started.error.is_none(), "{started:?}");
        assert!(frame.credentials.is_some());
        protocol::send_proto(
            &client,
            &WireCommand {
                cmd: CommandType::Ok as i32,
                ..Default::default()
            },
            &[],
        )
        .await
        .unwrap();
        let (finished, _) = protocol::recv_proto::<WireReply>(&client).await.unwrap();
        assert_eq!(finished.exec_reply.unwrap().status, 0);
        drop(client);
        execute_task.await.unwrap().unwrap();
    }

    #[test]
    fn reset_removes_contents_but_keeps_tmpfs_root() {
        let root = std::env::temp_dir().join(format!("rust-init-reset-{}", std::process::id()));
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::write(root.join("nested/file"), b"x").unwrap();
        let reply = reset(&[root.to_string_lossy().into_owned()]);
        assert!(reply.error.is_none());
        assert!(root.exists());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn filesystem_plan_keeps_mount_link_and_mask_order() {
        use crate::container::{mount::Mount, protocol::SymbolicLink};

        let mounts = [Mount {
            source: "tmpfs".into(),
            target: "/tmp".into(),
            fs_type: "tmpfs".into(),
            data: "size=8m".into(),
            flags: libc::MS_NODEV as u64,
        }];
        let links = [SymbolicLink {
            link_path: "/dev/stdout".into(),
            target: "/proc/self/fd/1".into(),
        }];
        let masks = ["/proc/kcore".to_owned()];
        let plan = filesystem_plan("/var/lib/container-root", &mounts, &links, &masks).unwrap();
        assert_eq!(plan.root.to_str().unwrap(), "/var/lib/container-root");
        assert_eq!(plan.mounts, &mounts);
        assert_eq!(plan.links, &links);
        assert_eq!(plan.mask_paths, &masks);
    }

    #[test]
    fn filesystem_plan_rejects_missing_or_relative_root() {
        let mounts = [];
        let links = [];
        let masks = [];
        for root in ["", "root"] {
            let error = filesystem_plan(root, &mounts, &links, &masks).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn filesystem_plan_rejects_embedded_nul_before_mounting() {
        let mounts = [crate::container::mount::Mount {
            target: "/tmp\0bad".into(),
            ..Default::default()
        }];
        let error = filesystem_plan("/root", &mounts, &[], &[]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn usage_parser_reads_user_cpu_and_kernel_peak_rss() {
        let stat = "123 (cmd with ) chars) S 0 0 0 0 0 0 0 0 0 0 1234 5678 0";
        assert_eq!(process_user_ticks(stat), Some(1234));
        let status = "Name:\tcmd\nVmPeak:\t9000 kB\nVmHWM:\t12 kB\n";
        assert_eq!(process_vm_hwm_bytes(status), Some(12 * 1024));
        assert_eq!(process_vm_hwm_bytes("Name:\tcmd\n"), None);
    }
}
