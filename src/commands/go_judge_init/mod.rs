//! Rust-native container control server used by the PID-1 helper.
//!
//! The control channel uses the repository's protobuf plus Unix seqpacket
//! transport. File descriptors are carried with `SCM_RIGHTS`; gob is not used.

use crate::container::{
    fork_exec::{Child, Credential, Runner},
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
    if command.mkdir_all
        && let Some(parent) = path.parent()
    {
        fs::create_dir_all(parent)?;
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

mod execute;
use execute::*;

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
mod tests;
