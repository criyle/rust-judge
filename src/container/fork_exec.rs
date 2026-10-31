//! Process creation for sandboxed commands.
//!
//! This module deliberately builds on [`std::process::Command`] and its Unix
//! `pre_exec` hook. The standard library owns the fork/exec handshake, file
//! descriptor remapping, close-on-exec error pipe, and child reaping contract.
//! The hook contains only direct syscalls and prebuilt values, following the
//! same post-fork constraints as `std`'s Unix spawn implementation.

use crate::container::rlimit::RLimits;
use crate::container::seccomp::Filter;
use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::io::{Error, ErrorKind, Read, Result, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};
use std::thread;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct Runner {
    /// argv, with argv[0] naming the executable.
    pub args: Vec<CString>,
    /// Environment entries in `KEY=value` form.
    pub env: Vec<CString>,
    pub work_dir: CString,
    /// Chroot directory prepared by the container layer.
    pub container_root: Option<CString>,
    /// Bind mounts made inside the child's private mount namespace.
    pub bind_mounts: Vec<BindMount>,
    /// Fresh procfs mounts created inside the child's mount namespace.
    pub proc_mounts: Vec<ProcMount>,
    /// tmpfs mounts created in the same private mount namespace.
    pub tmpfs_mounts: Vec<TmpfsMount>,
    /// Overlay a fresh tmpfs on `container_root` before creating submounts.
    pub rootfs_tmpfs: bool,
    /// Symlinks created after mount setup, with paths already rooted in the
    /// container root directory.
    pub symlinks: Vec<(CString, CString)>,
    /// Paths masked after mounts and symlinks are in place.
    pub mask_paths: Vec<CString>,
    /// Parent descriptors copied to the matching child descriptor numbers.
    pub fd_map: Vec<i32>,
    /// Optional descriptor naming the executable, passed through procfs so
    /// `Command` still owns the fork/exec handshake.
    pub exec_file: Option<i32>,
    /// Run through util-linux `unshare` and a post-namespace Rust exec helper.
    /// The helper path is inside `container_root` and installs seccomp just
    /// before replacing itself with the requested executable.
    pub pid_namespace_helper: Option<CString>,
    /// Additional namespaces created by util-linux before starting the helper.
    /// CLONE_NEWPID is always enabled by helper mode; CLONE_NEWUSER stays on
    /// the std::process child so the parent can install its ID maps safely.
    pub helper_unshare_flags: i32,
    /// Replace the standard helper `--seccomp-file ... -- executable` argv.
    /// Used to boot the persistent namespace init process.
    pub helper_args: Option<Vec<CString>>,
    /// Open cgroup.procs descriptors used by the payload after fork. A cgroup
    /// v2 execution has one entry; v1 may have one per controller hierarchy.
    pub cgroup_procs_fds: Vec<i32>,
    /// Existing user namespace to join in the single-threaded child. If the
    /// kernel rejects the join, `start` falls back to creating a mapped user
    /// namespace using `uid_map` and `gid_map`.
    pub user_namespace_fd: Option<i32>,
    /// Optional comma-separated CPU IDs/ranges for sched_setaffinity.
    pub cpu_set: Option<CString>,
    /// Process resource limits applied in the child before exec.
    pub rlimits: RLimits,
    pub pivot_root: Option<CString>,
    pub host_name: Option<CString>,
    pub domain_name: Option<CString>,
    /// Called in the parent with the child PID after child setup and before
    /// exec. The child waits for the callback to acknowledge completion. Keep
    /// the callback short because it runs inline on a Tokio worker task.
    pub sync_fn: Option<Box<dyn FnMut(i32) -> Result<()> + Send>>,
    /// Linux CLONE_NEW* flags. These are applied using `unshare` in the child.
    pub clone_flags: i32,
    pub credential: Option<Credential>,
    pub uid_map: Option<Vec<IdMap>>,
    pub gid_map: Option<Vec<IdMap>>,
    pub gid_map_enable_set_groups: bool,
    pub no_new_privs: bool,
    /// Classic BPF seccomp policy installed after credentials and limits.
    pub seccomp: Filter,
    pub drop_caps: bool,
    pub unshare_cgroup_after_sync: bool,
    pub control_tty: bool,
}

#[derive(Clone, Debug)]
pub struct BindMount {
    pub source: CString,
    pub target: CString,
    pub readonly: bool,
}

#[derive(Clone, Debug)]
pub struct TmpfsMount {
    pub target: CString,
    pub data: CString,
}

#[derive(Clone, Debug)]
pub struct ProcMount {
    pub target: CString,
    pub readonly: bool,
}

#[derive(Clone)]
pub struct IdMap {
    pub container_id: u32,
    pub host_id: u32,
    pub size: u32,
}

fn userns_map_files(
    flags: i32,
    uid_map: Option<&[IdMap]>,
    gid_map: Option<&[IdMap]>,
    gid_map_enable_set_groups: bool,
) -> Result<Vec<(CString, Vec<u8>)>> {
    if flags & libc::CLONE_NEWUSER == 0 {
        return Ok(Vec::new());
    }
    let uid_maps = uid_map.map(<[IdMap]>::to_vec).unwrap_or_else(|| {
        vec![IdMap {
            container_id: 0,
            host_id: unsafe { libc::geteuid() },
            size: 1,
        }]
    });
    let gid_maps = gid_map.map(<[IdMap]>::to_vec).unwrap_or_else(|| {
        vec![IdMap {
            container_id: 0,
            host_id: unsafe { libc::getegid() },
            size: 1,
        }]
    });
    let map_content = |maps: &[IdMap]| {
        let mut content = String::new();
        for mapping in maps {
            use std::fmt::Write as _;
            write!(
                content,
                "{} {} {}\n",
                mapping.container_id, mapping.host_id, mapping.size
            )
            .expect("writing to String cannot fail");
        }
        content.into_bytes()
    };
    let setgroups = if gid_map.is_some() && gid_map_enable_set_groups {
        b"allow".to_vec()
    } else {
        b"deny".to_vec()
    };
    Ok(vec![
        (
            CString::new("/proc/self/uid_map").unwrap(),
            map_content(&uid_maps),
        ),
        (CString::new("/proc/self/setgroups").unwrap(), setgroups),
        (
            CString::new("/proc/self/gid_map").unwrap(),
            map_content(&gid_maps),
        ),
    ])
}

fn write_userns_maps(files: &[(CString, Vec<u8>)]) -> Result<()> {
    for (path, content) in files {
        let fd = nix::fcntl::open(
            path.as_c_str(),
            nix::fcntl::OFlag::O_WRONLY | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        )
        .map_err(|errno| Error::from_raw_os_error(errno as i32))?;
        let written = loop {
            match nix::unistd::write(&fd, content) {
                Err(nix::errno::Errno::EINTR) => continue,
                result => break result,
            }
        }
        .map_err(|errno| Error::from_raw_os_error(errno as i32))?;
        if written != content.len() {
            return Err(Error::new(
                ErrorKind::WriteZero,
                format!("short write to {}", path.to_string_lossy()),
            ));
        }
    }
    Ok(())
}

fn pipe_cloexec() -> Result<[OwnedFd; 2]> {
    let mut fds = [-1; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } == -1 {
        return Err(Error::last_os_error());
    }
    Ok(unsafe { [OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])] })
}

struct UserNamespaceMapHandshake {
    child_pid_write: OwnedFd,
    child_ack_read: OwnedFd,
    mapper: UserNamespaceMapper,
}

enum UserNamespaceMapper {
    Tokio(std::sync::mpsc::Receiver<Result<()>>),
    LegacyThread(thread::JoinHandle<Result<()>>),
}

impl UserNamespaceMapper {
    fn join(self) -> std::thread::Result<Result<()>> {
        match self {
            Self::Tokio(result) => match result.recv() {
                Ok(result) => Ok(result),
                Err(_) => Err(Box::new("Tokio user namespace mapper stopped")
                    as Box<dyn std::any::Any + Send>),
            },
            Self::LegacyThread(thread) => thread.join(),
        }
    }
}

fn child_wait_for_parent_userns_map(pid_write: i32, ack_read: i32) -> Result<()> {
    let pid_bytes = unsafe { libc::getpid() }.to_ne_bytes();
    let mut offset = 0;
    while offset < pid_bytes.len() {
        let written = unsafe {
            libc::write(
                pid_write,
                pid_bytes[offset..].as_ptr().cast(),
                pid_bytes.len() - offset,
            )
        };
        if written == -1 {
            let error = Error::last_os_error();
            if error.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if written == 0 {
            return Err(Error::new(
                ErrorKind::WriteZero,
                "user namespace map handshake",
            ));
        }
        offset += written as usize;
    }
    let mut response = [0u8; 1];
    loop {
        let read = unsafe { libc::read(ack_read, response.as_mut_ptr().cast(), 1) };
        if read == -1 {
            let error = Error::last_os_error();
            if error.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if read == 0 {
            return Err(Error::new(
                ErrorKind::BrokenPipe,
                "user namespace map parent exited",
            ));
        }
        break;
    }
    if response[0] == 1 {
        Ok(())
    } else {
        Err(Error::new(
            ErrorKind::PermissionDenied,
            "parent could not install user namespace maps",
        ))
    }
}

fn requires_parent_userns_mapping(
    flags: i32,
    uid_map: Option<&[IdMap]>,
    gid_map: Option<&[IdMap]>,
) -> bool {
    if flags & libc::CLONE_NEWUSER == 0 {
        return false;
    }
    let is_self_mapping = |maps: Option<&[IdMap]>, current_id| {
        maps.is_some_and(|maps| {
            maps.len() == 1 && maps[0].host_id == current_id && maps[0].size == 1
        })
    };
    !is_self_mapping(uid_map, unsafe { libc::geteuid() })
        || !is_self_mapping(gid_map, unsafe { libc::getegid() })
}

fn start_userns_map_handshake(files: Vec<(CString, Vec<u8>)>) -> Result<UserNamespaceMapHandshake> {
    let [pid_read, pid_write] = pipe_cloexec()?;
    let [ack_read, ack_write] = pipe_cloexec()?;
    let mapper_work = move || {
        let mut pid_read = File::from(pid_read);
        let mut ack_write = File::from(ack_write);
        loop {
            let mut pid_bytes = [0u8; std::mem::size_of::<libc::pid_t>()];
            match pid_read.read_exact(&mut pid_bytes) {
                Ok(()) => {}
                Err(error) if error.kind() == ErrorKind::UnexpectedEof => return Ok(()),
                Err(error) => return Err(error),
            }
            let pid = libc::pid_t::from_ne_bytes(pid_bytes);
            let mapping: Result<()> = (|| {
                for (source, content) in &files {
                    let path = source
                        .to_string_lossy()
                        .replace("/proc/self/", &format!("/proc/{pid}/"));
                    let mut file = OpenOptions::new().write(true).open(path)?;
                    file.write_all(content)?;
                }
                Ok(())
            })();
            ack_write.write_all(&[u8::from(mapping.is_ok())])?;
            mapping?;
        }
    };
    let mapper = if std::env::var_os("RUST_SANDBOX_ABLATION_STD_USERNS_MAPPER").is_some() {
        UserNamespaceMapper::LegacyThread(
            thread::Builder::new()
                .name("rust-sandbox-userns-map".into())
                .spawn(mapper_work)?,
        )
    } else {
        UserNamespaceMapper::Tokio(crate::tokio_runtime::spawn_blocking(mapper_work))
    };
    Ok(UserNamespaceMapHandshake {
        child_pid_write: pid_write,
        child_ack_read: ack_read,
        mapper,
    })
}

pub struct Credential {
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
    pub no_set_groups: bool,
}

fn child_mount_targets(
    bind_mounts: &[(Vec<u8>, Vec<u8>, bool)],
    proc_mounts: &[(Vec<u8>, bool)],
    tmpfs_mounts: &[(Vec<u8>, Vec<u8>)],
    symlinks: &[(Vec<u8>, Vec<u8>)],
) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>)> {
    let mut directories = Vec::new();
    let mut files = Vec::new();
    let mut add_parents = |path: &[u8], include_leaf: bool| {
        for (index, byte) in path.iter().enumerate().skip(1) {
            if *byte == b'/' {
                let mut prefix = path[..index].to_vec();
                prefix.push(0);
                directories.push(prefix);
            }
        }
        if include_leaf {
            directories.push(path.to_vec());
        }
    };
    for (source, target, _) in bind_mounts {
        let source = CStr::from_bytes_with_nul(source)
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid bind source"))?;
        let is_dir = std::fs::metadata(std::ffi::OsStr::from_bytes(source.to_bytes()))?.is_dir();
        add_parents(target, is_dir);
        if !is_dir {
            files.push(target.clone());
        }
    }
    for (target, _) in proc_mounts {
        add_parents(target, true);
    }
    for (target, _) in tmpfs_mounts {
        add_parents(target, true);
    }
    for (path, _) in symlinks {
        add_parents(path, false);
    }
    directories.sort_by_key(Vec::len);
    directories.dedup();
    files.sort_by_key(Vec::len);
    files.dedup();
    Ok((directories, files))
}

fn pivot_relative_target(path: &[u8]) -> Result<Vec<u8>> {
    let path = CStr::from_bytes_with_nul(path)
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid pivot mount target"))?
        .to_bytes();
    let relative = path.strip_prefix(b"/").unwrap_or(path);
    if relative
        .split(|byte| *byte == b'/')
        .any(|component| component == b"..")
    {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "pivot mount target escapes the new root",
        ));
    }
    let mut target = if relative.is_empty() {
        b".".to_vec()
    } else {
        relative.to_vec()
    };
    target.push(0);
    Ok(target)
}

impl Runner {
    /// Starts the configured executable and returns its std-owned child handle.
    ///
    /// `Command` is used instead of implementing a Rust-side fork path: it
    /// provides the standard library's async-signal-safe child setup sequence
    /// and reports any `pre_exec` or `execve` failure to this process.
    /// On the tested Linux toolchain, registering this `pre_exec` hook selects
    /// ordinary `clone`/fork; it does not use `std::process::Command`'s plain
    /// spawn `clone3(CLONE_VM | CLONE_VFORK)` fast path. See BENCHMARKS.md before
    /// treating this Runner as a vfork/clone3 launch.
    pub fn start(&mut self) -> Result<Child> {
        // Use one helper process followed by the payload spawn, avoiding the
        // extra nsenter and chroot execs. TTY setup has already happened in
        // this process's std::process::Command pre_exec hook, so the helper
        // and payload inherit the session and controlling terminal.
        let optimized_exec = optimized_namespace_exec(&self.args);
        let helper_mode = self.pid_namespace_helper.is_some() || optimized_exec.is_some();
        if self.exec_file.is_some() && helper_mode {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "exec-file descriptors cannot be combined with helper execution",
            ));
        }
        let exec_file_path = self
            .exec_file
            .map(|fd| CString::new(format!("/proc/self/fd/{fd}")))
            .transpose()
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid executable fd path"))?;
        let executable = if helper_mode && self.helper_args.is_some() {
            None
        } else {
            Some(self.args.first().ok_or_else(|| {
                Error::new(ErrorKind::InvalidInput, "missing executable argument")
            })?)
        };
        let mut command = if let Some((program, helper_args)) = optimized_exec.as_ref() {
            let mut command = Command::new(os_str(program));
            let mut helper_args = helper_args.clone();
            if self.clone_flags & libc::CLONE_NEWUSER != 0 {
                insert_setgroups_denied(&mut helper_args);
            }
            for arg in &helper_args {
                command.arg(os_str(arg));
            }
            command
        } else if helper_mode {
            let mut command = Command::new("/usr/bin/unshare");
            command.args([
                "--pid",
                "--fork",
                "--kill-child=KILL",
                "--mount-proc",
                "--propagation",
                "unchanged",
            ]);
            for (flag, option) in [
                (libc::CLONE_NEWNS, "--mount"),
                (libc::CLONE_NEWIPC, "--ipc"),
                (libc::CLONE_NEWNET, "--net"),
                (libc::CLONE_NEWUTS, "--uts"),
            ] {
                if self.helper_unshare_flags & flag != 0 {
                    command.arg(option);
                }
            }
            if let Some(credential) = self.credential.as_ref().filter(|_| !self.rootfs_tmpfs) {
                command.args(["--setuid", &credential.uid.to_string()]);
                command.args(["--setgid", &credential.gid.to_string()]);
            }
            command.arg("--");
            command.arg(os_str(self.pid_namespace_helper.as_ref().unwrap()));
            if let Some(helper_args) = self.helper_args.as_ref() {
                let mut helper_args = helper_args.clone();
                if self.clone_flags & libc::CLONE_NEWUSER != 0 {
                    insert_setgroups_denied(&mut helper_args);
                }
                for arg in helper_args {
                    command.arg(os_str(&arg));
                }
            } else {
                command.arg("--seccomp-file");
                command.arg("/.rust-sandbox-seccomp");
                if !self.cgroup_procs_fds.is_empty() {
                    for index in 0..self.cgroup_procs_fds.len() {
                        command.arg("--cgroup-procs-fd");
                        command.arg((255 + index).to_string());
                    }
                }
                command.arg("--");
                command.arg(os_str(executable.unwrap()));
                for arg in self.args.iter().skip(1) {
                    command.arg(os_str(arg));
                }
            }
            command
        } else {
            let program = exec_file_path.as_ref().or(executable).unwrap();
            let mut command = Command::new(os_str(program));
            for arg in self.args.iter().skip(1) {
                command.arg(os_str(arg));
            }
            if self.exec_file.is_some() {
                command.arg0(os_str(self.args.first().ok_or_else(|| {
                    Error::new(ErrorKind::InvalidInput, "missing argv[0]")
                })?));
            }
            command
        };
        command.env_clear();
        for item in &self.env {
            let bytes = item.as_bytes();
            let Some(eq) = bytes.iter().position(|b| *b == b'=') else {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "environment entry lacks '='",
                ));
            };
            let key = CString::new(&bytes[..eq])
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "NUL in environment key"))?;
            let value = CString::new(&bytes[eq + 1..])
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "NUL in environment value"))?;
            command.env(os_str(&key), os_str(&value));
        }
        if self.container_root.is_none()
            && self.pivot_root.is_none()
            && !self.work_dir.as_bytes().is_empty()
        {
            command.current_dir(os_str(&self.work_dir));
        }

        // Own a syscall-ready snapshot. The closure runs in the child after
        // fork, where it must not allocate, lock, or call back into Rust code.
        let flags = self.clone_flags;
        if (!self.bind_mounts.is_empty()
            || !self.proc_mounts.is_empty()
            || !self.tmpfs_mounts.is_empty()
            || self.pivot_root.is_some())
            && flags & libc::CLONE_NEWNS == 0
        {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "bind mounts require a private mount namespace",
            ));
        }
        if flags & libc::CLONE_NEWPID != 0 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "CLONE_NEWPID requires clone-time namespace creation, not unshare",
            ));
        }
        if self.pivot_root.is_some()
            && (flags & libc::CLONE_NEWNS == 0
                || self.rootfs_tmpfs
                || self.container_root.is_some())
        {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "pivot_root requires a private mount namespace and cannot be combined with another root",
            ));
        }
        let hostname = self
            .host_name
            .as_deref()
            .map(CStr::to_bytes_with_nul)
            .map(<[u8]>::to_vec);
        let domainname = self
            .domain_name
            .as_deref()
            .map(CStr::to_bytes_with_nul)
            .map(<[u8]>::to_vec);
        let pivot_root = self
            .pivot_root
            .as_deref()
            .map(CStr::to_bytes_with_nul)
            .map(<[u8]>::to_vec);
        let container_root = self
            .container_root
            .as_deref()
            .map(CStr::to_bytes_with_nul)
            .map(<[u8]>::to_vec);
        let work_dir = self.work_dir.as_bytes_with_nul().to_vec();
        let mut bind_mounts: Vec<_> = self
            .bind_mounts
            .iter()
            .map(|m| {
                (
                    m.source.as_bytes_with_nul().to_vec(),
                    m.target.as_bytes_with_nul().to_vec(),
                    m.readonly,
                )
            })
            .collect();
        let mut proc_mounts: Vec<_> = self
            .proc_mounts
            .iter()
            .map(|mount| (mount.target.as_bytes_with_nul().to_vec(), mount.readonly))
            .collect();
        let mut tmpfs_mounts: Vec<_> = self
            .tmpfs_mounts
            .iter()
            .map(|mount| {
                (
                    mount.target.as_bytes_with_nul().to_vec(),
                    mount.data.as_bytes_with_nul().to_vec(),
                )
            })
            .collect();
        let mut symlinks: Vec<_> = self
            .symlinks
            .iter()
            .map(|(path, target)| {
                (
                    path.as_bytes_with_nul().to_vec(),
                    target.as_bytes_with_nul().to_vec(),
                )
            })
            .collect();
        let mut mask_paths: Vec<_> = self
            .mask_paths
            .iter()
            .map(|path| path.as_bytes_with_nul().to_vec())
            .collect();
        if pivot_root.is_some() {
            for (_, target, _) in &mut bind_mounts {
                *target = pivot_relative_target(target)?;
            }
            for (target, _) in &mut proc_mounts {
                *target = pivot_relative_target(target)?;
            }
            for (target, _) in &mut tmpfs_mounts {
                *target = pivot_relative_target(target)?;
            }
            for (path, _) in &mut symlinks {
                *path = pivot_relative_target(path)?;
            }
            for path in &mut mask_paths {
                *path = pivot_relative_target(path)?;
            }
        }
        let rootfs_tmpfs = self.rootfs_tmpfs;
        let root_mount = container_root.clone();
        let (mount_target_dirs, mount_target_files) =
            child_mount_targets(&bind_mounts, &proc_mounts, &tmpfs_mounts, &symlinks)?;
        let cgroup_procs_fds = self.cgroup_procs_fds.clone();
        // Namespace helpers must stay outside the per-command cgroup so a
        // pids.max of one still admits the final workload process. The helper
        // receives the already-open cgroup.procs descriptors and enrolls its
        // child immediately before exec.
        let enroll_in_cgroup = !cgroup_procs_fds.is_empty() && !helper_mode;
        let cpu_mask = self
            .cpu_set
            .as_deref()
            .map(CStr::to_str)
            .transpose()
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "CPU set is not UTF-8"))?
            .map(parse_cpu_mask)
            .transpose()?;
        let fd_map = self.fd_map.clone();
        let uid = if helper_mode {
            None
        } else {
            self.credential
                .as_ref()
                .map(|c| (c.uid, c.gid, c.groups.clone(), c.no_set_groups))
        };
        let no_new_privs = self.no_new_privs;
        let seccomp: Vec<Vec<seccompiler::sock_filter>> = self
            .seccomp
            .programs()
            .map(|program| {
                program
                    .iter()
                    .map(|instruction| seccompiler::sock_filter {
                        code: instruction.code,
                        jt: instruction.jt,
                        jf: instruction.jf,
                        k: instruction.k,
                    })
                    .collect()
            })
            .filter(|program: &Vec<_>| !program.is_empty())
            .collect();
        let drop_caps = self.drop_caps;
        let control_tty = self.control_tty;
        let rlimits = self.rlimits.prepare();
        let raw_rlimits = self.rlimits.raw.clone();
        if self.sync_fn.is_some() && helper_mode {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "parent-child sync callbacks require direct process execution",
            ));
        }
        let (sync_child_socket, sync_parent_socket, sync_child_fd) = if self.sync_fn.is_some() {
            let (child, parent) = UnixStream::pair()?;
            let child = sync_socket_above_stdio(child)?;
            let parent = sync_socket_above_stdio(parent)?;
            let child_fd = child.as_raw_fd();
            (Some(child), Some(parent), Some(child_fd))
        } else {
            (None, None, None)
        };
        let sync_parent_fd = sync_parent_socket.as_ref().map(AsRawFd::as_raw_fd);
        let userns_maps = userns_map_files(
            if flags & libc::CLONE_NEWUSER != 0 || self.user_namespace_fd.is_some() {
                libc::CLONE_NEWUSER
            } else {
                0
            },
            self.uid_map.as_deref(),
            self.gid_map.as_deref(),
            self.gid_map_enable_set_groups,
        )?;
        let mut userns_parent_map = if requires_parent_userns_mapping(
            flags,
            self.uid_map.as_deref(),
            self.gid_map.as_deref(),
        ) {
            Some(start_userns_map_handshake(userns_maps.clone())?)
        } else {
            None
        };
        let userns_parent_map_fds = userns_parent_map.as_ref().map(|handshake| {
            (
                handshake.child_pid_write.as_raw_fd(),
                handshake.child_ack_read.as_raw_fd(),
            )
        });
        let user_namespace_fd = self.user_namespace_fd;
        let unshare_cgroup_after_sync = self.unshare_cgroup_after_sync;

        // SAFETY: the closure performs only libc syscalls against prebuilt,
        // immutable data and returns immediately on syscall failure.
        unsafe {
            command.pre_exec(move || {
                // Only the parent should retain the callback endpoint. If the
                // child kept it open, parent cancellation would not produce
                // EOF on the child's acknowledgement read.
                if let Some(fd) = sync_parent_fd {
                    if libc::close(fd) == -1 {
                        return Err(Error::last_os_error());
                    }
                }
                // Drop host supplementary groups before entering a user
                // namespace whose setgroups file is denied. Once the map is
                // installed, setgroups(2) cannot be used to clear them.
                if helper_mode && libc::geteuid() == 0 {
                    if libc::setgroups(0, std::ptr::null()) == -1 {
                        return Err(Error::last_os_error());
                    }
                }
                for (index, fd) in cgroup_procs_fds.iter().copied().enumerate() {
                    let target = 255 + index as i32;
                    if libc::dup2(fd, target) == -1 {
                        return Err(Error::last_os_error());
                    }
                    if libc::fcntl(target, libc::F_SETFD, 0) == -1 {
                        return Err(Error::last_os_error());
                    }
                }
                // Enroll while still in the caller's cgroup namespace and
                // credentials. A child in a new user namespace cannot move
                // itself into a host cgroup; the membership then propagates
                // through its subsequent namespace setup and exec.
                if enroll_in_cgroup {
                    let mut digits = [0u8; 10];
                    let mut value = libc::getpid() as u32;
                    let mut start = digits.len();
                    loop {
                        start -= 1;
                        digits[start] = b'0' + (value % 10) as u8;
                        value /= 10;
                        if value == 0 {
                            break;
                        }
                    }
                    for index in 0..cgroup_procs_fds.len() {
                        let fd = 255 + index as i32;
                        let written =
                            libc::write(fd, digits[start..].as_ptr().cast(), digits.len() - start);
                        if written == -1 {
                            return Err(Error::last_os_error());
                        }
                        if written as usize != digits.len() - start {
                            return Err(Error::new(
                                ErrorKind::WriteZero,
                                "short cgroup.procs write",
                            ));
                        }
                        if libc::close(fd) == -1 {
                            return Err(Error::last_os_error());
                        }
                    }
                }
                if let Some(user_namespace_fd) = user_namespace_fd {
                    if libc::setns(user_namespace_fd, libc::CLONE_NEWUSER) == -1 {
                        // Rootless callers may not have permission to join a
                        // sibling's namespace. Retain the self-map path as a
                        // functional fallback for those hosts.
                        if libc::unshare(libc::CLONE_NEWUSER) == -1 {
                            return Err(Error::last_os_error());
                        }
                        write_userns_maps(&userns_maps)?;
                    }
                } else if flags & libc::CLONE_NEWUSER != 0 {
                    if libc::unshare(libc::CLONE_NEWUSER) == -1 {
                        return Err(Error::last_os_error());
                    }
                    if let Some((pid_write, ack_read)) = userns_parent_map_fds {
                        child_wait_for_parent_userns_map(pid_write, ack_read)?;
                    } else {
                        write_userns_maps(&userns_maps)?;
                    }
                    let remaining_flags = flags & !libc::CLONE_NEWUSER;
                    if remaining_flags != 0 && libc::unshare(remaining_flags as libc::c_int) == -1 {
                        return Err(Error::last_os_error());
                    }
                } else if flags != 0 && libc::unshare(flags as libc::c_int) == -1 {
                    return Err(Error::last_os_error());
                }
                if unshare_cgroup_after_sync {
                    // Go treats this namespace as optional and ignores errors
                    // when the host does not delegate the required capability.
                    let _ = libc::unshare(libc::CLONE_NEWCGROUP);
                }
                if let Some(mask) = cpu_mask.as_deref() {
                    if libc::sched_setaffinity(0, mask.len(), mask.as_ptr().cast()) == -1 {
                        return Err(Error::last_os_error());
                    }
                }
                if rootfs_tmpfs
                    || pivot_root.is_some()
                    || !bind_mounts.is_empty()
                    || !proc_mounts.is_empty()
                    || !tmpfs_mounts.is_empty()
                    || !mask_paths.is_empty()
                {
                    if libc::mount(
                        std::ptr::null(),
                        b"/\0".as_ptr().cast(),
                        std::ptr::null(),
                        (libc::MS_REC | libc::MS_PRIVATE) as _,
                        std::ptr::null(),
                    ) == -1
                    {
                        return Err(Error::last_os_error());
                    }
                    if rootfs_tmpfs {
                        libc::umask(0);
                        let root = root_mount.as_deref().ok_or_else(|| {
                            Error::new(
                                ErrorKind::InvalidInput,
                                "rootfs tmpfs requires container_root",
                            )
                        })?;
                        if libc::mount(
                            b"tmpfs\0".as_ptr().cast(),
                            root.as_ptr().cast(),
                            b"tmpfs\0".as_ptr().cast(),
                            0,
                            std::ptr::null(),
                        ) == -1
                        {
                            return Err(Error::other(format!(
                                "mount tmpfs on container root: {}",
                                Error::last_os_error()
                            )));
                        }
                        for path in &mount_target_dirs {
                            if libc::mkdir(path.as_ptr().cast(), 0o755) == -1
                                && Error::last_os_error().raw_os_error() != Some(libc::EEXIST)
                            {
                                return Err(Error::last_os_error());
                            }
                        }
                        for path in &mount_target_files {
                            let fd = libc::open(
                                path.as_ptr().cast(),
                                libc::O_CREAT | libc::O_WRONLY | libc::O_CLOEXEC,
                                0o644,
                            );
                            if fd == -1 {
                                return Err(Error::last_os_error());
                            }
                            libc::close(fd);
                        }
                    }
                    if let Some(root) = pivot_root.as_deref() {
                        if libc::mount(
                            b"tmpfs\0".as_ptr().cast(),
                            root.as_ptr().cast(),
                            b"tmpfs\0".as_ptr().cast(),
                            0,
                            std::ptr::null(),
                        ) == -1
                        {
                            return Err(Error::other(format!(
                                "mount tmpfs on pivot root: {}",
                                Error::last_os_error()
                            )));
                        }
                        if libc::chdir(root.as_ptr().cast()) == -1 {
                            return Err(Error::last_os_error());
                        }
                        for path in &mount_target_dirs {
                            if libc::mkdir(path.as_ptr().cast(), 0o755) == -1
                                && Error::last_os_error().raw_os_error() != Some(libc::EEXIST)
                            {
                                return Err(Error::last_os_error());
                            }
                        }
                        for path in &mount_target_files {
                            let fd = libc::open(
                                path.as_ptr().cast(),
                                libc::O_CREAT | libc::O_WRONLY | libc::O_CLOEXEC,
                                0o644,
                            );
                            if fd == -1 {
                                return Err(Error::last_os_error());
                            }
                            libc::close(fd);
                        }
                    }
                    for (source, target, readonly) in &bind_mounts {
                        if libc::mount(
                            source.as_ptr().cast(),
                            target.as_ptr().cast(),
                            std::ptr::null(),
                            (libc::MS_BIND | libc::MS_REC) as _,
                            std::ptr::null(),
                        ) == -1
                        {
                            return Err(Error::other(format!(
                                "bind mount {} on {}: {}",
                                String::from_utf8_lossy(source),
                                String::from_utf8_lossy(target),
                                Error::last_os_error()
                            )));
                        }
                        if *readonly
                            && libc::mount(
                                std::ptr::null(),
                                target.as_ptr().cast(),
                                std::ptr::null(),
                                (libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY) as _,
                                std::ptr::null(),
                            ) == -1
                        {
                            return Err(Error::other(format!(
                                "remount bind {} readonly: {}",
                                String::from_utf8_lossy(target),
                                Error::last_os_error()
                            )));
                        }
                    }
                    for (target, readonly) in proc_mounts.iter().filter(|_| !rootfs_tmpfs) {
                        let mut mount_flags = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
                        if *readonly {
                            mount_flags |= libc::MS_RDONLY;
                        }
                        if libc::mount(
                            b"proc\0".as_ptr().cast(),
                            target.as_ptr().cast(),
                            b"proc\0".as_ptr().cast(),
                            mount_flags as _,
                            std::ptr::null(),
                        ) == -1
                        {
                            return Err(Error::other(format!(
                                "mount proc on {}: {}",
                                String::from_utf8_lossy(target),
                                Error::last_os_error()
                            )));
                        }
                    }
                    for (target, data) in &tmpfs_mounts {
                        if libc::mount(
                            b"tmpfs\0".as_ptr().cast(),
                            target.as_ptr().cast(),
                            b"tmpfs\0".as_ptr().cast(),
                            (libc::MS_NOSUID | libc::MS_NODEV) as _,
                            data.as_ptr().cast(),
                        ) == -1
                        {
                            return Err(Error::last_os_error());
                        }
                    }
                    for (path, target) in &symlinks {
                        if libc::symlink(target.as_ptr().cast(), path.as_ptr().cast()) == -1 {
                            return Err(Error::last_os_error());
                        }
                    }
                    for path in mask_paths.iter().filter(|_| !rootfs_tmpfs) {
                        if libc::mount(
                            b"/dev/null\0".as_ptr().cast(),
                            path.as_ptr().cast(),
                            b"\0".as_ptr().cast(),
                            libc::MS_BIND as _,
                            b"\0".as_ptr().cast(),
                        ) == -1
                        {
                            let errno = Error::last_os_error();
                            if errno.kind() == ErrorKind::NotFound {
                                continue;
                            }
                            if errno.raw_os_error() == Some(libc::ENOTDIR) {
                                if libc::mount(
                                    b"tmpfs\0".as_ptr().cast(),
                                    path.as_ptr().cast(),
                                    b"tmpfs\0".as_ptr().cast(),
                                    libc::MS_RDONLY as _,
                                    b"\0".as_ptr().cast(),
                                ) == -1
                                {
                                    return Err(Error::last_os_error());
                                }
                            } else {
                                return Err(errno);
                            }
                        }
                    }
                    if rootfs_tmpfs {
                        let root = root_mount.as_deref().expect("validated root mount");
                        if libc::mount(
                            b"tmpfs\0".as_ptr().cast(),
                            root.as_ptr().cast(),
                            b"tmpfs\0".as_ptr().cast(),
                            (libc::MS_BIND
                                | libc::MS_REMOUNT
                                | libc::MS_RDONLY
                                | libc::MS_NOATIME
                                | libc::MS_NOSUID) as _,
                            b"\0".as_ptr().cast(),
                        ) == -1
                        {
                            return Err(Error::last_os_error());
                        }
                    }
                }
                if pivot_root.is_some() {
                    let old_root = b"old_root\0";
                    if libc::mkdir(old_root.as_ptr().cast(), 0o755) == -1 {
                        return Err(Error::last_os_error());
                    }
                    if libc::syscall(
                        libc::SYS_pivot_root,
                        b".\0".as_ptr().cast::<libc::c_char>(),
                        old_root.as_ptr().cast::<libc::c_char>(),
                    ) == -1
                    {
                        return Err(Error::last_os_error());
                    }
                    if libc::umount2(old_root.as_ptr().cast(), libc::MNT_DETACH) == -1 {
                        return Err(Error::last_os_error());
                    }
                    if libc::rmdir(old_root.as_ptr().cast()) == -1 {
                        return Err(Error::last_os_error());
                    }
                    if libc::mount(
                        b"tmpfs\0".as_ptr().cast(),
                        b"/\0".as_ptr().cast(),
                        b"tmpfs\0".as_ptr().cast(),
                        (libc::MS_BIND
                            | libc::MS_REMOUNT
                            | libc::MS_RDONLY
                            | libc::MS_NOATIME
                            | libc::MS_NOSUID) as _,
                        std::ptr::null(),
                    ) == -1
                    {
                        return Err(Error::last_os_error());
                    }
                }
                if let Some(name) = hostname.as_deref() {
                    if libc::sethostname(name.as_ptr().cast(), name.len() - 1) == -1 {
                        return Err(Error::last_os_error());
                    }
                }
                if let Some(name) = domainname.as_deref() {
                    if libc::setdomainname(name.as_ptr().cast(), name.len() - 1) == -1 {
                        return Err(Error::last_os_error());
                    }
                }
                if pivot_root.is_some() {
                    if libc::chdir(b"/\0".as_ptr().cast()) == -1 {
                        return Err(Error::last_os_error());
                    }
                    if work_dir.len() > 1 && libc::chdir(work_dir.as_ptr().cast()) == -1 {
                        return Err(Error::last_os_error());
                    }
                }
                // Chroot after namespace setup but before dropping the mapped
                // identity. This is needed when a child creates its own user
                // namespace and inherits a mount namespace owned by its
                // parent user namespace.
                if let Some(root) = container_root.as_deref() {
                    if libc::chroot(root.as_ptr().cast()) == -1
                        || libc::chdir(b"/\0".as_ptr().cast()) == -1
                    {
                        return Err(Error::last_os_error());
                    }
                    if work_dir.len() > 1 && libc::chdir(work_dir.as_ptr().cast()) == -1 {
                        return Err(Error::last_os_error());
                    }
                }
                if let Some((uid, gid, groups, no_set_groups)) = uid.as_ref() {
                    if !no_set_groups && libc::setgroups(groups.len(), groups.as_ptr()) == -1 {
                        return Err(Error::last_os_error());
                    }
                    if libc::setgid(*gid) == -1 || libc::setuid(*uid) == -1 {
                        return Err(Error::last_os_error());
                    }
                }
                if libc::setsid() == -1 {
                    return Err(Error::last_os_error());
                }
                if let Some(fd) = sync_child_fd {
                    child_sync_with_parent(fd)?;
                }
                for (target, source) in fd_map.iter().enumerate() {
                    let target = i32::try_from(target).map_err(|_| {
                        Error::new(ErrorKind::InvalidInput, "descriptor index overflow")
                    })?;
                    if target != *source && libc::dup2(*source, target) == -1 {
                        return Err(Error::last_os_error());
                    }
                    if target == *source {
                        let flags = libc::fcntl(target, libc::F_GETFD);
                        if flags == -1
                            || libc::fcntl(target, libc::F_SETFD, flags & !libc::FD_CLOEXEC) == -1
                        {
                            return Err(Error::last_os_error());
                        }
                    }
                }
                // Descriptor remapping must happen before TIOCSCTTY so fd 0
                // refers to the PTY slave, not the server's original stdin.
                // setsid above makes this process the session leader first.
                if control_tty && libc::ioctl(0, libc::TIOCSCTTY as _, 1) == -1 {
                    return Err(Error::last_os_error());
                }
                // `std::process::Command` resets dispositions that must not
                // leak across exec (including Rust's ignored SIGPIPE). Avoid
                // assuming exec resets ignored signals: container PID 1
                // deliberately ignores fatal signals, and those dispositions
                // survive exec. Restore the subset ignored by container init.
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
                    if libc::signal(signal, libc::SIG_DFL) == libc::SIG_ERR {
                        return Err(Error::last_os_error());
                    }
                }
                // Go's child setup applies resource limits after chdir and
                // before no_new_privs/seccomp. The standard-library child is
                // already in the requested working directory here.
                for limit in &rlimits {
                    nix::sys::resource::setrlimit(limit.resource, limit.soft, limit.hard)
                        .map_err(|errno| Error::from_raw_os_error(errno as i32))?;
                }
                for limit in &raw_rlimits {
                    let value = libc::rlimit {
                        rlim_cur: limit.soft as libc::rlim_t,
                        rlim_max: limit.hard as libc::rlim_t,
                    };
                    if libc::setrlimit(limit.resource, &value) == -1 {
                        return Err(Error::last_os_error());
                    }
                }
                if !helper_mode
                    && no_new_privs
                    && libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1
                {
                    return Err(Error::last_os_error());
                }
                if drop_caps && !helper_mode {
                    // Root regains its traditional capability set during
                    // exec unless NOROOT is locked. A non-root caller cannot
                    // set securebits; in that case capset(2) may still safely
                    // clear any capabilities it currently owns.
                    if libc::geteuid() == 0 {
                        const SECUREBITS_DROP_ROOT: libc::c_int = 0x1 | 0x2 | 0x4 | 0x8 | 0x20;
                        if libc::prctl(libc::PR_SET_SECUREBITS, SECUREBITS_DROP_ROOT, 0, 0, 0) == -1
                        {
                            return Err(Error::last_os_error());
                        }
                    }
                    let header = CapUserHeader {
                        version: 0x2008_0522,
                        pid: 0,
                    };
                    let data = [CapUserData {
                        effective: 0,
                        permitted: 0,
                        inheritable: 0,
                    }; 2];
                    if libc::syscall(libc::SYS_capset, &header, data.as_ptr()) == -1 {
                        return Err(Error::last_os_error());
                    }
                }
                if !helper_mode {
                    for filter in &seccomp {
                        seccompiler::apply_filter(filter).map_err(|error| {
                            Error::other(format!("install seccomp filter: {error}"))
                        })?;
                    }
                }
                Ok(())
            });
        }

        let sync_result = match (sync_parent_socket, self.sync_fn.take()) {
            (Some(socket), Some(callback)) => Some(spawn_parent_sync(socket, callback)?),
            (None, None) => None,
            _ => return Err(Error::other("incomplete parent-child sync handshake")),
        };
        // A concurrent fork can briefly retain an O_WRONLY descriptor for a
        // copied executable until that child reaches exec. Linux then returns
        // ETXTBSY even though the copy itself is complete. Match go-sandbox's
        // bounded 1 ms retry window; a sync callback is one-shot, so its
        // handshake attempt is not retried.
        let mut attempt = 0;
        let spawn_result = loop {
            match command.spawn() {
                Ok(child) => break Ok(child),
                Err(error)
                    if sync_result.is_none()
                        && error.raw_os_error() == Some(libc::ETXTBSY)
                        && attempt < 50 =>
                {
                    attempt += 1;
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => break Err(error),
            }
        };
        drop(command);
        drop(sync_child_socket);
        let spawn_result = match sync_result {
            Some(result) => match result.recv() {
                Ok(Ok(())) => spawn_result,
                Ok(Err(error)) => match spawn_result {
                    Ok(mut child) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        Err(error)
                    }
                    Err(_) => Err(error),
                },
                Err(_) => match spawn_result {
                    Ok(mut child) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        Err(Error::other("parent-child sync task stopped"))
                    }
                    Err(error) => Err(error),
                },
            },
            None => spawn_result,
        };
        if let Some(handshake) = userns_parent_map.take() {
            drop(handshake.child_pid_write);
            drop(handshake.child_ack_read);
            match handshake.mapper.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    if spawn_result.is_ok() {
                        return Err(error);
                    }
                }
                Err(_) if spawn_result.is_ok() => {
                    return Err(Error::other("user namespace map worker panicked"));
                }
                Err(_) => {}
            }
        }
        spawn_result
    }
}

fn child_sync_with_parent(fd: i32) -> Result<()> {
    let pid = (unsafe { libc::getpid() }).to_ne_bytes();
    let mut written = 0;
    while written < pid.len() {
        // SAFETY: `pid` is a valid byte buffer for the remaining length.
        let result =
            unsafe { libc::write(fd, pid[written..].as_ptr().cast(), pid.len() - written) };
        if result == -1 {
            let error = Error::last_os_error();
            if error.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if result == 0 {
            return Err(Error::new(
                ErrorKind::WriteZero,
                "parent sync socket closed before sending child PID",
            ));
        }
        written += result as usize;
    }

    let mut acknowledgement = [0u8; 1];
    loop {
        // SAFETY: `acknowledgement` is a valid one-byte output buffer.
        let result = unsafe { libc::read(fd, acknowledgement.as_mut_ptr().cast(), 1) };
        if result == -1 {
            let error = Error::last_os_error();
            if error.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if result == 0 {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "parent sync socket closed before acknowledgement",
            ));
        }
        break;
    }
    // SAFETY: this descriptor is the child endpoint created for this
    // handshake and is no longer needed once the acknowledgement is read.
    if unsafe { libc::close(fd) } == -1 {
        return Err(Error::last_os_error());
    }
    if acknowledgement[0] != 0 {
        return Err(Error::other("parent-child sync callback failed"));
    }
    Ok(())
}

fn sync_socket_above_stdio(socket: UnixStream) -> Result<UnixStream> {
    let fd = socket.as_raw_fd();
    if fd >= 3 {
        return Ok(socket);
    }
    // SAFETY: F_DUPFD_CLOEXEC duplicates this owned Unix socket to the first
    // descriptor at or above 3, leaving standard streams untouched.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate == -1 {
        return Err(Error::last_os_error());
    }
    drop(socket);
    // SAFETY: `duplicate` is a fresh descriptor for the same Unix socket.
    Ok(unsafe { UnixStream::from_raw_fd(duplicate) })
}

fn spawn_parent_sync(
    socket: UnixStream,
    callback: Box<dyn FnMut(i32) -> Result<()> + Send>,
) -> Result<std::sync::mpsc::Receiver<Result<()>>> {
    socket.set_nonblocking(true)?;
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    crate::tokio_runtime::runtime().handle().spawn(async move {
        let result = match tokio::net::UnixStream::from_std(socket) {
            Ok(socket) => parent_sync_with_child(socket, callback).await,
            Err(error) => Err(error),
        };
        let _ = tx.send(result);
    });
    Ok(rx)
}

async fn parent_sync_with_child(
    mut socket: tokio::net::UnixStream,
    mut callback: Box<dyn FnMut(i32) -> Result<()> + Send>,
) -> Result<()> {
    let mut pid = [0u8; std::mem::size_of::<i32>()];
    socket.read_exact(&mut pid).await?;
    let pid = i32::from_ne_bytes(pid);
    if pid <= 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "child sync handshake supplied an invalid PID",
        ));
    }
    let result = callback(pid);
    socket.write_all(&[u8::from(result.is_err())]).await?;
    result
}

fn insert_setgroups_denied(args: &mut Vec<CString>) {
    if args
        .iter()
        .any(|arg| arg.as_bytes() == b"--setgroups-denied")
    {
        return;
    }
    let option = CString::new("--setgroups-denied").expect("static option has no NUL");
    let insertion = args
        .iter()
        .position(|arg| arg.as_bytes() == b"--")
        .unwrap_or(args.len());
    args.insert(insertion, option);
}

/// Recognize the current non-TTY `nsenter -> chroot -> container-init` argv
/// and replace it with one helper invocation. The helper enters the saved
/// namespaces and chroots before using `Command` to spawn the workload.
fn optimized_namespace_exec(args: &[CString]) -> Option<(CString, Vec<CString>)> {
    if args.len() < 11
        || args[0].as_bytes() != b"/usr/bin/nsenter"
        || args[1].as_bytes() != b"--target"
        || args[3].as_bytes() != b"--mount"
        || args[4].as_bytes() != b"--pid"
        || args[5].as_bytes() != b"--"
        || args[6].as_bytes() != b"/usr/sbin/chroot"
        || args[8].as_bytes() != b"/.rust-sandbox-init"
        || args[9].as_bytes() != b"--exec-direct"
    {
        return None;
    }
    let pid = args[2].to_str().ok()?;
    pid.parse::<i32>().ok()?;
    let root = args[7].as_c_str();
    let helper_path = std::path::Path::new(os_str(root)).join(".rust-sandbox-init");
    let helper = CString::new(helper_path.as_os_str().as_bytes()).ok()?;
    let mut helper_args = vec![
        CString::new("--exec-direct").ok()?,
        CString::new("--namespace-pid").ok()?,
        args[2].clone(),
        CString::new("--root").ok()?,
        root.to_owned(),
    ];
    helper_args.extend(args[10..].iter().cloned());
    Some((helper, helper_args))
}

#[repr(C)]
struct CapUserHeader {
    version: u32,
    pid: i32,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct CapUserData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn os_str(value: &CStr) -> &std::ffi::OsStr {
    std::ffi::OsStr::from_bytes(value.to_bytes())
}

fn parse_cpu_mask(input: &str) -> Result<Vec<u8>> {
    const CPU_SET_BYTES: usize = 128;
    let mut mask = vec![0u8; CPU_SET_BYTES];
    for item in input.split(',') {
        let (first, last) = match item.trim().split_once('-') {
            Some((first, last)) => (
                first
                    .parse::<usize>()
                    .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid CPU set range"))?,
                last.parse::<usize>()
                    .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid CPU set range"))?,
            ),
            None => {
                let cpu = item
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid CPU set ID"))?;
                (cpu, cpu)
            }
        };
        if first > last || last >= CPU_SET_BYTES * 8 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "CPU set range is out of bounds",
            ));
        }
        for cpu in first..=last {
            mask[cpu / 8] |= 1 << (cpu % 8);
        }
    }
    if mask.iter().all(|byte| *byte == 0) {
        return Err(Error::new(ErrorKind::InvalidInput, "empty CPU set"));
    }
    Ok(mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(value: &str) -> CString {
        CString::new(value).unwrap()
    }

    #[test]
    fn rewrites_non_tty_namespace_wrappers_to_direct_helper() {
        let args = [
            "/usr/bin/nsenter",
            "--target",
            "1234",
            "--mount",
            "--pid",
            "--",
            "/usr/sbin/chroot",
            "/tmp/container-root",
            "/.rust-sandbox-init",
            "--exec-direct",
            "--seccomp-file",
            "/.rust-sandbox-seccomp",
            "--work-dir",
            "/w",
            "--uid",
            "1000",
            "--gid",
            "1000",
            "--",
            "/bin/true",
        ]
        .into_iter()
        .map(c)
        .collect::<Vec<_>>();
        let (program, helper_args) = optimized_namespace_exec(&args).unwrap();
        assert_eq!(program, c("/tmp/container-root/.rust-sandbox-init"));
        assert_eq!(
            helper_args,
            [
                "--exec-direct",
                "--namespace-pid",
                "1234",
                "--root",
                "/tmp/container-root",
                "--seccomp-file",
                "/.rust-sandbox-seccomp",
                "--work-dir",
                "/w",
                "--uid",
                "1000",
                "--gid",
                "1000",
                "--",
                "/bin/true",
            ]
            .into_iter()
            .map(c)
            .collect::<Vec<_>>()
        );
    }

    #[test]
    fn pivot_mount_targets_are_relative_to_the_new_root() {
        assert_eq!(
            pivot_relative_target(b"/usr/bin/tool\0").unwrap(),
            b"usr/bin/tool\0"
        );
        assert_eq!(pivot_relative_target(b"/\0").unwrap(), b".\0");
        assert_eq!(
            pivot_relative_target(b"/../../host/etc\0")
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidInput
        );
    }

    fn runner(args: &[&str]) -> Runner {
        Runner {
            args: args.iter().map(|v| c(v)).collect(),
            env: vec![c("PATH=/usr/bin:/bin")],
            work_dir: c(""),
            container_root: None,
            bind_mounts: vec![],
            proc_mounts: vec![],
            tmpfs_mounts: vec![],
            rootfs_tmpfs: false,
            symlinks: vec![],
            mask_paths: vec![],
            fd_map: vec![],
            exec_file: None,
            pid_namespace_helper: None,
            helper_unshare_flags: 0,
            helper_args: None,
            cgroup_procs_fds: vec![],
            user_namespace_fd: None,
            cpu_set: None,
            rlimits: RLimits::default(),
            pivot_root: None,
            host_name: None,
            domain_name: None,
            sync_fn: None,
            clone_flags: 0,
            credential: None,
            uid_map: None,
            gid_map: None,
            gid_map_enable_set_groups: false,
            no_new_privs: false,
            seccomp: Filter::default(),
            drop_caps: false,
            unshare_cgroup_after_sync: false,
            control_tty: false,
        }
    }

    #[test]
    fn starts_program_and_passes_arguments_and_environment() {
        let mut runner = Runner {
            args: vec![
                c("/bin/sh"),
                c("-c"),
                c("test \"$1\" = arg && test \"$VALUE\" = env"),
                c("sh"),
                c("arg"),
            ],
            env: vec![c("VALUE=env")],
            work_dir: c(""),
            container_root: None,
            bind_mounts: vec![],
            proc_mounts: vec![],
            tmpfs_mounts: vec![],
            rootfs_tmpfs: false,
            symlinks: vec![],
            mask_paths: vec![],
            fd_map: vec![],
            exec_file: None,
            pid_namespace_helper: None,
            helper_unshare_flags: 0,
            helper_args: None,
            cgroup_procs_fds: vec![],
            user_namespace_fd: None,
            cpu_set: None,
            rlimits: RLimits::default(),
            pivot_root: None,
            host_name: None,
            domain_name: None,
            sync_fn: None,
            clone_flags: 0,
            credential: None,
            uid_map: None,
            gid_map: None,
            gid_map_enable_set_groups: false,
            no_new_privs: false,
            seccomp: Filter::default(),
            drop_caps: false,
            unshare_cgroup_after_sync: false,
            control_tty: false,
        };
        let child = runner.start().unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
    }

    #[test]
    fn pivots_into_a_fresh_readonly_tmpfs_root() {
        let root = std::env::temp_dir().join(format!(
            "rust-sandbox-pivot-root-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();

        let mut runner = runner(&["/bin/true"]);
        runner.pivot_root = Some(CString::new(root.as_os_str().as_bytes()).unwrap());
        runner.clone_flags = libc::CLONE_NEWUSER | libc::CLONE_NEWNS;
        runner.bind_mounts.push(BindMount {
            source: c("/bin/true"),
            target: c("/bin/true"),
            readonly: true,
        });
        for path in ["/lib", "/lib64"] {
            runner.bind_mounts.push(BindMount {
                source: c(path),
                target: c(path),
                readonly: true,
            });
        }
        let status = runner.start().unwrap().wait().unwrap();
        let _ = std::fs::remove_dir(&root);
        assert!(status.success(), "{status}");
    }

    #[test]
    fn payload_session_uses_its_pid_as_process_group() {
        let mut runner = runner(&["/bin/sleep", "1"]);
        let mut child = runner.start().unwrap();
        let pid = child.id() as libc::pid_t;
        assert_eq!(unsafe { libc::getpgid(pid) }, pid);
        child.kill().unwrap();
        let _ = child.wait();
    }

    #[test]
    fn executes_binary_from_an_open_executable_file() {
        use std::os::fd::AsRawFd;

        let executable = std::fs::File::open("/bin/true").unwrap();
        let mut runner = runner(&["/bin/true"]);
        runner.exec_file = Some(executable.as_raw_fd());
        runner.no_new_privs = true;
        runner.drop_caps = true;
        runner.credential = Some(Credential {
            uid: 1000,
            gid: 1000,
            groups: Vec::new(),
            no_set_groups: true,
        });
        let status = runner.start().unwrap().wait().unwrap();
        assert!(status.success());
    }

    #[test]
    fn sets_the_controlling_tty_after_mapping_the_slave_to_stdin() {
        use std::os::fd::AsRawFd;

        let pair = nix::pty::openpty(None, None).unwrap();
        let mut runner = runner(&[
            "/bin/sh",
            "-c",
            "test -t 0 && test \"$(tty)\" != 'not a tty'",
        ]);
        runner.fd_map = vec![pair.slave.as_raw_fd()];
        runner.control_tty = true;
        let status = runner.start().unwrap().wait().unwrap();
        assert!(status.success(), "child did not receive a controlling tty");
    }

    #[test]
    fn reports_exec_errors() {
        let mut runner = Runner {
            args: vec![c("/this/path/does/not/exist")],
            env: vec![],
            work_dir: c(""),
            container_root: None,
            bind_mounts: vec![],
            proc_mounts: vec![],
            tmpfs_mounts: vec![],
            rootfs_tmpfs: false,
            symlinks: vec![],
            mask_paths: vec![],
            fd_map: vec![],
            exec_file: None,
            pid_namespace_helper: None,
            helper_unshare_flags: 0,
            helper_args: None,
            cgroup_procs_fds: vec![],
            user_namespace_fd: None,
            cpu_set: None,
            rlimits: RLimits::default(),
            pivot_root: None,
            host_name: None,
            domain_name: None,
            sync_fn: None,
            clone_flags: 0,
            credential: None,
            uid_map: None,
            gid_map: None,
            gid_map_enable_set_groups: false,
            no_new_privs: false,
            seccomp: Filter::default(),
            drop_caps: false,
            unshare_cgroup_after_sync: false,
            control_tty: false,
        };
        assert_eq!(runner.start().unwrap_err().kind(), ErrorKind::NotFound);
    }

    #[test]
    fn applies_rlimits_before_exec() {
        let mut runner = runner(&["/bin/sh", "-c", "test \"$(ulimit -n)\" = 64"]);
        runner.rlimits.open_file = 64;
        assert!(runner.start().unwrap().wait().unwrap().success());
    }

    #[test]
    fn applies_arbitrary_linux_rlimits_before_exec() {
        let output = std::env::temp_dir().join(format!(
            "rust-sandbox-rlimit-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let script = format!("ulimit -u > {}", output.display());
        let mut runner = runner(&["/usr/bin/bash", "-c", &script]);
        runner.rlimits.raw.push(crate::container::rlimit::RawLimit {
            resource: libc::RLIMIT_NPROC,
            soft: 37,
            hard: 37,
        });
        assert!(runner.start().unwrap().wait().unwrap().success());
        assert_eq!(std::fs::read_to_string(&output).unwrap().trim(), "37");
        std::fs::remove_file(output).unwrap();
    }

    #[test]
    fn creates_user_namespace_and_self_maps_current_uid_and_gid() {
        let mut runner = runner(&[
            "/bin/sh",
            "-c",
            "test \"$(id -u)\" = 0 && test \"$(id -g)\" = 0",
        ]);
        runner.clone_flags = libc::CLONE_NEWUSER;
        let status = runner.start().unwrap().wait().unwrap();
        assert!(
            status.success(),
            "user namespace command exited with {status}"
        );
    }

    #[test]
    fn parent_installs_multiple_user_namespace_mapping_extents() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        // An unprivileged process in a subordinate user namespace can only
        // map its own effective UID/GID, as a single extent. The multi-extent
        // parent mapping path requires the initial user namespace (or a
        // privileged newuidmap helper), which this test intentionally avoids.
        let initial_user_namespace = std::fs::read_to_string("/proc/self/uid_map")
            .is_ok_and(|map| map.trim() == "0 0 4294967295");
        if !initial_user_namespace {
            return;
        }
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        let mut runner = runner(&[
            "/bin/sh",
            "-c",
            &format!(
                "test \"$(id -u)\" = 0 && test \"$(id -g)\" = 0 && grep -q '^0 {uid} 1$' /proc/self/uid_map && grep -q '^1000 1000 1$' /proc/self/uid_map && grep -q '^0 {gid} 1$' /proc/self/gid_map && grep -q '^1000 1000 1$' /proc/self/gid_map"
            ),
        ]);
        runner.clone_flags = libc::CLONE_NEWUSER;
        runner.uid_map = Some(vec![
            IdMap {
                container_id: 0,
                host_id: uid,
                size: 1,
            },
            IdMap {
                container_id: 1000,
                host_id: 1000,
                size: 1,
            },
        ]);
        runner.gid_map = Some(vec![
            IdMap {
                container_id: 0,
                host_id: gid,
                size: 1,
            },
            IdMap {
                container_id: 1000,
                host_id: 1000,
                size: 1,
            },
        ]);
        let status = runner.start().unwrap().wait().unwrap();
        assert!(
            status.success(),
            "multi-range user namespace exited {status}"
        );
    }

    #[test]
    fn enrolls_child_in_every_cgroup_membership_file_before_exec() {
        use std::os::fd::AsRawFd;
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "rust-sandbox-cgroup-enroll-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let first_path = directory.join("memory.procs");
        let second_path = directory.join("pids.procs");
        let first = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&first_path)
            .unwrap();
        let second = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&second_path)
            .unwrap();
        let mut runner = runner(&["/bin/true"]);
        runner.cgroup_procs_fds = vec![first.as_raw_fd(), second.as_raw_fd()];
        let mut child = runner.start().unwrap();
        let child_pid = child.id().to_string();
        assert!(child.wait().unwrap().success());
        drop((first, second));
        assert_eq!(std::fs::read_to_string(&first_path).unwrap(), child_pid);
        assert_eq!(std::fs::read_to_string(&second_path).unwrap(), child_pid);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn enables_no_new_privs_before_exec() {
        let mut runner = runner(&[
            "/bin/sh",
            "-c",
            "grep -q '^NoNewPrivs:[[:space:]]*1$' /proc/self/status",
        ]);
        runner.no_new_privs = true;
        assert!(runner.start().unwrap().wait().unwrap().success());
    }

    #[test]
    fn installs_seccomp_filter_before_exec() {
        let mut runner = runner(&[
            "/bin/sh",
            "-c",
            "grep -q '^Seccomp:[[:space:]]*2$' /proc/self/status",
        ]);
        runner.seccomp = Filter(
            vec![libc::sock_filter {
                code: (libc::BPF_RET | libc::BPF_K) as u16,
                jt: 0,
                jf: 0,
                k: 0x7fff_0000,
            }],
            Vec::new(),
        );
        assert!(runner.start().unwrap().wait().unwrap().success());
    }

    #[test]
    fn drops_capabilities_in_an_unprivileged_safe_child() {
        let mut runner = runner(&[
            "/bin/sh",
            "-c",
            "grep -q '^CapEff:[[:space:]]*0000000000000000$' /proc/self/status",
        ]);
        runner.drop_caps = true;
        assert!(runner.start().unwrap().wait().unwrap().success());
    }

    #[test]
    fn credential_setup_accepts_current_unprivileged_identity() {
        // Setting the process to its existing real ids is allowed without
        // privilege, and skipping setgroups avoids requiring CAP_SETGID.
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        let mut runner = runner(&[
            "/bin/sh",
            "-c",
            "test \"$(id -u)\" = \"$EXPECT_UID\" && test \"$(id -g)\" = \"$EXPECT_GID\"",
        ]);
        runner
            .env
            .push(CString::new(format!("EXPECT_UID={uid}")).unwrap());
        runner
            .env
            .push(CString::new(format!("EXPECT_GID={gid}")).unwrap());
        runner.credential = Some(Credential {
            uid,
            gid,
            groups: Vec::new(),
            no_set_groups: true,
        });
        assert!(runner.start().unwrap().wait().unwrap().success());
    }

    #[test]
    fn unsupported_namespace_and_invalid_pivot_fail_before_spawn() {
        let mut runner = runner(&["/bin/true"]);
        runner.clone_flags = libc::CLONE_NEWPID;
        assert_eq!(runner.start().unwrap_err().kind(), ErrorKind::Unsupported);
        runner.clone_flags = 0;
        runner.pivot_root = Some(c("/tmp"));
        assert_eq!(runner.start().unwrap_err().kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn parent_sync_callback_receives_child_pid_before_exec() {
        let base = std::env::temp_dir().join(format!(
            "rust-sandbox-sync-{}-{}",
            std::process::id(),
            crate::tokio_runtime::runtime().handle().id()
        ));
        let callback_pid_file = base.with_extension("parent");
        let child_pid_file = base.with_extension("child");
        let callback_path = callback_pid_file.clone();
        let mut runner = runner(&[
            "/bin/sh",
            "-c",
            &format!("printf '%s' $$ > {}", child_pid_file.display()),
        ]);
        runner.sync_fn = Some(Box::new(move |pid| {
            std::fs::write(&callback_path, pid.to_string())
        }));

        assert!(runner.start().unwrap().wait().unwrap().success());
        let callback_pid = std::fs::read_to_string(&callback_pid_file).unwrap();
        let exec_pid = std::fs::read_to_string(&child_pid_file).unwrap();
        assert_eq!(callback_pid, exec_pid);
        let _ = std::fs::remove_file(callback_pid_file);
        let _ = std::fs::remove_file(child_pid_file);
    }

    #[test]
    fn parent_sync_callback_error_aborts_exec() {
        let mut runner = runner(&["/bin/true"]);
        runner.sync_fn = Some(Box::new(|_| Err(Error::other("intentional sync failure"))));
        let error = runner.start().unwrap_err();
        assert!(error.to_string().contains("intentional sync failure"));
    }

    #[test]
    fn unshares_cgroup_namespace_best_effort_after_cgroup_setup() {
        let mut runner = runner(&["/bin/true"]);
        runner.unshare_cgroup_after_sync = true;
        assert!(runner.start().unwrap().wait().unwrap().success());
    }
}
