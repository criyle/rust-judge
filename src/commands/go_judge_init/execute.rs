use super::*;

pub(super) async fn execute(
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
    // Keep one directory descriptor for clone3(CLONE_INTO_CGROUP), and open
    // membership files for any additional hierarchies or older kernels.
    let mut cgroup_procs_files = Vec::with_capacity(cgroup_fds.len());
    let mut _cgroup_directory_files = Vec::new();
    let mut cgroup_into_fd = None;
    let mut cgroup_into_procs_index = None;
    for (index, directory) in cgroup_fds.into_iter().enumerate() {
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
                // A caller may pass cgroup.procs directly; retain the
                // membership-file fallback for that form.
                cgroup_procs_files.push(File::from(directory));
                continue;
            }
            return Ok((error_reply(error), false));
        }
        if cgroup_into_fd.is_none() {
            cgroup_into_fd = Some(directory.as_raw_fd());
            cgroup_into_procs_index = Some(index);
        }
        _cgroup_directory_files.push(File::from(directory));
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
        cgroup_into_fd,
        cgroup_into_procs_index,
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
pub(super) struct ProcessUsage {
    pub(super) user_time_ns: u64,
    pub(super) peak_memory_bytes: u64,
}

// Keep common PID readiness events inline; boxing the uncommon control frame
// would allocate on every init request.
#[allow(clippy::large_enum_variant)]
enum ChildWaitEvent {
    Pidfd(io::Result<()>),
    Poll,
    Control(io::Result<(WireCommand, protocol::ReceivedFrame)>),
}

pub(super) fn open_pidfd_async(pid: i32) -> Option<tokio::io::unix::AsyncFd<OwnedFd>> {
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

pub(super) async fn wait_pidfd_ready(pidfd: &tokio::io::unix::AsyncFd<OwnedFd>) -> io::Result<()> {
    let mut ready = pidfd.readable().await?;
    ready.clear_ready();
    Ok(())
}

fn sample_process_usage(pid: i32, usage: &mut ProcessUsage) {
    let proc_dir = Path::new("/proc").join(pid.to_string());
    if let Ok(stat) = fs::read_to_string(proc_dir.join("stat"))
        && let Some(ticks) = process_user_ticks(&stat)
    {
        let ticks_per_second = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as u64;
        let ns = ticks.saturating_mul(1_000_000_000) / ticks_per_second;
        usage.user_time_ns = usage.user_time_ns.max(ns);
    }
    if let Ok(status) = fs::read_to_string(proc_dir.join("status"))
        && let Some(bytes) = process_vm_hwm_bytes(&status)
    {
        usage.peak_memory_bytes = usage.peak_memory_bytes.max(bytes);
    }
}

/// Reap an exited child with wait4 so the final user CPU time and peak RSS
/// match Go's syscall.Wait4 result. waitid with WNOWAIT detects completion
/// without consuming the status, keeping the child available to std's
/// Child::kill cleanup path if the container control socket closes first.
pub(super) fn try_wait_process_usage(
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

pub(super) fn process_user_ticks(stat: &str) -> Option<u64> {
    // comm is parenthesized and may itself contain spaces or `)`, so split
    // only after its final closing parenthesis as /proc/PID/stat requires.
    let end_comm = stat.rfind(") ")?;
    stat[end_comm + 2..]
        .split_whitespace()
        .nth(11)?
        .parse()
        .ok()
}

pub(super) fn process_vm_hwm_bytes(status: &str) -> Option<u64> {
    let line = status.lines().find(|line| line.starts_with("VmHWM:"))?;
    let kib = line.split_whitespace().nth(1)?.parse::<u64>().ok()?;
    Some(kib.saturating_mul(1024))
}

pub(super) fn reap_children(workload_pgid: i32) {
    // Reap the workload's process group first. Only PID 1 may fall back to
    // namespace-wide cleanup, and only when a descendant escaped that group.
    let child_selector = -workload_pgid;
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
    if unsafe { libc::getpid() } != 1 {
        return;
    }

    let mut status = 0;
    let remaining = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
    if remaining == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
        return;
    }
    unsafe { libc::kill(-1, libc::SIGKILL) };
    loop {
        let mut status = 0;
        let pid = unsafe { libc::waitpid(-1, &mut status, 0) };
        if pid > 0 {
            continue;
        }
        if pid == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        break;
    }
}

fn stop_child_and_reap(child: &mut Child, pid: i32) {
    let _ = unsafe { libc::kill(-pid, libc::SIGKILL) };
    let _ = child.wait();
    reap_children(pid);
}

pub(super) fn convert_rlimits(
    limits: &[crate::container::protocol::ResourceLimit],
) -> io::Result<RLimits> {
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
