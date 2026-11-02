//! PID-namespace init helper used by the production `rust-judge` executable.
//!
//! `unshare --pid --fork --mount-proc` starts this program as PID 1. It loads
//! the prebuilt seccomp filter only after util-linux completed namespace and
//! proc setup, then replaces itself with the workload.

use std::fs::File;
use std::io::{self, Write};
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};

pub fn run(args: impl IntoIterator<Item = std::ffi::OsString>) -> io::Result<()> {
    let mut args = args.into_iter();
    let mut first = args.next();
    if first.as_deref() == Some(std::ffi::OsStr::new("container_init")) {
        first = args.next();
    }
    if first.as_deref() == Some(std::ffi::OsStr::new("--keepalive")) {
        return run_keepalive(args);
    }
    if first.as_deref() == Some(std::ffi::OsStr::new("--exec-direct")) {
        return run_exec_direct(args);
    }
    let mut args = std::iter::once(first.unwrap_or_default()).chain(args);
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--seccomp-file")) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing --seccomp-file",
        ));
    }
    let filter_path = args
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing seccomp file path"))?;
    let mut args = args.collect::<Vec<_>>().into_iter();
    let mut cgroup_procs_fds = Vec::new();
    let mut separator = args.next();
    while separator.as_deref() == Some(std::ffi::OsStr::new("--cgroup-procs-fd")) {
        cgroup_procs_fds.push(
            args.next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing cgroup fd"))?
                .to_string_lossy()
                .parse::<i32>()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cgroup fd"))?,
        );
        separator = args.next();
    }
    if separator.as_deref() != Some(std::ffi::OsStr::new("--")) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing workload separator",
        ));
    }
    let executable = args
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing executable"))?;
    let workload_args = args.collect::<Vec<_>>();

    let bytes = std::fs::read(filter_path)?;
    if bytes.len() % 8 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid seccomp BPF length",
        ));
    }
    let filter = bytes
        .as_chunks::<8>()
        .0
        .iter()
        .map(|chunk| seccompiler::sock_filter {
            code: u16::from_ne_bytes([chunk[0], chunk[1]]),
            jt: chunk[2],
            jf: chunk[3],
            k: u32::from_ne_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]),
        })
        .collect::<Vec<_>>();
    if filter.is_empty() {
        // SAFETY: no_new_privs takes a scalar boolean and no pointer arguments.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == -1 {
            return Err(io::Error::last_os_error());
        }
    } else {
        seccompiler::apply_filter(&filter).map_err(io::Error::other)?;
    }

    ignore_container_signals();
    let mut command = Command::new(executable);
    command.args(workload_args);
    // The helper remains PID 1 and reaps descendants, matching go-sandbox's
    // container init. Restore default signal dispositions in the workload.
    // SAFETY: the hook only resets process signal dispositions using sigaction.
    unsafe {
        command.pre_exec(move || {
            for fd in cgroup_procs_fds.iter().copied() {
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
                let written =
                    libc::write(fd, digits[start..].as_ptr().cast(), digits.len() - start);
                if written == -1 {
                    return Err(io::Error::last_os_error());
                }
                if written as usize != digits.len() - start {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "short cgroup.procs write",
                    ));
                }
                if libc::close(fd) == -1 {
                    return Err(io::Error::last_os_error());
                }
            }
            for signal in ignored_signals() {
                if libc::signal(signal, libc::SIG_DFL) == libc::SIG_ERR {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let status = command.status()?;
    // Kill and reap any descendants the workload left behind before PID 1
    // exits. These syscalls are allowed by the installed sandbox profile.
    unsafe {
        libc::kill(-1, libc::SIGKILL);
        let mut status = 0;
        loop {
            let result = libc::waitpid(-1, &mut status, 0);
            if result > 0 {
                continue;
            }
            if result == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }
    }
    let code = status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(libc::SIGKILL));
    std::process::exit(code)
}

fn run_keepalive(args: impl IntoIterator<Item = std::ffi::OsString>) -> io::Result<()> {
    let mut args = args.into_iter();
    let mut proc_mode = None;
    let mut mask_paths = Vec::new();
    let mut work_dir = std::ffi::OsString::from("/");
    let mut init_command = Vec::new();
    let mut uid = None;
    let mut gid = None;
    let mut setgroups_denied = false;
    while let Some(option) = args.next() {
        match option.to_string_lossy().as_ref() {
            "--setgroups-denied" => setgroups_denied = true,
            "--proc-mode" => {
                proc_mode = Some(
                    args.next()
                        .ok_or_else(|| io::Error::other("missing proc mode"))?
                        .into_string()
                        .map_err(|_| io::Error::other("proc mode is not UTF-8"))?,
                );
            }
            "--mask-path" => mask_paths.push(
                args.next()
                    .ok_or_else(|| io::Error::other("missing mask path"))?,
            ),
            "--work-dir" => {
                work_dir = args
                    .next()
                    .ok_or_else(|| io::Error::other("missing work directory"))?;
            }
            "--init-cmd-len" => {
                let count = args
                    .next()
                    .ok_or_else(|| io::Error::other("missing init command length"))?
                    .to_string_lossy()
                    .parse::<usize>()
                    .map_err(|_| io::Error::other("invalid init command length"))?;
                init_command.reserve(count);
                for _ in 0..count {
                    init_command.push(
                        args.next()
                            .ok_or_else(|| io::Error::other("missing init command argument"))?,
                    );
                }
            }
            "--uid" => {
                uid = Some(parse_id(args.next(), "uid")?);
            }
            "--gid" => {
                gid = Some(parse_id(args.next(), "gid")?);
            }
            _ => return Err(io::Error::other("unknown keepalive option")),
        }
    }

    // util-linux `unshare --mount-proc` is deliberately not used for the
    // server path: procfs must be mounted after entering the new PID namespace,
    // then masks applied to that final procfs instance.
    let startup = (|| {
        if let Some(mode) = proc_mode.as_deref() {
            let flags = libc::MS_NOSUID
                | libc::MS_NODEV
                | libc::MS_NOEXEC
                | if mode == "ro" { libc::MS_RDONLY } else { 0 };
            if mode != "ro" && mode != "rw" {
                return Err(io::Error::other("invalid proc mode"));
            }
            mount(
                "proc",
                "/proc",
                "proc",
                flags | libc::MS_REMOUNT as libc::c_ulong,
                "",
            )?;
        }
        for path in mask_paths {
            mask_path(&path)?;
        }
        std::env::set_current_dir(&work_dir)?;
        run_init_command(&init_command, &work_dir)
    })();
    // fd 0 is remapped from the parent to this one-shot readiness channel.
    // The parent does not expose the keeper until initialization succeeds.
    let mut ready = unsafe { File::from_raw_fd(0) };
    write_keeper_startup(&mut ready, &startup)?;
    drop(ready);
    startup?;

    if unsafe { libc::geteuid() } == 0 {
        if !setgroups_denied && unsafe { libc::setgroups(0, std::ptr::null()) } == -1 {
            return Err(io::Error::last_os_error());
        }
        if let Some(gid) = gid
            && unsafe { libc::setgid(gid) } == -1
        {
            return Err(io::Error::last_os_error());
        }
        if let Some(uid) = uid
            && unsafe { libc::setuid(uid) } == -1
        {
            return Err(io::Error::last_os_error());
        }
    }

    ignore_container_signals();
    let mut child_signal = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    if unsafe { libc::sigemptyset(&mut child_signal) } == -1
        || unsafe { libc::sigaddset(&mut child_signal, libc::SIGCHLD) } == -1
        || unsafe { libc::sigprocmask(libc::SIG_BLOCK, &child_signal, std::ptr::null_mut()) } == -1
    {
        return Err(io::Error::last_os_error());
    }
    loop {
        // PID 1 is the reaper for payloads forked by the executor thread into
        // this namespace. Block SIGCHLD and use sigwaitinfo so there is no
        // race between the nonblocking reap sweep and sleeping for a child.
        loop {
            let mut status = 0;
            let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            if pid > 0 {
                continue;
            }
            if pid == -1 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                if error.raw_os_error() != Some(libc::ECHILD) {
                    return Err(error);
                }
            }
            break;
        }
        let signal = unsafe { libc::sigwaitinfo(&child_signal, std::ptr::null_mut()) };
        if signal == -1 && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return Err(io::Error::last_os_error());
        }
    }
}

fn run_init_command(command: &[std::ffi::OsString], work_dir: &std::ffi::OsStr) -> io::Result<()> {
    let Some(executable) = command.first() else {
        return Ok(());
    };
    let output = Command::new(executable)
        .args(&command[1..])
        .current_dir(work_dir)
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .output()?;
    if output.status.success() {
        return Ok(());
    }
    let mut stderr = io::stderr().lock();
    stderr.write_all(&output.stdout)?;
    stderr.write_all(&output.stderr)?;
    let mut combined = output.stdout;
    combined.extend_from_slice(&output.stderr);
    Err(io::Error::other(format!(
        "init command failed with status {}: {}",
        output.status,
        String::from_utf8_lossy(&combined)
    )))
}

fn write_keeper_startup(channel: &mut File, result: &io::Result<()>) -> io::Result<()> {
    let message = result
        .as_ref()
        .err()
        .map(ToString::to_string)
        .unwrap_or_default();
    let len = u32::try_from(message.len())
        .map_err(|_| io::Error::other("keeper startup error message is too large"))?;
    channel.write_all(&[u8::from(result.is_err())])?;
    channel.write_all(&len.to_be_bytes())?;
    channel.write_all(message.as_bytes())?;
    channel.flush()
}

fn parse_id(value: Option<std::ffi::OsString>, name: &str) -> io::Result<u32> {
    value
        .ok_or_else(|| io::Error::other(format!("missing {name}")))?
        .to_string_lossy()
        .parse()
        .map_err(|_| io::Error::other(format!("invalid {name}")))
}

fn mount(
    source: &str,
    target: &str,
    fs_type: &str,
    flags: libc::c_ulong,
    data: &str,
) -> io::Result<()> {
    let source = std::ffi::CString::new(source).map_err(io::Error::other)?;
    let target = std::ffi::CString::new(target).map_err(io::Error::other)?;
    let fs_type = std::ffi::CString::new(fs_type).map_err(io::Error::other)?;
    let data = std::ffi::CString::new(data).map_err(io::Error::other)?;
    if unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fs_type.as_ptr(),
            flags,
            data.as_ptr().cast(),
        )
    } == -1
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn mask_path(path: &std::ffi::OsStr) -> io::Result<()> {
    let path = std::ffi::CString::new(path.as_bytes()).map_err(io::Error::other)?;
    let empty = c"";
    if unsafe {
        libc::mount(
            c"/dev/null".as_ptr(),
            path.as_ptr(),
            empty.as_ptr().cast(),
            libc::MS_BIND as _,
            empty.as_ptr().cast(),
        )
    } == 0
    {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound {
        return Ok(());
    }
    if error.raw_os_error() == Some(libc::ENOTDIR) {
        return mount(
            "tmpfs",
            path.to_str().unwrap_or_default(),
            "tmpfs",
            libc::MS_RDONLY as _,
            "",
        );
    }
    Err(error)
}

fn run_exec_direct(args: impl IntoIterator<Item = std::ffi::OsString>) -> io::Result<()> {
    let mut args = args.into_iter();
    let mut filter_path = None;
    let mut work_dir = None;
    let mut uid = None;
    let mut gid = None;
    let mut cgroup_procs_fds = Vec::new();
    let mut namespace_pid = None;
    let mut root = None;
    let mut setgroups_denied = false;
    loop {
        let Some(option) = args.next() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "missing workload separator",
            ));
        };
        if option == "--setgroups-denied" {
            setgroups_denied = true;
            continue;
        }
        let value = match option.to_string_lossy().as_ref() {
            "--" => break,
            "--seccomp-file" => args.next().map(|v| filter_path = Some(v)),
            "--work-dir" => args.next().map(|v| work_dir = Some(v)),
            "--namespace-pid" => args
                .next()
                .and_then(|v| v.to_string_lossy().parse::<i32>().ok())
                .map(|v| namespace_pid = Some(v)),
            "--root" => args.next().map(|v| root = Some(v)),
            "--uid" => args
                .next()
                .and_then(|v| v.to_string_lossy().parse().ok())
                .map(|v| uid = Some(v)),
            "--gid" => args
                .next()
                .and_then(|v| v.to_string_lossy().parse().ok())
                .map(|v| gid = Some(v)),
            "--cgroup-procs-fd" => args
                .next()
                .and_then(|v| v.to_string_lossy().parse().ok())
                .map(|v| cgroup_procs_fds.push(v)),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unknown helper option",
                ));
            }
        };
        if value.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "missing or invalid helper option value",
            ));
        }
    }

    // Open both namespace handles before entering either namespace: joining
    // the mount namespace changes the procfs view used to resolve the PID
    // namespace path. setns(CLONE_NEWPID) applies to children subsequently
    // created by this process, which is exactly what Command::spawn needs.
    // Runner may have created and mapped a per-workload user namespace in its
    // single-threaded pre-exec child. That child already inherited the
    // executor's mount and PID namespaces; trying to re-enter the mount
    // namespace after switching user namespaces can fail because it is owned
    // by the parent user namespace.
    if let Some(pid) = namespace_pid.filter(|_| !setgroups_denied) {
        let mount_path = std::ffi::CString::new(format!("/proc/{pid}/ns/mnt")).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid mount namespace PID")
        })?;
        let pid_path = std::ffi::CString::new(format!("/proc/{pid}/ns/pid")).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid PID namespace PID")
        })?;
        let mount_fd = unsafe { libc::open(mount_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if mount_fd == -1 {
            return Err(io::Error::last_os_error());
        }
        let pid_fd = unsafe { libc::open(pid_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if pid_fd == -1 {
            let error = io::Error::last_os_error();
            unsafe { libc::close(mount_fd) };
            return Err(error);
        }
        let enter_result = unsafe {
            if libc::setns(mount_fd, libc::CLONE_NEWNS) == -1
                || libc::setns(pid_fd, libc::CLONE_NEWPID) == -1
            {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        };
        unsafe {
            libc::close(mount_fd);
            libc::close(pid_fd);
        }
        enter_result?;
    }
    if let Some(root) = root.as_ref() {
        let root = std::ffi::CString::new(root.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in root path"))?;
        if unsafe { libc::chroot(root.as_ptr()) } == -1
            || unsafe { libc::chdir(c"/".as_ptr()) } == -1
        {
            return Err(io::Error::last_os_error());
        }
    }
    let executable = args
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing executable"))?;
    let workload_args = args.collect::<Vec<_>>();

    if let Some(path) = work_dir.as_ref() {
        let path = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in work directory"))?;
        if unsafe { libc::chdir(path.as_ptr()) } == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    if unsafe { libc::geteuid() } == 0 {
        if !setgroups_denied && unsafe { libc::setgroups(0, std::ptr::null()) } == -1 {
            return Err(io::Error::last_os_error());
        }
        if let Some(gid) = gid
            && unsafe { libc::setgid(gid) } == -1
        {
            return Err(io::Error::last_os_error());
        }
        if let Some(uid) = uid
            && unsafe { libc::setuid(uid) } == -1
        {
            return Err(io::Error::last_os_error());
        }
    }
    for signal in ignored_signals() {
        unsafe {
            libc::signal(signal, libc::SIG_DFL);
        }
    }

    let filter_path = filter_path
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing seccomp file"))?;
    let filters = read_filters(filter_path)?;
    let mut command = Command::new(executable);
    command.args(workload_args);
    command
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    // Keep the exec wrapper outside the per-command cgroup. This lets a
    // pids.max of one admit the payload itself while retaining wait status.
    unsafe {
        command.pre_exec(move || {
            for fd in cgroup_procs_fds.iter().copied() {
                write_self_to_cgroup(fd)?;
                if libc::close(fd) == -1 {
                    return Err(io::Error::last_os_error());
                }
            }
            for signal in ignored_signals() {
                if libc::signal(signal, libc::SIG_DFL) == libc::SIG_ERR {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    if filters.is_empty() {
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == -1 {
            return Err(io::Error::last_os_error());
        }
    } else {
        for filter in &filters {
            seccompiler::apply_filter(filter).map_err(io::Error::other)?;
        }
    }
    let mut child = command.spawn()?;
    let status = child.wait()?;
    kill_namespaced_workload_descendants()?;
    let code = status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(libc::SIGKILL));
    std::process::exit(code)
}

fn kill_namespaced_workload_descendants() -> io::Result<()> {
    // PID 1 remains the container reaper. Kill every other process in this
    // PID namespace, including descendants that escaped the workload's
    // process group with setsid(), then wait until PID 1 has reaped them before
    // the environment can be reused for another command.
    if unsafe { libc::kill(-1, libc::SIGKILL) } == -1 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error);
        }
    }
    let self_pid = unsafe { libc::getpid() };
    loop {
        let mut remaining = false;
        for entry in std::fs::read_dir("/proc")? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(pid) = name.to_str().and_then(|name| name.parse::<i32>().ok()) else {
                continue;
            };
            if pid != 1 && pid != self_pid {
                remaining = true;
                break;
            }
        }
        if !remaining {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

fn read_filters(path: std::ffi::OsString) -> io::Result<Vec<Vec<seccompiler::sock_filter>>> {
    let bytes = std::fs::read(path)?;
    if bytes.starts_with(b"RSECCMP1") {
        let mut cursor = 8;
        let read_u32 = |cursor: &mut usize| -> io::Result<u32> {
            let end = cursor.checked_add(4).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid seccomp file")
            })?;
            let raw = bytes.get(*cursor..end).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "truncated seccomp file")
            })?;
            *cursor = end;
            Ok(u32::from_ne_bytes(raw.try_into().unwrap()))
        };
        let count = usize::try_from(read_u32(&mut cursor)?).map_err(io::Error::other)?;
        let mut filters = Vec::with_capacity(count);
        for _ in 0..count {
            let len = usize::try_from(read_u32(&mut cursor)?).map_err(io::Error::other)?;
            let bytes_len = len.checked_mul(8).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid seccomp length")
            })?;
            let end = cursor.checked_add(bytes_len).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid seccomp length")
            })?;
            let raw = bytes.get(cursor..end).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "truncated seccomp program")
            })?;
            cursor = end;
            filters.push(parse_filter(raw)?);
        }
        if cursor != bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trailing seccomp bytes",
            ));
        }
        return Ok(filters);
    }
    Ok(vec![parse_filter(&bytes)?])
}

fn parse_filter(bytes: &[u8]) -> io::Result<Vec<seccompiler::sock_filter>> {
    if !bytes.len().is_multiple_of(8) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid seccomp BPF length",
        ));
    }
    Ok(bytes
        .as_chunks::<8>()
        .0
        .iter()
        .map(|chunk| seccompiler::sock_filter {
            code: u16::from_ne_bytes([chunk[0], chunk[1]]),
            jt: chunk[2],
            jf: chunk[3],
            k: u32::from_ne_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]),
        })
        .collect())
}

fn write_self_to_cgroup(fd: i32) -> io::Result<()> {
    let mut digits = [0u8; 10];
    let mut value = unsafe { libc::getpid() } as u32;
    let mut start = digits.len();
    loop {
        start -= 1;
        digits[start] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    let written = unsafe { libc::write(fd, digits[start..].as_ptr().cast(), digits.len() - start) };
    if written == -1 {
        return Err(io::Error::last_os_error());
    }
    if written as usize != digits.len() - start {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short cgroup.procs write",
        ));
    }
    Ok(())
}

fn ignored_signals() -> [libc::c_int; 12] {
    [
        libc::SIGHUP,
        libc::SIGINT,
        libc::SIGTERM,
        libc::SIGQUIT,
        libc::SIGILL,
        libc::SIGTRAP,
        libc::SIGABRT,
        libc::SIGBUS,
        libc::SIGFPE,
        libc::SIGSEGV,
        libc::SIGSTKFLT,
        libc::SIGSYS,
    ]
}

fn ignore_container_signals() {
    for signal in ignored_signals() {
        // PID namespace init only accepts signals for which it has installed
        // a handler. A no-op handler matches the init process behavior while
        // keeping these external signals from terminating the container.
        // SAFETY: signal disposition installation and handler are valid.
        unsafe {
            libc::signal(
                signal,
                handle_container_signal as *const () as libc::sighandler_t,
            );
        }
    }
}

extern "C" fn handle_container_signal(_: libc::c_int) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_incomplete_helper_arguments() {
        assert!(run(Vec::<std::ffi::OsString>::new()).is_err());
    }

    #[test]
    fn init_command_uses_container_path_and_working_directory() {
        let dir = std::env::temp_dir().join(format!(
            "rust-sandbox-init-command-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let command = [
            "/bin/sh",
            "-c",
            "test \"$PATH\" = /usr/local/bin:/usr/bin:/bin && pwd > init-cwd",
        ]
        .into_iter()
        .map(std::ffi::OsString::from)
        .collect::<Vec<_>>();
        run_init_command(&command, dir.as_os_str()).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join("init-cwd"))
                .unwrap()
                .trim(),
            dir.display().to_string()
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
