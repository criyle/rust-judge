use super::*;

impl Runner {
    /// Starts the configured executable and returns its process handle.
    ///
    /// The command builder remains `std::process::Command`-style. When the
    /// child needs no parent coordination, Runner uses its raw clone3/vfork
    /// path and returns a compatible `Child`; special coordination modes use
    /// `Command::spawn` and the same child setup closure.
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
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        let use_vfork_path = !helper_mode
            && self.sync_fn.is_none()
            && self.user_namespace_fd.is_none()
            && flags & libc::CLONE_NEWUSER == 0;
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let use_vfork_path = false;
        let use_clone3 = clone3_available();
        let clone3_cgroup_fd = if use_vfork_path {
            self.cgroup_into_fd
                .filter(|fd| clone3_into_cgroup_available(*fd))
        } else {
            None
        };
        let cgroup_procs_skip = Arc::new(AtomicUsize::new(usize::MAX));
        let cgroup_procs_skip_child = Arc::clone(&cgroup_procs_skip);
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

        // The same prebuilt setup closure serves both paths. On the raw path,
        // clone3 gives the child a separate stack and CLONE_VFORK suspends
        // this spawning thread until execve. The child must not allocate or
        // mutate captured state while it shares the parent's VM.
        let mut child_setup = move || -> Result<()> {
            unsafe {
                // Only the parent should retain the callback endpoint. If the
                // child kept it open, parent cancellation would not produce
                // EOF on the child's acknowledgement read.
                if let Some(fd) = sync_parent_fd
                    && libc::close(fd) == -1
                {
                    return Err(child_errno_error());
                }
                // Drop host supplementary groups before entering a user
                // namespace whose setgroups file is denied. Once the map is
                // installed, setgroups(2) cannot be used to clear them.
                if helper_mode && libc::geteuid() == 0 && libc::setgroups(0, std::ptr::null()) == -1
                {
                    return Err(child_errno_error());
                }
                for (index, fd) in cgroup_procs_fds.iter().copied().enumerate() {
                    if cgroup_procs_skip_child.load(Ordering::Relaxed) == index {
                        continue;
                    }
                    let target = 255 + index as i32;
                    if libc::dup2(fd, target) == -1 {
                        return Err(child_errno_error());
                    }
                    if libc::fcntl(target, libc::F_SETFD, 0) == -1 {
                        return Err(child_errno_error());
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
                        if cgroup_procs_skip_child.load(Ordering::Relaxed) == index {
                            continue;
                        }
                        let fd = 255 + index as i32;
                        let written =
                            libc::write(fd, digits[start..].as_ptr().cast(), digits.len() - start);
                        if written == -1 {
                            return Err(child_errno_error());
                        }
                        if written as usize != digits.len() - start {
                            return Err(Error::from_raw_os_error(libc::EIO));
                        }
                        if libc::close(fd) == -1 {
                            return Err(child_errno_error());
                        }
                    }
                }
                if let Some(user_namespace_fd) = user_namespace_fd {
                    if libc::setns(user_namespace_fd, libc::CLONE_NEWUSER) == -1 {
                        // Rootless callers may not have permission to join a
                        // sibling's namespace. Retain the self-map path as a
                        // functional fallback for those hosts.
                        if libc::unshare(libc::CLONE_NEWUSER) == -1 {
                            return Err(child_errno_error());
                        }
                        write_userns_maps(&userns_maps)?;
                    }
                } else if flags & libc::CLONE_NEWUSER != 0 {
                    if libc::unshare(libc::CLONE_NEWUSER) == -1 {
                        return Err(child_errno_error());
                    }
                    if let Some((pid_write, ack_read)) = userns_parent_map_fds {
                        child_wait_for_parent_userns_map(pid_write, ack_read)?;
                    } else {
                        write_userns_maps(&userns_maps)?;
                    }
                    let remaining_flags = flags & !libc::CLONE_NEWUSER;
                    if remaining_flags != 0 && libc::unshare(remaining_flags as libc::c_int) == -1 {
                        return Err(child_errno_error());
                    }
                } else if flags != 0 && libc::unshare(flags as libc::c_int) == -1 {
                    return Err(child_errno_error());
                }
                if unshare_cgroup_after_sync {
                    // Go treats this namespace as optional and ignores errors
                    // when the host does not delegate the required capability.
                    let _ = libc::unshare(libc::CLONE_NEWCGROUP);
                }
                if let Some(mask) = cpu_mask.as_deref()
                    && libc::sched_setaffinity(0, mask.len(), mask.as_ptr().cast()) == -1
                {
                    return Err(child_errno_error());
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
                        c"/".as_ptr(),
                        std::ptr::null(),
                        (libc::MS_REC | libc::MS_PRIVATE) as _,
                        std::ptr::null(),
                    ) == -1
                    {
                        return Err(child_errno_error());
                    }
                    if rootfs_tmpfs {
                        libc::umask(0);
                        let root = root_mount
                            .as_deref()
                            .ok_or_else(|| Error::from_raw_os_error(libc::EINVAL))?;
                        if libc::mount(
                            c"tmpfs".as_ptr(),
                            root.as_ptr().cast(),
                            c"tmpfs".as_ptr(),
                            0,
                            std::ptr::null(),
                        ) == -1
                        {
                            return Err(child_errno_error());
                        }
                        for path in &mount_target_dirs {
                            if libc::mkdir(path.as_ptr().cast(), 0o755) == -1
                                && child_errno_error().raw_os_error() != Some(libc::EEXIST)
                            {
                                return Err(child_errno_error());
                            }
                        }
                        for path in &mount_target_files {
                            let fd = libc::open(
                                path.as_ptr().cast(),
                                libc::O_CREAT | libc::O_WRONLY | libc::O_CLOEXEC,
                                0o644,
                            );
                            if fd == -1 {
                                return Err(child_errno_error());
                            }
                            libc::close(fd);
                        }
                    }
                    if let Some(root) = pivot_root.as_deref() {
                        if libc::mount(
                            c"tmpfs".as_ptr(),
                            root.as_ptr().cast(),
                            c"tmpfs".as_ptr(),
                            0,
                            std::ptr::null(),
                        ) == -1
                        {
                            return Err(child_errno_error());
                        }
                        if libc::chdir(root.as_ptr().cast()) == -1 {
                            return Err(child_errno_error());
                        }
                        for path in &mount_target_dirs {
                            if libc::mkdir(path.as_ptr().cast(), 0o755) == -1
                                && child_errno_error().raw_os_error() != Some(libc::EEXIST)
                            {
                                return Err(child_errno_error());
                            }
                        }
                        for path in &mount_target_files {
                            let fd = libc::open(
                                path.as_ptr().cast(),
                                libc::O_CREAT | libc::O_WRONLY | libc::O_CLOEXEC,
                                0o644,
                            );
                            if fd == -1 {
                                return Err(child_errno_error());
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
                            return Err(child_errno_error());
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
                            return Err(child_errno_error());
                        }
                    }
                    for (target, readonly) in proc_mounts.iter().filter(|_| !rootfs_tmpfs) {
                        let mut mount_flags = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
                        if *readonly {
                            mount_flags |= libc::MS_RDONLY;
                        }
                        if libc::mount(
                            c"proc".as_ptr(),
                            target.as_ptr().cast(),
                            c"proc".as_ptr(),
                            mount_flags as _,
                            std::ptr::null(),
                        ) == -1
                        {
                            return Err(child_errno_error());
                        }
                    }
                    for (target, data) in &tmpfs_mounts {
                        if libc::mount(
                            c"tmpfs".as_ptr(),
                            target.as_ptr().cast(),
                            c"tmpfs".as_ptr(),
                            (libc::MS_NOSUID | libc::MS_NODEV) as _,
                            data.as_ptr().cast(),
                        ) == -1
                        {
                            return Err(child_errno_error());
                        }
                    }
                    for (path, target) in &symlinks {
                        if libc::symlink(target.as_ptr().cast(), path.as_ptr().cast()) == -1 {
                            return Err(child_errno_error());
                        }
                    }
                    for path in mask_paths.iter().filter(|_| !rootfs_tmpfs) {
                        if libc::mount(
                            c"/dev/null".as_ptr(),
                            path.as_ptr().cast(),
                            c"".as_ptr().cast(),
                            libc::MS_BIND as _,
                            c"".as_ptr().cast(),
                        ) == -1
                        {
                            let errno = child_errno_error();
                            if errno.kind() == ErrorKind::NotFound {
                                continue;
                            }
                            if errno.raw_os_error() == Some(libc::ENOTDIR) {
                                if libc::mount(
                                    c"tmpfs".as_ptr(),
                                    path.as_ptr().cast(),
                                    c"tmpfs".as_ptr(),
                                    libc::MS_RDONLY as _,
                                    c"".as_ptr().cast(),
                                ) == -1
                                {
                                    return Err(child_errno_error());
                                }
                            } else {
                                return Err(errno);
                            }
                        }
                    }
                    if rootfs_tmpfs {
                        let Some(root) = root_mount.as_deref() else {
                            return Err(Error::from_raw_os_error(libc::EINVAL));
                        };
                        if libc::mount(
                            c"tmpfs".as_ptr(),
                            root.as_ptr().cast(),
                            c"tmpfs".as_ptr(),
                            (libc::MS_BIND
                                | libc::MS_REMOUNT
                                | libc::MS_RDONLY
                                | libc::MS_NOATIME
                                | libc::MS_NOSUID) as _,
                            c"".as_ptr().cast(),
                        ) == -1
                        {
                            return Err(child_errno_error());
                        }
                    }
                }
                if pivot_root.is_some() {
                    let old_root = c"old_root";
                    if libc::mkdir(old_root.as_ptr().cast(), 0o755) == -1 {
                        return Err(child_errno_error());
                    }
                    if libc::syscall(
                        libc::SYS_pivot_root,
                        c".".as_ptr(),
                        old_root.as_ptr().cast::<libc::c_char>(),
                    ) == -1
                    {
                        return Err(child_errno_error());
                    }
                    if libc::umount2(old_root.as_ptr().cast(), libc::MNT_DETACH) == -1 {
                        return Err(child_errno_error());
                    }
                    if libc::rmdir(old_root.as_ptr().cast()) == -1 {
                        return Err(child_errno_error());
                    }
                    if libc::mount(
                        c"tmpfs".as_ptr(),
                        c"/".as_ptr(),
                        c"tmpfs".as_ptr(),
                        (libc::MS_BIND
                            | libc::MS_REMOUNT
                            | libc::MS_RDONLY
                            | libc::MS_NOATIME
                            | libc::MS_NOSUID) as _,
                        std::ptr::null(),
                    ) == -1
                    {
                        return Err(child_errno_error());
                    }
                }
                if let Some(name) = hostname.as_deref()
                    && libc::sethostname(name.as_ptr().cast(), name.len() - 1) == -1
                {
                    return Err(child_errno_error());
                }
                if let Some(name) = domainname.as_deref()
                    && libc::setdomainname(name.as_ptr().cast(), name.len() - 1) == -1
                {
                    return Err(child_errno_error());
                }
                if pivot_root.is_some() {
                    if libc::chdir(c"/".as_ptr()) == -1 {
                        return Err(child_errno_error());
                    }
                    if work_dir.len() > 1 && libc::chdir(work_dir.as_ptr().cast()) == -1 {
                        return Err(child_errno_error());
                    }
                }
                // Chroot after namespace setup but before dropping the mapped
                // identity. This is needed when a child creates its own user
                // namespace and inherits a mount namespace owned by its
                // parent user namespace.
                if let Some(root) = container_root.as_deref() {
                    if libc::chroot(root.as_ptr().cast()) == -1 || libc::chdir(c"/".as_ptr()) == -1
                    {
                        return Err(child_errno_error());
                    }
                    if work_dir.len() > 1 && libc::chdir(work_dir.as_ptr().cast()) == -1 {
                        return Err(child_errno_error());
                    }
                }
                if let Some((uid, gid, groups, no_set_groups)) = uid.as_ref() {
                    if !no_set_groups && libc::setgroups(groups.len(), groups.as_ptr()) == -1 {
                        return Err(child_errno_error());
                    }
                    if libc::setgid(*gid) == -1 || libc::setuid(*uid) == -1 {
                        return Err(child_errno_error());
                    }
                }
                if libc::setsid() == -1 {
                    return Err(child_errno_error());
                }
                if let Some(fd) = sync_child_fd {
                    child_sync_with_parent(fd)?;
                }
                for (target, source) in fd_map.iter().enumerate() {
                    let target = i32::try_from(target)
                        .map_err(|_| Error::from_raw_os_error(libc::EINVAL))?;
                    if target != *source && libc::dup2(*source, target) == -1 {
                        return Err(child_errno_error());
                    }
                    if target == *source {
                        let flags = libc::fcntl(target, libc::F_GETFD);
                        if flags == -1
                            || libc::fcntl(target, libc::F_SETFD, flags & !libc::FD_CLOEXEC) == -1
                        {
                            return Err(child_errno_error());
                        }
                    }
                }
                // Descriptor remapping must happen before TIOCSCTTY so fd 0
                // refers to the PTY slave, not the server's original stdin.
                // setsid above makes this process the session leader first.
                if control_tty && libc::ioctl(0, libc::TIOCSCTTY as _, 1) == -1 {
                    return Err(child_errno_error());
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
                        return Err(child_errno_error());
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
                        return Err(child_errno_error());
                    }
                }
                if !helper_mode
                    && no_new_privs
                    && libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1
                {
                    return Err(child_errno_error());
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
                            return Err(child_errno_error());
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
                        return Err(child_errno_error());
                    }
                }
                if !helper_mode {
                    for filter in &seccomp {
                        seccompiler::apply_filter(filter)
                            .map_err(|_| Error::from_raw_os_error(libc::EINVAL))?;
                    }
                }
                Ok(())
            }
        };

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
        let vfork_eligible = use_vfork_path && sync_result.is_none();
        let spawn_result = if vfork_eligible {
            let mut attempt = 0;
            loop {
                match clone3_vfork(
                    &command,
                    &mut child_setup,
                    self.exec_file.map(|_| &self.args[0]),
                    (self.fd_map.len() as i32)
                        .max(255 + self.cgroup_procs_fds.len() as i32)
                        .max(3),
                    use_clone3,
                    clone3_cgroup_fd,
                    &cgroup_procs_skip,
                    self.cgroup_into_procs_index,
                ) {
                    Ok(child) => break Ok(child),
                    Err(error) if error.raw_os_error() == Some(libc::ETXTBSY) && attempt < 50 => {
                        attempt += 1;
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => break Err(error),
                }
            }
        } else {
            // Modes requiring parent coordination keep the established std
            // fork/exec handshake; only the independent fast path uses vfork.
            unsafe { command.pre_exec(child_setup) };
            let mut attempt = 0;
            loop {
                match command.spawn() {
                    Ok(child) => {
                        break Ok(Child {
                            process: ChildProcess::Standard(child),
                        });
                    }
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
