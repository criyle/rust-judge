use super::*;
use std::fs::OpenOptions;

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
        cgroup_into_fd: None,
        cgroup_into_procs_index: None,
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
        cgroup_into_fd: None,
        cgroup_into_procs_index: None,
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
fn resolves_program_names_using_the_command_path() {
    let mut runner = runner(&["sh", "-c", "test \"$PATH\" = /usr/bin:/bin"]);
    runner.env = vec![c("PATH=/usr/bin:/bin")];
    let original_cwd = std::env::current_dir().unwrap();
    runner.work_dir = c("/tmp");
    assert!(runner.start().unwrap().wait().unwrap().success());
    assert_eq!(std::env::current_dir().unwrap(), original_cwd);
}

#[test]
fn clone3_places_a_child_in_the_requested_cgroup_when_available() {
    let Ok(self_cgroup) = std::fs::read_to_string("/proc/self/cgroup") else {
        return;
    };
    let Some(relative_path) = self_cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
    else {
        return;
    };
    let directory_path =
        std::path::Path::new("/sys/fs/cgroup").join(relative_path.trim_start_matches('/'));
    use std::os::unix::fs::OpenOptionsExt;
    let Ok(directory) = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(&directory_path)
    else {
        return;
    };
    let Ok(procs) = OpenOptions::new()
        .write(true)
        .open(directory_path.join("cgroup.procs"))
    else {
        return;
    };
    let mut runner = runner(&["/bin/sleep", "0.2"]);
    runner.cgroup_into_fd = Some(directory.as_raw_fd());
    runner.cgroup_into_procs_index = Some(0);
    runner.cgroup_procs_fds = vec![procs.as_raw_fd()];
    let mut child = runner.start().unwrap();
    let child_cgroup = std::fs::read_to_string(format!("/proc/{}/cgroup", child.id())).unwrap();
    assert!(
        child_cgroup
            .lines()
            .any(|line| line == format!("0::{relative_path}"))
    );
    assert!(child.wait().unwrap().success());
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
        cgroup_into_fd: None,
        cgroup_into_procs_index: None,
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
