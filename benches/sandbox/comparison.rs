use super::prelude::*;

fn go_simplefork_runner(dev_null_fd: i32) -> Runner {
    Runner {
        args: vec![CString::new("/bin/echo").unwrap()],
        env: vec![CString::new("PATH=/bin").unwrap()],
        work_dir: CString::new("/bin").unwrap(),
        container_root: None,
        bind_mounts: vec![],
        proc_mounts: vec![],
        tmpfs_mounts: vec![],
        rootfs_tmpfs: false,
        symlinks: vec![],
        mask_paths: vec![],
        fd_map: vec![dev_null_fd; 3],
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
        seccomp: Default::default(),
        drop_caps: false,
        unshare_cgroup_after_sync: false,
        control_tty: false,
    }
}

pub(crate) fn forkexec_true(c: &mut Criterion) {
    let mut group = c.benchmark_group("forkexec/bin_true");
    group.bench_function("std_command", |b| {
        b.iter(|| {
            let status = std::process::Command::new("/bin/true")
                .env_clear()
                .status()
                .unwrap();
            assert!(status.success());
            black_box(status);
        });
    });
    group.bench_function("std_command_noop_pre_exec", |b| {
        b.iter(|| {
            let mut command = std::process::Command::new("/bin/true");
            // Registering even an empty hook measures the std fork fallback
            // used by Runner's parent-coordinated launch modes.
            unsafe { command.pre_exec(|| Ok(())) };
            let status = command.env_clear().status().unwrap();
            assert!(status.success());
            black_box(status);
        });
    });
    group.bench_function("runner_clone3_vfork", |b| {
        b.iter(|| {
            let mut runner = Runner {
                args: vec![CString::new("/bin/true").unwrap()],
                env: vec![],
                work_dir: CString::new("").unwrap(),
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
                seccomp: Default::default(),
                drop_caps: false,
                unshare_cgroup_after_sync: false,
                control_tty: false,
            };
            let status = runner.start().unwrap().wait().unwrap();
            assert!(status.success());
            black_box(status);
        });
    });
    // Go's BenchmarkSimpleFork builds its Runner once before timing. Keep a
    // corresponding Rust case so per-request Runner construction does not get
    // conflated with the fork/exec and child setup path.
    let mut reused_runner = Runner {
        args: vec![CString::new("/bin/true").unwrap()],
        env: vec![],
        work_dir: CString::new("").unwrap(),
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
        seccomp: Default::default(),
        drop_caps: false,
        unshare_cgroup_after_sync: false,
        control_tty: false,
    };
    group.bench_function("runner_clone3_vfork_reused_config", |b| {
        b.iter(|| {
            let status = reused_runner.start().unwrap().wait().unwrap();
            assert!(status.success());
            black_box(status);
        });
    });
    let null = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .unwrap();
    let mut go_runner = go_simplefork_runner(null.as_raw_fd());
    group.bench_function("go_simplefork_matched", |b| {
        b.iter(|| {
            let status = go_runner.start().unwrap().wait().unwrap();
            assert!(status.success());
            black_box(status);
        });
    });
    group.bench_function("runner_fork_parent_sync_callback", |b| {
        b.iter(|| {
            let mut runner = Runner {
                args: vec![CString::new("/bin/true").unwrap()],
                env: vec![],
                work_dir: CString::new("").unwrap(),
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
                sync_fn: Some(Box::new(|pid| {
                    if pid > 0 {
                        Ok(())
                    } else {
                        Err(io::Error::other("invalid child PID"))
                    }
                })),
                clone_flags: 0,
                credential: None,
                uid_map: None,
                gid_map: None,
                gid_map_enable_set_groups: false,
                no_new_privs: false,
                seccomp: Default::default(),
                drop_caps: false,
                unshare_cgroup_after_sync: false,
                control_tty: false,
            };
            let status = runner.start().unwrap().wait().unwrap();
            assert!(status.success());
            black_box(status);
        });
    });
    group.finish();
}
