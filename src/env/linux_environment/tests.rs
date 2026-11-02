use super::*;
use crate::worker::EnvironmentPool;
use std::os::fd::FromRawFd;
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicU64, Ordering};

#[test]
fn go_judge_execution_cgroup_is_sibling_to_api_group() {
    assert_eq!(
        default_cgroup_v2_root("service.scope").unwrap(),
        PathBuf::from("/sys/fs/cgroup/service.scope/containers")
    );
    assert!(default_cgroup_v2_root("../escape").is_err());
}

#[test]
fn parses_proc_vm_hwm_as_peak_rss_bytes() {
    assert_eq!(
        parse_vm_hwm_bytes("Name:\tworker\nVmRSS:\t4096 kB\nVmHWM:\t8192 kB\n"),
        8 * 1024 * 1024
    );
    assert_eq!(parse_vm_hwm_bytes("Name:\tworker\nVmHWM:\tbad kB\n"), 0);
    assert_eq!(parse_vm_hwm_bytes("Name:\tworker\n"), 0);
}

#[test]
fn exit_signals_map_to_go_runner_statuses() {
    use std::os::unix::process::ExitStatusExt;
    for (signal, expected) in [
        (libc::SIGXCPU, Status::TimeLimitExceeded),
        (libc::SIGKILL, Status::TimeLimitExceeded),
        (libc::SIGXFSZ, Status::OutputLimitExceeded),
        (libc::SIGSYS, Status::DisallowedSyscall),
        (libc::SIGTERM, Status::Signalled),
    ] {
        assert_eq!(
            result_from_exit_status(std::process::ExitStatus::from_raw(signal)),
            (expected, signal)
        );
    }
}

#[test]
fn executable_lookup_uses_container_environment_path() {
    let root =
        std::env::temp_dir().join(format!("rust-sandbox-path-lookup-{}", std::process::id()));
    let bin = root.join("usr/bin");
    fs::create_dir_all(&bin).unwrap();
    let executable = bin.join("tool");
    fs::write(&executable, b"#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
    let root_file = fs::File::open(&root).unwrap();

    assert_eq!(
        lookup_container_executable(&root_file, "/w", "tool", &["PATH=/usr/bin".to_owned()])
            .unwrap(),
        "/usr/bin/tool"
    );
    let error = lookup_container_executable(&root_file, "/w", "tool", &[]).unwrap_err();
    assert_eq!(
        error.to_string(),
        "no PATH environment variable provided for look up"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn dotenv_lines_match_go_container_defaults() {
    let path = std::env::temp_dir().join(format!(
        "rust-sandbox-dotenv-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::write(&path, "# comment\n\nFOO=bar\nPATH=/usr/bin:/bin\n").unwrap();
    assert_eq!(
        read_dotenv(path.to_str().unwrap()).unwrap(),
        ["FOO=bar", "PATH=/usr/bin:/bin"]
    );
    fs::write(&path, "invalid-line\n").unwrap();
    assert!(read_dotenv(path.to_str().unwrap()).is_err());
    fs::remove_file(path).unwrap();
}

#[test]
fn only_anonymous_pipes_are_reowned_as_stdio_descriptors() {
    let mut pipe_fds = [-1; 2];
    assert_eq!(
        unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    let pipe = unsafe { fs::File::from_raw_fd(pipe_fds[0]) };
    let pipe_writer = unsafe { fs::File::from_raw_fd(pipe_fds[1]) };
    assert!(is_anonymous_pipe(pipe.as_raw_fd()).unwrap());
    chown_fd(pipe.as_raw_fd(), unsafe { libc::getuid() }, unsafe {
        libc::getgid()
    })
    .unwrap();

    let ordinary_path =
        std::env::temp_dir().join(format!("rust-sandbox-ordinary-fd-{}", std::process::id()));
    let ordinary = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&ordinary_path)
        .unwrap();
    assert!(!is_anonymous_pipe(ordinary.as_raw_fd()).unwrap());
    fs::remove_file(ordinary_path).unwrap();
    drop(pipe_writer);
}

#[test]
fn opened_container_files_keep_init_owner_and_go_creation_mode() {
    let helper = find_container_init().unwrap();
    unsafe { std::env::set_var("RUST_SANDBOX_CONTAINER_INIT", &helper) };
    let env = LinuxEnvironment::build(config()).unwrap();
    let opened = env
        .open(&[OpenParam {
            path: "w/stdout".into(),
            flag: 1 | 64 | 512,
            perm: 0o777,
            mkdir_all: true,
        }])
        .unwrap();
    let file = opened[0].file.as_ref().unwrap();
    let metadata = file.metadata().unwrap();
    assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
    assert_eq!(metadata.gid(), unsafe { libc::getegid() });
    assert_eq!(metadata.permissions().mode() & 0o777, 0o777);

    let restricted = env
        .open(&[OpenParam {
            path: "w/restricted".into(),
            flag: libc::O_WRONLY | libc::O_CREAT,
            perm: 0o600,
            mkdir_all: true,
        }])
        .unwrap();
    drop(restricted);
    let reopened = env
        .open(&[OpenParam {
            path: "w/restricted".into(),
            flag: libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            perm: 0o777,
            mkdir_all: false,
        }])
        .unwrap();
    let metadata = reopened[0].file.as_ref().unwrap().metadata().unwrap();
    assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
    assert_eq!(metadata.gid(), unsafe { libc::getegid() });
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
}

#[test]
fn container_init_path_override_is_used_and_validated() {
    let path =
        std::env::temp_dir().join(format!("rust-sandbox-custom-init-{}", std::process::id()));
    fs::write(&path, b"test helper").unwrap();
    let config = LinuxEnvironmentConfig {
        container_init_path: Some(path.clone()),
        ..LinuxEnvironmentConfig::default()
    };
    assert_eq!(container_init_source(&config).unwrap(), Some(path.clone()));
    fs::remove_file(&path).unwrap();

    let missing = LinuxEnvironmentConfig {
        container_init_path: Some(path.clone()),
        ..LinuxEnvironmentConfig::default()
    };
    assert_eq!(
        container_init_source(&missing).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
}

#[test]
fn production_container_init_defaults_to_the_current_executable() {
    // Go uses /proc/self/exe, independent of the executable's filename.
    let executable = Path::new("/opt/bin/rust-judge-custom-name");
    assert_eq!(resolve_container_init(executable), executable);
}

fn config() -> LinuxEnvironmentConfig {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let parent = std::env::temp_dir().join(format!(
        "rust-sandbox-env-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    LinuxEnvironmentConfig {
        root_parent: parent,
        no_seccomp: true,
        ..LinuxEnvironmentConfig::default()
    }
}

fn execute(env: &LinuxEnvironment, script: &str) -> ResultInfo {
    let process = env
        .execve(ExecveParam {
            args: vec!["/bin/sh".into(), "-c".into(), script.into()],
            env: vec!["PATH=/usr/bin:/bin".into()],
            ..Default::default()
        })
        .unwrap();
    process.result()
}

#[test]
fn reuses_pid_mount_and_user_namespaces_across_commands() {
    let helper = find_container_init().unwrap();
    unsafe { std::env::set_var("RUST_SANDBOX_CONTAINER_INIT", &helper) };
    let env = LinuxEnvironment::build(config()).unwrap();
    let first = execute(
        &env,
        "readlink /proc/self/ns/pid > /w/pidns-id; readlink /proc/self/ns/user > /w/userns-id",
    );
    assert_eq!(first.status, Status::Normal, "{first:?}");
    let keeper_pid = env.keeper.lock().unwrap().as_ref().unwrap().pid;
    let second = execute(
        &env,
        "test \"$(readlink /proc/self/ns/pid)\" = \"$(cat /w/pidns-id)\" && test \"$(readlink /proc/self/ns/user)\" = \"$(cat /w/userns-id)\"",
    );
    assert_eq!(second.status, Status::Normal, "{second:?}");
    assert_eq!(env.keeper.lock().unwrap().as_ref().unwrap().pid, keeper_pid);
}

#[test]
fn workload_with_configured_credential_maps_host_identity() {
    let helper = find_container_init().unwrap();
    unsafe { std::env::set_var("RUST_SANDBOX_CONTAINER_INIT", &helper) };
    let env = LinuxEnvironment::build(config()).unwrap();
    let host_uid = unsafe { libc::geteuid() };
    let host_gid = unsafe { libc::getegid() };
    let container_uid = env.uid.unwrap_or(0);
    let container_gid = env.gid.unwrap_or(0);
    for (description, script) in [
        (
            "effective UID",
            format!("test \"$(id -u)\" = {container_uid}"),
        ),
        (
            "effective GID",
            format!("test \"$(id -g)\" = {container_gid}"),
        ),
        (
            "UID mapping",
            format!(
                "set -- $(cat /proc/self/uid_map); test \"$1\" = {container_uid} && test \"$2\" = {host_uid} && test \"$3\" = 1"
            ),
        ),
        (
            "GID mapping",
            format!(
                "set -- $(cat /proc/self/gid_map); test \"$1\" = {container_gid} && test \"$2\" = {host_gid} && test \"$3\" = 1"
            ),
        ),
    ] {
        let result = execute(&env, &script);
        assert_eq!(result.status, Status::Normal, "{description}: {result:?}");
    }
}

#[test]
fn workload_with_root_credential_maps_root_to_host_identity() {
    let helper = find_container_init().unwrap();
    unsafe { std::env::set_var("RUST_SANDBOX_CONTAINER_INIT", &helper) };
    let mut cfg = config();
    cfg.uid = 0;
    cfg.gid = 0;
    let env = LinuxEnvironment::build(cfg).unwrap();
    let host_uid = unsafe { libc::geteuid() };
    let host_gid = unsafe { libc::getegid() };
    let result = execute(
        &env,
        &format!(
            "test \"$(id -u)\" = 0 && test \"$(id -g)\" = 0 && set -- $(cat /proc/self/uid_map); test \"$1\" = 0 && test \"$2\" = {host_uid} && test \"$3\" = 1 && set -- $(cat /proc/self/gid_map); test \"$1\" = 0 && test \"$2\" = {host_gid} && test \"$3\" = 1"
        ),
    );
    assert_eq!(result.status, Status::Normal, "{result:?}");
}

#[test]
fn generated_container_credential_maps_root_and_workload_ids() {
    let helper = find_container_init().unwrap();
    unsafe { std::env::set_var("RUST_SANDBOX_CONTAINER_INIT", &helper) };
    let mut cfg = config();
    cfg.uid = 1000;
    cfg.gid = 1000;
    cfg.container_cred_start = Some(1000);
    cfg.host_credential_id = Some(1001);
    let env = LinuxEnvironment::build(cfg).unwrap();
    let host_uid = unsafe { libc::geteuid() };
    let host_gid = unsafe { libc::getegid() };
    let result = execute(
        &env,
        &format!(
            "test \"$(id -u)\" = 1000 && test \"$(id -g)\" = 1000 \
                 && set -- $(cat /proc/self/uid_map) \
                 && test \"$1 $2 $3\" = \"0 {host_uid} 1\" \
                 && set -- $(sed -n '2p' /proc/self/uid_map) \
                 && test \"$1 $2 $3\" = \"1000 1001 1\" \
                 && set -- $(cat /proc/self/gid_map) \
                 && test \"$1 $2 $3\" = \"0 {host_gid} 1\" \
                 && set -- $(sed -n '2p' /proc/self/gid_map) \
                 && test \"$1 $2 $3\" = \"1000 1001 1\""
        ),
    );
    assert_eq!(result.status, Status::Normal, "{result:?}");
}

#[test]
fn generated_container_credential_can_reopen_mapped_pipe() {
    use std::os::fd::{FromRawFd, OwnedFd};

    let helper = find_container_init().unwrap();
    unsafe { std::env::set_var("RUST_SANDBOX_CONTAINER_INIT", &helper) };
    let mut cfg = config();
    cfg.uid = 1000;
    cfg.gid = 1000;
    cfg.container_cred_start = Some(1000);
    cfg.host_credential_id = Some(1001);
    let env = LinuxEnvironment::build(cfg).unwrap();
    let mut fds = [-1; 2];
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    let mut pipe_read = unsafe { fs::File::from(OwnedFd::from_raw_fd(fds[0])) };
    let pipe_write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    let null = fs::File::open("/dev/null").unwrap();
    let process = env
        .execve(ExecveParam {
            args: vec![
                "/bin/sh".into(),
                "-c".into(),
                "printf pipe-ok > /dev/stdout".into(),
            ],
            env: vec!["PATH=/usr/bin:/bin".into()],
            files: vec![
                null.as_raw_fd() as u64,
                pipe_write.as_raw_fd() as u64,
                null.as_raw_fd() as u64,
            ],
            ..Default::default()
        })
        .unwrap();
    let result = process.result();
    drop(pipe_write);
    assert_eq!(result.status, Status::Normal, "{result:?}");
    let mut output = String::new();
    std::io::Read::read_to_string(&mut pipe_read, &mut output).unwrap();
    assert_eq!(output, "pipe-ok");
}

#[test]
fn environment_pool_allocates_distinct_generated_host_ids() {
    let mut cfg = config();
    cfg.uid = 1000;
    cfg.gid = 1000;
    cfg.container_cred_start = Some(1000);
    let pool = LinuxEnvironmentPool::new(cfg).unwrap();
    let first = crate::worker::EnvironmentPool::get(&pool).unwrap();
    let second = crate::worker::EnvironmentPool::get(&pool).unwrap();
    let mut ids = pool
        .leased
        .lock()
        .unwrap()
        .values()
        .filter_map(|environment| environment.upgrade())
        .map(|environment| environment.host_credential_id.unwrap())
        .collect::<Vec<_>>();
    ids.sort_unstable();
    assert_eq!(ids, [1001, 1002]);
    drop(first);
    drop(second);
}

#[test]
fn runs_concurrent_commands_in_the_shared_namespace() {
    let helper = find_container_init().unwrap();
    unsafe { std::env::set_var("RUST_SANDBOX_CONTAINER_INIT", &helper) };
    let env = LinuxEnvironment::build(config()).unwrap();
    let first = env
        .execve(ExecveParam {
            args: vec![
                "/bin/sh".into(),
                "-c".into(),
                "sleep 0.03; test -d /proc/1".into(),
            ],
            env: vec!["PATH=/usr/bin:/bin".into()],
            ..Default::default()
        })
        .unwrap();
    let second = env
        .execve(ExecveParam {
            args: vec![
                "/bin/sh".into(),
                "-c".into(),
                "sleep 0.03; test -d /proc/1".into(),
            ],
            env: vec!["PATH=/usr/bin:/bin".into()],
            ..Default::default()
        })
        .unwrap();
    let first = first.result();
    let second = second.result();
    assert_eq!(first.status, Status::Normal, "{first:?}");
    assert_eq!(second.status, Status::Normal, "{second:?}");
}

#[test]
fn cancelling_one_command_does_not_kill_another_commands_group() {
    let helper = find_container_init().unwrap();
    unsafe { std::env::set_var("RUST_SANDBOX_CONTAINER_INIT", &helper) };
    let env = LinuxEnvironment::build(config()).unwrap();
    let canceled = env
        .execve(ExecveParam {
            args: vec!["/bin/sh".into(), "-c".into(), "sleep 5".into()],
            env: vec!["PATH=/usr/bin:/bin".into()],
            ..Default::default()
        })
        .unwrap();
    canceled.cancel();
    let canceled_result = canceled.result();
    let surviving = env
        .execve(ExecveParam {
            args: vec!["/bin/sh".into(), "-c".into(), "sleep 0.03; exit 0".into()],
            env: vec!["PATH=/usr/bin:/bin".into()],
            ..Default::default()
        })
        .unwrap();
    let surviving_result = surviving.result();
    assert_eq!(
        canceled_result.status,
        // The container result protocol classifies SIGKILL as a time
        // limit, matching go-sandbox's convertReply behavior.
        Status::TimeLimitExceeded,
        "{canceled_result:?}"
    );
    assert_eq!(
        surviving_result.status,
        Status::Normal,
        "{surviving_result:?}"
    );
}

#[test]
fn applies_custom_mount_metadata_and_relative_sources() {
    let cwd = std::env::current_dir().unwrap();
    let source_name = format!("custom-passwd-{}", std::process::id());
    let source = cwd.join(&source_name);
    fs::write(&source, "sandbox:x:1536:1536::/w:/bin/sh\n").unwrap();
    let mut config = config();
    config.mount_config = Some(crate::env::MountConfig {
        mounts: vec![crate::env::Mount {
            kind: "bind".into(),
            source: source_name,
            target: "/etc/passwd".into(),
            readonly: true,
            data: String::new(),
        }],
        symlinks: vec![crate::env::Link {
            link_path: "/dev/fd".into(),
            target: "/proc/self/fd".into(),
        }],
        work_dir: "/work".into(),
        uid: 1536,
        gid: 1536,
        ..Default::default()
    });
    let env = LinuxEnvironment::build(config).unwrap();
    assert_eq!(env.uid, Some(0));
    assert_eq!(env.gid, Some(0));
    assert_eq!(env.work_dir, "/work");
    assert!(env.mounts.iter().any(|mount| {
        mount.source.to_string_lossy() == source.to_string_lossy()
            && mount.target.to_string_lossy().ends_with("/etc/passwd")
    }));
    assert!(
        env.root
            .join("dev/fd")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink()
    );
    fs::remove_file(source).unwrap();
}

#[test]
fn opens_follow_chrooted_symlinks_without_escaping_environment_root() {
    let env = LinuxEnvironment::build(config()).unwrap();
    let results = env
        .open(&[OpenParam {
            path: "/w/nested/data.txt".into(),
            flag: libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            perm: 0o644,
            mkdir_all: true,
        }])
        .unwrap();
    assert!(results[0].error.is_none());
    assert!(results[0].file.is_some());
    let relative = env
        .open(&[OpenParam {
            path: "relative.txt".into(),
            flag: libc::O_WRONLY | libc::O_CREAT,
            perm: 0o644,
            mkdir_all: false,
        }])
        .unwrap();
    assert!(relative[0].error.is_none());
    let read_write_without_create = env
        .open(&[OpenParam {
            path: "/w/relative.txt".into(),
            flag: libc::O_RDWR,
            perm: 0o777,
            mkdir_all: false,
        }])
        .unwrap();
    assert!(read_write_without_create[0].error.is_none());
    let parent_segments = env
        .open(&[OpenParam {
            path: "../../w/relative.txt".into(),
            flag: libc::O_RDONLY,
            perm: 0,
            mkdir_all: false,
        }])
        .unwrap();
    assert!(parent_segments[0].error.is_none());
    assert_eq!(
        env.symlink(&[SymlinkParam {
            link_path: "/w/link".into(),
            target: "nested/data.txt".into(),
        }])
        .unwrap(),
        [None]
    );
    let missing_parent = env
        .symlink(&[SymlinkParam {
            link_path: "/w/missing-parent/link".into(),
            target: "target".into(),
        }])
        .unwrap();
    assert!(
        missing_parent[0].is_some(),
        "Go Symlink does not mkdir parents"
    );
    let symlink_exists = execute(&env, "test -L /w/link");
    assert_eq!(symlink_exists.status, Status::Normal, "{symlink_exists:?}");
    assert!(
        env.open(&[OpenParam {
            path: "/w/link".into(),
            flag: libc::O_RDONLY,
            perm: 0,
            mkdir_all: false,
        }])
        .unwrap()[0]
            .error
            .is_some()
    );

    let target_dir = env
        .open(&[OpenParam {
            path: "/w/target-dir/seed".into(),
            flag: libc::O_WRONLY | libc::O_CREAT,
            perm: 0o644,
            mkdir_all: true,
        }])
        .unwrap();
    assert!(target_dir[0].error.is_none());
    let root = env.namespace_root().unwrap();
    let created_dir = open_directory_at(&root, Path::new("w/target-dir"), false).unwrap();
    assert_eq!(
        created_dir.metadata().unwrap().permissions().mode() & 0o777,
        0o777
    );
    let target_subdir = env
        .open(&[OpenParam {
            path: "/w/target-dir/subdir/marker".into(),
            flag: libc::O_WRONLY | libc::O_CREAT,
            perm: 0o644,
            mkdir_all: true,
        }])
        .unwrap();
    assert!(target_subdir[0].error.is_none());
    assert_eq!(
        env.symlink(&[SymlinkParam {
            link_path: "/w/escape".into(),
            target: "/w/target-dir/subdir".into(),
        }])
        .unwrap(),
        [None]
    );
    assert!(
        env.open(&[OpenParam {
            path: "escape/marker".into(),
            flag: libc::O_RDONLY,
            perm: 0,
            mkdir_all: false,
        }])
        .unwrap()[0]
            .error
            .is_none()
    );
    assert!(
        env.open(&[OpenParam {
            path: "/w/escape/../seed".into(),
            flag: libc::O_RDONLY,
            perm: 0,
            mkdir_all: false,
        }])
        .unwrap()[0]
            .error
            .is_none()
    );
    assert_eq!(
        env.symlink(&[SymlinkParam {
            link_path: "/w/dir-link".into(),
            target: "/w/target-dir".into(),
        }])
        .unwrap(),
        [None]
    );
    let through_directory_link = env
        .open(&[OpenParam {
            path: "/w/dir-link/new/file".into(),
            flag: libc::O_WRONLY | libc::O_CREAT,
            perm: 0o644,
            mkdir_all: true,
        }])
        .unwrap();
    assert!(through_directory_link[0].error.is_none());
    assert!(
        env.open(&[OpenParam {
            path: "/proc/1/root/etc/passwd".into(),
            flag: libc::O_RDONLY,
            perm: 0,
            mkdir_all: false,
        }])
        .unwrap()[0]
            .error
            .is_some()
    );
}

#[test]
fn host_file_open_sees_tmpfs_and_reset_clears_it() {
    let env = LinuxEnvironment::build(config()).unwrap();
    for path in ["/tmp/rust-sandbox-open-test", "/w/rust-sandbox-open-test"] {
        let mut opened = env
            .open(&[OpenParam {
                path: path.into(),
                flag: libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                perm: 0o644,
                mkdir_all: true,
            }])
            .unwrap()
            .remove(0)
            .file
            .unwrap();
        std::io::Write::write_all(&mut opened, b"visible-in-tmpfs").unwrap();
        drop(opened);
    }

    let visible = execute(
        &env,
        "test \"$(cat /tmp/rust-sandbox-open-test)\" = visible-in-tmpfs && test \"$(cat /w/rust-sandbox-open-test)\" = visible-in-tmpfs",
    );
    assert_eq!(visible.status, Status::Normal, "{visible:?}");

    env.reset().unwrap();
    let cleared = execute(
        &env,
        "test ! -e /tmp/rust-sandbox-open-test && test ! -e /w/rust-sandbox-open-test",
    );
    assert_eq!(cleared.status, Status::Normal, "{cleared:?}");
}

#[test]
fn reset_clears_every_configured_tmpfs_mount() {
    let mut config = config();
    let mounts = ["/bin", "/lib", "/lib64", "/usr"]
        .into_iter()
        .map(|source| crate::env::Mount {
            kind: "bind".into(),
            source: source.into(),
            target: source.into(),
            ..Default::default()
        })
        .chain(std::iter::once(crate::env::Mount {
            kind: "tmpfs".into(),
            target: "/cache".into(),
            data: "size=8m".into(),
            ..Default::default()
        }))
        .collect();
    config.mount_config = Some(crate::env::MountConfig {
        mounts,
        work_dir: "/w".into(),
        proc: true,
        ..Default::default()
    });
    let env = LinuxEnvironment::build(config).unwrap();

    let created = execute(
        &env,
        "mkdir -p /cache && printf stale >/cache/request-marker",
    );
    assert_eq!(created.status, Status::Normal, "{created:?}");
    let visible = execute(&env, "test -s /cache/request-marker");
    assert_eq!(visible.status, Status::Normal, "{visible:?}");

    env.reset().unwrap();
    let cleared = execute(&env, "test ! -e /cache/request-marker");
    assert_eq!(cleared.status, Status::Normal, "{cleared:?}");
}

#[test]
fn workload_inherits_dotenv_and_resolves_path_from_container_environment() {
    let dotenv = std::env::temp_dir().join(format!(
        "rust-sandbox-container-dotenv-{}",
        std::process::id()
    ));
    fs::write(
        &dotenv,
        "RUST_SANDBOX_TEST_ENV=loaded\nPATH=/usr/bin:/bin\n",
    )
    .unwrap();
    let mut config = config();
    let mounts = ["/bin", "/lib", "/lib64", "/usr"]
        .into_iter()
        .map(|source| crate::env::Mount {
            kind: "bind".into(),
            source: source.into(),
            target: source.into(),
            ..Default::default()
        })
        .chain(std::iter::once(crate::env::Mount {
            kind: "bind".into(),
            source: dotenv.to_string_lossy().into_owned(),
            target: "/.env".into(),
            ..Default::default()
        }))
        .collect();
    config.mount_config = Some(crate::env::MountConfig {
        mounts,
        work_dir: "/w".into(),
        proc: true,
        ..Default::default()
    });
    let env = LinuxEnvironment::build(config).unwrap();
    let process = env
        .execve(ExecveParam {
            args: vec![
                "sh".into(),
                "-c".into(),
                "test \"$RUST_SANDBOX_TEST_ENV\" = loaded".into(),
            ],
            ..Default::default()
        })
        .unwrap();
    let result = process.result();
    assert_eq!(result.status, Status::Normal, "{result:?}");
    fs::remove_file(dotenv).unwrap();
}

#[test]
fn mount_config_init_command_runs_once_before_workload_startup() {
    let mut config = config();
    config.mount_config = Some(crate::env::MountConfig {
            init_cmd: "/bin/sh -c 'id -u > /tmp/init-uid; pwd > /tmp/init-cwd; printf %s \"$PATH\" > /tmp/init-path; touch /tmp/init-marker'".into(),
            ..Default::default()
        });
    let env = LinuxEnvironment::build(config).unwrap();
    let result = execute(
        &env,
        "test \"$(cat /tmp/init-uid)\" = 0 && test \"$(cat /tmp/init-cwd)\" = /w && test \"$(cat /tmp/init-path)\" = /usr/local/bin:/usr/bin:/bin && test -e /tmp/init-marker",
    );
    assert_eq!(result.status, Status::Normal, "{result:?}");
    let second = execute(&env, "test -e /tmp/init-marker");
    assert_eq!(second.status, Status::Normal, "{second:?}");
}

#[test]
fn failed_mount_config_init_command_aborts_keeper_startup() {
    let mut config = config();
    config.mount_config = Some(crate::env::MountConfig {
        init_cmd: "/bin/sh -c 'printf init-failed; exit 7'".into(),
        ..Default::default()
    });
    let env = LinuxEnvironment::build(config).unwrap();
    let error = env.ensure_keeper().unwrap_err();
    assert!(error.to_string().contains("init command failed"), "{error}");
    assert!(error.to_string().contains("init-failed"), "{error}");
}

#[test]
fn pool_reuses_reset_environment_and_drops_root_on_shutdown() {
    let config = config();
    let pool = LinuxEnvironmentPool::new(config.clone()).unwrap();
    let env = pool.get().unwrap();
    assert_eq!(env.open(&[]).unwrap().len(), 0);
    pool.put(env);
    assert_eq!(fs::read_dir(&config.root_parent).unwrap().count(), 1);
    let keeper_pid = pool.idle.lock().unwrap()[0]
        .keeper
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .pid;
    drop(pool);
    let roots = fs::read_dir(&config.root_parent).unwrap().count();
    assert_eq!(roots, 0);
    let keeper_path = PathBuf::from(format!("/proc/{keeper_pid}"));
    let deadline = Instant::now() + Duration::from_secs(1);
    while keeper_path.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(!keeper_path.exists(), "namespace init {keeper_pid} leaked");
    fs::remove_dir(config.root_parent).unwrap();
}

#[test]
fn starts_shell_as_pid_one_with_private_procfs_when_helper_is_built() {
    let Ok(helper) = find_container_init() else {
        return;
    };
    unsafe { std::env::set_var("RUST_SANDBOX_CONTAINER_INIT", &helper) };
    let env = LinuxEnvironment::build(config()).unwrap();
    let process = env
        .execve(ExecveParam {
            args: vec![
                "/bin/sh".into(),
                "-c".into(),
                "test $$ -eq 2 && test -e /proc/self/fd/1 && test -e /dev/stdout".into(),
            ],
            env: vec!["PATH=/usr/bin:/bin".into()],
            ..Default::default()
        })
        .unwrap();
    while !process.done() {
        thread::sleep(Duration::from_millis(5));
    }
    let result = process.result();
    assert_eq!(result.status, Status::Normal, "{result:?}");
}

#[test]
fn rootfs_is_tmpfs_readonly_with_writable_workdir_and_masked_files() {
    let Ok(helper) = find_container_init() else {
        return;
    };
    unsafe { std::env::set_var("RUST_SANDBOX_CONTAINER_INIT", &helper) };
    let mut config = config();
    let mounts = [
        "/bin",
        "/lib",
        "/lib64",
        "/usr",
        "/dev/null",
        "/etc/hostname",
    ]
    .into_iter()
    .map(|source| crate::env::Mount {
        kind: "bind".into(),
        source: source.into(),
        target: source.into(),
        readonly: false,
        data: String::new(),
    })
    .collect();
    config.mount_config = Some(crate::env::MountConfig {
        mounts,
        mask_paths: vec!["/proc/kcore".into()],
        work_dir: "/w".into(),
        proc: true,
        proc_rw: false,
        ..Default::default()
    });
    let env = LinuxEnvironment::build(config).unwrap();
    let result = execute(
        &env,
        "test \"$(stat -f -c %T /)\" = tmpfs && ! touch /rootfs-readonly 2>/dev/null && touch /w/workdir-writable && grep ' /proc ' /proc/self/mountinfo | grep -q ' ro[, ]' && test -r /proc/kcore && test ! -s /proc/kcore",
    );
    assert_eq!(result.status, Status::Normal, "{result:?}");
}

#[test]
fn configured_rw_proc_mount_survives_pid_namespace_startup() {
    let Ok(helper) = find_container_init() else {
        return;
    };
    unsafe { std::env::set_var("RUST_SANDBOX_CONTAINER_INIT", &helper) };
    let mut config = config();
    let mounts = ["/bin", "/lib", "/lib64", "/usr"]
        .into_iter()
        .map(|source| crate::env::Mount {
            kind: "bind".into(),
            source: source.into(),
            target: source.into(),
            readonly: false,
            data: String::new(),
        })
        .collect();
    config.mount_config = Some(crate::env::MountConfig {
        mounts,
        work_dir: "/w".into(),
        proc: true,
        proc_rw: true,
        ..Default::default()
    });
    let env = LinuxEnvironment::build(config).unwrap();
    let result = execute(
        &env,
        "grep ' /proc ' /proc/self/mountinfo | grep -q ' rw[, ]'",
    );
    assert_eq!(result.status, Status::Normal, "{result:?}");
}

#[test]
fn pid_one_ignores_sigint_without_signalling_workload() {
    let Ok(helper) = find_container_init() else {
        return;
    };
    unsafe { std::env::set_var("RUST_SANDBOX_CONTAINER_INIT", &helper) };
    let env = LinuxEnvironment::build(config()).unwrap();
    let process = env
        .execve(ExecveParam {
            args: vec![
                "/bin/sh".into(),
                "-c".into(),
                "kill -INT 1; test $? -eq 0".into(),
            ],
            env: vec!["PATH=/usr/bin:/bin".into()],
            ..Default::default()
        })
        .unwrap();
    while !process.done() {
        thread::sleep(Duration::from_millis(5));
    }
    let result = process.result();
    assert_eq!(result.status, Status::Normal, "{result:?}");
}

#[test]
fn compiles_and_runs_cpp_inside_default_container_root() {
    let Ok(helper) = find_container_init() else {
        return;
    };
    unsafe { std::env::set_var("RUST_SANDBOX_CONTAINER_INIT", &helper) };
    let mut config = config();
    config.no_seccomp = false;
    let env = LinuxEnvironment::build(config).unwrap();
    let mut source = env
        .open(&[OpenParam {
            path: "/w/main.cpp".into(),
            flag: libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            perm: 0o644,
            mkdir_all: true,
        }])
        .unwrap()
        .remove(0)
        .file
        .unwrap();
    std::io::Write::write_all(&mut source, b"int main() { return 0; }\n").unwrap();
    drop(source);
    let compile = env
        .execve(ExecveParam {
            args: vec![
                "/usr/bin/g++".into(),
                "/w/main.cpp".into(),
                "-o".into(),
                "/w/program".into(),
            ],
            env: vec!["PATH=/usr/bin:/bin".into()],
            ..Default::default()
        })
        .unwrap();
    let compile_result = compile.result();
    assert_eq!(compile_result.status, Status::Normal, "{compile_result:?}");
    let run = env
        .execve(ExecveParam {
            args: vec!["/w/program".into()],
            env: vec![],
            ..Default::default()
        })
        .unwrap();
    let run_result = run.result();
    assert_eq!(run_result.status, Status::Normal, "{run_result:?}");
}

#[test]
fn maps_pid_one_signal_to_signalled_status() {
    let Ok(helper) = find_container_init() else {
        return;
    };
    unsafe { std::env::set_var("RUST_SANDBOX_CONTAINER_INIT", &helper) };
    let env = LinuxEnvironment::build(config()).unwrap();
    let process = env
        .execve(ExecveParam {
            args: vec!["/bin/sh".into(), "-c".into(), "kill -INT $$".into()],
            env: vec!["PATH=/usr/bin:/bin".into()],
            ..Default::default()
        })
        .unwrap();
    let result = process.result();
    assert_eq!(result.status, Status::Signalled, "{result:?}");
    assert_eq!(result.exit_status, libc::SIGINT);
}

#[test]
fn pidfd_wait_wakes_when_workload_exits() {
    let env = LinuxEnvironment::build(config()).unwrap();
    let process = env
        .execve(ExecveParam {
            args: vec!["/bin/sh".into(), "-c".into(), "exit 0".into()],
            env: vec!["PATH=/usr/bin:/bin".into()],
            ..Default::default()
        })
        .unwrap();
    let start = Instant::now();
    process.wait_timeout(Duration::from_secs(2));
    assert!(start.elapsed() < Duration::from_secs(1));
    assert!(process.done());
}

#[test]
fn opens_pidfd_for_a_live_child() {
    let mut child = std::process::Command::new("/bin/sleep")
        .arg("1")
        .spawn()
        .unwrap();
    assert!(open_pidfd(child.id()).is_some());
    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
fn maps_open_descriptors_to_child_stdio() {
    use std::fs::File;
    use std::os::fd::AsRawFd;
    let Ok(helper) = find_container_init() else {
        return;
    };
    unsafe { std::env::set_var("RUST_SANDBOX_CONTAINER_INIT", &helper) };
    let env = LinuxEnvironment::build(config()).unwrap();
    let dir = env.root.join("w");
    let output_path = dir.join("stdout.txt");
    let null = File::open("/dev/null").unwrap();
    let output = File::create(&output_path).unwrap();
    let process = env
        .execve(ExecveParam {
            args: vec!["/bin/echo".into(), "fd-map-ok".into()],
            env: vec![],
            files: vec![
                null.as_raw_fd() as u64,
                output.as_raw_fd() as u64,
                null.as_raw_fd() as u64,
            ],
            ..Default::default()
        })
        .unwrap();
    assert_eq!(process.result().status, Status::Normal);
    drop(output);
    assert_eq!(fs::read_to_string(output_path).unwrap(), "fd-map-ok\n");
}

#[test]
fn maps_pipe_descriptors_to_child_stdin_and_stdout() {
    use std::fs::File;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    let Ok(helper) = find_container_init() else {
        return;
    };
    unsafe { std::env::set_var("RUST_SANDBOX_CONTAINER_INIT", &helper) };
    let writer_env = LinuxEnvironment::build(config()).unwrap();
    let reader_env = LinuxEnvironment::build(config()).unwrap();
    let mut pipe_fds = [-1; 2];
    assert_eq!(
        unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    // SAFETY: pipe2 created these two descriptors, and ownership transfers
    // to the File values exactly once.
    let read_end = File::from(unsafe { OwnedFd::from_raw_fd(pipe_fds[0]) });
    let write_end = File::from(unsafe { OwnedFd::from_raw_fd(pipe_fds[1]) });
    let null = File::open("/dev/null").unwrap();
    let output_path = reader_env.root.join("w/pipe-output");
    let output = File::create(&output_path).unwrap();
    let writer = writer_env
        .execve(ExecveParam {
            args: vec!["/bin/sh".into(), "-c".into(), "printf pipe-ok".into()],
            env: vec!["PATH=/usr/bin:/bin".into()],
            files: vec![null.as_raw_fd() as u64, write_end.as_raw_fd() as u64],
            ..Default::default()
        })
        .unwrap();
    let reader = reader_env
        .execve(ExecveParam {
            args: vec!["/bin/cat".into()],
            env: vec!["PATH=/usr/bin:/bin".into()],
            files: vec![read_end.as_raw_fd() as u64, output.as_raw_fd() as u64],
            ..Default::default()
        })
        .unwrap();
    drop((read_end, write_end, null));
    assert_eq!(writer.result().status, Status::Normal);
    assert_eq!(reader.result().status, Status::Normal);
    drop(output);
    assert_eq!(fs::read_to_string(output_path).unwrap(), "pipe-ok");
}

#[test]
fn group_pipe_preserves_stdio_across_environment_executors() {
    use crate::envexec::{Cmd, File as ExecFile, Group, PipeIndex, PipeMapping};
    use std::collections::HashMap;
    use std::io::{Read, Seek, SeekFrom};

    let Ok(helper) = find_container_init() else {
        return;
    };
    unsafe { std::env::set_var("RUST_SANDBOX_CONTAINER_INIT", &helper) };
    let producer: Arc<dyn Environment> = Arc::new(LinuxEnvironment::build(config()).unwrap());
    let consumer: Arc<dyn Environment> = Arc::new(LinuxEnvironment::build(config()).unwrap());
    let make_command = |environment: Arc<dyn Environment>, args: Vec<String>, files| Cmd {
        environment,
        copy_in: HashMap::new(),
        symlinks: HashMap::new(),
        args,
        env: vec!["PATH=/usr/bin:/bin".into()],
        files,
        tty: false,
        terminal_resize: None,
        time_limit: Duration::from_secs(2),
        clock_limit: Duration::from_secs(5),
        memory_limit: Size(64 << 20),
        stack_limit: Size::default(),
        extra_memory_limit: Size::default(),
        output_limit: Size(1 << 20),
        proc_limit: 50,
        open_file_limit: 64,
        cpu_rate_limit: 0,
        cpu_set_limit: String::new(),
        copy_out: vec![],
        copy_out_max: Size(1 << 20),
        copy_out_truncate: false,
        address_space_limit: false,
        data_segment_limit: false,
    };
    let producer = make_command(
        producer,
        vec![
            "python3".into(),
            "-c".into(),
            "import sys; sys.stdout.write('A' * 1048576)".into(),
        ],
        vec![
            Some(ExecFile::input("/dev/null")),
            None,
            Some(ExecFile::collector("stderr", Size(10240), false)),
        ],
    );
    let consumer = make_command(
        consumer,
        vec![
            "python3".into(),
            "-c".into(),
            "import sys; print(len(sys.stdin.read()))".into(),
        ],
        vec![
            None,
            Some(ExecFile::collector("stdout", Size(10240), false)),
            Some(ExecFile::collector("stderr", Size(10240), false)),
        ],
    );
    let store =
        std::env::temp_dir().join(format!("rust-sandbox-group-store-{}", std::process::id()));
    fs::create_dir_all(&store).unwrap();
    let store_for_files = store.clone();
    let next = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let next_file = next.clone();
    let new_store: crate::envexec::NewStoreFile = Arc::new(move || {
        let id = next_file.fetch_add(1, Ordering::Relaxed);
        OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(store_for_files.join(format!("{id}")))
    });
    let results = Group {
        commands: vec![producer, consumer],
        pipes: vec![PipeMapping {
            input: PipeIndex { index: 0, fd: 1 },
            output: PipeIndex { index: 1, fd: 0 },
            ..Default::default()
        }],
        new_store_file: new_store,
    }
    .run()
    .unwrap();
    assert_eq!(
        results[0].status,
        crate::envexec::Status::Accepted,
        "{:?}",
        results[0].error
    );
    assert_eq!(
        results[1].status,
        crate::envexec::Status::Accepted,
        "{:?}",
        results[1].error
    );
    let mut output = results[1].files.get("stdout").unwrap().try_clone().unwrap();
    output.seek(SeekFrom::Start(0)).unwrap();
    let mut text = String::new();
    output.read_to_string(&mut text).unwrap();
    assert_eq!(text.trim(), "1048576");
    fs::remove_dir_all(store).unwrap();
}
