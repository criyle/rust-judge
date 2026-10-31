use rust_judge::go_judge_config::{Config, ParseOutcome, USAGE};
use rust_judge::{
    env::linux_environment::{
        LinuxEnvironmentConfig, LinuxEnvironmentPool, current_cgroup_v2_path,
        default_cgroup_v1_roots, default_cgroup_v2_root,
    },
    filestore::LocalFileStore,
    server::{ServerState, serve_with_monitor},
    worker::{AsyncWorker, ExecDefaults, WorkerConfig},
};
use std::{collections::HashMap, net::ToSocketAddrs, process::ExitCode, sync::Arc};

fn main() -> ExitCode {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    // Match rust-judge's package init hook: the production server executable is
    // re-executed as each container's PID 1 and runs the container control
    // loop here. Do not route production containers through a helper binary.
    if is_container_init_invocation(unsafe { libc::getpid() }, &arguments) {
        return match rust_judge::commands::go_judge_init::run() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("rust-judge container_init: {error}");
                ExitCode::from(2)
            }
        };
    }

    let environment: HashMap<String, String> = std::env::vars().collect();
    let cpu_count = logical_cpu_count();
    match Config::parse_from(
        std::env::args(),
        &environment,
        std::process::id(),
        cpu_count,
    ) {
        Ok(ParseOutcome::Help) => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Ok(ParseOutcome::Config(config)) if config.version => {
            println!("{}", build_version());
            ExitCode::SUCCESS
        }
        Ok(ParseOutcome::Config(config)) => match run(config) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("rust-judge: {error}");
                ExitCode::from(1)
            }
        },
        Err(error) => {
            eprintln!("rust-judge: {error}\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn is_container_init_invocation(pid: i32, arguments: &[std::ffi::OsString]) -> bool {
    pid == 1 && arguments.get(1).is_some_and(|arg| arg == "container_init")
}

/// Match Go's runtime.NumCPU default: count CPUs in the process affinity mask,
/// without reducing the count for a cgroup CPU quota.
fn logical_cpu_count() -> usize {
    #[cfg(target_os = "linux")]
    {
        if let Ok(affinity) = nix::sched::sched_getaffinity(nix::unistd::Pid::from_raw(0)) {
            let count = (0..nix::sched::CpuSet::count())
                .filter(|cpu| affinity.is_set(*cpu).unwrap_or(false))
                .count();
            if count > 0 {
                return count;
            }
        }
    }

    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
}

fn run(mut config: Config) -> std::io::Result<()> {
    if !cfg!(target_os = "linux") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "the container environment is currently Linux-only",
        ));
    }
    rust_judge::runtime_metrics::set_enabled(config.enable_metrics);
    rust_judge::runtime_trace::set_schedule_latency_enabled(config.enable_debug);
    if config.enable_debug {
        rpprof::alloc::start();
    }

    let default_file_dir = config.dir.is_empty();
    let file_dir = if default_file_dir {
        std::path::PathBuf::from("/dev/shm/go-judge")
    } else {
        std::path::PathBuf::from(&config.dir)
    };
    std::fs::create_dir_all(&file_dir)?;
    let files = LocalFileStore::with_timeout(
        &file_dir,
        config.file_timeout,
        std::time::Duration::from_secs(15),
    );

    let mut environment_config = LinuxEnvironmentConfig::default();
    environment_config.root_parent = if default_file_dir {
        std::env::temp_dir()
    } else {
        std::path::PathBuf::from(&config.dir)
    };
    environment_config.tmpfs_data = config.tmp_fs_param.clone();
    environment_config.net_share = config.net_share;
    environment_config.no_seccomp = config.no_seccomp;
    environment_config.container_init_path = Some(container_init_executable(&config)?);
    environment_config.mount_config = if std::path::Path::new(&config.mount_conf).is_file() {
        Some(rust_judge::env::read_mount_config(&config.mount_conf)?)
    } else {
        None
    };
    environment_config.seccomp_config = if config.seccomp_conf.is_empty() {
        None
    } else {
        Some(std::path::PathBuf::from(&config.seccomp_conf))
    };
    if std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").is_file() {
        // Match Go's v2 setup: ask systemd to place this server in a delegated
        // transient scope, falling back to the caller's current subtree when
        // no bus connection is available.
        let scoped = rust_judge::tokio_runtime::runtime().block_on(start_systemd_scope(
            &config.cgroup_prefix,
            std::process::id(),
        ));
        let systemd_scope_started = match scoped {
            Ok(started) => started,
            Err(error) if unsafe { libc::getuid() } != 0 && !config.no_fallback => {
                eprintln!("rust-judge: systemd scope unavailable, using current cgroup: {error}");
                false
            }
            Err(error) => return Err(std::io::Error::other(error)),
        };
        let current = current_cgroup_v2_path()?;
        // The default prefix is already represented by the transient scope's
        // cgroup path. Go uses the configured prefix only as the unit name.
        let root = if systemd_scope_started {
            current.join("containers")
        } else {
            default_cgroup_v2_root("")?
        };
        let controllers = std::fs::read_to_string(current.join("cgroup.controllers"))
            .map(|available| go_cgroup_controller_names(&available))
            .unwrap_or_default();
        let prepared = if systemd_scope_started {
            rust_judge::env::linuxcontainer::prepare_cgroup_v2_systemd_scope(&current, &root)
        } else {
            rust_judge::env::linuxcontainer::prepare_cgroup_v2_hierarchy(&current, &root)
        };
        match prepared {
            Ok(()) => {
                environment_config.cgroup_root = Some(root);
                environment_config.cgroup_v2_controllers = controllers;
            }
            Err(_error) if unsafe { libc::getuid() } != 0 && !config.no_fallback => {}
            Err(error) => {
                return Err(std::io::Error::other(format!(
                    "prepare cgroup v2 hierarchy: {error}"
                )));
            }
        }
    } else {
        let roots = default_cgroup_v1_roots(&config.cgroup_prefix)?;
        match rust_judge::env::cgroup_v1::prepare_go_judge_hierarchy(&roots) {
            Ok(()) => environment_config.cgroup_v1_roots = Some(roots),
            Err(_) if unsafe { libc::getuid() } != 0 && !config.no_fallback => {}
            Err(error) => {
                return Err(std::io::Error::other(format!(
                    "prepare cgroup v1 hierarchy: {error}"
                )));
            }
        }
    }
    environment_config.enable_cpu_rate = config.enable_cpu_rate;
    environment_config.cpu_cfs_period = config.cpu_cfs_period;
    environment_config.no_fallback = config.no_fallback;
    // Go stores the resolved default path back in its config before serving
    // /config, so expose the same path even when --dir was omitted.
    config.dir = file_dir.to_string_lossy().into_owned();
    if config.container_cred_start > 0 && unsafe { libc::geteuid() } == 0 {
        // `container_cred_start` is the host-side UID/GID allocation base.
        // Go's workload identity comes from the container metadata, which
        // defaults to UID/GID 1000 and may be overridden by mount.yaml.
        let meta = rust_judge::env::container_meta(environment_config.mount_config.as_ref())?;
        environment_config.uid = u32::try_from(meta.uid).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "container UID must be non-negative",
            )
        })?;
        environment_config.gid = u32::try_from(meta.gid).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "container GID must be non-negative",
            )
        })?;
        environment_config.container_cred_start =
            Some(u32::try_from(config.container_cred_start).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "container credential start must be non-negative",
                )
            })?);
    }
    let runner_config = runner_config_json(&config, &environment_config)?;
    let environments = Arc::new(LinuxEnvironmentPool::new(environment_config)?);
    if config.pre_fork > 0 {
        let mut preforked = Vec::with_capacity(config.pre_fork as usize);
        for _ in 0..config.pre_fork {
            let environment = rust_judge::worker::EnvironmentPool::get(environments.as_ref())?;
            rust_judge::runtime_metrics::environment_acquired();
            preforked.push(environment);
        }
        for environment in preforked {
            rust_judge::worker::EnvironmentPool::put(environments.as_ref(), environment);
            rust_judge::runtime_metrics::environment_released();
        }
    }

    let mut worker_config = WorkerConfig::new(files.clone(), environments);
    if config.enable_metrics {
        worker_config.exec_observer = Some(Arc::new(rust_judge::server::observe_execution));
    }
    worker_config.parallelism = config.parallelism.max(1);
    worker_config.tick_interval = config.time_limit_checker_interval;
    worker_config.cpu_sets = config.cpuset.clone();
    worker_config.defaults = ExecDefaults {
        extra_memory_limit: config.extra_memory_limit,
        output_limit: config.output_limit,
        copy_out_limit: config.copy_out_limit,
        open_file_limit: config.open_file_limit.max(0) as u64,
        cpu_set: String::new(),
    };
    let worker = AsyncWorker::new(worker_config);
    worker.start()?;

    let state = ServerState {
        worker: worker.clone(),
        files: files.clone(),
        config: Arc::new(config.clone()),
        runner_config,
        version: build_version().to_owned(),
    };
    let http = resolve_addr(&config.http_addr)?;
    let grpc = if config.enable_grpc {
        resolve_addr(&config.grpc_addr)?
    } else {
        None
    };
    let monitor = if config.enable_metrics || config.enable_debug {
        resolve_addr(&config.monitor_addr)?
    } else {
        None
    };
    let runtime = rust_judge::tokio_runtime::runtime();
    let memory_reclaimer =
        rust_judge::memory_reclaimer::spawn(config.force_gc_interval, config.force_gc_target.0)?;
    let result = runtime.block_on(serve_with_monitor(http, grpc, monitor, state));
    if let Some(task) = memory_reclaimer {
        task.abort();
    }
    worker.shutdown();
    drop(worker);
    drop(files);
    if default_file_dir {
        let cleanup = std::fs::remove_dir_all(&file_dir);
        match (result, cleanup) {
            (Err(error), _) => Err(error),
            (Ok(()), Err(error)) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
    } else {
        result
    }
}

async fn start_systemd_scope(prefix: &str, pid: u32) -> Result<bool, String> {
    let connection = if unsafe { libc::getuid() } == 0 {
        zbus::Connection::system().await
    } else {
        zbus::Connection::session().await
    };
    let Ok(connection) = connection else {
        // Go falls back to the caller's current cgroup when a bus connection
        // itself cannot be established.
        return Ok(false);
    };
    let unit = format!("{prefix}.scope");
    let wants = vec![unit.clone()];
    let properties: Vec<(&str, zbus::zvariant::OwnedValue)> = vec![
        (
            "Description",
            zbus::zvariant::OwnedValue::try_from(zbus::zvariant::Value::new(
                "go judge - a high performance sandbox service base on container technologies",
            ))
            .map_err(|error| error.to_string())?,
        ),
        (
            "Wants",
            zbus::zvariant::OwnedValue::try_from(zbus::zvariant::Value::new(wants))
                .map_err(|error| error.to_string())?,
        ),
        (
            "PIDs",
            zbus::zvariant::OwnedValue::try_from(zbus::zvariant::Value::new(vec![pid]))
                .map_err(|error| error.to_string())?,
        ),
        ("Delegate", true.into()),
        (
            "KillMode",
            zbus::zvariant::OwnedValue::try_from(zbus::zvariant::Value::new("process"))
                .map_err(|error| error.to_string())?,
        ),
    ];
    let proxy = zbus::Proxy::new(
        &connection,
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
    )
    .await
    .map_err(|error| error.to_string())?;
    let aux: Vec<(String, Vec<(String, zbus::zvariant::OwnedValue)>)> = Vec::new();
    let _: zbus::zvariant::OwnedObjectPath = proxy
        .call(
            "StartTransientUnit",
            &(unit.as_str(), "replace", properties, aux),
        )
        .await
        .map_err(|error| error.to_string())?;

    // StartTransientUnit acknowledges the job before systemd finishes moving
    // the process. Wait until /proc reflects the new scope before preparing
    // controllers beneath it.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let current = current_cgroup_v2_path().map_err(|error| error.to_string())?;
        if current
            .components()
            .any(|component| component.as_os_str() == unit.as_str())
        {
            return Ok(true);
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!("systemd did not move the server into {unit}"));
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// Resolve Go's `/proc/self/exe` default to the running server image. The
/// namespace launcher bind-mounts the executable before PID 1 starts, so the
/// host-side path is needed as the mount source. Keep the explicit path option
/// for deployments that override Go's default behavior.
fn container_init_executable(config: &Config) -> std::io::Result<std::path::PathBuf> {
    if config.container_init_path.is_empty() {
        std::env::current_exe()
    } else {
        Ok(std::path::PathBuf::from(&config.container_init_path))
    }
}

fn runner_config_json(
    config: &Config,
    environment: &LinuxEnvironmentConfig,
) -> std::io::Result<serde_json::Value> {
    let cwd = std::env::current_dir()?;
    let prepared = rust_judge::env::prepare_mount_config(
        environment.mount_config.as_ref(),
        &cwd,
        &environment.tmpfs_data,
    )?;
    let mounts = rust_judge::env::to_mount_builder(&rust_judge::env::filter_missing_sources(
        prepared.mounts,
    ));
    let mount_values: Vec<_> = mounts
        .mounts
        .iter()
        .map(|mount| {
            serde_json::json!({
                "Source": mount.source,
                "Target": mount.target,
                "FsType": mount.fs_type,
                "Data": mount.data,
                "Flags": mount.flags,
            })
        })
        .collect();
    let symbolic_links: Vec<_> = prepared
        .symlinks
        .iter()
        .map(|link| serde_json::json!({"LinkPath": link.link_path, "Target": link.target}))
        .collect();
    let meta = rust_judge::env::container_meta(environment.mount_config.as_ref())?;
    let (cgroup_type, cgroup_controllers) = if environment.cgroup_root.is_some() {
        (2, environment.cgroup_v2_controllers.clone())
    } else if let Some(roots) = environment.cgroup_v1_roots.as_ref() {
        (1, roots.keys().cloned().collect())
    } else {
        (0, Vec::new())
    };
    Ok(serde_json::json!({
        "cgroupType": cgroup_type,
        "seccomp": !config.no_seccomp,
        // The production runner intentionally uses std::process::Command's
        // standard-library fork/exec path, not Go's clone3 optimization.
        "clone3": false,
        "mount": mount_values,
        "symbolicLink": symbolic_links,
        "maskedPaths": prepared.mask_paths,
        "hostName": meta.host_name,
        "domainName": meta.domain_name,
        "workDir": meta.work_dir,
        "uid": meta.uid,
        "gid": meta.gid,
        "cgroupControllers": cgroup_controllers,
    }))
}

fn go_cgroup_controller_names(available: &str) -> Vec<String> {
    ["cpu", "cpuacct", "cpuset", "memory", "pids"]
        .into_iter()
        .filter(|name| available.split_whitespace().any(|item| item == *name))
        .map(str::to_owned)
        .collect()
}

fn build_version() -> &'static str {
    option_env!("RUST_SANDBOX_VERSION")
        .or(option_env!("GO_JUDGE_VERSION"))
        .unwrap_or(env!("CARGO_PKG_VERSION"))
}

fn resolve_addr(addr: &str) -> std::io::Result<Option<std::net::SocketAddr>> {
    if addr.is_empty() {
        return Ok(None);
    }
    addr.to_socket_addrs()?.next().map(Some).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "empty listen address")
    })
}

#[cfg(test)]
mod tests {
    use super::{
        Config, LinuxEnvironmentConfig, container_init_executable, go_cgroup_controller_names,
        is_container_init_invocation, logical_cpu_count, runner_config_json,
    };
    use rust_judge::go_judge_config::ParseOutcome;
    use std::collections::HashMap;

    #[test]
    fn production_container_init_defaults_to_the_rust_judge_executable() {
        let ParseOutcome::Config(config) =
            Config::parse_from(["rust-judge"], &HashMap::new(), 1, 1).unwrap()
        else {
            panic!("expected config");
        };
        assert_eq!(
            container_init_executable(&config).unwrap(),
            std::env::current_exe().unwrap()
        );
    }

    #[test]
    fn go_judge_pid1_always_uses_the_persistent_container_server() {
        let arguments = [
            "rust-judge".into(),
            "container_init".into(),
            "--exec-direct".into(),
        ];
        assert!(is_container_init_invocation(1, &arguments));
        assert!(!is_container_init_invocation(2, &arguments));
        assert!(!is_container_init_invocation(
            1,
            &["rust-judge".into(), "--version".into()]
        ));
    }

    #[test]
    fn cgroup_v2_controller_names_match_go_supported_set_and_order() {
        assert_eq!(
            go_cgroup_controller_names("pids io cpuset cpu memory hugetlb cpuacct"),
            ["cpu", "cpuacct", "cpuset", "memory", "pids"]
        );
        assert!(go_cgroup_controller_names("io hugetlb rdma").is_empty());
    }

    #[test]
    fn explicit_container_init_path_still_overrides_the_executable() {
        let ParseOutcome::Config(config) = Config::parse_from(
            ["rust-judge", "--container-init-path", "/opt/custom-init"],
            &HashMap::new(),
            1,
            1,
        )
        .unwrap() else {
            panic!("expected config");
        };
        assert_eq!(
            container_init_executable(&config).unwrap(),
            std::path::PathBuf::from("/opt/custom-init")
        );
    }

    #[test]
    fn default_cpu_count_uses_the_process_affinity_mask() {
        #[cfg(target_os = "linux")]
        {
            let affinity = nix::sched::sched_getaffinity(nix::unistd::Pid::from_raw(0)).unwrap();
            let expected = (0..nix::sched::CpuSet::count())
                .filter(|cpu| affinity.is_set(*cpu).unwrap_or(false))
                .count();
            assert_eq!(logical_cpu_count(), expected.max(1));
        }
    }

    #[test]
    fn runner_config_endpoint_payload_matches_builder_fields() {
        let config = Config::defaults(2, 1);
        let mut environment = LinuxEnvironmentConfig::default();
        environment.cgroup_root = Some(std::path::PathBuf::from("/sys/fs/cgroup/test/containers"));
        environment.cgroup_v2_controllers = go_cgroup_controller_names("pids io cpuset cpu memory");
        let value = runner_config_json(&config, &environment).unwrap();
        for field in [
            "cgroupType",
            "seccomp",
            "clone3",
            "mount",
            "symbolicLink",
            "maskedPaths",
            "hostName",
            "domainName",
            "workDir",
            "uid",
            "gid",
            "cgroupControllers",
        ] {
            assert!(value.get(field).is_some(), "runnerConfig lacks {field}");
        }
        assert_eq!(value["workDir"], "/w");
        assert_eq!(value["uid"], 1000);
        assert_eq!(value["gid"], 1000);
        assert!(value["seccomp"].as_bool().unwrap());
        assert_eq!(value["clone3"], false);
        assert_eq!(
            value["cgroupControllers"],
            serde_json::json!(["cpu", "cpuset", "memory", "pids"])
        );
    }
}
