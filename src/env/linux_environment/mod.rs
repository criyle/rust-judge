//! Linux environment backed by a private mount namespace and a temporary root.
//!
//! The launcher uses `std::process::Command` through `container::fork_exec`.
//! It requires permission to create mount namespaces and bind mounts. The
//! production rust-judge executable is re-executed as PID 1 and workload
//! commands are sent to it over the container control socket.

use crate::container::{
    fork_exec::{BindMount, Child, IdMap, ProcMount, Runner, TmpfsMount},
    protocol::{
        self, Command as InitCommand, CommandType, ConfigureCommand, ContainerConfig, WireCommand,
        WireReply,
    },
    rlimit::RLimits,
    unix_socket::Socket,
};
use crate::env::linuxcontainer::{
    Cgroup, CgroupPool, CgroupV2Builder, ExecutionLimits, FreshCgroupPool, set_cgroup_limits,
};
use crate::env::{DEFAULT_WORK_DIR, MountOperation, default_mounts, filter_missing_sources};
use crate::envexec::{
    Environment, ExecveParam, OpenParam, OpenResult, Process, SymlinkParam, Usage,
};
use crate::runner::{ResultInfo, Size, Status};
use nix::fcntl::{AtFlags, OFlag, OpenHow, ResolveFlag, openat2};
use nix::sys::socket::ControlMessage;
use nix::sys::stat::{Mode, SFlag, fchmod, fstatat, mkdirat};
use nix::unistd::symlinkat;
use std::collections::HashMap;
use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
#[cfg(test)]
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct LinuxEnvironmentConfig {
    pub root_parent: PathBuf,
    pub work_dir: String,
    pub tmpfs_data: String,
    /// Mount the work directory as tmpfs instead of leaving it on the
    /// environment's host-side temporary root. Standalone runprog uses this
    /// to match go-sandbox's 8 MiB work mount.
    pub work_dir_tmpfs: bool,
    pub net_share: bool,
    /// Match go-judge's per-workload CLONE_NEWCGROUP request on kernels that
    /// support cgroup namespaces (Linux 4.6 and newer).
    pub unshare_cgroup: bool,
    pub uid: u32,
    pub gid: u32,
    pub no_seccomp: bool,
    /// Optional precompiled classic BPF filter. When supplied it replaces the
    /// default profile for this environment (used by the standalone runprog
    /// container backend, whose policy differs from go-judge's profile).
    pub seccomp_filter: Option<crate::container::seccomp::Filter>,
    pub mount_config: Option<crate::env::MountConfig>,
    /// Whether an explicit mount config with empty symlink/mask lists should
    /// inherit go-judge's default symlinks and masked paths.
    pub default_mount_policy: bool,
    /// Optional explicit container-init executable, matching go-judge's
    /// `--container-init-path` setting.
    pub container_init_path: Option<PathBuf>,
    pub seccomp_config: Option<PathBuf>,
    pub cgroup_root: Option<PathBuf>,
    /// Supported v2 controllers observed at the server's original cgroup
    /// subtree before hierarchy preparation moves the process into init.
    pub cgroup_v2_controllers: Vec<String>,
    /// Per-controller cgroup v1 hierarchy roots. When set, this takes
    /// precedence over the unified v2 root above.
    pub cgroup_v1_roots: Option<crate::env::cgroup_v1::ControllerPaths>,
    pub enable_cpu_rate: bool,
    pub cpu_cfs_period: Duration,
    pub no_fallback: bool,
    /// Host UID/GID allocation base used by go-judge's container credential
    /// generator. Each newly built environment receives `start + 1`, then the
    /// next ID, matching Go's atomic credential allocator.
    pub container_cred_start: Option<u32>,
    /// Host identity allocated to this environment by LinuxEnvironmentPool.
    /// Directly built environments default to `container_cred_start + 1`.
    pub host_credential_id: Option<u32>,
}

impl Default for LinuxEnvironmentConfig {
    fn default() -> Self {
        Self {
            root_parent: std::env::temp_dir(),
            work_dir: DEFAULT_WORK_DIR.into(),
            tmpfs_data: "size=64m,nr_inodes=16k".into(),
            work_dir_tmpfs: false,
            net_share: false,
            unshare_cgroup: crate::env::kernel_version()
                .map(|version| crate::env::kernel_version_at_least(version.0, version.1, 4, 6))
                .unwrap_or(false),
            // Go runs as container root unless `container_cred_start` enables
            // generated per-container credentials.
            uid: 0,
            gid: 0,
            no_seccomp: false,
            seccomp_filter: None,
            mount_config: None,
            default_mount_policy: true,
            container_init_path: None,
            seccomp_config: None,
            cgroup_root: None,
            cgroup_v2_controllers: Vec::new(),
            cgroup_v1_roots: None,
            enable_cpu_rate: false,
            cpu_cfs_period: Duration::from_millis(100),
            no_fallback: false,
            container_cred_start: None,
            host_credential_id: None,
        }
    }
}

pub struct LinuxEnvironment {
    root: PathBuf,
    work_dir: String,
    init_cmd: Vec<String>,
    mounts: Vec<BindMount>,
    proc_mounts: Vec<ProcMount>,
    tmpfs_mounts: Vec<TmpfsMount>,
    symlinks: Vec<(std::ffi::CString, std::ffi::CString)>,
    mask_paths: Vec<std::ffi::CString>,
    uid: Option<u32>,
    gid: Option<u32>,
    host_credential_id: Option<u32>,
    default_env: Mutex<Vec<String>>,
    net_share: bool,
    unshare_cgroup: bool,
    helper_inside: Option<String>,
    seccomp: crate::container::seccomp::Filter,
    host_name: String,
    domain_name: String,
    enable_cpu_rate: bool,
    cpu_cfs_period: Duration,
    no_fallback: bool,
    cgroup_pool: Option<Arc<dyn CgroupPool>>,
    keeper: Mutex<Option<NamespaceKeeper>>,
    init_socket: Mutex<Option<Arc<tokio::sync::Mutex<Socket>>>>,
    cgroup_creation_unavailable: AtomicBool,
}

struct NamespaceKeeper {
    child: Child,
    pid: i32,
    host_pid: i32,
}

/// Worker-compatible factory. Each checkout gets a fresh temporary root;
/// returning it to the pool drops it and removes the root tree.
pub struct LinuxEnvironmentPool {
    config: LinuxEnvironmentConfig,
    next_credential_id: AtomicU32,
    idle: Mutex<Vec<Arc<LinuxEnvironment>>>,
    leased: Mutex<HashMap<usize, std::sync::Weak<LinuxEnvironment>>>,
}

impl LinuxEnvironmentPool {
    pub fn new(config: LinuxEnvironmentConfig) -> io::Result<Self> {
        fs::create_dir_all(&config.root_parent)?;
        Ok(Self {
            next_credential_id: AtomicU32::new(config.container_cred_start.unwrap_or(0)),
            config,
            idle: Mutex::new(Vec::new()),
            leased: Mutex::new(HashMap::new()),
        })
    }
}

impl crate::worker::EnvironmentPool for LinuxEnvironmentPool {
    fn get(&self) -> io::Result<Arc<dyn Environment>> {
        let idle = self
            .idle
            .lock()
            .map_err(|_| io::Error::other("environment pool poisoned"))?
            .pop();
        let environment = match idle {
            Some(environment) => environment,
            None => {
                let mut config = self.config.clone();
                if config.container_cred_start.is_some() {
                    let mut previous = self.next_credential_id.load(Ordering::Acquire);
                    loop {
                        let next = previous.checked_add(1).ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "container credential ID range overflow",
                            )
                        })?;
                        match self.next_credential_id.compare_exchange_weak(
                            previous,
                            next,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        ) {
                            Ok(_) => break,
                            Err(actual) => previous = actual,
                        }
                    }
                    config.host_credential_id = Some(previous + 1);
                }
                Arc::new(LinuxEnvironment::build(config)?)
            }
        };
        let key = Arc::as_ptr(&environment) as usize;
        self.leased
            .lock()
            .map_err(|_| io::Error::other("environment lease map poisoned"))?
            .insert(key, Arc::downgrade(&environment));
        Ok(environment)
    }

    fn put(&self, environment: Arc<dyn Environment>) {
        let key = Arc::as_ptr(&environment) as *const () as usize;
        let typed = self
            .leased
            .lock()
            .ok()
            .and_then(|mut leased| leased.remove(&key))
            .and_then(|weak| weak.upgrade());
        drop(environment);
        if let Some(environment) = typed
            && environment.reset().is_ok()
            && let Ok(mut idle) = self.idle.lock()
        {
            idle.push(environment);
        }
    }
}

impl LinuxEnvironment {
    pub fn build(mut config: LinuxEnvironmentConfig) -> io::Result<Self> {
        if config.host_credential_id.is_none()
            && let Some(start) = config.container_cred_start
        {
            config.host_credential_id = Some(start.checked_add(1).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "container credential ID range overflow",
                )
            })?);
        }
        let cgroup_pool = if let Some(roots) = config.cgroup_v1_roots.as_ref() {
            Some(Arc::new(FreshCgroupPool::new(Box::new(
                crate::env::cgroup_v1::CgroupV1Builder::new(roots.clone()),
            ))) as Arc<dyn CgroupPool>)
        } else {
            config.cgroup_root.as_ref().map(|root| {
                Arc::new(FreshCgroupPool::new(Box::new(CgroupV2Builder::new(root))))
                    as Arc<dyn CgroupPool>
            })
        };
        let environment = Self::build_with_cgroup_pool(config, cgroup_pool)?;
        crate::runtime_metrics::environment_built();
        Ok(environment)
    }

    fn build_with_cgroup_pool(
        config: LinuxEnvironmentConfig,
        cgroup_pool: Option<Arc<dyn CgroupPool>>,
    ) -> io::Result<Self> {
        let root = make_temp_root(&config.root_parent)?;
        let mut root_guard = TempRootGuard(Some(root.clone()));
        let cwd = std::env::current_dir()?;
        let mut prepared_config = crate::env::prepare_mount_config(
            config.mount_config.as_ref(),
            &cwd,
            &config.tmpfs_data,
        )?;
        if config.mount_config.is_some() && !config.default_mount_policy {
            prepared_config.symlinks.clear();
            prepared_config.mask_paths.clear();
        }
        let meta = crate::env::container_meta(config.mount_config.as_ref())?;
        let work_dir = normalize_container_path(if config.mount_config.is_some() {
            &meta.work_dir
        } else {
            &config.work_dir
        })?;
        let mount_operations = if prepared_config.mounts.is_empty() {
            default_mounts(&config.tmpfs_data)
        } else {
            prepared_config.mounts
        };
        let prepared = filter_missing_sources(mount_operations);
        let mut mounts = Vec::new();
        let mut proc_mounts = Vec::new();
        let mut tmpfs_mounts = Vec::new();
        for operation in prepared {
            match operation {
                MountOperation::Bind {
                    source,
                    target,
                    readonly,
                } => {
                    let target_path = root.join(target);
                    prepare_mount_target(&source, &target_path)?;
                    mounts.push(BindMount {
                        source: cstring_path(&source)?,
                        target: cstring_path(&target_path)?,
                        readonly,
                    });
                }
                MountOperation::Tmpfs { target, data } => {
                    if target == Path::new("w") && !config.work_dir_tmpfs {
                        continue;
                    }
                    let target_path = root.join(&target);
                    fs::create_dir_all(&target_path)?;
                    tmpfs_mounts.push(TmpfsMount {
                        target: cstring_path(&target_path)?,
                        data: cstring(&data)?,
                    });
                }
                MountOperation::Proc { readonly } => {
                    let target_path = root.join("proc");
                    fs::create_dir_all(&target_path)?;
                    proc_mounts.push(ProcMount {
                        target: cstring_path(&target_path)?,
                        readonly,
                    });
                }
            }
        }
        let work_target = root.join(work_dir.trim_start_matches('/'));
        if !mounts.iter().any(|mount| {
            Path::new(std::ffi::OsStr::from_bytes(mount.target.as_bytes())) == work_target
        }) && !tmpfs_mounts.iter().any(|mount| {
            Path::new(std::ffi::OsStr::from_bytes(mount.target.as_bytes())) == work_target
        }) {
            // The root tmpfs is remounted read-only after setup, so the
            // configured work directory must remain its own writable mount.
            fs::create_dir_all(&work_target)?;
            tmpfs_mounts.push(TmpfsMount {
                target: cstring_path(&work_target)?,
                data: cstring(&config.tmpfs_data)?,
            });
        }
        let helper_source = container_init_source(&config)?;
        let helper_inside = helper_source
            .as_ref()
            .map(|_| "/.rust-sandbox-init".to_string());
        if let (Some(helper_inside), Some(helper_source)) = (&helper_inside, &helper_source) {
            let helper_target = root.join(helper_inside.trim_start_matches('/'));
            // The namespace runner overlays a fresh tmpfs on `root` and then
            // creates bind-mount targets inside that tmpfs. Pre-copying the
            // full rust-judge executable here would be discarded by the overlay.
            mounts.push(BindMount {
                source: cstring_path(helper_source)?,
                target: cstring_path(&helper_target)?,
                readonly: true,
            });
        }
        let proc_path = root.join("proc");
        fs::create_dir_all(&proc_path)?;
        for link in &prepared_config.symlinks {
            normalize_container_path(&link.link_path)?;
        }
        for path in &prepared_config.mask_paths {
            normalize_container_path(path)?;
        }
        create_symlinks(&root, &prepared_config.symlinks)?;
        let symlinks = prepared_config
            .symlinks
            .iter()
            .map(|link| {
                Ok((
                    cstring_path(&root.join(link.link_path.trim_start_matches('/')))?,
                    cstring(&link.target)?,
                ))
            })
            .collect::<io::Result<Vec<_>>>()?;
        let mask_paths = prepared_config
            .mask_paths
            .iter()
            .map(|path| cstring_path(&root.join(path.trim_start_matches('/'))))
            .collect::<io::Result<Vec<_>>>()?;
        let work_host = root.join(work_dir.trim_start_matches('/'));
        fs::create_dir_all(&work_host)?;
        fs::set_permissions(&work_host, fs::Permissions::from_mode(0o777))?;
        let (uid, gid) = if unsafe { libc::geteuid() } == 0 {
            (Some(config.uid), Some(config.gid))
        } else {
            (None, None)
        };
        if let (Some(uid), Some(gid)) = (uid, gid)
            && unsafe { libc::chown(cstring_path(&work_host)?.as_ptr(), uid, gid) } == -1
        {
            return Err(io::Error::last_os_error());
        }
        let seccomp = if let Some(filter) = config.seccomp_filter.clone() {
            filter
        } else if config.no_seccomp {
            crate::container::seccomp::Filter::default()
        } else {
            (if let Some(path) = config.seccomp_config.as_ref() {
                crate::env::seccomp_policy::PolicyProfile::from_path(path)
            } else {
                crate::env::seccomp_policy::PolicyProfile::load_default()
            })
            .and_then(|profile| profile.assemble(std::env::consts::ARCH))
            .map_err(io::Error::other)?
        };
        let environment = Self {
            root,
            work_dir,
            init_cmd: meta.init_cmd,
            mounts,
            proc_mounts,
            tmpfs_mounts,
            symlinks,
            mask_paths,
            uid,
            gid,
            host_credential_id: config.host_credential_id,
            default_env: Mutex::new(Vec::new()),
            net_share: config.net_share,
            unshare_cgroup: config.unshare_cgroup,
            helper_inside,
            seccomp,
            host_name: meta.host_name,
            domain_name: meta.domain_name,
            enable_cpu_rate: config.enable_cpu_rate,
            cpu_cfs_period: config.cpu_cfs_period,
            no_fallback: config.no_fallback,
            cgroup_pool,
            keeper: Mutex::new(None),
            init_socket: Mutex::new(None),
            cgroup_creation_unavailable: AtomicBool::new(false),
        };
        root_guard.0.take();
        Ok(environment)
    }

    fn namespace_root(&self) -> io::Result<fs::File> {
        self.ensure_keeper()?;
        let keeper = self
            .keeper
            .lock()
            .map_err(|_| io::Error::other("namespace keeper poisoned"))?;
        let host_pid = keeper
            .as_ref()
            .ok_or_else(|| io::Error::other("namespace keeper disappeared"))?
            .host_pid;
        fs::File::open(format!("/proc/{host_pid}/root"))
    }

    fn reset(&self) -> io::Result<()> {
        let work_relative = self.work_dir.trim_start_matches('/');
        let work_host = self.root.join(work_relative);
        let work_is_tmpfs = self.tmpfs_mounts.iter().any(|mount| {
            Path::new(std::ffi::OsStr::from_bytes(mount.target.as_bytes())) == work_host
        });
        if !self.tmpfs_mounts.is_empty() {
            let namespace_root = self.namespace_root()?;
            for mount in &self.tmpfs_mounts {
                let target = Path::new(std::ffi::OsStr::from_bytes(mount.target.as_bytes()));
                let relative = target.strip_prefix(&self.root).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "tmpfs mount target escaped the environment root",
                    )
                })?;
                let directory = open_directory_at(&namespace_root, relative, true)?;
                clear_open_directory(&directory)?;
            }
        }
        if !work_is_tmpfs {
            clear_directory(&work_host)?;
        }
        Ok(())
    }

    fn ensure_keeper(&self) -> io::Result<i32> {
        let mut keeper = self
            .keeper
            .lock()
            .map_err(|_| io::Error::other("namespace keeper poisoned"))?;
        if let Some(current) = keeper.as_mut() {
            if current.child.try_wait()?.is_none() {
                return Ok(current.pid);
            }
            // `unshare --kill-child` cannot run its cleanup if its parent is
            // killed with SIGKILL. The PID namespace init is a separate host
            // process, so reap it explicitly before forgetting the keeper.
            kill_namespace_init(current.pid);
            *keeper = None;
        }
        let helper_inside = self.helper_inside.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "container-init executable missing")
        })?;
        let (host_socket, init_socket) =
            crate::tokio_runtime::runtime().block_on(async { Socket::pair() })?;
        let init_fd = init_socket.as_raw_fd();
        let helper_args = vec![cstring("container_init")?];
        let mut runner = self.namespace_runner(helper_inside, helper_args);
        // Match go-sandbox/container: the re-executed rust-judge binary is PID 1
        // and receives its SOCK_SEQPACKET control channel at fd 3. Keep the
        // inherited standard descriptors in place before mapping the socket.
        runner.fd_map = vec![0, 1, 2, init_fd];
        let mut child = runner
            .start()
            .map_err(|error| io::Error::other(format!("spawn container init: {error}")))?;
        drop(init_socket);
        let parent_pid = child.id() as i32;
        let pid = match wait_namespace_child(parent_pid, Duration::from_secs(3)) {
            Ok(pid) => pid,
            Err(error) => {
                let _ = child.kill();
                let status = child.wait().ok();
                return Err(io::Error::other(format!(
                    "container init startup failed ({status:?}): {error}"
                )));
            }
        };
        let root_string = self
            .root
            .to_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "root path is not UTF-8"))?;
        let proc_mounts = self
            .proc_mounts
            .iter()
            .map(|mount| {
                let host_target = mount.target.to_str().map_err(io::Error::other)?;
                let target = host_target.strip_prefix(root_string).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "proc target outside root")
                })?;
                Ok(crate::container::mount::Mount {
                    source: "proc".into(),
                    target: if target.is_empty() {
                        "/".into()
                    } else {
                        target.to_owned()
                    },
                    fs_type: "proc".into(),
                    data: String::new(),
                    flags: (libc::MS_NOSUID
                        | libc::MS_NODEV
                        | libc::MS_NOEXEC
                        | if mount.readonly { libc::MS_RDONLY } else { 0 }),
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        let mask_paths = self
            .mask_paths
            .iter()
            .map(|path| {
                let host_path = path.to_str().map_err(io::Error::other)?;
                let path = host_path.strip_prefix(root_string).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "mask path outside root")
                })?;
                Ok(if path.is_empty() {
                    "/".to_owned()
                } else {
                    path.to_owned()
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        let config_command = InitCommand {
            cmd: Some(CommandType::Configure),
            conf_cmd: Some(ConfigureCommand {
                conf: ContainerConfig {
                    work_dir: self.work_dir.clone(),
                    container_root: "/".to_owned(),
                    mounts: proc_mounts,
                    mask_paths,
                    init_command: self.init_cmd.clone(),
                    container_uid: self.uid.unwrap_or_default() as i32,
                    container_gid: self.gid.unwrap_or_default() as i32,
                    cred: self.host_credential_id.is_some()
                        && self.uid.is_some()
                        && self.gid.is_some(),
                    unshare_cgroup: self.unshare_cgroup,
                    seccomp: self.seccomp.clone(),
                    ..Default::default()
                },
            }),
            ..Default::default()
        };
        let configured = crate::tokio_runtime::runtime().block_on(async {
            protocol::send_proto(&host_socket, &WireCommand::from(&config_command), &[]).await?;
            let (reply, _) = protocol::recv_proto::<WireReply>(&host_socket).await?;
            let reply = crate::container::protocol::Reply::from(reply);
            if let Some(error) = reply.error {
                return Err(io::Error::other(error.message));
            }
            Ok(())
        });
        if let Err(error) = configured {
            kill_namespace_init(pid);
            let _ = child.kill();
            let status = child.wait().ok();
            return Err(io::Error::other(format!(
                "container init configuration failed ({status:?}): {error}"
            )));
        }
        *self
            .init_socket
            .lock()
            .map_err(|_| io::Error::other("container init socket poisoned"))? =
            Some(Arc::new(tokio::sync::Mutex::new(host_socket)));
        let default_env = read_dotenv(&format!("/proc/{parent_pid}/root/.env"))?;
        *self
            .default_env
            .lock()
            .map_err(|_| io::Error::other("container default environment poisoned"))? = default_env;
        *keeper = Some(NamespaceKeeper {
            child,
            pid,
            host_pid: parent_pid,
        });
        Ok(pid)
    }

    fn namespace_runner(&self, helper_inside: &str, helper_args: Vec<CString>) -> Runner {
        // Seccomp bytecode is sent to PID 1 in the Configure protobuf. It
        // installs the filter for each workload through fork_exec.
        let (uid_map, gid_map) = self.host_credential_id.map_or((None, None), |host_id| {
            let container_uid = self.uid.filter(|id| *id != 0).unwrap_or(1000);
            let container_gid = self.gid.filter(|id| *id != 0).unwrap_or(1000);
            (
                Some(vec![
                    IdMap {
                        container_id: 0,
                        host_id: unsafe { libc::geteuid() },
                        size: 1,
                    },
                    IdMap {
                        container_id: container_uid,
                        host_id,
                        size: 1,
                    },
                ]),
                Some(vec![
                    IdMap {
                        container_id: 0,
                        host_id: unsafe { libc::getegid() },
                        size: 1,
                    },
                    IdMap {
                        container_id: container_gid,
                        host_id,
                        size: 1,
                    },
                ]),
            )
        });
        Runner {
            args: vec![],
            env: vec![
                cstring("PATH=/usr/local/bin:/usr/bin:/bin").expect("static PATH has no NUL"),
            ],
            work_dir: cstring("/").expect("valid root path"),
            container_root: Some(cstring_path(&self.root).expect("valid root path")),
            bind_mounts: self.mounts.clone(),
            proc_mounts: self.proc_mounts.clone(),
            tmpfs_mounts: self.tmpfs_mounts.clone(),
            rootfs_tmpfs: true,
            symlinks: self.symlinks.clone(),
            mask_paths: self.mask_paths.clone(),
            fd_map: vec![],
            exec_file: None,
            rlimits: RLimits::default(),
            pivot_root: None,
            host_name: Some(cstring(&self.host_name).expect("valid hostname")),
            domain_name: Some(cstring(&self.domain_name).expect("valid domain name")),
            sync_fn: None,
            clone_flags: libc::CLONE_NEWUSER
                | libc::CLONE_NEWNS
                | libc::CLONE_NEWIPC
                | libc::CLONE_NEWUTS
                | if self.net_share {
                    0
                } else {
                    libc::CLONE_NEWNET
                },
            credential: None,
            uid_map,
            gid_map,
            gid_map_enable_set_groups: false,
            no_new_privs: false,
            seccomp: crate::container::seccomp::Filter::default(),
            drop_caps: false,
            unshare_cgroup_after_sync: false,
            control_tty: false,
            pid_namespace_helper: Some(cstring(helper_inside).expect("valid helper path")),
            helper_unshare_flags: 0,
            helper_args: Some(helper_args),
            cgroup_procs_fds: vec![],
            cgroup_into_fd: None,
            cgroup_into_procs_index: None,
            user_namespace_fd: None,
            cpu_set: None,
        }
    }

    fn start_process(&self, param: ExecveParam) -> io::Result<Box<dyn Process>> {
        self.helper_inside.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "container-init executable missing; build rust-judge or container-init, or set RUST_SANDBOX_CONTAINER_INIT",
            )
        })?;
        if param.args.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "missing executable",
            ));
        }
        self.ensure_keeper()?;
        let namespace_root = self.namespace_root()?;
        let mut args = param
            .args
            .iter()
            .map(|s| cstring(s))
            .collect::<io::Result<Vec<_>>>()?;
        let mut env = self
            .default_env
            .lock()
            .map_err(|_| io::Error::other("container default environment poisoned"))?
            .clone();
        env.extend(param.env.iter().cloned());
        let resolved_executable = lookup_container_executable(
            &namespace_root,
            &self.work_dir,
            args[0].to_str().map_err(io::Error::other)?,
            &env,
        )?;
        args[0] = cstring(&resolved_executable)?;
        let env = env
            .iter()
            .map(|s| cstring(s))
            .collect::<io::Result<Vec<_>>>()?;
        let mut fd_map = param
            .files
            .iter()
            .map(|fd| {
                i32::try_from(*fd)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "fd overflow"))
            })
            .collect::<io::Result<Vec<_>>>()?;
        if fd_map.is_empty() {
            // Keep the service's standard streams available to a workload
            // when the caller did not provide an explicit descriptor map.
            fd_map.extend([0, 1, 2]);
        }
        // Pipes created by the server are root-owned (normally 0600). A
        // workload running as the container UID must be able to reopen an
        // inherited pipe through /proc/self/fd/N, as Go's pipe setup allows.
        for &fd in &fd_map {
            if is_anonymous_pipe(fd)? && self.uid.is_some() && self.gid.is_some() {
                // Pipe inodes live in the host user namespace. Translate
                // the container credential through the keeper's ID map
                // before changing their ownership so `/proc/self/fd/N`
                // can be reopened by the workload.
                let host_uid = self
                    .host_credential_id
                    .unwrap_or_else(|| unsafe { libc::geteuid() });
                let host_gid = self
                    .host_credential_id
                    .unwrap_or_else(|| unsafe { libc::getegid() });
                chown_fd(fd, host_uid, host_gid)?;
            }
        }
        let limits = ExecutionLimits {
            time: param.limit.time,
            memory_bytes: param.limit.memory.0,
            process_count: param.limit.proc,
            output_bytes: param.limit.output.0,
            stack_bytes: param.limit.stack.0,
            open_files: param.limit.open_file,
            cpu_rate: param.limit.rate,
            cpu_set: param.limit.cpu_set.clone(),
            data_segment: param.limit.data_segment,
            address_space: param.limit.address_space,
        };
        let mut cgroup = if self.cgroup_creation_unavailable.load(Ordering::Relaxed) {
            None
        } else if let Some(pool) = self.cgroup_pool.as_ref() {
            match pool.get() {
                Ok(mut group) => {
                    if let Err(error) = set_cgroup_limits(
                        &mut *group,
                        &limits,
                        self.enable_cpu_rate,
                        self.cpu_cfs_period,
                    ) {
                        pool.put(group);
                        // Go returns real controller write failures from
                        // setCgroupLimit; only unavailable/absent optional
                        // controllers are ignored by set_cgroup_limits.
                        return Err(io::Error::other(error));
                    } else {
                        Some(group)
                    }
                }
                Err(error) if !self.no_fallback => {
                    if cgroup_error_is_permanent(&error) {
                        self.cgroup_creation_unavailable
                            .store(true, Ordering::Relaxed);
                    }
                    None
                }
                Err(error) => return Err(io::Error::other(error)),
            }
        } else {
            None
        };
        let cgroup_procs_files = cgroup
            .as_ref()
            .map(|group| group.open_procs().map_err(io::Error::other))
            .transpose()?;
        let exec_file = (param.exec_file != 0)
            .then(|| i32::try_from(param.exec_file))
            .transpose()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "exec fd overflow"))?;
        let limits = execution_rlimits(&param, cgroup.is_some());
        let rlimits = limits
            .prepare()
            .into_iter()
            .map(|limit| crate::container::protocol::ResourceLimit {
                res: rlimit_id(limit.resource),
                rlim: crate::container::protocol::ResourceLimitValues {
                    cur: limit.soft,
                    max: limit.hard,
                },
            })
            .collect();
        let cgroup_fds = cgroup_procs_files
            .as_ref()
            .into_iter()
            .flatten()
            .map(AsRawFd::as_raw_fd)
            .collect::<Vec<_>>();
        let mut passed_fds = Vec::new();
        if let Some(fd) = exec_file {
            passed_fds.push(fd);
        }
        passed_fds.extend(cgroup_fds.iter().copied());
        passed_fds.extend(fd_map.iter().copied());
        let request = crate::container::protocol::Command {
            cmd: Some(CommandType::Exec),
            exec_cmd: Some(crate::container::protocol::ExecCommand {
                argv: args
                    .iter()
                    .map(|value| value.to_string_lossy().into_owned())
                    .collect(),
                env: env
                    .iter()
                    .map(|value| value.to_string_lossy().into_owned())
                    .collect(),
                rlimits,
                seccomp: param.seccomp.clone().unwrap_or_default(),
                fd_exec: exec_file.is_some(),
                fd_cgroup: !cgroup_fds.is_empty(),
                ctty: param.tty,
                sync_after: false,
                cpu_set: param.limit.cpu_set.clone(),
                cgroup_fd_count: cgroup_fds.len() as u32,
            }),
            ..Default::default()
        };
        let init_socket = self
            .init_socket
            .lock()
            .map_err(|_| io::Error::other("container init socket poisoned"))?
            .clone()
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "container init is not ready")
            })?;
        let (remote, cancel_rx) = RemoteProcess::new(cgroup.take(), self.cgroup_pool.clone());
        let remote = Arc::new(remote);
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let monitor_remote = remote.clone();
        crate::tokio_runtime::runtime().handle().spawn(async move {
            let socket = init_socket.lock_owned().await;
            let control = if passed_fds.is_empty() {
                Vec::new()
            } else {
                vec![ControlMessage::ScmRights(&passed_fds)]
            };
            let startup_result = async {
                protocol::send_proto(&socket, &WireCommand::from(&request), &control).await?;
                let (wire, frame) = protocol::recv_proto::<WireReply>(&socket).await?;
                let reply = crate::container::protocol::Reply::from(wire);
                if let Some(error) = reply.error.as_ref() {
                    return Err(io::Error::other(error.message.clone()));
                }
                if frame.credentials.is_none() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "container init did not acknowledge workload start",
                    ));
                }
                Ok(())
            }
            .await;
            if let Err(error) = startup_result {
                monitor_remote.complete(Err(io::Error::other(error.to_string())));
                let _ = started_tx.send(Err(io::Error::other(error.to_string())));
                return;
            }
            let _ = started_tx.send(Ok(()));
            let mut cancel_rx = cancel_rx;
            loop {
                tokio::select! {
                    received = protocol::recv_proto::<WireReply>(&socket) => {
                        let mut reply = received
                            .map(|(wire, _)| crate::container::protocol::Reply::from(wire));
                        if reply
                            .as_ref()
                            .is_ok_and(|reply| reply.exec_reply.is_some())
                        {
                            let kill = crate::container::protocol::Command {
                                cmd: Some(CommandType::Kill),
                                ..Default::default()
                            };
                            if let Err(error) = protocol::send_proto(
                                &socket,
                                &WireCommand::from(&kill),
                                &[],
                            )
                            .await
                            {
                                reply = Err(error);
                            }
                        }
                        monitor_remote.complete(reply);
                        break;
                    }
                    changed = cancel_rx.changed() => {
                        if changed.is_err() || !*cancel_rx.borrow() {
                            continue;
                        }
                        let kill = crate::container::protocol::Command {
                            cmd: Some(CommandType::Kill),
                            ..Default::default()
                        };
                        if let Err(error) = protocol::send_proto(
                            &socket,
                            &WireCommand::from(&kill),
                            &[],
                        ).await {
                            monitor_remote.complete(Err(error));
                            break;
                        }
                        let reply = protocol::recv_proto::<WireReply>(&socket)
                            .await
                            .map(|(wire, _)| crate::container::protocol::Reply::from(wire));
                        monitor_remote.complete(reply);
                        break;
                    }
                }
            }
        });
        match started_rx.recv() {
            Ok(Ok(())) => Ok(Box::new(remote)),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(io::Error::other("container init dropped workload startup")),
        }
    }
}

impl Drop for LinuxEnvironment {
    fn drop(&mut self) {
        if let Ok(keeper) = self.keeper.get_mut()
            && let Some(mut keeper) = keeper.take()
        {
            kill_namespace_init(keeper.pid);
            let _ = keeper.child.kill();
            let _ = keeper.child.wait();
        }
        if let Some(pool) = self.cgroup_pool.as_ref() {
            let _ = pool.shutdown();
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn kill_namespace_init(pid: i32) {
    if pid > 0 {
        // This is the direct child of the unshare launcher, which is PID 1
        // inside the container namespace and the reaper for workload children.
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
}

mod environment;

mod helpers;
use helpers::*;
pub use helpers::{
    cgroup_v1_roots_at_current_membership, cgroup_v1_roots_at_mount_prefix, current_cgroup_v2_path,
    default_cgroup_v1_roots, default_cgroup_v2_root,
};

mod process;
use process::RemoteProcess;

#[cfg(test)]
fn result_from_exit_status(status: std::process::ExitStatus) -> (Status, i32) {
    use std::os::unix::process::ExitStatusExt;
    match status.code() {
        Some(0) => (Status::Normal, 0),
        Some(code) => (Status::NonzeroExitStatus, code),
        None => {
            let signal = status.signal().unwrap_or(0);
            let result = match signal {
                libc::SIGXCPU | libc::SIGKILL => Status::TimeLimitExceeded,
                libc::SIGXFSZ => Status::OutputLimitExceeded,
                libc::SIGSYS => Status::DisallowedSyscall,
                _ => Status::Signalled,
            };
            (result, signal)
        }
    }
}

#[cfg(test)]
fn open_pidfd(pid: u32) -> Option<OwnedFd> {
    // SAFETY: pidfd_open takes a PID and flags; the returned descriptor is
    // uniquely owned when the syscall succeeds.
    // Linux sets close-on-exec for pidfd_open descriptors automatically; the
    // syscall's flags argument is reserved for PIDFD_NONBLOCK, not O_CLOEXEC.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

#[cfg(test)]
fn parse_vm_hwm_bytes(status: &str) -> u64 {
    status
        .lines()
        .find_map(|line| {
            let value = line.strip_prefix("VmHWM:")?.split_whitespace().next()?;
            value.parse::<u64>().ok()
        })
        .unwrap_or(0)
        .saturating_mul(1024)
}

#[cfg(test)]
mod tests;
