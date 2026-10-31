//! Linux environment backed by a private mount namespace and a temporary root.
//!
//! The launcher uses `std::process::Command` through `container::fork_exec`.
//! It requires permission to create mount namespaces and bind mounts. The
//! production go-judge executable is re-executed as PID 1 and workload
//! commands are sent to it over the container control socket.

use crate::container::{
    fork_exec::{BindMount, IdMap, ProcMount, Runner, TmpfsMount},
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
use std::process::Child;
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
                    let previous = self
                        .next_credential_id
                        .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                            current.checked_add(1)
                        })
                        .map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "container credential ID range overflow",
                            )
                        })?;
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
        if let Some(environment) = typed {
            if environment.reset().is_ok() {
                if let Ok(mut idle) = self.idle.lock() {
                    idle.push(environment);
                }
            }
        }
    }
}

impl LinuxEnvironment {
    pub fn build(mut config: LinuxEnvironmentConfig) -> io::Result<Self> {
        if config.host_credential_id.is_none() {
            if let Some(start) = config.container_cred_start {
                config.host_credential_id = Some(start.checked_add(1).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "container credential ID range overflow",
                    )
                })?);
            }
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
            // full go-judge executable here would be discarded by the overlay.
            mounts.push(BindMount {
                source: cstring_path(&helper_source)?,
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
        if let (Some(uid), Some(gid)) = (uid, gid) {
            if unsafe { libc::chown(cstring_path(&work_host)?.as_ptr(), uid, gid) } == -1 {
                return Err(io::Error::last_os_error());
            }
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
        // Match go-sandbox/container: the re-executed go-judge binary is PID 1
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
                        | if mount.readonly { libc::MS_RDONLY } else { 0 })
                        as u64,
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
            user_namespace_fd: None,
            cpu_set: None,
        }
    }

    fn start_process(&self, param: ExecveParam) -> io::Result<Box<dyn Process>> {
        self.helper_inside.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "container-init executable missing; build go-judge or container-init, or set RUST_SANDBOX_CONTAINER_INIT",
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
            if is_anonymous_pipe(fd)? {
                if self.uid.is_some() && self.gid.is_some() {
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
        if let Ok(keeper) = self.keeper.get_mut() {
            if let Some(mut keeper) = keeper.take() {
                kill_namespace_init(keeper.pid);
                let _ = keeper.child.kill();
                let _ = keeper.child.wait();
            }
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

impl Environment for LinuxEnvironment {
    fn execve(&self, param: ExecveParam) -> io::Result<Box<dyn Process>> {
        self.start_process(param)
    }

    fn open(&self, params: &[OpenParam]) -> io::Result<Vec<OpenResult>> {
        let root = self.namespace_root()?;
        Ok(params
            .iter()
            .map(|param| {
                let result: io::Result<fs::File> = (|| {
                    let path = self.container_relative_path(&param.path)?;
                    if param.mkdir_all {
                        create_parent_directories(&root, &path)?;
                    }
                    let target_missing = check_open_target(&root, &path, &param.path)?;
                    let flags = OFlag::from_bits_retain(param.flag);
                    let mode = if flags.intersects(OFlag::O_CREAT | OFlag::O_TMPFILE) {
                        Mode::from_bits_truncate(param.perm)
                    } else {
                        Mode::empty()
                    };
                    let open = |open_flags: OFlag| -> io::Result<fs::File> {
                        let how = OpenHow::new()
                            .flags(open_flags | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW)
                            .mode(mode)
                            .resolve(container_resolve_flags());
                        openat2(&root, &path, how)
                            .map(fs::File::from)
                            .map_err(io::Error::from)
                    };
                    let mut created = false;
                    let file = if flags.contains(OFlag::O_CREAT)
                        && target_missing
                        && !flags.contains(OFlag::O_EXCL)
                    {
                        match open(flags | OFlag::O_EXCL) {
                            Ok(file) => {
                                created = true;
                                file
                            }
                            Err(error) if error.raw_os_error() == Some(libc::EEXIST) => {
                                // Another request created the path after the
                                // regular-file check. Preserve that file's
                                // existing mode and ownership, as Go does.
                                check_open_target(&root, &path, &param.path)?;
                                open(flags)?
                            }
                            Err(error) => return Err(error),
                        }
                    } else {
                        let file = open(flags)?;
                        created = flags.contains(OFlag::O_CREAT) && target_missing;
                        file
                    };
                    if created {
                        // PID 1 uses umask(0); this host-side open inherits the
                        // service umask, so restore Go's requested creation
                        // mode only when this call actually created the file.
                        fchmod(&file, mode).map_err(io::Error::from)?;
                    }
                    Ok(file)
                })();
                match result {
                    Ok(file) => OpenResult {
                        file: Some(file),
                        error: None,
                    },
                    Err(error) => OpenResult {
                        file: None,
                        error: Some(error.to_string()),
                    },
                }
            })
            .collect())
    }

    fn symlink(&self, params: &[SymlinkParam]) -> io::Result<Vec<Option<String>>> {
        let root = self.namespace_root()?;
        Ok(params
            .iter()
            .map(|param| {
                let result = (|| {
                    let link = self.container_relative_path(&param.link_path)?;
                    let parent_path = link.parent().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "path has no parent")
                    })?;
                    let name = link.file_name().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "path has no file name")
                    })?;
                    let parent = open_directory_at(&root, parent_path, false)?;
                    symlinkat(param.target.as_str(), &parent, name).map_err(io::Error::from)
                })();
                result.err().map(|e| e.to_string())
            })
            .collect())
    }
}

impl LinuxEnvironment {
    fn container_relative_path(&self, path: &str) -> io::Result<PathBuf> {
        if path.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "empty path"));
        }
        let requested = Path::new(path);
        let container_path = if requested.is_absolute() {
            requested.to_path_buf()
        } else {
            Path::new(&self.work_dir).join(requested)
        };
        container_path
            .strip_prefix("/")
            .map(Path::to_path_buf)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "path is not valid inside the container root",
                )
            })
    }
}

fn container_resolve_flags() -> ResolveFlag {
    // Match path resolution in the container's chroot: absolute symlinks are
    // rooted at this environment, and `..` cannot escape it. Procfs magic
    // links remain disabled for host-side opens through the namespace root.
    ResolveFlag::RESOLVE_IN_ROOT | ResolveFlag::RESOLVE_NO_MAGICLINKS
}

fn open_directory_at(root: &fs::File, path: &Path, no_symlinks: bool) -> io::Result<fs::File> {
    if path.as_os_str().is_empty() || path == Path::new(".") {
        return root.try_clone();
    }
    let mut how = OpenHow::new()
        .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
        .resolve(container_resolve_flags());
    if no_symlinks {
        how = how.resolve(container_resolve_flags() | ResolveFlag::RESOLVE_NO_SYMLINKS);
    }
    openat2(root, path, how)
        .map(fs::File::from)
        .map_err(io::Error::from)
}

fn check_open_target(root: &fs::File, path: &Path, requested: &str) -> io::Result<bool> {
    if path.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{requested} is not a regular file"),
        ));
    }
    let parent_path = path.parent().unwrap_or(Path::new(""));
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "open target has no file name"))?;
    let parent = open_directory_at(root, parent_path, false)?;
    match fstatat(&parent, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(metadata) if SFlag::from_bits_truncate(metadata.st_mode) != SFlag::S_IFREG => {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{requested} is not a regular file"),
            ))
        }
        Ok(_) => Ok(false),
        Err(nix::errno::Errno::ENOENT) => Ok(true),
        Err(error) => Err(io::Error::from(error)),
    }
}

fn create_parent_directories(root: &fs::File, path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    let mut current = root.try_clone()?;
    let mut prefix = PathBuf::new();
    for component in parent.components() {
        match component {
            Component::Normal(name) => {
                prefix.push(name);
                match open_directory_at(root, &prefix, false) {
                    Ok(directory) => current = directory,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        let created = match mkdirat(&current, name, Mode::from_bits_truncate(0o777))
                        {
                            Ok(()) => true,
                            Err(nix::errno::Errno::EEXIST) => false,
                            Err(error) => return Err(io::Error::from(error)),
                        };
                        let directory = open_directory_at(root, &prefix, false)?;
                        if created {
                            // PID 1 has umask(0) in Go, while these mkdirs
                            // run in the host server process. Set the
                            // resulting mode explicitly to preserve MkdirAll
                            // semantics regardless of the service umask.
                            fchmod(&directory, Mode::from_bits_truncate(0o777))
                                .map_err(io::Error::from)?;
                        }
                        current = directory;
                    }
                    Err(error) => return Err(error),
                }
            }
            Component::ParentDir => {
                prefix.push("..");
                current = open_directory_at(root, &prefix, false)?;
            }
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "path is not relative to the container root",
                ));
            }
        }
    }
    Ok(())
}

fn clear_directory(path: &Path) -> io::Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() && !file_type.is_symlink() {
            fs::remove_dir_all(entry_path)?;
        } else {
            fs::remove_file(entry_path)?;
        }
    }
    Ok(())
}

fn clear_open_directory(directory: &fs::File) -> io::Result<()> {
    let path = format!("/proc/self/fd/{}", directory.as_raw_fd());
    clear_directory(Path::new(&path))
}

fn execution_rlimits(param: &ExecveParam, cgroup_enabled: bool) -> RLimits {
    let limits = &param.limit;
    RLimits {
        cpu: limits.time.as_secs().saturating_add(1),
        data: if limits.data_segment || !cgroup_enabled {
            limits.memory.0
        } else {
            0
        },
        file_size: limits.output.0,
        stack: limits.stack.0,
        address_space: if limits.address_space {
            limits.memory.0
        } else {
            0
        },
        open_file: limits.open_file,
        disable_core: true,
        ..Default::default()
    }
}

fn rlimit_id(resource: nix::sys::resource::Resource) -> i32 {
    use nix::sys::resource::Resource;
    match resource {
        Resource::RLIMIT_CPU => libc::RLIMIT_CPU as i32,
        Resource::RLIMIT_DATA => libc::RLIMIT_DATA as i32,
        Resource::RLIMIT_FSIZE => libc::RLIMIT_FSIZE as i32,
        Resource::RLIMIT_STACK => libc::RLIMIT_STACK as i32,
        Resource::RLIMIT_AS => libc::RLIMIT_AS as i32,
        Resource::RLIMIT_NOFILE => libc::RLIMIT_NOFILE as i32,
        Resource::RLIMIT_CORE => libc::RLIMIT_CORE as i32,
        _ => -1,
    }
}

fn cgroup_error_is_permanent(error: &crate::env::linuxcontainer::EnvError) -> bool {
    match error {
        crate::env::linuxcontainer::EnvError::Unsupported(_) => true,
        crate::env::linuxcontainer::EnvError::Io(error) => matches!(
            error.kind(),
            io::ErrorKind::NotFound
                | io::ErrorKind::PermissionDenied
                | io::ErrorKind::ReadOnlyFilesystem
        ),
        crate::env::linuxcontainer::EnvError::Backend(_) => false,
        crate::env::linuxcontainer::EnvError::Poisoned => false,
    }
}

fn make_temp_root(parent: &Path) -> io::Result<PathBuf> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    fs::create_dir_all(parent)?;
    for _ in 0..64 {
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = parent.join(format!("rust-sandbox-{}-{id}", std::process::id()));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "temporary container root collisions",
    ))
}

struct TempRootGuard(Option<PathBuf>);
impl Drop for TempRootGuard {
    fn drop(&mut self) {
        if let Some(root) = self.0.take() {
            let _ = fs::remove_dir_all(root);
        }
    }
}

/// Resolve the Go-style cgroup prefix to the leaf directory used by per-run
/// groups. Empty prefixes use the caller's current cgroup subtree.
pub fn default_cgroup_v2_root(prefix: &str) -> io::Result<PathBuf> {
    let relative = if prefix.is_empty() {
        let membership = fs::read_to_string("/proc/self/cgroup")?;
        let current = membership
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .unwrap_or("/")
            .trim_start_matches('/');
        if current.is_empty() {
            PathBuf::from("go-judge/containers")
        } else {
            PathBuf::from(current).join("containers")
        }
    } else {
        let path = Path::new(prefix);
        if path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cgroup prefix must be a safe relative path",
            ));
        }
        path.join("containers")
    };
    Ok(Path::new("/sys/fs/cgroup").join(relative))
}

/// Resolve the current process's unified cgroup directory from procfs.
pub fn current_cgroup_v2_path() -> io::Result<PathBuf> {
    let membership = fs::read_to_string("/proc/self/cgroup")?;
    let raw = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "process is not in a unified cgroup v2 hierarchy",
            )
        })?;
    let relative = Path::new(raw.trim_start_matches('/'));
    if raw != "/"
        && relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid current cgroup v2 membership path",
        ));
    }
    Ok(Path::new("/sys/fs/cgroup").join(relative))
}

/// Resolve the per-controller v1 roots used by go-judge's `containers` child
/// hierarchy. Controller mount points are discovered from procfs; an empty
/// configured prefix uses Go's `go-judge` default.
pub fn default_cgroup_v1_roots(prefix: &str) -> io::Result<crate::env::cgroup_v1::ControllerPaths> {
    let root = if prefix.is_empty() {
        PathBuf::from("go-judge/containers")
    } else {
        let prefix_path = Path::new(prefix);
        if prefix_path.is_absolute()
            || prefix_path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cgroup prefix must be a safe relative path",
            ));
        }
        prefix_path.join("containers")
    };
    cgroup_v1_roots_at_mount_prefix(&root)
}

/// Resolve a relative v1 hierarchy below each controller's mount point. Go's
/// server and runprog use `cgroup.New(prefix)`, which is mount-root-relative.
pub fn cgroup_v1_roots_at_mount_prefix(
    relative_root: &Path,
) -> io::Result<crate::env::cgroup_v1::ControllerPaths> {
    if relative_root.as_os_str().is_empty()
        || relative_root.is_absolute()
        || relative_root
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cgroup root must be a safe relative path",
        ));
    }
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
    let mounts = crate::env::cgroup_v1::discover_controller_mount_paths(&mountinfo)
        .map_err(io::Error::other)?;
    Ok(mounts
        .into_iter()
        .map(|(controller, mount)| (controller, mount.join(relative_root)))
        .collect())
}

/// Resolve a relative v1 cgroup hierarchy below the current process's
/// controller memberships. Use this only when the caller intentionally wants
/// a delegated subtree rooted at its own memberships.
pub fn cgroup_v1_roots_at_current_membership(
    relative_root: &Path,
) -> io::Result<crate::env::cgroup_v1::ControllerPaths> {
    let builder = crate::env::cgroup_v1::CgroupV1Builder::from_proc_data(
        &fs::read_to_string("/proc/self/cgroup")?,
        &fs::read_to_string("/proc/self/mountinfo")?,
        relative_root.to_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "cgroup root is not UTF-8")
        })?,
    )
    .map_err(io::Error::other)?;
    Ok(builder.roots().clone())
}

fn find_container_init() -> io::Result<PathBuf> {
    if let Some(path) = std::env::var_os("RUST_SANDBOX_CONTAINER_INIT") {
        return Ok(path.into());
    }
    let current = std::env::current_exe()?;
    #[cfg(test)]
    if let Some(helper) = find_test_container_init(&current) {
        return Ok(helper);
    }
    Ok(resolve_container_init(&current))
}

/// Go's container.Builder defaults ExecFile to `/proc/self/exe`, which
/// re-executes the production server as the container PID 1. Rust cannot run
/// package init hooks, so the `go-judge` binary dispatches `container_init`
/// before starting its server (see `src/bin/go-judge.rs`). Keep this resolver
/// identical to Go's default; standalone helpers are explicit overrides only.
fn resolve_container_init(current: &Path) -> PathBuf {
    current.to_owned()
}

#[cfg(test)]
fn find_test_container_init(current: &Path) -> Option<PathBuf> {
    let direct = current.with_file_name("container-init");
    if direct.is_file() {
        return Some(direct);
    }
    if let Some(parent) = current.parent() {
        if parent.file_name().is_some_and(|name| name == "deps") {
            let sibling = parent.parent().unwrap_or(parent).join("container-init");
            if sibling.is_file() {
                return Some(sibling);
            }
        }
    }
    None
}

fn container_init_source(config: &LinuxEnvironmentConfig) -> io::Result<Option<PathBuf>> {
    if let Some(path) = config.container_init_path.as_ref() {
        if path.is_file() {
            return Ok(Some(path.clone()));
        }
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("container-init helper not found: {}", path.display()),
        ));
    }
    Ok(find_container_init().ok())
}

fn wait_namespace_child(parent_pid: i32, timeout: Duration) -> io::Result<i32> {
    let children_path = format!("/proc/{parent_pid}/task/{parent_pid}/children");
    let start = Instant::now();
    loop {
        match fs::read_to_string(&children_path) {
            Ok(children) => {
                if let Some(pid) = children
                    .split_whitespace()
                    .next()
                    .and_then(|value| value.parse::<i32>().ok())
                {
                    return Ok(pid);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        if start.elapsed() >= timeout {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "namespace keeper did not start in time",
            ));
        }
        thread::sleep(Duration::from_millis(2));
    }
}

fn prepare_mount_target(source: &Path, target: &Path) -> io::Result<()> {
    if source.is_dir() {
        fs::create_dir_all(target)
    } else {
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        OpenOptions::new()
            .create(true)
            .write(true)
            .open(target)
            .map(|_| ())
    }
}

fn create_symlinks(root: &Path, links: &[crate::env::Link]) -> io::Result<()> {
    for link in links {
        let path = root.join(normalize_container_path(&link.link_path)?.trim_start_matches('/'));
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let _ = fs::remove_file(&path);
        std::os::unix::fs::symlink(&link.target, path)?;
    }
    Ok(())
}

fn normalize_container_path(path: &str) -> io::Result<String> {
    let path = Path::new(path);
    let mut clean = PathBuf::from("/");
    for part in path.components() {
        match part {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(value) => clean.push(value),
            Component::ParentDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "path escapes container root",
                ));
            }
        }
    }
    Ok(clean.to_string_lossy().into_owned())
}

fn read_dotenv(path: &str) -> io::Result<Vec<String>> {
    let content = match fs::read_to_string(path) {
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
                None
            } else if line.contains('=') {
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

fn lookup_container_executable(
    root: &fs::File,
    work_dir: &str,
    name: &str,
    environment: &[String],
) -> io::Result<String> {
    if Path::new(name).file_name().is_none_or(|base| base != name) {
        return Ok(name.to_owned());
    }

    let is_executable = |container_path: &Path| {
        let relative = if container_path.is_absolute() {
            container_path
                .strip_prefix("/")
                .unwrap_or(container_path)
                .to_path_buf()
        } else {
            Path::new(work_dir.trim_start_matches('/')).join(container_path)
        };
        let how = OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_IN_ROOT | ResolveFlag::RESOLVE_NO_MAGICLINKS);
        openat2(root, &relative, how)
            .ok()
            .and_then(|fd| fs::File::from(fd).metadata().ok())
            .is_some_and(|metadata| !metadata.is_dir() && metadata.mode() & 0o111 != 0)
    };
    let work_path = Path::new(work_dir).join(name);
    if is_executable(&work_path) {
        return Ok(format!("./{name}"));
    }

    let path = environment
        .iter()
        .rev()
        .find_map(|entry| entry.strip_prefix("PATH="))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "no PATH environment variable provided for look up",
            )
        })?;
    for directory in path.split(':') {
        let directory = if directory.is_empty() { "." } else { directory };
        let candidate = Path::new(directory).join(name);
        if is_executable(&candidate) {
            let candidate = if candidate.is_absolute() {
                candidate
            } else {
                Path::new(".").join(candidate)
            };
            return Ok(candidate.to_string_lossy().into_owned());
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "executable file not found in $PATH",
    ))
}

fn cstring(value: &str) -> io::Result<CString> {
    CString::new(value).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in string"))
}
fn cstring_path(value: &Path) -> io::Result<CString> {
    CString::new(value.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))
}

fn chown_fd(fd: i32, uid: u32, gid: u32) -> io::Result<()> {
    if unsafe { libc::fchown(fd, uid as libc::uid_t, gid as libc::gid_t) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn is_anonymous_pipe(fd: i32) -> io::Result<bool> {
    let target = fs::read_link(format!("/proc/self/fd/{fd}"))?;
    Ok(target.to_string_lossy().starts_with("pipe:["))
}

struct RemoteProcessState {
    result: Option<ResultInfo>,
    usage: Usage,
    started: Instant,
    cgroup: Option<Box<dyn Cgroup>>,
    cgroup_pool: Option<Arc<dyn CgroupPool>>,
}

struct RemoteProcess {
    state: Arc<Mutex<RemoteProcessState>>,
    changed: Arc<Condvar>,
    async_changed: Arc<tokio::sync::Notify>,
    cancel: tokio::sync::watch::Sender<bool>,
}

impl RemoteProcess {
    fn new(
        cgroup: Option<Box<dyn Cgroup>>,
        cgroup_pool: Option<Arc<dyn CgroupPool>>,
    ) -> (Self, tokio::sync::watch::Receiver<bool>) {
        let (cancel, receiver) = tokio::sync::watch::channel(false);
        (
            Self {
                state: Arc::new(Mutex::new(RemoteProcessState {
                    result: None,
                    usage: Usage::default(),
                    started: Instant::now(),
                    cgroup,
                    cgroup_pool,
                })),
                changed: Arc::new(Condvar::new()),
                async_changed: Arc::new(tokio::sync::Notify::new()),
                cancel,
            },
            receiver,
        )
    }

    fn complete(&self, reply: io::Result<crate::container::protocol::Reply>) {
        let mut state = self.state.lock().unwrap();
        let (result, reported_usage) = match reply {
            Ok(reply) if reply.error.is_none() => match reply.exec_reply {
                Some(result) => {
                    let status = match result.status {
                        0 => Status::Normal,
                        1 => Status::Normal,
                        2 => Status::TimeLimitExceeded,
                        3 => Status::MemoryLimitExceeded,
                        4 => Status::OutputLimitExceeded,
                        5 => Status::DisallowedSyscall,
                        6 => Status::Signalled,
                        7 => Status::NonzeroExitStatus,
                        _ => Status::RunnerError,
                    };
                    let usage = Usage {
                        time: Duration::from_nanos(result.time_ns.max(0) as u64),
                        memory: Size(result.memory_bytes),
                    };
                    (
                        ResultInfo {
                            status,
                            exit_status: result.exit_status,
                            time: usage.time,
                            memory: usage.memory,
                            proc_peak: 0,
                            running_time: state.started.elapsed(),
                            ..Default::default()
                        },
                        usage,
                    )
                }
                None => (
                    ResultInfo {
                        status: Status::RunnerError,
                        error: "container init returned no execution result".into(),
                        ..Default::default()
                    },
                    Usage::default(),
                ),
            },
            Ok(reply) => (
                ResultInfo {
                    status: Status::RunnerError,
                    error: reply.error.map_or_else(
                        || "container init execution failed".into(),
                        |error| error.message,
                    ),
                    ..Default::default()
                },
                Usage::default(),
            ),
            Err(error) => (
                ResultInfo {
                    status: Status::RunnerError,
                    error: error.to_string(),
                    ..Default::default()
                },
                Usage::default(),
            ),
        };
        state.usage.time = state.usage.time.max(reported_usage.time);
        state.usage.memory = state.usage.memory.max(reported_usage.memory);
        let mut result = result;
        if let Some(group) = state.cgroup.as_mut() {
            result.time = result.time.max(group.cpu_usage().unwrap_or_default());
            result.memory = Size(
                group
                    .max_memory()
                    .ok()
                    .filter(|value| *value > 0)
                    .unwrap_or(result.memory.0),
            );
            result.proc_peak = group.proc_peak().unwrap_or_default();
        }
        result.time = result.time.max(state.usage.time);
        result.memory = result.memory.max(state.usage.memory);
        state.usage.time = result.time;
        state.usage.memory = result.memory;
        state.result = Some(result);
        if let Some(group) = state.cgroup.take() {
            if let Some(pool) = state.cgroup_pool.as_ref() {
                pool.put(group);
            }
        }
        self.changed.notify_all();
        self.async_changed.notify_one();
    }

    fn update_usage(&self) {
        let mut state = self.state.lock().unwrap();
        if state.result.is_some() {
            return;
        }
        if let Some(group) = state.cgroup.as_mut() {
            let time = group.cpu_usage().ok();
            let memory = group.current_memory().ok();
            if let Some(time) = time {
                state.usage.time = state.usage.time.max(time);
            }
            if let Some(memory) = memory {
                state.usage.memory = state.usage.memory.max(Size(memory));
            }
        }
    }
}

impl Process for Arc<RemoteProcess> {
    fn done(&self) -> bool {
        self.update_usage();
        self.state.lock().unwrap().result.is_some()
    }

    fn result(&self) -> ResultInfo {
        let mut state = self.state.lock().unwrap();
        while state.result.is_none() {
            state = self.changed.wait(state).unwrap();
        }
        state.result.clone().unwrap_or_default()
    }

    fn usage(&self) -> Usage {
        self.update_usage();
        self.state.lock().unwrap().usage
    }

    fn wait_timeout(&self, timeout: Duration) {
        if self.done() {
            return;
        }
        let state = self.state.lock().unwrap();
        if state.result.is_none() {
            let _ = self.changed.wait_timeout(state, timeout);
        }
    }

    fn wait_timeout_async<'a>(
        &'a self,
        timeout: Duration,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        let process = self.clone();
        let changed = self.async_changed.clone();
        Box::pin(async move {
            let notified = changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if process.done() {
                return;
            }
            tokio::select! {
                _ = &mut notified => {},
                _ = tokio::time::sleep(timeout) => {},
            }
        })
    }

    fn cancel(&self) {
        let _ = self.cancel.send(true);
    }
}

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
mod tests {
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
        let executable = Path::new("/opt/bin/go-judge-custom-name");
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
}
