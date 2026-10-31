//! Environment construction and lifecycle abstractions translated from
//! `go-judge/env`. Linux mount and namespace planning is supported here;
//! platform backends that need operating-system-specific process APIs remain
//! explicitly unsupported until their native implementation is added.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(target_os = "linux")]
pub mod cgroup_v1;
#[cfg(target_os = "linux")]
pub mod linux_environment;
pub mod linuxcontainer;
pub mod macsandbox;
pub mod pool;
pub mod seccomp_policy;
pub mod winc;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub container_init_path: String,
    pub tmp_fs_param: String,
    pub net_share: bool,
    pub mount_conf: String,
    pub seccomp_conf: String,
    pub no_seccomp: bool,
    pub cgroup_prefix: String,
    pub container_cred_start: i32,
    pub enable_cpu_rate: bool,
    pub cpu_cfs_period: Duration,
    pub no_fallback: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct MountConfig {
    #[serde(rename = "mount")]
    pub mounts: Vec<Mount>,
    #[serde(rename = "symLink")]
    pub symlinks: Vec<Link>,
    #[serde(rename = "maskPath")]
    pub mask_paths: Vec<String>,
    #[serde(rename = "initCmd")]
    pub init_cmd: String,
    #[serde(rename = "workDir")]
    pub work_dir: String,
    #[serde(rename = "hostName")]
    pub host_name: String,
    #[serde(rename = "domainName")]
    pub domain_name: String,
    pub uid: i32,
    pub gid: i32,
    pub proc: bool,
    #[serde(rename = "procrw")]
    pub proc_rw: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Mount {
    #[serde(rename = "type")]
    pub kind: String,
    pub source: String,
    pub target: String,
    pub readonly: bool,
    pub data: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Link {
    #[serde(rename = "linkPath")]
    pub link_path: String,
    pub target: String,
}

/// Resolved mount operation matching Go's bind/tmpfs mount builder inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MountOperation {
    Bind {
        source: PathBuf,
        target: PathBuf,
        readonly: bool,
    },
    Tmpfs {
        target: PathBuf,
        data: String,
    },
    Proc {
        readonly: bool,
    },
}

pub const DEFAULT_WORK_DIR: &str = "/w";
pub const DEFAULT_CONTAINER_NAME: &str = "executor_server";
pub const DEFAULT_CONTAINER_CRED: i32 = 1000;

pub const DEFAULT_SYMLINKS: &[(&str, &str)] = &[
    ("/dev/fd", "/proc/self/fd"),
    ("/dev/stdin", "/proc/self/fd/0"),
    ("/dev/stdout", "/proc/self/fd/1"),
    ("/dev/stderr", "/proc/self/fd/2"),
];

pub const DEFAULT_MASK_PATHS: &[&str] = &[
    "/sys/firmware",
    "/sys/devices/virtual/powercap",
    "/proc/acpi",
    "/proc/asound",
    "/proc/kcore",
    "/proc/keys",
    "/proc/latency_stats",
    "/proc/timer_list",
    "/proc/timer_stats",
    "/proc/sched_debug",
    "/proc/scsi",
    "/usr/lib/wsl/drivers",
    "/usr/lib/wsl/lib",
];

/// Default Linux rootfs mounts from `env/mount_linux.go`. Missing host sources
/// are left in the plan and can be removed by the caller's existence filter.
pub fn default_mounts(tmpfs_data: &str) -> Vec<MountOperation> {
    let mut mounts = Vec::new();
    for source in [
        "/bin",
        "/lib",
        "/lib64",
        "/usr",
        "/etc/ld.so.cache",
        "/etc/alternatives",
        "/etc/fpc.cfg",
        "/etc/mono",
        "/etc/java-21-openjdk",
        "/var/lib/ghc",
    ] {
        mounts.push(MountOperation::Bind {
            source: source.into(),
            target: Path::new(source).strip_prefix("/").unwrap().into(),
            readonly: true,
        });
    }
    mounts.push(MountOperation::Proc { readonly: true });
    for source in [
        "/dev/null",
        "/dev/urandom",
        "/dev/random",
        "/dev/zero",
        "/dev/full",
    ] {
        mounts.push(MountOperation::Bind {
            source: source.into(),
            target: Path::new(source).strip_prefix("/").unwrap().into(),
            readonly: false,
        });
    }
    mounts.push(MountOperation::Tmpfs {
        target: "w".into(),
        data: tmpfs_data.into(),
    });
    mounts.push(MountOperation::Tmpfs {
        target: "tmp".into(),
        data: tmpfs_data.into(),
    });
    mounts
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedMountConfig {
    pub mounts: Vec<MountOperation>,
    pub symlinks: Vec<Link>,
    pub mask_paths: Vec<String>,
}

pub fn prepare_mount_config(
    config: Option<&MountConfig>,
    cwd: &Path,
    tmpfs_data: &str,
) -> std::io::Result<PreparedMountConfig> {
    let Some(config) = config else {
        return Ok(PreparedMountConfig {
            mounts: default_mounts(tmpfs_data),
            symlinks: DEFAULT_SYMLINKS
                .iter()
                .map(|(link_path, target)| Link {
                    link_path: (*link_path).into(),
                    target: (*target).into(),
                })
                .collect(),
            mask_paths: DEFAULT_MASK_PATHS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
        });
    };
    Ok(PreparedMountConfig {
        mounts: parse_mount_config(config, cwd)?,
        symlinks: if config.symlinks.is_empty() {
            DEFAULT_SYMLINKS
                .iter()
                .map(|(link_path, target)| Link {
                    link_path: (*link_path).into(),
                    target: (*target).into(),
                })
                .collect()
        } else {
            config.symlinks.clone()
        },
        mask_paths: if config.mask_paths.is_empty() {
            DEFAULT_MASK_PATHS
                .iter()
                .map(|s| (*s).to_string())
                .collect()
        } else {
            config.mask_paths.clone()
        },
    })
}

pub fn filter_missing_sources(mounts: Vec<MountOperation>) -> Vec<MountOperation> {
    mounts
        .into_iter()
        .filter(|mount| match mount {
            MountOperation::Bind { source, .. } => source.exists(),
            MountOperation::Tmpfs { .. } | MountOperation::Proc { .. } => true,
        })
        .collect()
}

pub fn to_mount_builder(operations: &[MountOperation]) -> crate::container::mount::Builder {
    operations.iter().fold(
        crate::container::mount::Builder::new(),
        |builder, op| match op {
            MountOperation::Bind {
                source,
                target,
                readonly,
            } => builder.with_bind(
                source.to_string_lossy().into_owned(),
                target.to_string_lossy().into_owned(),
                *readonly,
            ),
            MountOperation::Tmpfs { target, data } => {
                builder.with_tmpfs(target.to_string_lossy().into_owned(), data.clone())
            }
            MountOperation::Proc { readonly } => builder.with_proc_rw(!readonly),
        },
    )
}

pub fn read_mount_config(path: impl AsRef<Path>) -> std::io::Result<MountConfig> {
    let bytes = std::fs::read(path)?;
    serde_yaml::from_slice(&bytes).map_err(std::io::Error::other)
}

/// Convert configured paths to mount operations. Relative sources resolve
/// against `cwd`; absolute targets are rooted in the container namespace.
pub fn parse_mount_config(
    config: &MountConfig,
    cwd: &Path,
) -> std::io::Result<Vec<MountOperation>> {
    let mut result = Vec::with_capacity(config.mounts.len() + usize::from(config.proc));
    for mount in &config.mounts {
        let target = normalize_target(&mount.target)?;
        let operation = match mount.kind.as_str() {
            "bind" => {
                let source = Path::new(&mount.source);
                let source = if source.is_absolute() {
                    source.to_path_buf()
                } else {
                    cwd.join(source)
                };
                MountOperation::Bind {
                    source,
                    target,
                    readonly: mount.readonly,
                }
            }
            "tmpfs" => MountOperation::Tmpfs {
                target,
                data: mount.data.clone(),
            },
            other => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid_mount_type: {other}"),
                ));
            }
        };
        result.push(operation);
    }
    if config.proc {
        result.push(MountOperation::Proc {
            readonly: !config.proc_rw,
        });
    }
    Ok(result)
}

fn normalize_target(target: &str) -> std::io::Result<PathBuf> {
    let path = Path::new(target);
    let relative = if path.is_absolute() {
        path.strip_prefix("/").unwrap_or(path)
    } else {
        path
    };
    let normalized = relative
        .components()
        .filter(|c| !matches!(c, std::path::Component::CurDir))
        .collect::<PathBuf>();
    if normalized
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "mount target escapes container root",
        ));
    }
    Ok(normalized)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerMeta {
    pub host_name: String,
    pub domain_name: String,
    pub work_dir: String,
    pub uid: i32,
    pub gid: i32,
    pub init_cmd: Vec<String>,
}

pub fn container_meta(config: Option<&MountConfig>) -> std::io::Result<ContainerMeta> {
    let mut meta = ContainerMeta {
        host_name: DEFAULT_CONTAINER_NAME.into(),
        domain_name: DEFAULT_CONTAINER_NAME.into(),
        work_dir: DEFAULT_WORK_DIR.into(),
        uid: DEFAULT_CONTAINER_CRED,
        gid: DEFAULT_CONTAINER_CRED,
        init_cmd: Vec::new(),
    };
    if let Some(c) = config {
        if !c.host_name.is_empty() {
            meta.host_name.clone_from(&c.host_name);
        }
        if !c.domain_name.is_empty() {
            meta.domain_name.clone_from(&c.domain_name);
        }
        if !c.work_dir.is_empty() {
            meta.work_dir.clone_from(&c.work_dir);
        }
        if c.uid != 0 {
            meta.uid = c.uid;
        }
        if c.gid != 0 {
            meta.gid = c.gid;
        }
        if !c.init_cmd.trim().is_empty() {
            meta.init_cmd = split_command(&c.init_cmd)?;
        }
    }
    Ok(meta)
}

/// Small shell-like word splitter for `initCmd`; supports quotes and escapes.
pub fn split_command(input: &str) -> std::io::Result<Vec<String>> {
    let mut words = Vec::new();
    let (mut word, mut quote, mut escaped, mut started) = (String::new(), None, false, false);
    for ch in input.chars() {
        if escaped {
            word.push(ch);
            escaped = false;
            started = true;
            continue;
        }
        match (quote, ch) {
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (Some('"'), '\\') => escaped = true,
            (Some(q), _) if Some(q) == quote => word.push(ch),
            (None, '\'' | '"') => {
                quote = Some(ch);
                started = true;
            }
            (None, '\\') => {
                escaped = true;
                started = true;
            }
            (None, c) if c.is_whitespace() => {
                if started {
                    words.push(std::mem::take(&mut word));
                    started = false;
                }
            }
            (_, c) => {
                word.push(c);
                started = true;
            }
        }
    }
    if escaped || quote.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "unterminated quote or escape in initCmd",
        ));
    }
    if started {
        words.push(word);
    }
    Ok(words)
}

#[cfg(target_os = "linux")]
pub fn unshare_flags(net_share: bool, kernel: (u32, u32)) -> (libc::c_int, bool) {
    let mut flags = libc::CLONE_NEWIPC
        | libc::CLONE_NEWNS
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWUSER
        | libc::CLONE_NEWUTS;
    if !net_share {
        flags |= libc::CLONE_NEWNET;
    }
    (flags, kernel >= (4, 6))
}

pub fn kernel_version_at_least(
    major: u32,
    minor: u32,
    required_major: u32,
    required_minor: u32,
) -> bool {
    (major, minor) >= (required_major, required_minor)
}

#[cfg(target_os = "linux")]
pub fn kernel_version() -> std::io::Result<(u32, u32)> {
    let mut uname = std::mem::MaybeUninit::<libc::utsname>::uninit();
    // SAFETY: uname initializes the supplied utsname on success.
    if unsafe { libc::uname(uname.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: uname succeeded, so release is NUL terminated.
    let release =
        unsafe { std::ffi::CStr::from_ptr((*uname.as_ptr()).release.as_ptr()) }.to_string_lossy();
    let mut components = release.split('.');
    let parse = |s: Option<&str>| {
        s.unwrap_or_default()
            .chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>()
            .parse::<u32>()
            .unwrap_or(0)
    };
    Ok((parse(components.next()), parse(components.next())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mount_yaml_and_resolves_paths() {
        let config: MountConfig = serde_yaml::from_str("mount:\n  - type: bind\n    source: data\n    target: /work/data\n    readonly: true\n  - type: tmpfs\n    target: /tmp\n    data: size=8m\nproc: true\nprocrw: false\n").unwrap();
        let mounts = parse_mount_config(&config, Path::new("/srv/app")).unwrap();
        assert_eq!(
            mounts,
            vec![
                MountOperation::Bind {
                    source: PathBuf::from("/srv/app/data"),
                    target: PathBuf::from("work/data"),
                    readonly: true
                },
                MountOperation::Tmpfs {
                    target: PathBuf::from("tmp"),
                    data: "size=8m".into()
                },
                MountOperation::Proc { readonly: true },
            ]
        );
    }

    #[test]
    fn rejects_unknown_mount_types_and_root_escape() {
        let c = MountConfig {
            mounts: vec![Mount {
                kind: "wat".into(),
                ..Mount::default()
            }],
            ..MountConfig::default()
        };
        assert_eq!(
            parse_mount_config(&c, Path::new("/")).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        assert!(normalize_target("../../host").is_err());
    }

    #[test]
    fn metadata_and_init_command_defaults_match_go() {
        let meta = container_meta(Some(&MountConfig {
            init_cmd: "sh -c 'echo hello'".into(),
            ..MountConfig::default()
        }))
        .unwrap();
        assert_eq!(meta.host_name, "executor_server");
        assert_eq!(meta.work_dir, "/w");
        assert_eq!(meta.init_cmd, ["sh", "-c", "echo hello"]);
    }

    #[test]
    fn default_mounts_and_fallback_symlinks_match_go_policy() {
        let prepared = prepare_mount_config(None, Path::new("/"), "size=64m").unwrap();
        assert!(
            prepared
                .mounts
                .contains(&MountOperation::Proc { readonly: true })
        );
        assert!(prepared.mounts.contains(&MountOperation::Tmpfs {
            target: "w".into(),
            data: "size=64m".into()
        }));
        assert_eq!(prepared.symlinks.len(), 4);
        assert!(prepared.mask_paths.contains(&"/proc/kcore".to_string()));
        let builder = to_mount_builder(&prepared.mounts);
        assert_eq!(builder.mounts.len(), prepared.mounts.len());
        assert!(
            builder
                .mounts
                .iter()
                .any(|m| m.is_bind_mount() && m.is_read_only())
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_unshare_flags_honor_network_and_kernel_version() {
        let (flags, unshare_cgroup_after_exec) = unshare_flags(true, (6, 8));
        assert_eq!(flags & libc::CLONE_NEWNET, 0);
        assert_eq!(flags & libc::CLONE_NEWCGROUP, 0);
        assert!(unshare_cgroup_after_exec);
        let (_, old_kernel) = unshare_flags(false, (4, 5));
        assert!(!old_kernel);
        assert!(!kernel_version_at_least(6, 8, 6, 9));
        assert!(kernel_version_at_least(7, 0, 6, 9));
    }
}
