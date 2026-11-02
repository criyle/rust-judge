//! Process creation for sandboxed commands.
//!
//! Eligible Linux x86-64 launches use clone3 with `CLONE_VM | CLONE_VFORK` on
//! a separate child stack. The child setup reads only prebuilt state, performs
//! syscalls, and immediately execs; it does not allocate, lock, unwind, or
//! mutate parent-owned configuration while the address space is shared.
//! Parent-coordinated user namespace, sync callback, and helper launches keep
//! the standard library's fork/exec path.

use crate::container::rlimit::RLimits;
use crate::container::seccomp::Filter;
use std::ffi::{CStr, CString};
use std::io::{Error, ErrorKind, Result};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use super::child::{Child, ChildProcess};
use super::namespace::{
    CapUserData, CapUserHeader, insert_setgroups_denied, optimized_namespace_exec, os_str,
    parse_cpu_mask,
};
use super::sync::{child_sync_with_parent, spawn_parent_sync, sync_socket_above_stdio};
use super::userns::{
    child_wait_for_parent_userns_map, requires_parent_userns_mapping, start_userns_map_handshake,
    userns_map_files, write_userns_maps,
};
use super::vfork::{
    child_errno_error, clone3_available, clone3_into_cgroup_available, clone3_vfork,
};

pub struct Runner {
    /// argv, with argv[0] naming the executable.
    pub args: Vec<CString>,
    /// Environment entries in `KEY=value` form.
    pub env: Vec<CString>,
    pub work_dir: CString,
    /// Chroot directory prepared by the container layer.
    pub container_root: Option<CString>,
    /// Bind mounts made inside the child's private mount namespace.
    pub bind_mounts: Vec<BindMount>,
    /// Fresh procfs mounts created inside the child's mount namespace.
    pub proc_mounts: Vec<ProcMount>,
    /// tmpfs mounts created in the same private mount namespace.
    pub tmpfs_mounts: Vec<TmpfsMount>,
    /// Overlay a fresh tmpfs on `container_root` before creating submounts.
    pub rootfs_tmpfs: bool,
    /// Symlinks created after mount setup, with paths already rooted in the
    /// container root directory.
    pub symlinks: Vec<(CString, CString)>,
    /// Paths masked after mounts and symlinks are in place.
    pub mask_paths: Vec<CString>,
    /// Parent descriptors copied to the matching child descriptor numbers.
    pub fd_map: Vec<i32>,
    /// Optional descriptor naming the executable, passed through procfs for
    /// execve after the child setup completes.
    pub exec_file: Option<i32>,
    /// Run through util-linux `unshare` and a post-namespace Rust exec helper.
    /// The helper path is inside `container_root` and installs seccomp just
    /// before replacing itself with the requested executable.
    pub pid_namespace_helper: Option<CString>,
    /// Additional namespaces created by util-linux before starting the helper.
    /// CLONE_NEWPID is always enabled by helper mode; CLONE_NEWUSER stays on
    /// the std::process child so the parent can install its ID maps safely.
    pub helper_unshare_flags: i32,
    /// Replace the standard helper `--seccomp-file ... -- executable` argv.
    /// Used to boot the persistent namespace init process.
    pub helper_args: Option<Vec<CString>>,
    /// Open cgroup.procs descriptors used by the payload after fork. A cgroup
    /// v2 execution has one entry; v1 may have one per controller hierarchy.
    pub cgroup_procs_fds: Vec<i32>,
    /// Optional cgroup directory descriptor for clone3(CLONE_INTO_CGROUP).
    pub cgroup_into_fd: Option<i32>,
    /// Index in `cgroup_procs_fds` already covered by `cgroup_into_fd`.
    pub cgroup_into_procs_index: Option<usize>,
    /// Existing user namespace to join in the single-threaded child. If the
    /// kernel rejects the join, `start` falls back to creating a mapped user
    /// namespace using `uid_map` and `gid_map`.
    pub user_namespace_fd: Option<i32>,
    /// Optional comma-separated CPU IDs/ranges for sched_setaffinity.
    pub cpu_set: Option<CString>,
    /// Process resource limits applied in the child before exec.
    pub rlimits: RLimits,
    pub pivot_root: Option<CString>,
    pub host_name: Option<CString>,
    pub domain_name: Option<CString>,
    /// Called in the parent with the child PID after child setup and before
    /// exec. The child waits for the callback to acknowledge completion. Keep
    /// the callback short because it runs inline on a Tokio worker task.
    pub sync_fn: Option<Box<dyn FnMut(i32) -> Result<()> + Send>>,
    /// Linux CLONE_NEW* flags. These are applied using `unshare` in the child.
    pub clone_flags: i32,
    pub credential: Option<Credential>,
    pub uid_map: Option<Vec<IdMap>>,
    pub gid_map: Option<Vec<IdMap>>,
    pub gid_map_enable_set_groups: bool,
    pub no_new_privs: bool,
    /// Classic BPF seccomp policy installed after credentials and limits.
    pub seccomp: Filter,
    pub drop_caps: bool,
    pub unshare_cgroup_after_sync: bool,
    pub control_tty: bool,
}

#[derive(Clone, Debug)]
pub struct BindMount {
    pub source: CString,
    pub target: CString,
    pub readonly: bool,
}

#[derive(Clone, Debug)]
pub struct TmpfsMount {
    pub target: CString,
    pub data: CString,
}

#[derive(Clone, Debug)]
pub struct ProcMount {
    pub target: CString,
    pub readonly: bool,
}

#[derive(Clone)]
pub struct IdMap {
    pub container_id: u32,
    pub host_id: u32,
    pub size: u32,
}

pub struct Credential {
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
    pub no_set_groups: bool,
}

type MountTargets = (Vec<Vec<u8>>, Vec<Vec<u8>>);

fn child_mount_targets(
    bind_mounts: &[(Vec<u8>, Vec<u8>, bool)],
    proc_mounts: &[(Vec<u8>, bool)],
    tmpfs_mounts: &[(Vec<u8>, Vec<u8>)],
    symlinks: &[(Vec<u8>, Vec<u8>)],
) -> Result<MountTargets> {
    let mut directories = Vec::new();
    let mut files = Vec::new();
    let mut add_parents = |path: &[u8], include_leaf: bool| {
        for (index, byte) in path.iter().enumerate().skip(1) {
            if *byte == b'/' {
                let mut prefix = path[..index].to_vec();
                prefix.push(0);
                directories.push(prefix);
            }
        }
        if include_leaf {
            directories.push(path.to_vec());
        }
    };
    for (source, target, _) in bind_mounts {
        let source = CStr::from_bytes_with_nul(source)
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid bind source"))?;
        let is_dir = std::fs::metadata(std::ffi::OsStr::from_bytes(source.to_bytes()))?.is_dir();
        add_parents(target, is_dir);
        if !is_dir {
            files.push(target.clone());
        }
    }
    for (target, _) in proc_mounts {
        add_parents(target, true);
    }
    for (target, _) in tmpfs_mounts {
        add_parents(target, true);
    }
    for (path, _) in symlinks {
        add_parents(path, false);
    }
    directories.sort_by_key(Vec::len);
    directories.dedup();
    files.sort_by_key(Vec::len);
    files.dedup();
    Ok((directories, files))
}

fn pivot_relative_target(path: &[u8]) -> Result<Vec<u8>> {
    let path = CStr::from_bytes_with_nul(path)
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid pivot mount target"))?
        .to_bytes();
    let relative = path.strip_prefix(b"/").unwrap_or(path);
    if relative
        .split(|byte| *byte == b'/')
        .any(|component| component == b"..")
    {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "pivot mount target escapes the new root",
        ));
    }
    let mut target = if relative.is_empty() {
        b".".to_vec()
    } else {
        relative.to_vec()
    };
    target.push(0);
    Ok(target)
}

mod start;

#[cfg(test)]
mod tests;
