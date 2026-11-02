use super::runner::IdMap;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Error, ErrorKind, Read, Result, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::thread;

pub(super) fn userns_map_files(
    flags: i32,
    uid_map: Option<&[IdMap]>,
    gid_map: Option<&[IdMap]>,
    gid_map_enable_set_groups: bool,
) -> Result<Vec<(CString, Vec<u8>)>> {
    if flags & libc::CLONE_NEWUSER == 0 {
        return Ok(Vec::new());
    }
    let uid_maps = uid_map.map(<[IdMap]>::to_vec).unwrap_or_else(|| {
        vec![IdMap {
            container_id: 0,
            host_id: unsafe { libc::geteuid() },
            size: 1,
        }]
    });
    let gid_maps = gid_map.map(<[IdMap]>::to_vec).unwrap_or_else(|| {
        vec![IdMap {
            container_id: 0,
            host_id: unsafe { libc::getegid() },
            size: 1,
        }]
    });
    let map_content = |maps: &[IdMap]| {
        let mut content = String::new();
        for mapping in maps {
            use std::fmt::Write as _;
            writeln!(
                content,
                "{} {} {}",
                mapping.container_id, mapping.host_id, mapping.size
            )
            .expect("writing to String cannot fail");
        }
        content.into_bytes()
    };
    let setgroups = if gid_map.is_some() && gid_map_enable_set_groups {
        b"allow".to_vec()
    } else {
        b"deny".to_vec()
    };
    Ok(vec![
        (
            CString::new("/proc/self/uid_map").unwrap(),
            map_content(&uid_maps),
        ),
        (CString::new("/proc/self/setgroups").unwrap(), setgroups),
        (
            CString::new("/proc/self/gid_map").unwrap(),
            map_content(&gid_maps),
        ),
    ])
}

pub(super) fn write_userns_maps(files: &[(CString, Vec<u8>)]) -> Result<()> {
    for (path, content) in files {
        let fd = nix::fcntl::open(
            path.as_c_str(),
            nix::fcntl::OFlag::O_WRONLY | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        )
        .map_err(|errno| Error::from_raw_os_error(errno as i32))?;
        let written = loop {
            match nix::unistd::write(&fd, content) {
                Err(nix::errno::Errno::EINTR) => continue,
                result => break result,
            }
        }
        .map_err(|errno| Error::from_raw_os_error(errno as i32))?;
        if written != content.len() {
            return Err(Error::new(
                ErrorKind::WriteZero,
                format!("short write to {}", path.to_string_lossy()),
            ));
        }
    }
    Ok(())
}

fn pipe_cloexec() -> Result<[OwnedFd; 2]> {
    let mut fds = [-1; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } == -1 {
        return Err(Error::last_os_error());
    }
    Ok(unsafe { [OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])] })
}

pub(super) struct UserNamespaceMapHandshake {
    pub(super) child_pid_write: OwnedFd,
    pub(super) child_ack_read: OwnedFd,
    pub(super) mapper: UserNamespaceMapper,
}

pub(super) enum UserNamespaceMapper {
    Tokio(std::sync::mpsc::Receiver<Result<()>>),
    LegacyThread(thread::JoinHandle<Result<()>>),
}

impl UserNamespaceMapper {
    pub(super) fn join(self) -> std::thread::Result<Result<()>> {
        match self {
            Self::Tokio(result) => match result.recv() {
                Ok(result) => Ok(result),
                Err(_) => Err(Box::new("Tokio user namespace mapper stopped")
                    as Box<dyn std::any::Any + Send>),
            },
            Self::LegacyThread(thread) => thread.join(),
        }
    }
}

pub(super) fn child_wait_for_parent_userns_map(pid_write: i32, ack_read: i32) -> Result<()> {
    let pid_bytes = unsafe { libc::getpid() }.to_ne_bytes();
    let mut offset = 0;
    while offset < pid_bytes.len() {
        let written = unsafe {
            libc::write(
                pid_write,
                pid_bytes[offset..].as_ptr().cast(),
                pid_bytes.len() - offset,
            )
        };
        if written == -1 {
            let error = Error::last_os_error();
            if error.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if written == 0 {
            return Err(Error::new(
                ErrorKind::WriteZero,
                "user namespace map handshake",
            ));
        }
        offset += written as usize;
    }
    let mut response = [0u8; 1];
    loop {
        let read = unsafe { libc::read(ack_read, response.as_mut_ptr().cast(), 1) };
        if read == -1 {
            let error = Error::last_os_error();
            if error.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if read == 0 {
            return Err(Error::new(
                ErrorKind::BrokenPipe,
                "user namespace map parent exited",
            ));
        }
        break;
    }
    if response[0] == 1 {
        Ok(())
    } else {
        Err(Error::new(
            ErrorKind::PermissionDenied,
            "parent could not install user namespace maps",
        ))
    }
}

pub(super) fn requires_parent_userns_mapping(
    flags: i32,
    uid_map: Option<&[IdMap]>,
    gid_map: Option<&[IdMap]>,
) -> bool {
    if flags & libc::CLONE_NEWUSER == 0 {
        return false;
    }
    let is_self_mapping = |maps: Option<&[IdMap]>, current_id| {
        maps.is_some_and(|maps| {
            maps.len() == 1 && maps[0].host_id == current_id && maps[0].size == 1
        })
    };
    !is_self_mapping(uid_map, unsafe { libc::geteuid() })
        || !is_self_mapping(gid_map, unsafe { libc::getegid() })
}

pub(super) fn start_userns_map_handshake(
    files: Vec<(CString, Vec<u8>)>,
) -> Result<UserNamespaceMapHandshake> {
    let [pid_read, pid_write] = pipe_cloexec()?;
    let [ack_read, ack_write] = pipe_cloexec()?;
    let mapper_work = move || {
        let mut pid_read = File::from(pid_read);
        let mut ack_write = File::from(ack_write);
        loop {
            let mut pid_bytes = [0u8; std::mem::size_of::<libc::pid_t>()];
            match pid_read.read_exact(&mut pid_bytes) {
                Ok(()) => {}
                Err(error) if error.kind() == ErrorKind::UnexpectedEof => return Ok(()),
                Err(error) => return Err(error),
            }
            let pid = libc::pid_t::from_ne_bytes(pid_bytes);
            let mapping: Result<()> = (|| {
                for (source, content) in &files {
                    let path = source
                        .to_string_lossy()
                        .replace("/proc/self/", &format!("/proc/{pid}/"));
                    let mut file = OpenOptions::new().write(true).open(path)?;
                    file.write_all(content)?;
                }
                Ok(())
            })();
            ack_write.write_all(&[u8::from(mapping.is_ok())])?;
            mapping?;
        }
    };
    let mapper = if std::env::var_os("RUST_SANDBOX_ABLATION_STD_USERNS_MAPPER").is_some() {
        UserNamespaceMapper::LegacyThread(
            thread::Builder::new()
                .name("rust-sandbox-userns-map".into())
                .spawn(mapper_work)?,
        )
    } else {
        UserNamespaceMapper::Tokio(crate::tokio_runtime::spawn_blocking(mapper_work))
    };
    Ok(UserNamespaceMapHandshake {
        child_pid_write: pid_write,
        child_ack_read: ack_read,
        mapper,
    })
}
