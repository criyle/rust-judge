//! Mount configuration and fork-exec syscall argument preparation.
use std::ffi::CString;
use std::fmt;
use std::io;
use std::path::Path;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Mount {
    pub source: String,
    pub target: String,
    pub fs_type: String,
    pub data: String,
    pub flags: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyscallParams {
    pub source: CString,
    pub target: CString,
    pub fs_type: CString,
    pub data: Option<CString>,
    pub flags: u64,
    pub prefixes: Vec<CString>,
    pub make_node: bool,
}

impl Mount {
    pub fn is_bind_mount(&self) -> bool {
        self.flags & libc::MS_BIND != 0
    }
    pub fn is_read_only(&self) -> bool {
        self.flags & libc::MS_RDONLY != 0
    }
    pub fn is_tmpfs(&self) -> bool {
        self.fs_type == "tmpfs"
    }

    pub fn to_syscall(&self) -> io::Result<SyscallParams> {
        let cstr = |s: &str| {
            CString::new(s).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "mount argument contains NUL byte",
                )
            })
        };
        let mut prefixes = Vec::new();
        for (index, byte) in self.target.bytes().enumerate().skip(1) {
            if byte == b'/' {
                prefixes.push(cstr(&self.target[..index])?);
            }
        }
        prefixes.push(cstr(&self.target)?);
        Ok(SyscallParams {
            source: cstr(&self.source)?,
            target: cstr(&self.target)?,
            fs_type: cstr(&self.fs_type)?,
            data: if self.data.is_empty() {
                None
            } else {
                Some(cstr(&self.data)?)
            },
            flags: self.flags,
            prefixes,
            make_node: false,
        })
    }

    /// Create the target and issue the mount syscall. This generally requires
    /// the appropriate mount namespace and privileges.
    pub fn mount(&self) -> io::Result<()> {
        ensure_target_exists(&self.source, &self.target, self.is_bind_mount())?;
        let params = self.to_syscall()?;
        // SAFETY: all pointers reference NUL terminated strings kept alive for
        // the duration of the syscall; a null data pointer means no mount data.
        let result = unsafe {
            libc::mount(
                params.source.as_ptr(),
                params.target.as_ptr(),
                params.fs_type.as_ptr(),
                params.flags as libc::c_ulong,
                params
                    .data
                    .as_ref()
                    .map_or(std::ptr::null(), |d| d.as_ptr().cast()),
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        if self.is_bind_mount() && self.is_read_only() {
            let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
            let source = CString::new(self.source.as_str()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "mount source contains NUL byte",
                )
            })?;
            // SAFETY: statvfs initializes the supplied structure on success.
            if unsafe { libc::statvfs(source.as_ptr(), stat.as_mut_ptr()) } != 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: statvfs returned success above.
            let stat = unsafe { stat.assume_init() };
            let preserve = (libc::MS_NOSUID
                | libc::MS_NODEV
                | libc::MS_NOEXEC
                | libc::MS_NOATIME
                | libc::MS_NODIRATIME
                | libc::MS_RELATIME) as libc::c_ulong;
            let flags = params.flags as libc::c_ulong
                | libc::MS_REMOUNT as libc::c_ulong
                | (stat.f_flag as libc::c_ulong & preserve);
            let empty = b"\0";
            // SAFETY: mount target and filesystem strings remain live; empty
            // source/data strings are static and NUL terminated.
            let result = unsafe {
                libc::mount(
                    empty.as_ptr().cast(),
                    params.target.as_ptr(),
                    params.fs_type.as_ptr(),
                    flags,
                    params
                        .data
                        .as_ref()
                        .map_or(std::ptr::null(), |d| d.as_ptr().cast()),
                )
            };
            if result != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

fn ensure_target_exists(source: &str, target: &str, bind: bool) -> io::Result<()> {
    let file_source = if bind {
        Some(
            std::fs::metadata(source)
                .map_err(|e| io::Error::other(format!("stat mount source: {e}")))?
                .is_file(),
        )
    } else {
        None
    };
    let target_path = Path::new(target);
    if file_source == Some(true) {
        if let Some(parent) = target_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        match std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(target)
        {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(e),
        }
    } else {
        std::fs::create_dir_all(target_path)
    }
}

impl fmt::Display for Mount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ro = if self.is_read_only() { "ro" } else { "rw" };
        if self.is_bind_mount() {
            return write!(f, "bind[{}:{}:{}]", self.source, self.target, ro);
        }
        match self.fs_type.as_str() {
            "tmpfs" => write!(f, "tmpfs[{}]", self.target),
            "proc" => write!(f, "proc[{ro}]"),
            _ => write!(
                f,
                "mount[{},{}:{}:{:x},{}]",
                self.fs_type, self.source, self.target, self.flags, self.data
            ),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Builder {
    pub mounts: Vec<Mount>,
}

impl Builder {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_mount(mut self, mount: Mount) -> Self {
        self.mounts.push(mount);
        self
    }
    pub fn with_mounts(mut self, mounts: impl IntoIterator<Item = Mount>) -> Self {
        self.mounts.extend(mounts);
        self
    }
    pub fn with_bind(
        mut self,
        source: impl Into<String>,
        target: impl Into<String>,
        readonly: bool,
    ) -> Self {
        let mut flags = libc::MS_BIND | libc::MS_NOSUID | libc::MS_PRIVATE | libc::MS_REC;
        if readonly {
            flags |= libc::MS_RDONLY;
        }
        self.mounts.push(Mount {
            source: source.into(),
            target: target.into(),
            flags,
            ..Default::default()
        });
        self
    }
    pub fn with_tmpfs(mut self, target: impl Into<String>, data: impl Into<String>) -> Self {
        self.mounts.push(Mount {
            source: "tmpfs".into(),
            target: target.into(),
            fs_type: "tmpfs".into(),
            data: data.into(),
            flags: libc::MS_NOSUID | libc::MS_NOATIME | libc::MS_NODEV,
        });
        self
    }
    pub fn with_proc(self) -> Self {
        self.with_proc_rw(false)
    }
    pub fn with_proc_rw(mut self, can_write: bool) -> Self {
        let mut flags = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
        if !can_write {
            flags |= libc::MS_RDONLY;
        }
        self.mounts.push(Mount {
            source: "proc".into(),
            target: "proc".into(),
            fs_type: "proc".into(),
            flags,
            ..Default::default()
        });
        self
    }
    pub fn filter_not_exist(mut self) -> Self {
        self.mounts
            .retain(|m| !m.is_bind_mount() || Path::new(&m.source).exists());
        self
    }
    pub fn build(&self) -> io::Result<Vec<SyscallParams>> {
        self.mounts
            .iter()
            .map(|m| {
                let mut params = m.to_syscall()?;
                if m.is_bind_mount() {
                    let meta = std::fs::metadata(&m.source)?;
                    params.make_node = !meta.is_dir();
                }
                Ok(params)
            })
            .collect()
    }
}

impl fmt::Display for Builder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Mounts: ")?;
        for (i, mount) in self.mounts.iter().enumerate() {
            if i != 0 {
                f.write_str(", ")?;
            }
            write!(f, "{mount}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn describes_mounts_and_builds_prefixes() {
        let m = Mount {
            source: "/src".into(),
            target: "/a/b/c".into(),
            flags: libc::MS_BIND,
            ..Default::default()
        };
        assert_eq!(m.to_string(), "bind[/src:/a/b/c:rw]");
        let p = m.to_syscall().unwrap();
        assert_eq!(
            p.prefixes
                .iter()
                .map(|p| p.to_str().unwrap())
                .collect::<Vec<_>>(),
            ["/a", "/a/b", "/a/b/c"]
        );
    }

    #[test]
    fn builder_flags_and_display_match_go() {
        let b = Builder::new()
            .with_bind("/src", "/dst", true)
            .with_tmpfs("/tmp", "size=64m")
            .with_proc();
        assert!(b.mounts[0].is_read_only());
        assert!(b.mounts[1].is_tmpfs());
        assert!(b.mounts[2].is_read_only());
        assert!(b.to_string().contains("tmpfs[/tmp]"));
    }

    #[test]
    fn build_marks_file_bind_mounts_and_rejects_missing_sources() {
        let dir = std::env::temp_dir().join(format!("rust-sandbox-mount-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("source");
        fs::write(&file, b"x").unwrap();
        let b = Builder::new().with_bind(file.to_string_lossy(), "/target", false);
        assert!(b.build().unwrap()[0].make_node);
        assert!(
            Builder::new()
                .with_bind(dir.join("missing").to_string_lossy(), "/dst", false)
                .build()
                .is_err()
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
