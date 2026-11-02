use super::*;

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
