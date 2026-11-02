use super::prelude::*;

pub(super) fn bench_command(args: &[&str], files: Vec<Option<EnvFile>>) -> Cmd {
    Cmd {
        environment: Arc::new(BenchEnvironment),
        copy_in: Default::default(),
        symlinks: Default::default(),
        args: args.iter().map(|arg| (*arg).to_owned()).collect(),
        env: vec!["PATH=/usr/bin:/bin".into()],
        files,
        tty: false,
        terminal_resize: None,
        time_limit: std::time::Duration::ZERO,
        clock_limit: std::time::Duration::ZERO,
        memory_limit: Default::default(),
        stack_limit: Default::default(),
        extra_memory_limit: Default::default(),
        output_limit: Default::default(),
        proc_limit: 0,
        open_file_limit: 0,
        cpu_rate_limit: 0,
        cpu_set_limit: String::new(),
        copy_out: Vec::new(),
        copy_out_max: Default::default(),
        copy_out_truncate: false,
        address_space_limit: false,
        data_segment_limit: false,
    }
}

pub(super) fn bench_null_stdio() -> EnvFile {
    EnvFile::opened(
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .expect("open /dev/null for benchmark stdio"),
    )
}

struct BenchEnvironment;
struct BenchProcess {
    child: Mutex<Child>,
    result: Mutex<Option<rust_judge::runner::ResultInfo>>,
    started: Instant,
}

impl Environment for BenchEnvironment {
    fn execve(&self, param: ExecveParam) -> io::Result<Box<dyn rust_judge::envexec::Process>> {
        let Some(program) = param.args.first() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "missing program",
            ));
        };
        let mut command = Command::new(program);
        command.args(&param.args[1..]).env_clear();
        for entry in &param.env {
            if let Some((key, value)) = entry.split_once('=') {
                command.env(key, value);
            }
        }
        if param.files.len() > 3 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "benchmark environment only maps standard descriptors",
            ));
        }
        for (index, fd) in param.files.iter().copied().enumerate() {
            let duplicated = unsafe { libc::fcntl(fd as i32, libc::F_DUPFD_CLOEXEC, 0) };
            if duplicated < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: dup returned a new descriptor owned by this File.
            let file = unsafe { std::fs::File::from_raw_fd(duplicated) };
            match index {
                0 => command.stdin(Stdio::from(file)),
                1 => command.stdout(Stdio::from(file)),
                2 => command.stderr(Stdio::from(file)),
                _ => unreachable!(),
            };
        }
        let child = command.spawn()?;
        Ok(Box::new(BenchProcess {
            child: Mutex::new(child),
            result: Mutex::new(None),
            started: Instant::now(),
        }))
    }

    fn open(&self, params: &[OpenParam]) -> io::Result<Vec<OpenResult>> {
        if params.is_empty() {
            Ok(Vec::new())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "pipe benchmarks do not open container paths",
            ))
        }
    }

    fn symlink(&self, params: &[SymlinkParam]) -> io::Result<Vec<Option<String>>> {
        if params.is_empty() {
            Ok(Vec::new())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "pipe benchmarks do not create symlinks",
            ))
        }
    }
}

impl rust_judge::envexec::Process for BenchProcess {
    fn done(&self) -> bool {
        let mut result = self.result.lock().expect("benchmark process result lock");
        if result.is_some() {
            return true;
        }
        let mut child = self.child.lock().expect("benchmark child lock");
        match child.try_wait() {
            Ok(Some(status)) => {
                *result = Some(bench_result(status, self.started.elapsed()));
                true
            }
            Ok(None) => false,
            Err(error) => {
                *result = Some(rust_judge::runner::ResultInfo {
                    status: rust_judge::runner::Status::RunnerError,
                    error: error.to_string(),
                    ..Default::default()
                });
                true
            }
        }
    }

    fn result(&self) -> rust_judge::runner::ResultInfo {
        if !self.done() {
            let status = self.child.lock().expect("benchmark child lock").wait();
            let mut result = self.result.lock().expect("benchmark process result lock");
            if result.is_none() {
                *result = Some(match status {
                    Ok(status) => bench_result(status, self.started.elapsed()),
                    Err(error) => rust_judge::runner::ResultInfo {
                        status: rust_judge::runner::Status::RunnerError,
                        error: error.to_string(),
                        ..Default::default()
                    },
                });
            }
        }
        self.result
            .lock()
            .expect("benchmark process result lock")
            .clone()
            .unwrap_or_default()
    }

    fn usage(&self) -> rust_judge::envexec::Usage {
        rust_judge::envexec::Usage::default()
    }

    fn cancel(&self) {
        let _ = self.child.lock().expect("benchmark child lock").kill();
    }

    fn wait_timeout(&self, timeout: std::time::Duration) {
        thread::sleep(timeout.min(std::time::Duration::from_millis(1)));
    }
}

fn bench_result(
    status: ExitStatus,
    elapsed: std::time::Duration,
) -> rust_judge::runner::ResultInfo {
    let (status_kind, exit_status) = if status.success() {
        (rust_judge::runner::Status::Normal, 0)
    } else if let Some(code) = status.code() {
        (rust_judge::runner::Status::NonzeroExitStatus, code)
    } else {
        (
            rust_judge::runner::Status::Signalled,
            status.signal().unwrap_or(0),
        )
    };
    rust_judge::runner::ResultInfo {
        status: status_kind,
        exit_status,
        running_time: elapsed,
        ..Default::default()
    }
}

pub(super) struct CgroupV2Cleanup(pub(super) Option<CgroupV2>);
impl Drop for CgroupV2Cleanup {
    fn drop(&mut self) {
        if let Some(cgroup) = self.0.take() {
            let _ = Box::new(cgroup).destroy();
        }
    }
}

pub(super) struct CgroupCleanup(pub(super) Option<Box<dyn Cgroup>>);
impl CgroupCleanup {
    pub(super) fn destroy(&mut self) -> std::io::Result<()> {
        if let Some(cgroup) = self.0.take() {
            cgroup
                .destroy()
                .map_err(|error| std::io::Error::other(error.to_string()))?;
        }
        Ok(())
    }
}
impl Drop for CgroupCleanup {
    fn drop(&mut self) {
        let _ = self.destroy();
    }
}

pub(super) fn cgroup_bench_root() -> Option<std::path::PathBuf> {
    let raw = std::env::var_os("RUST_SANDBOX_CGROUP_V2_BENCH_ROOT")?;
    let path = std::path::PathBuf::from(raw).canonicalize().ok()?;
    let cgroup_mount = std::path::Path::new("/sys/fs/cgroup").canonicalize().ok()?;
    if path == cgroup_mount || !path.starts_with(&cgroup_mount) || !path.is_dir() {
        return None;
    }
    Some(path)
}

pub(super) fn delegated_cgroup_cpus(root: &std::path::Path) -> Result<String, String> {
    let controllers = std::fs::read_to_string(root.join("cgroup.controllers"))
        .map_err(|error| format!("cannot read delegated controllers: {error}"))?;
    let enabled = std::fs::read_to_string(root.join("cgroup.subtree_control"))
        .map_err(|error| format!("cannot read subtree controller delegation: {error}"))?;
    for controller in ["cpu", "cpuset", "memory", "pids"] {
        if !controllers
            .split_whitespace()
            .any(|item| item == controller)
        {
            return Err(format!("controller {controller} is unavailable"));
        }
        if !enabled.split_whitespace().any(|item| item == controller) {
            return Err(format!(
                "controller {controller} is not enabled in subtree_control"
            ));
        }
    }
    let cpus = std::fs::read_to_string(root.join("cpuset.cpus.effective"))
        .map_err(|error| format!("cannot read effective cpuset: {error}"))?;
    let first = cpus
        .trim()
        .split(',')
        .next()
        .and_then(|segment| segment.split('-').next())
        .filter(|cpu| !cpu.is_empty())
        .ok_or_else(|| "delegated cgroup has an empty effective cpuset".to_owned())?;
    first
        .parse::<u32>()
        .map_err(|_| "delegated cgroup has an invalid effective cpuset".to_owned())?;
    Ok(first.to_owned())
}
