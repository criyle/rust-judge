//! Reusable command and result helpers from `go-sandbox/cmd/runprog`.
use super::{ResultInfo, Size, Status};
use crate::container::seccomp::Filter;
use crate::env::linux_environment::{
    LinuxEnvironment, LinuxEnvironmentConfig, cgroup_v1_roots_at_mount_prefix,
    current_cgroup_v2_path,
};
use crate::env::{Mount, MountConfig};
use crate::envexec::{Environment, ExecveParam, Limit};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// UOJ `run_program` result constants emitted by the Go command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum ProgramStatus {
    Normal = 0,
    Invalid = 1,
    RuntimeError = 2,
    MemoryLimitExceeded = 3,
    TimeLimitExceeded = 4,
    OutputLimitExceeded = 5,
    BannedSyscall = 6,
    Fatal = 7,
}

pub const fn get_status(status: Status) -> ProgramStatus {
    match status {
        Status::Normal => ProgramStatus::Normal,
        Status::Invalid => ProgramStatus::Invalid,
        Status::TimeLimitExceeded => ProgramStatus::TimeLimitExceeded,
        Status::MemoryLimitExceeded => ProgramStatus::MemoryLimitExceeded,
        Status::OutputLimitExceeded => ProgramStatus::OutputLimitExceeded,
        Status::DisallowedSyscall => ProgramStatus::BannedSyscall,
        Status::Signalled | Status::NonzeroExitStatus => ProgramStatus::RuntimeError,
        Status::RunnerError => ProgramStatus::Fatal,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Options {
    pub time_limit: u64,
    pub real_time_limit: u64,
    pub memory_limit_mb: u64,
    pub output_limit_mb: u64,
    pub stack_limit_mb: u64,
    pub work_path: PathBuf,
    pub input_file: Option<PathBuf>,
    pub output_file: Option<PathBuf>,
    pub error_file: Option<PathBuf>,
    pub result_output: String,
    pub program_type: String,
    pub runner: String,
    pub command: Vec<OsString>,
    pub add_readable: Vec<String>,
    pub add_writable: Vec<String>,
    pub add_readable_raw: Vec<String>,
    pub add_writable_raw: Vec<String>,
    pub unsafe_mode: bool,
    pub show_trace_details: bool,
    pub allow_proc: bool,
    pub cgroup: bool,
    pub cgroup_fd: bool,
    pub memfd: bool,
    pub credentials: bool,
    pub no_cgroup_unshare: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            time_limit: 1,
            real_time_limit: 0,
            memory_limit_mb: 256,
            output_limit_mb: 64,
            stack_limit_mb: 1024,
            work_path: PathBuf::new(),
            input_file: None,
            output_file: None,
            error_file: None,
            result_output: "stdout".into(),
            program_type: "default".into(),
            // This Rust port intentionally implements the container backend
            // only; selecting the Go CLI's ptrace default would make the
            // default invocation unavailable and select the unsafe backend
            // the caller asked us to omit.
            runner: "container".into(),
            command: Vec::new(),
            add_readable: Vec::new(),
            add_writable: Vec::new(),
            add_readable_raw: Vec::new(),
            add_writable_raw: Vec::new(),
            unsafe_mode: false,
            show_trace_details: false,
            allow_proc: false,
            cgroup: false,
            cgroup_fd: false,
            memfd: false,
            credentials: false,
            no_cgroup_unshare: false,
        }
    }
}

impl Options {
    /// Parse the Linux runprog flags. As in Go's `flag` package, parsing stops
    /// at the first command argument and preserves all following arguments.
    pub fn parse_cli(args: impl IntoIterator<Item = OsString>) -> Result<Option<Self>, String> {
        let mut options = Self::default();
        let mut args = args.into_iter().peekable();
        while let Some(raw) = args.next() {
            let arg = raw
                .into_string()
                .map_err(|_| "option is not valid UTF-8".to_string())?;
            if arg == "--" {
                options.command.extend(args);
                break;
            }
            if !arg.starts_with('-') || arg == "-" {
                options.command.push(arg.into());
                options.command.extend(args);
                break;
            }
            let (key, inline) = arg
                .split_once('=')
                .map_or((arg.as_str(), None), |(k, v)| (k, Some(v)));
            match key {
                "-h" | "-help" | "--help" => return Ok(None),
                "-tl" | "--tl" => {
                    options.time_limit = parse_u64(take_cli_value(inline, &mut args, key)?, key)?
                }
                "-rtl" | "--rtl" => {
                    options.real_time_limit =
                        parse_u64(take_cli_value(inline, &mut args, key)?, key)?
                }
                "-ml" | "--ml" => {
                    options.memory_limit_mb =
                        parse_u64(take_cli_value(inline, &mut args, key)?, key)?
                }
                "-ol" | "--ol" => {
                    options.output_limit_mb =
                        parse_u64(take_cli_value(inline, &mut args, key)?, key)?
                }
                "-sl" | "--sl" => {
                    options.stack_limit_mb =
                        parse_u64(take_cli_value(inline, &mut args, key)?, key)?
                }
                "-in" | "--in" => {
                    options.input_file = Some(take_cli_value(inline, &mut args, key)?.into())
                }
                "-out" | "--out" => {
                    options.output_file = Some(take_cli_value(inline, &mut args, key)?.into())
                }
                "-err" | "--err" => {
                    options.error_file = Some(take_cli_value(inline, &mut args, key)?.into())
                }
                "-work-path" | "--work-path" => {
                    options.work_path = take_cli_value(inline, &mut args, key)?.into()
                }
                "-type" | "--type" => {
                    options.program_type = take_cli_value(inline, &mut args, key)?
                }
                "-res" | "--res" => options.result_output = take_cli_value(inline, &mut args, key)?,
                "-runner" | "--runner" => options.runner = take_cli_value(inline, &mut args, key)?,
                "-add-readable" | "--add-readable" => options
                    .add_readable
                    .push(take_cli_value(inline, &mut args, key)?),
                "-add-writable" | "--add-writable" => options
                    .add_writable
                    .push(take_cli_value(inline, &mut args, key)?),
                "-add-readable-raw" | "--add-readable-raw" => options
                    .add_readable_raw
                    .push(take_cli_value(inline, &mut args, key)?),
                "-add-writable-raw" | "--add-writable-raw" => options
                    .add_writable_raw
                    .push(take_cli_value(inline, &mut args, key)?),
                "-unsafe" | "--unsafe" => options.unsafe_mode = parse_bool(inline, key)?,
                "-show-trace-details" | "--show-trace-details" => {
                    options.show_trace_details = parse_bool(inline, key)?
                }
                "-allow-proc" | "--allow-proc" => options.allow_proc = parse_bool(inline, key)?,
                "-cgroup" | "--cgroup" => options.cgroup = parse_bool(inline, key)?,
                "-cgroupfd" | "--cgroupfd" => options.cgroup_fd = parse_bool(inline, key)?,
                "-memfd" | "--memfd" => options.memfd = parse_bool(inline, key)?,
                "-cred" | "--cred" => options.credentials = parse_bool(inline, key)?,
                "-nucg" | "--nucg" => options.no_cgroup_unshare = parse_bool(inline, key)?,
                _ => return Err(format!("unknown runprog flag {key}")),
            }
        }
        if options.command.is_empty() {
            return Err(format!("no command specified\n{}", cli_usage()));
        }
        Ok(Some(options))
    }

    /// Normalize time and stack defaults exactly as Linux `runprog` does.
    pub fn normalize(
        &mut self,
        current_dir: impl FnOnce() -> io::Result<PathBuf>,
    ) -> io::Result<()> {
        if self.real_time_limit < self.time_limit {
            self.real_time_limit = self.time_limit.saturating_add(2);
        }
        if self.stack_limit_mb > self.memory_limit_mb {
            self.stack_limit_mb = self.memory_limit_mb;
        }
        if self.work_path.as_os_str().is_empty() {
            self.work_path = current_dir()?;
        }
        Ok(())
    }

    /// Validate backend selection and report the first unavailable execution
    /// path without pretending the requested sandbox was applied.
    pub fn execution_error(&self) -> Result<(), String> {
        if !matches!(self.runner.as_str(), "ptrace" | "ns" | "container") {
            return Err(format!("invalid runner type: {}", self.runner));
        }
        if self.runner == "ns" {
            return Err("runner ns is unavailable: clone-time PID/user namespace setup and process-tree supervision are not implemented".into());
        }
        if self.runner == "container" {
            Ok(())
        } else {
            Err(format!("runner {} is unavailable", self.runner))
        }
    }
}

/// Execute the command using the go-sandbox container backend. The ptrace and
/// standalone namespace runners are intentionally not part of this backend.
pub fn run_container(options: &Options) -> io::Result<ResultInfo> {
    if options.runner != "container" {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("runner {} is unavailable", options.runner),
        ));
    }
    if options.credentials && unsafe { libc::geteuid() } != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "-cred requires effective uid 0",
        ));
    }
    let mut command = options
        .command
        .iter()
        .map(|arg| {
            arg.to_str().map(str::to_owned).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "command argument is not UTF-8")
            })
        })
        .collect::<io::Result<Vec<_>>>()?;
    match options.program_type.as_str() {
        "python2.7" => {
            command.splice(
                0..0,
                ["/usr/bin/python2.7", "-E", "-s", "-B"].map(str::to_owned),
            );
        }
        "python3" => {
            command.splice(0..0, ["/usr/bin/python3", "-I", "-B"].map(str::to_owned));
        }
        _ => {}
    }
    let mut stdio = prepare_files(
        options.input_file.as_deref(),
        options.output_file.as_deref(),
        options.error_file.as_deref(),
    )?;
    let files = stdio
        .iter_mut()
        .enumerate()
        .map(|(index, file)| {
            file.as_ref()
                .map_or(index as u64, |file| file.as_raw_fd() as u64)
        })
        .collect();
    let exec_file = if options.memfd {
        let executable = command
            .first()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing executable"))?;
        let source = File::open(executable)?;
        Some(crate::container::memfd::dup_to_memfd(
            "run_program",
            source,
        )?)
    } else {
        None
    };

    let seccomp = if options.unsafe_mode {
        None
    } else {
        Some(runprog_seccomp_filter(options)?)
    };
    let mut config = runprog_environment_config(options);
    if options.cgroup {
        let cgroup_v2 = Path::new("/sys/fs/cgroup/cgroup.controllers").is_file();
        validate_cgroup_fd_mode(options, cgroup_v2)?;
        if cgroup_v2 {
            let current = current_cgroup_v2_path()?;
            let root = current.join("runprog");
            crate::env::linuxcontainer::prepare_cgroup_v2_hierarchy(&current, &root)
                .map_err(io::Error::other)?;
            config.cgroup_root = Some(root);
        } else {
            config.cgroup_v1_roots = Some(cgroup_v1_roots_at_mount_prefix(Path::new("runprog"))?);
        }
        config.no_fallback = true;
    }
    let environment = LinuxEnvironment::build(config)?;
    let param = ExecveParam {
        args: command,
        env: vec!["PATH=/usr/local/bin:/usr/bin:/bin".into()],
        seccomp,
        files,
        exec_file: exec_file.as_ref().map_or(0, |file| file.as_raw_fd() as u64),
        tty: false,
        limit: Limit {
            time: Duration::from_secs(options.time_limit),
            memory: Size(options.memory_limit_mb.saturating_mul(1 << 20)),
            proc: 0,
            stack: Size(options.stack_limit_mb.saturating_mul(1 << 20)),
            output: Size(options.output_limit_mb.saturating_mul(1 << 20)),
            rate: 0,
            open_file: 256,
            cpu_set: String::new(),
            data_segment: true,
            address_space: false,
        },
    };
    let process = environment.execve(param)?;
    let started = std::time::Instant::now();
    let wall_limit = Duration::from_secs(
        options
            .real_time_limit
            .max(options.time_limit.saturating_add(2)),
    );
    let cpu_limit = Duration::from_secs(options.time_limit);
    let mut forced_time_limit = false;
    while !process.done() {
        if process.usage().time > cpu_limit || started.elapsed() >= wall_limit {
            forced_time_limit = true;
            process.cancel();
            break;
        }
        process.wait_timeout(Duration::from_millis(10));
    }
    let mut result = process.result();
    drop(environment);
    if forced_time_limit
        || (matches!(result.status, Status::Normal | Status::TimeLimitExceeded)
            && result.time > cpu_limit)
    {
        result.status = Status::TimeLimitExceeded;
    }
    if matches!(result.status, Status::Normal | Status::MemoryLimitExceeded)
        && result.memory.0 > options.memory_limit_mb.saturating_mul(1 << 20)
    {
        result.status = Status::MemoryLimitExceeded;
    }
    Ok(result)
}

fn validate_cgroup_fd_mode(options: &Options, cgroup_v2: bool) -> io::Result<()> {
    if options.cgroup && options.cgroup_fd && !cgroup_v2 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "use cgroup fd cannot be enabled without cgroup v2",
        ));
    }
    Ok(())
}

fn runprog_environment_config(options: &Options) -> LinuxEnvironmentConfig {
    LinuxEnvironmentConfig {
        work_dir: "/w".into(),
        tmpfs_data: "size=8m,nr_inodes=4k".into(),
        work_dir_tmpfs: true,
        uid: if options.credentials { 10_001 } else { 0 },
        gid: if options.credentials { 10_001 } else { 0 },
        // go-sandbox/runprog attaches its allowlist to ExecveParam. Keep
        // PID 1 unrestricted so it can serve the control socket; the
        // workload inherits and receives the command-specific filter.
        no_seccomp: true,
        seccomp_filter: None,
        // The Go container runner has no generated credential unless -cred is
        // requested; keep the normal root credential here as well.
        mount_config: Some(runprog_mount_config()),
        default_mount_policy: false,
        unshare_cgroup: LinuxEnvironmentConfig::default().unshare_cgroup
            && !options.no_cgroup_unshare,
        ..LinuxEnvironmentConfig::default()
    }
}

/// Reproduce `cmd/runprog`'s explicit mount.Builder plan. The runprog
/// container intentionally has a smaller rootfs than go-judge's server
/// environment, even though both use the same container implementation.
fn runprog_mount_config() -> MountConfig {
    let binds = [
        ("/bin", "bin"),
        ("/lib", "lib"),
        ("/lib64", "lib64"),
        ("/usr", "usr"),
        ("/etc/alternatives", "etc/alternatives"),
        ("/etc/fpc.cfg", "etc/fpc.cfg"),
        ("/dev/null", "dev/null"),
        ("/var/lib/ghc", "var/lib/ghc"),
    ];
    let mut mounts = binds
        .into_iter()
        .map(|(source, target)| Mount {
            kind: "bind".into(),
            source: source.into(),
            target: target.into(),
            readonly: source != "/dev/null",
            data: String::new(),
        })
        .collect::<Vec<_>>();
    mounts.extend(["w", "tmp"].map(|target| Mount {
        kind: "tmpfs".into(),
        source: String::new(),
        target: target.into(),
        readonly: false,
        data: "size=8m,nr_inodes=4k".into(),
    }));
    MountConfig {
        mounts,
        work_dir: "/w".into(),
        proc: true,
        proc_rw: false,
        ..MountConfig::default()
    }
}

fn runprog_seccomp_filter(options: &Options) -> io::Result<Filter> {
    let mut allowed = vec![
        "read",
        "write",
        "readv",
        "writev",
        "close",
        "fstat",
        "lseek",
        "dup",
        "dup3",
        "ioctl",
        "fcntl",
        "fadvise64",
        "pread64",
        "pwrite64",
        "mmap",
        "mprotect",
        "munmap",
        "brk",
        "mremap",
        "msync",
        "mincore",
        "madvise",
        "rt_sigaction",
        "rt_sigprocmask",
        "rt_sigreturn",
        "rt_sigpending",
        "sigaltstack",
        "getcwd",
        "exit",
        "exit_group",
        "gettimeofday",
        "getrlimit",
        "getrusage",
        "times",
        "clock_gettime",
        "restart_syscall",
        "execve",
        "execveat",
        "openat",
        "unlinkat",
        "readlinkat",
        "faccessat",
    ];
    if options.allow_proc {
        allowed.extend(["clone", "fork", "vfork", "nanosleep"]);
    }
    match options.program_type.as_str() {
        "python2.7" => allowed.extend([
            "futex",
            "getdents",
            "getdents64",
            "prlimit64",
            "getpid",
            "sysinfo",
        ]),
        "python3" => allowed.extend([
            "futex",
            "getdents",
            "getdents64",
            "prlimit64",
            "getpid",
            "sysinfo",
            "getrandom",
        ]),
        "compiler" => allowed.extend([
            "gettid",
            "set_tid_address",
            "set_robust_list",
            "futex",
            "getpid",
            "vfork",
            "fork",
            "clone",
            "execve",
            "wait4",
            "clock_getres",
            "setrlimit",
            "pipe",
            "getdents64",
            "getdents",
            "umask",
            "rename",
            "chmod",
            "mkdir",
            "chdir",
            "fchdir",
            "ftruncate",
            "sched_getaffinity",
            "sched_yield",
            "uname",
            "sysinfo",
            "prlimit64",
            "getrandom",
            "fchmodat",
            "rseq",
            // Go's non-ptrace container path appends the configured trace
            // syscall names to its allowlist, including compiler ExtraBan.
            "socket",
            "connect",
            "geteuid",
            "getuid",
        ]),
        _ => {}
    }
    #[cfg(target_arch = "x86_64")]
    allowed.extend([
        "dup2",
        "time",
        "arch_prctl",
        "open",
        "unlink",
        "readlink",
        "lstat",
        "stat",
        "access",
        "newfstatat",
    ]);
    #[cfg(target_arch = "aarch64")]
    allowed.extend(["fstatat", "openat", "unlinkat", "readlinkat"]);
    let rules = vec![crate::env::seccomp_policy::SyscallRule {
        names: allowed.into_iter().map(str::to_owned).collect(),
        names_with_args: Vec::new(),
        action: "allow".into(),
    }];
    let profile = crate::env::seccomp_policy::PolicyProfile {
        default_action: if options.show_trace_details {
            "trace"
        } else {
            "kill"
        }
        .into(),
        base: crate::env::seccomp_policy::PolicySection::default(),
        architectures: BTreeMap::from([(
            crate::env::seccomp_policy::native_architecture()
                .map_err(io::Error::other)?
                .into(),
            crate::env::seccomp_policy::PolicySection { syscalls: rules },
        )]),
    };
    profile
        .assemble(crate::env::seccomp_policy::native_architecture().map_err(io::Error::other)?)
        .map_err(io::Error::other)
}

fn take_cli_value(
    inline: Option<&str>,
    args: &mut impl Iterator<Item = OsString>,
    flag: &str,
) -> Result<String, String> {
    let value = match inline {
        Some(value) => value.to_owned(),
        None => args
            .next()
            .ok_or_else(|| format!("flag {flag} requires a value"))?
            .into_string()
            .map_err(|_| format!("value for {flag} is not valid UTF-8"))?,
    };
    if value.is_empty() {
        return Err(format!("flag {flag} requires a nonempty value"));
    }
    Ok(value)
}

fn parse_u64(value: String, flag: &str) -> Result<u64, String> {
    value
        .parse()
        .map_err(|_| format!("invalid unsigned integer for {flag}: {value}"))
}

fn parse_bool(value: Option<&str>, flag: &str) -> Result<bool, String> {
    match value.unwrap_or("true") {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        other => Err(format!("invalid boolean for {flag}: {other}")),
    }
}

pub const fn cli_usage() -> &'static str {
    "Usage: runprog [options] <args> (options: -tl -rtl -ml -ol -sl -in -out -err -work-path -type -res -runner; default runner: container)"
}

/// Open stdio replacement files. An omitted entry preserves the inherited
/// descriptor at that index, matching Go's `prepareFiles` behavior.
pub fn prepare_files(
    input: Option<&Path>,
    output: Option<&Path>,
    error: Option<&Path>,
) -> io::Result<[Option<File>; 3]> {
    use std::os::unix::fs::OpenOptionsExt;
    let open_input = |path: &Path| OpenOptions::new().read(true).open(path);
    let open_output = |path: &Path| {
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o755)
            .open(path)
    };
    Ok([
        input.map(open_input).transpose()?,
        output.map(open_output).transpose()?,
        error.map(open_output).transpose()?,
    ])
}

/// Emit the four-column line consumed by UOJ. Time is rounded to milliseconds;
/// memory is truncated to KiB as in the Go command.
pub fn write_result(mut writer: impl Write, result: &ResultInfo) -> io::Result<()> {
    let status = get_status(result.status) as i32;
    let millis = result.time.as_nanos().saturating_add(500_000) / 1_000_000;
    writeln!(
        writer,
        "{status} {millis} {} {}",
        result.memory.0 >> 10,
        result.exit_status
    )
}

pub const fn seconds(value: u64) -> Duration {
    Duration::from_secs(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_runner_status_to_uoj_codes() {
        assert_eq!(get_status(Status::Normal) as i32, 0);
        assert_eq!(get_status(Status::Invalid) as i32, 1);
        assert_eq!(get_status(Status::Signalled) as i32, 2);
        assert_eq!(get_status(Status::NonzeroExitStatus) as i32, 2);
        assert_eq!(get_status(Status::MemoryLimitExceeded) as i32, 3);
        assert_eq!(get_status(Status::TimeLimitExceeded) as i32, 4);
        assert_eq!(get_status(Status::OutputLimitExceeded) as i32, 5);
        assert_eq!(get_status(Status::DisallowedSyscall) as i32, 6);
        assert_eq!(get_status(Status::RunnerError) as i32, 7);
    }

    #[test]
    fn normalizes_limits_and_work_path() {
        let mut options = Options {
            time_limit: 4,
            stack_limit_mb: 512,
            ..Options::default()
        };
        options.normalize(|| Ok(PathBuf::from("/work"))).unwrap();
        assert_eq!(options.real_time_limit, 6);
        assert_eq!(options.stack_limit_mb, 256);
        assert_eq!(options.work_path, PathBuf::from("/work"));
    }

    #[test]
    fn prepares_and_truncates_stdio_files() -> io::Result<()> {
        let dir = std::env::temp_dir().join(format!("rust-runprog-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let input = dir.join("input");
        let output = dir.join("output");
        std::fs::write(&input, b"in")?;
        std::fs::write(&output, b"old content")?;
        let files = prepare_files(Some(&input), Some(&output), None)?;
        assert!(files[0].is_some());
        assert!(files[1].is_some());
        assert!(files[2].is_none());
        drop(files);
        assert_eq!(std::fs::read(&output)?, b"");
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn writes_result_line_with_go_rounding() {
        let result = ResultInfo {
            status: Status::NonzeroExitStatus,
            exit_status: 7,
            time: Duration::from_micros(1499),
            memory: super::super::Size(2047),
            ..Default::default()
        };
        let mut output = Vec::new();
        write_result(&mut output, &result).unwrap();
        assert_eq!(String::from_utf8(output).unwrap(), "2 1 1 7\n");
    }

    #[test]
    fn parses_cli_limits_files_repeated_flags_and_command_args() {
        let args = [
            "-tl=5",
            "--rtl",
            "9",
            "-ml",
            "128",
            "-in",
            "input.txt",
            "--add-readable=/etc/one",
            "-add-readable",
            "/etc/two",
            "--unsafe=false",
            "-runner",
            "ns",
            "/bin/sh",
            "-c",
            "exit 2",
        ]
        .into_iter()
        .map(OsString::from);
        let options = Options::parse_cli(args).unwrap().unwrap();
        assert_eq!(options.time_limit, 5);
        assert_eq!(options.real_time_limit, 9);
        assert_eq!(options.memory_limit_mb, 128);
        assert_eq!(options.input_file, Some(PathBuf::from("input.txt")));
        assert_eq!(options.add_readable, ["/etc/one", "/etc/two"]);
        assert!(!options.unsafe_mode);
        assert_eq!(options.runner, "ns");
        assert_eq!(
            options.command,
            ["/bin/sh", "-c", "exit 2"].map(OsString::from)
        );
    }

    #[test]
    fn cli_help_and_invalid_arguments_are_reported() {
        assert!(
            Options::parse_cli([OsString::from("--help")])
                .unwrap()
                .is_none()
        );
        assert!(Options::parse_cli([OsString::from("-unknown"), OsString::from("x")]).is_err());
        assert!(
            Options::parse_cli([
                OsString::from("-tl"),
                OsString::from("fast"),
                OsString::from("cmd")
            ])
            .is_err()
        );
        assert!(
            Options::parse_cli([OsString::from("-tl"), OsString::from("1")])
                .unwrap_err()
                .contains("no command")
        );
    }

    #[test]
    fn known_but_unimplemented_backends_fail_clearly() {
        for (runner, expected) in [("ptrace", "unavailable"), ("ns", "clone-time PID/user")] {
            let options = Options {
                runner: runner.into(),
                ..Options::default()
            };
            assert!(options.execution_error().unwrap_err().contains(expected));
        }
        let options = Options {
            runner: "invalid".into(),
            ..Options::default()
        };
        assert!(
            options
                .execution_error()
                .unwrap_err()
                .contains("invalid runner type")
        );
        assert!(
            Options {
                runner: "container".into(),
                ..Options::default()
            }
            .execution_error()
            .is_ok()
        );
    }

    #[test]
    fn defaults_to_the_supported_container_backend() {
        let options = Options::default();
        assert_eq!(options.runner, "container");
        assert!(options.execution_error().is_ok());
    }

    #[test]
    fn compiles_the_container_allowlist() {
        let options = Options::default();
        let filter = runprog_seccomp_filter(&options).unwrap();
        assert!(!filter.0.is_empty());
        let mut process_options = options;
        process_options.allow_proc = true;
        let process_filter = runprog_seccomp_filter(&process_options).unwrap();
        assert!(!process_filter.0.is_empty());
    }

    #[test]
    fn container_mount_plan_matches_runprog_builder() {
        let config = runprog_mount_config();
        assert_eq!(
            config
                .mounts
                .iter()
                .map(|mount| (
                    mount.kind.as_str(),
                    mount.source.as_str(),
                    mount.target.as_str(),
                    mount.readonly
                ))
                .collect::<Vec<_>>(),
            [
                ("bind", "/bin", "bin", true),
                ("bind", "/lib", "lib", true),
                ("bind", "/lib64", "lib64", true),
                ("bind", "/usr", "usr", true),
                ("bind", "/etc/alternatives", "etc/alternatives", true),
                ("bind", "/etc/fpc.cfg", "etc/fpc.cfg", true),
                ("bind", "/dev/null", "dev/null", false),
                ("bind", "/var/lib/ghc", "var/lib/ghc", true),
                ("tmpfs", "", "w", false),
                ("tmpfs", "", "tmp", false),
            ]
        );
        assert!(config.proc);
        assert!(!config.proc_rw);
        assert_eq!(config.work_dir, "/w");
    }

    #[test]
    fn nucg_disables_cgroup_namespace_for_runprog() {
        let options = Options {
            no_cgroup_unshare: true,
            ..Options::default()
        };
        assert!(!runprog_environment_config(&options).unshare_cgroup);
    }

    #[test]
    fn cgroupfd_requires_cgroup_v2_only_when_cgroups_are_enabled() {
        let options = Options {
            cgroup: true,
            cgroup_fd: true,
            ..Options::default()
        };
        assert_eq!(
            validate_cgroup_fd_mode(&options, false)
                .unwrap_err()
                .to_string(),
            "use cgroup fd cannot be enabled without cgroup v2"
        );
        assert!(validate_cgroup_fd_mode(&options, true).is_ok());

        let ignored = Options {
            cgroup: false,
            cgroup_fd: true,
            ..Options::default()
        };
        assert!(validate_cgroup_fd_mode(&ignored, false).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn container_runner_preserves_nonzero_exit_result() {
        let options = Options {
            runner: "container".into(),
            program_type: "compiler".into(),
            unsafe_mode: true,
            command: ["/bin/sh", "-c", "exit 7"].map(OsString::from).into(),
            ..Options::default()
        };
        let result = run_container(&options).unwrap();
        assert_eq!(result.status, Status::NonzeroExitStatus);
        assert_eq!(result.exit_status, 7);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn container_runner_applies_the_default_seccomp_filter() {
        let options = Options {
            runner: "container".into(),
            program_type: "compiler".into(),
            command: ["/bin/true"].map(OsString::from).into(),
            ..Options::default()
        };
        let result = run_container(&options).unwrap();
        assert_eq!(result.status, Status::Normal, "{result:?}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn container_runner_executes_a_sealed_memfd_image() {
        let options = Options {
            runner: "container".into(),
            unsafe_mode: true,
            memfd: true,
            command: ["/bin/echo", "memfd-ok"].map(OsString::from).into(),
            ..Options::default()
        };
        let result = run_container(&options).unwrap();
        assert_eq!(result.status, Status::Normal, "{result:?}");
    }
}
