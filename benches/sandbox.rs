//! Performance benchmarks for Rust implementations of Go sandbox hot paths.
//!
//! Run with `cargo bench --bench sandbox`. Filter a case with Criterion's
//! arguments, for example `cargo bench --bench sandbox -- socket/ping`.
use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use nix::unistd::pipe;
use prost::Message;
use rust_judge::container::fork_exec::Runner;
use rust_judge::container::memfd;
use rust_judge::container::rlimit::RLimits;
use rust_judge::env::linux_environment::{LinuxEnvironment, LinuxEnvironmentConfig};
use rust_judge::env::linuxcontainer::{Cgroup, CgroupV2, CgroupV2Builder};
use rust_judge::envexec::{
    Cmd, Environment, ExecveParam, File as EnvFile, Group, OpenParam, OpenResult, PipeIndex,
    PipeMapping, SymlinkParam,
};
use rust_judge::pb::{
    self,
    request::{CmdType, File, MemoryFile, file::Kind},
};
use rust_judge::unixsocket::{SendMessage, Socket};
use std::ffi::CString;
use std::io::{self, Cursor};
use std::os::fd::{AsFd, AsRawFd, FromRawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Instant;

fn socket_ping(c: &mut Criterion) {
    let (server, client) = Socket::pair().expect("socketpair");
    let server_thread = thread::spawn(move || {
        let mut input = [0u8; 64];
        loop {
            match server.recv_msg(&mut input) {
                Ok((n, _)) => server
                    .send_msg(&input[..n], &SendMessage::default())
                    .unwrap(),
                Err(_) => break,
            }
        }
    });
    c.bench_function("socket/ping_roundtrip", |b| {
        let mut response = [0u8; 64];
        b.iter(|| {
            client
                .send_msg(black_box(b"ping"), &SendMessage::default())
                .unwrap();
            let (n, _) = client.recv_msg(&mut response).unwrap();
            black_box(&response[..n]);
        });
    });
    drop(client);
    server_thread.join().expect("server thread");
}

fn unixsocket_baselines(c: &mut Criterion) {
    let (server, client) = Socket::pair().expect("socketpair");
    let drain = thread::spawn(move || {
        let mut buffer = [0u8; 64];
        while server.recv_msg(&mut buffer).is_ok() {}
    });
    c.bench_function("transport/socket_send_drain_small", |b| {
        b.iter(|| {
            client
                .send_msg(black_box(b"message"), &SendMessage::default())
                .unwrap();
        });
    });
    drop(client);
    drain.join().expect("socket drain");

    channel_send_drain(c, "transport/mpsc_unbounded_send_drain", None);
    channel_send_drain(c, "transport/mpsc_bounded_1_send_drain", Some(1));
    channel_send_drain(c, "transport/mpsc_bounded_4_send_drain", Some(4));
}

fn channel_send_drain(c: &mut Criterion, name: &str, bound: Option<usize>) {
    let (sender, receiver) = match bound {
        Some(capacity) => {
            let (tx, rx) = mpsc::sync_channel::<&'static [u8]>(capacity);
            (ChannelSender::Bounded(tx), rx)
        }
        None => {
            let (tx, rx) = mpsc::channel::<&'static [u8]>();
            (ChannelSender::Unbounded(tx), rx)
        }
    };
    let drain = thread::spawn(move || while receiver.recv().is_ok() {});
    c.bench_function(name, |b| {
        b.iter(|| sender.send(black_box(b"message")).unwrap());
    });
    drop(sender);
    drain.join().expect("channel drain");
}

fn worker_result_delivery(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Tokio benchmark runtime");
    runtime.block_on(async {
        // Warm the reusable blocking pool before Criterion starts sampling.
        tokio::task::spawn_blocking(|| {}).await.unwrap();
    });

    c.bench_function("worker/result_delivery_tokio_oneshot", |b| {
        b.iter(|| {
            runtime.block_on(async {
                let (sender, receiver) = tokio::sync::oneshot::channel();
                let producer = tokio::task::spawn_blocking(move || {
                    let _ = sender.send(black_box(1u8));
                });
                black_box(receiver.await.unwrap());
                producer.await.unwrap();
            });
        });
    });
    c.bench_function("worker/result_delivery_blocking_mpsc_ablation", |b| {
        b.iter(|| {
            runtime.block_on(async {
                let (sender, receiver) = mpsc::channel();
                let producer = tokio::task::spawn_blocking(move || {
                    let _ = sender.send(black_box(1u8));
                });
                let consumer = tokio::task::spawn_blocking(move || receiver.recv());
                black_box(consumer.await.unwrap().unwrap());
                producer.await.unwrap();
            });
        });
    });
}

fn profile_sampler_blocking_pool_availability(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .expect("Tokio benchmark runtime");
    let sample_window = std::time::Duration::from_millis(5);

    c.bench_function("runtime/profile_pool_probe_async_timer", |b| {
        b.iter_custom(|iterations| {
            let mut elapsed = std::time::Duration::ZERO;
            for _ in 0..iterations {
                elapsed += runtime.block_on(async {
                    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
                    let sampling = tokio::spawn(async move {
                        let _ = started_tx.send(());
                        tokio::time::sleep(sample_window).await;
                    });
                    started_rx.await.unwrap();
                    let started = Instant::now();
                    tokio::task::spawn_blocking(|| {}).await.unwrap();
                    let probe_elapsed = started.elapsed();
                    sampling.await.unwrap();
                    black_box(probe_elapsed)
                });
            }
            elapsed
        });
    });

    c.bench_function("runtime/profile_pool_probe_blocking_ablation", |b| {
        b.iter_custom(|iterations| {
            let mut elapsed = std::time::Duration::ZERO;
            for _ in 0..iterations {
                elapsed += runtime.block_on(async {
                    let (started_tx, started_rx) = mpsc::channel();
                    let sampling = tokio::task::spawn_blocking(move || {
                        let _ = started_tx.send(());
                        thread::sleep(sample_window);
                    });
                    started_rx.recv().unwrap();
                    let started = Instant::now();
                    tokio::task::spawn_blocking(|| {}).await.unwrap();
                    let probe_elapsed = started.elapsed();
                    sampling.await.unwrap();
                    black_box(probe_elapsed)
                });
            }
            elapsed
        });
    });
}

fn tokio_task_poll_hook_overhead(c: &mut Criterion) {
    let mut plain_builder = tokio::runtime::Builder::new_current_thread();
    plain_builder.enable_all();
    let plain_runtime = plain_builder
        .build()
        .expect("plain Tokio benchmark runtime");

    let mut hooks_only_builder = tokio::runtime::Builder::new_current_thread();
    hooks_only_builder.enable_all();
    rust_judge::runtime_trace::install_task_poll_hooks_without_schedule_latency(
        &mut hooks_only_builder,
    );
    let hooks_only_runtime = hooks_only_builder
        .build()
        .expect("Tokio hooks-only benchmark runtime");

    let mut schedule_latency_builder = tokio::runtime::Builder::new_current_thread();
    schedule_latency_builder.enable_all();
    rust_judge::runtime_trace::install_task_poll_hooks_with_schedule_latency(
        &mut schedule_latency_builder,
        true,
    );
    let schedule_latency_runtime = schedule_latency_builder
        .build()
        .expect("Tokio schedule-latency benchmark runtime");

    for (name, runtime) in [
        ("runtime/task_poll_hooks_disabled", &plain_runtime),
        (
            "runtime/task_poll_hooks_no_schedule_latency",
            &hooks_only_runtime,
        ),
        (
            "runtime/task_poll_hooks_with_schedule_latency",
            &schedule_latency_runtime,
        ),
    ] {
        c.bench_function(name, |b| {
            b.iter(|| {
                runtime.block_on(async {
                    let task = tokio::spawn(async {
                        tokio::task::yield_now().await;
                        black_box(1u8)
                    });
                    black_box(task.await.unwrap());
                });
            });
        });
    }
}

enum ChannelSender {
    Bounded(mpsc::SyncSender<&'static [u8]>),
    Unbounded(mpsc::Sender<&'static [u8]>),
}
impl ChannelSender {
    fn send(&self, value: &'static [u8]) -> Result<(), mpsc::SendError<&'static [u8]>> {
        match self {
            Self::Bounded(sender) => sender.send(value),
            Self::Unbounded(sender) => sender.send(value),
        }
    }
}

fn socket_fd_batches(c: &mut Criterion) {
    let (_pipe_read, descriptor) = pipe().expect("pipe");
    let mut group = c.benchmark_group("socket/fd_batch_roundtrip");
    for count in [10usize, 100, 200] {
        let (server, client) = Socket::pair().expect("socketpair");
        let service = thread::spawn(move || {
            let mut buffer = [0u8; 32];
            loop {
                match server.recv_msg(&mut buffer) {
                    Ok(_) => server.send_msg(b"ok", &SendMessage::default()).unwrap(),
                    Err(_) => break,
                }
            }
        });
        let fds: Vec<_> = (0..count).map(|_| descriptor.as_fd()).collect();
        let send = SendMessage {
            fds,
            credentials: false,
        };
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::from_parameter(count), &send, |b, send| {
            let mut response = [0u8; 8];
            b.iter(|| {
                client.send_msg(black_box(b"open"), send).unwrap();
                let (n, _) = client.recv_msg(&mut response).unwrap();
                black_box(&response[..n]);
            });
        });
        drop(client);
        service.join().expect("fd service thread");
    }
    group.finish();
}

fn protobuf_encode_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc/protobuf_encode_decode");
    for size in [1024usize, 32 << 10, 64 << 10, 128 << 10] {
        let request = pb::Request {
            request_id: "benchmark".into(),
            cmd: vec![CmdType {
                files: vec![File {
                    kind: Some(Kind::Memory(MemoryFile {
                        content: vec![b'x'; size],
                    })),
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        let encoded = request.encode_to_vec();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("encode", size), &request, |b, message| {
            b.iter(|| black_box(message.encode_to_vec()));
        });
        group.bench_with_input(BenchmarkId::new("decode", size), &encoded, |b, bytes| {
            b.iter(|| black_box(pb::Request::decode(bytes.as_slice()).unwrap()));
        });
    }
    group.finish();
}

fn go_simplefork_runner(dev_null_fd: i32) -> Runner {
    Runner {
        args: vec![CString::new("/bin/echo").unwrap()],
        env: vec![CString::new("PATH=/bin").unwrap()],
        work_dir: CString::new("/bin").unwrap(),
        container_root: None,
        bind_mounts: vec![],
        proc_mounts: vec![],
        tmpfs_mounts: vec![],
        rootfs_tmpfs: false,
        symlinks: vec![],
        mask_paths: vec![],
        fd_map: vec![dev_null_fd; 3],
        exec_file: None,
        pid_namespace_helper: None,
        helper_unshare_flags: 0,
        helper_args: None,
        cgroup_procs_fds: vec![],
        user_namespace_fd: None,
        cpu_set: None,
        rlimits: RLimits::default(),
        pivot_root: None,
        host_name: None,
        domain_name: None,
        sync_fn: None,
        clone_flags: 0,
        credential: None,
        uid_map: None,
        gid_map: None,
        gid_map_enable_set_groups: false,
        no_new_privs: false,
        seccomp: Default::default(),
        drop_caps: false,
        unshare_cgroup_after_sync: false,
        control_tty: false,
    }
}

fn forkexec_true(c: &mut Criterion) {
    let mut group = c.benchmark_group("forkexec/bin_true");
    group.bench_function("std_command", |b| {
        b.iter(|| {
            let status = std::process::Command::new("/bin/true")
                .env_clear()
                .status()
                .unwrap();
            assert!(status.success());
            black_box(status);
        });
    });
    group.bench_function("std_command_noop_pre_exec", |b| {
        b.iter(|| {
            let mut command = std::process::Command::new("/bin/true");
            // Registering even an empty hook exercises std's fork fallback
            // used by Runner, without adding sandbox syscalls to the child.
            unsafe { command.pre_exec(|| Ok(())) };
            let status = command.env_clear().status().unwrap();
            assert!(status.success());
            black_box(status);
        });
    });
    group.bench_function("runner_pre_exec", |b| {
        b.iter(|| {
            let mut runner = Runner {
                args: vec![CString::new("/bin/true").unwrap()],
                env: vec![],
                work_dir: CString::new("").unwrap(),
                container_root: None,
                bind_mounts: vec![],
                proc_mounts: vec![],
                tmpfs_mounts: vec![],
                rootfs_tmpfs: false,
                symlinks: vec![],
                mask_paths: vec![],
                fd_map: vec![],
                exec_file: None,
                pid_namespace_helper: None,
                helper_unshare_flags: 0,
                helper_args: None,
                cgroup_procs_fds: vec![],
                user_namespace_fd: None,
                cpu_set: None,
                rlimits: RLimits::default(),
                pivot_root: None,
                host_name: None,
                domain_name: None,
                sync_fn: None,
                clone_flags: 0,
                credential: None,
                uid_map: None,
                gid_map: None,
                gid_map_enable_set_groups: false,
                no_new_privs: false,
                seccomp: Default::default(),
                drop_caps: false,
                unshare_cgroup_after_sync: false,
                control_tty: false,
            };
            let status = runner.start().unwrap().wait().unwrap();
            assert!(status.success());
            black_box(status);
        });
    });
    // Go's BenchmarkSimpleFork builds its Runner once before timing. Keep a
    // corresponding Rust case so per-request Runner construction does not get
    // conflated with the fork/exec and child setup path.
    let mut reused_runner = Runner {
        args: vec![CString::new("/bin/true").unwrap()],
        env: vec![],
        work_dir: CString::new("").unwrap(),
        container_root: None,
        bind_mounts: vec![],
        proc_mounts: vec![],
        tmpfs_mounts: vec![],
        rootfs_tmpfs: false,
        symlinks: vec![],
        mask_paths: vec![],
        fd_map: vec![],
        exec_file: None,
        pid_namespace_helper: None,
        helper_unshare_flags: 0,
        helper_args: None,
        cgroup_procs_fds: vec![],
        user_namespace_fd: None,
        cpu_set: None,
        rlimits: RLimits::default(),
        pivot_root: None,
        host_name: None,
        domain_name: None,
        sync_fn: None,
        clone_flags: 0,
        credential: None,
        uid_map: None,
        gid_map: None,
        gid_map_enable_set_groups: false,
        no_new_privs: false,
        seccomp: Default::default(),
        drop_caps: false,
        unshare_cgroup_after_sync: false,
        control_tty: false,
    };
    group.bench_function("runner_pre_exec_reused_config", |b| {
        b.iter(|| {
            let status = reused_runner.start().unwrap().wait().unwrap();
            assert!(status.success());
            black_box(status);
        });
    });
    let null = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .unwrap();
    let mut go_runner = go_simplefork_runner(null.as_raw_fd());
    group.bench_function("go_simplefork_matched", |b| {
        b.iter(|| {
            let status = go_runner.start().unwrap().wait().unwrap();
            assert!(status.success());
            black_box(status);
        });
    });
    group.bench_function("runner_pre_exec_parent_sync_callback", |b| {
        b.iter(|| {
            let mut runner = Runner {
                args: vec![CString::new("/bin/true").unwrap()],
                env: vec![],
                work_dir: CString::new("").unwrap(),
                container_root: None,
                bind_mounts: vec![],
                proc_mounts: vec![],
                tmpfs_mounts: vec![],
                rootfs_tmpfs: false,
                symlinks: vec![],
                mask_paths: vec![],
                fd_map: vec![],
                exec_file: None,
                pid_namespace_helper: None,
                helper_unshare_flags: 0,
                helper_args: None,
                cgroup_procs_fds: vec![],
                user_namespace_fd: None,
                cpu_set: None,
                rlimits: RLimits::default(),
                pivot_root: None,
                host_name: None,
                domain_name: None,
                sync_fn: Some(Box::new(|pid| {
                    if pid > 0 {
                        Ok(())
                    } else {
                        Err(io::Error::other("invalid child PID"))
                    }
                })),
                clone_flags: 0,
                credential: None,
                uid_map: None,
                gid_map: None,
                gid_map_enable_set_groups: false,
                no_new_privs: false,
                seccomp: Default::default(),
                drop_caps: false,
                unshare_cgroup_after_sync: false,
                control_tty: false,
            };
            let status = runner.start().unwrap().wait().unwrap();
            assert!(status.success());
            black_box(status);
        });
    });
    group.finish();
}

fn container_exec_true(c: &mut Criterion) {
    // Construct the namespace, mounts, and keeper once so this measures the
    // repeated per-command helper path used by a warm environment.
    let root_parent =
        std::env::temp_dir().join(format!("rust-sandbox-bench-{}", std::process::id()));
    let environment = LinuxEnvironment::build(LinuxEnvironmentConfig {
        root_parent,
        no_seccomp: true,
        ..LinuxEnvironmentConfig::default()
    })
    .expect("build warm Linux environment");
    c.bench_function("container_exec/warm_bin_true_non_tty", |b| {
        b.iter(|| {
            let process = environment
                .execve(ExecveParam {
                    args: vec!["/bin/true".into()],
                    env: vec!["PATH=/usr/bin:/bin".into()],
                    ..ExecveParam::default()
                })
                .expect("spawn /bin/true");
            black_box(process.result());
        });
    });
}

/// Measures the production `envexec::Group` pipe and relay path while keeping
/// container setup out of the sample. The small adapter only maps the file
/// descriptors prepared by Group onto std::process::Command's stdio handles.
/// Workloads and pipe topology mirror Go's envexec pipe benchmarks.
fn envexec_pipe_stream(c: &mut Criterion) {
    let mut group = c.benchmark_group("envexec/pipe_stream_1mib");
    group.sample_size(10);
    group.warm_up_time(std::time::Duration::from_secs(1));
    group.measurement_time(std::time::Duration::from_secs(1));

    for block_size in [1usize << 10, 64 << 10, 1 << 20] {
        let blocks = (1 << 20) / block_size;
        for (mode, proxy, disable_zero_copy) in [
            ("direct", false, false),
            ("user_copy", true, true),
            ("splice", true, false),
        ] {
            let id = format!("{mode}/block_{}b", block_size);
            group.throughput(Throughput::Bytes(1 << 20));
            group.bench_function(id, |b| {
                b.iter(|| {
                    let commands = vec![
                        bench_command(
                            &[
                                "/bin/dd",
                                "if=/dev/zero",
                                &format!("bs={block_size}"),
                                &format!("count={blocks}"),
                                "status=none",
                            ],
                            vec![Some(bench_null_stdio()), None],
                        ),
                        bench_command(&["/bin/cat"], vec![None, Some(bench_null_stdio())]),
                    ];
                    let mapping = PipeMapping {
                        input: PipeIndex { index: 0, fd: 1 },
                        output: PipeIndex { index: 1, fd: 0 },
                        proxy,
                        disable_zero_copy,
                        ..Default::default()
                    };
                    let results = Group {
                        commands,
                        pipes: vec![mapping],
                        new_store_file: std::sync::Arc::new(|| std::fs::File::open("/dev/null")),
                    }
                    .run()
                    .expect("run pipe benchmark group");
                    assert!(results.iter().all(|result| {
                        result.status == rust_judge::envexec::Status::Accepted
                    }));
                    black_box(results);
                });
            });
        }
    }
    group.finish();
}

/// Measures interactive request/reply traffic over two production Group pipe
/// mappings. Each Criterion iteration launches the process pair once and
/// exchanges 256 messages, amortizing process startup while retaining the
/// blocking, small-write behavior of Go's interactive proxy benchmark.
fn envexec_pipe_interactive(c: &mut Criterion) {
    const MESSAGES: usize = 256;
    let mut group = c.benchmark_group("envexec/pipe_interactive_256_roundtrips");
    group.sample_size(10);
    group.warm_up_time(std::time::Duration::from_secs(1));
    group.measurement_time(std::time::Duration::from_secs(1));

    for message_size in [8usize, 64, 256, 1024] {
        let message = "x".repeat(message_size);
        let script_a = format!(
            r#"i=0; while [ "$i" -lt {MESSAGES} ]; do printf '%s\n' "$1"; IFS= read -r reply || exit 2; [ "$reply" = "$1" ] || exit 3; i=$((i+1)); done"#,
        );
        let script_b = r#"while IFS= read -r line; do printf '%s\n' "$line"; done"#;

        for (mode, proxy, disable_zero_copy) in [
            ("direct", false, false),
            ("user_copy", true, true),
            ("splice", true, false),
        ] {
            let id = format!("{mode}/message_{message_size}b");
            group.throughput(Throughput::Elements(MESSAGES as u64));
            group.bench_function(id, |b| {
                b.iter(|| {
                    let commands = vec![
                        bench_command(
                            &["/bin/sh", "-c", &script_a, "bench", &message],
                            vec![None, None],
                        ),
                        bench_command(&["/bin/sh", "-c", script_b], vec![None, None]),
                    ];
                    let pipe = |input, output| PipeMapping {
                        input: PipeIndex {
                            index: input,
                            fd: 1,
                        },
                        output: PipeIndex {
                            index: output,
                            fd: 0,
                        },
                        proxy,
                        disable_zero_copy,
                        ..Default::default()
                    };
                    let results = Group {
                        commands,
                        pipes: vec![pipe(0, 1), pipe(1, 0)],
                        new_store_file: std::sync::Arc::new(|| std::fs::File::open("/dev/null")),
                    }
                    .run()
                    .expect("run interactive pipe benchmark group");
                    assert!(results.iter().all(|result| {
                        result.status == rust_judge::envexec::Status::Accepted
                    }));
                    black_box(results);
                });
            });
        }
    }
    group.finish();
}

fn bench_command(args: &[&str], files: Vec<Option<EnvFile>>) -> Cmd {
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

fn bench_null_stdio() -> EnvFile {
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

fn memfd_copy(c: &mut Criterion) {
    let mut group = c.benchmark_group("memfd/copy_and_seal");
    for size in [4096usize, 1 << 20] {
        let payload = vec![b'x'; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &payload, |b, bytes| {
            b.iter(|| {
                let file = memfd::dup_to_memfd("criterion", Cursor::new(black_box(bytes)))
                    .expect("copy into memfd");
                black_box(file);
            });
        });
    }
    group.finish();
}

/// This benchmark is opt-in because changing cgroup controller state on an
/// arbitrary system cgroup is unsafe. The environment variable must point to
/// a dedicated, already-delegated cgroup v2 directory below /sys/fs/cgroup.
fn cgroup_v2(c: &mut Criterion) {
    let Some(root) = cgroup_bench_root() else {
        eprintln!(
            "skipping cgroup_v2/configure_sample_destroy: set RUST_SANDBOX_CGROUP_V2_BENCH_ROOT to a dedicated delegated cgroup v2 directory"
        );
        return;
    };

    let cpus = match delegated_cgroup_cpus(&root) {
        Ok(cpus) => cpus,
        Err(reason) => {
            eprintln!("skipping cgroup_v2/configure_sample_destroy: {reason}");
            return;
        }
    };
    let builder = CgroupV2Builder::new(&root);
    let cgroup = match builder.create("rust-sandbox-bench") {
        Ok(cgroup) => cgroup,
        Err(error) => {
            eprintln!("skipping cgroup_v2/configure_sample_destroy: {error}");
            return;
        }
    };
    let root_guard = CgroupV2Cleanup(Some(cgroup));
    // Validate the kernel exposes memory.peak before Criterion starts. Older
    // kernels lack this file; in that case the Go-equivalent benchmark cannot
    // sample its requested metric.
    if let Err(error) = root_guard
        .0
        .as_ref()
        .expect("benchmark cgroup")
        .max_memory()
    {
        eprintln!("skipping cgroup_v2/configure_sample_destroy: memory.peak unavailable: {error}");
        return;
    }

    c.bench_function("cgroup_v2/configure_sample_destroy", |b| {
        b.iter(|| {
            let mut child = CgroupCleanup(Some(
                root_guard
                    .0
                    .as_ref()
                    .expect("benchmark cgroup")
                    .new_child("test")
                    .expect("create cgroup test child"),
            ));
            let group = child.0.as_deref_mut().expect("child cgroup");
            group.set_cpuset(&cpus).expect("set cgroup cpuset");
            group
                .set_memory_limit(4096)
                .expect("set cgroup memory limit");
            group.set_proc_limit(1).expect("set cgroup process limit");
            black_box(group.cpu_usage().expect("sample cgroup CPU usage"));
            black_box(group.current_memory().expect("sample cgroup memory"));
            black_box(group.max_memory().expect("sample cgroup peak memory"));
            child.destroy().expect("destroy cgroup test child");
        });
    });
    drop(root_guard);
}

struct CgroupV2Cleanup(Option<CgroupV2>);
impl Drop for CgroupV2Cleanup {
    fn drop(&mut self) {
        if let Some(cgroup) = self.0.take() {
            let _ = Box::new(cgroup).destroy();
        }
    }
}

struct CgroupCleanup(Option<Box<dyn Cgroup>>);
impl CgroupCleanup {
    fn destroy(&mut self) -> std::io::Result<()> {
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

fn cgroup_bench_root() -> Option<std::path::PathBuf> {
    let raw = std::env::var_os("RUST_SANDBOX_CGROUP_V2_BENCH_ROOT")?;
    let path = std::path::PathBuf::from(raw).canonicalize().ok()?;
    let cgroup_mount = std::path::Path::new("/sys/fs/cgroup").canonicalize().ok()?;
    if path == cgroup_mount || !path.starts_with(&cgroup_mount) || !path.is_dir() {
        return None;
    }
    Some(path)
}

fn delegated_cgroup_cpus(root: &std::path::Path) -> Result<String, String> {
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

criterion_group!(
    benches,
    socket_ping,
    unixsocket_baselines,
    worker_result_delivery,
    profile_sampler_blocking_pool_availability,
    tokio_task_poll_hook_overhead,
    socket_fd_batches,
    protobuf_encode_decode,
    forkexec_true,
    container_exec_true,
    envexec_pipe_stream,
    envexec_pipe_interactive,
    memfd_copy,
    cgroup_v2
);
criterion_main!(benches);
