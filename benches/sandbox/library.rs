use super::prelude::*;
use super::support::*;

pub(crate) fn socket_ping(c: &mut Criterion) {
    let (server, client) = Socket::pair().expect("socketpair");
    let server_thread = thread::spawn(move || {
        let mut input = [0u8; 64];
        while let Ok((n, _)) = server.recv_msg(&mut input) {
            server
                .send_msg(&input[..n], &SendMessage::default())
                .unwrap();
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

pub(crate) fn unixsocket_baselines(c: &mut Criterion) {
    let (server, client) = Socket::pair().expect("socketpair");
    let drain = thread::spawn(move || {
        let mut buffer = [0u8; 64];
        while let Ok((received, _)) = server.recv_msg(&mut buffer) {
            black_box(received);
        }
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

pub(crate) fn socket_fd_batches(c: &mut Criterion) {
    let (_pipe_read, descriptor) = pipe().expect("pipe");
    let mut group = c.benchmark_group("socket/fd_batch_roundtrip");
    for count in [10usize, 100, 200] {
        let (server, client) = Socket::pair().expect("socketpair");
        let service = thread::spawn(move || {
            let mut buffer = [0u8; 32];
            while let Ok((received, _)) = server.recv_msg(&mut buffer) {
                black_box(received);
                server.send_msg(b"ok", &SendMessage::default()).unwrap();
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

pub(crate) fn protobuf_encode_decode(c: &mut Criterion) {
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

/// Measures the production `envexec::Group` pipe and relay path while keeping
/// container setup out of the sample. The small adapter only maps the file
/// descriptors prepared by Group onto std::process::Command's stdio handles.
/// Workloads and pipe topology mirror Go's envexec pipe benchmarks.
pub(crate) fn envexec_pipe_stream(c: &mut Criterion) {
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
                    assert!(
                        results.iter().all(|result| {
                            result.status == rust_judge::envexec::Status::Accepted
                        })
                    );
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
pub(crate) fn envexec_pipe_interactive(c: &mut Criterion) {
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
                    assert!(
                        results.iter().all(|result| {
                            result.status == rust_judge::envexec::Status::Accepted
                        })
                    );
                    black_box(results);
                });
            });
        }
    }
    group.finish();
}

pub(crate) fn memfd_copy(c: &mut Criterion) {
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
pub(crate) fn cgroup_v2(c: &mut Criterion) {
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
