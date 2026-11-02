use super::*;

struct GateProcess(Arc<std::sync::atomic::AtomicBool>);
impl envexec::Process for GateProcess {
    fn done(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
    fn result(&self) -> crate::runner::ResultInfo {
        crate::runner::ResultInfo {
            status: crate::runner::Status::Normal,
            ..Default::default()
        }
    }
    fn usage(&self) -> envexec::Usage {
        envexec::Usage::default()
    }
    fn cancel(&self) {
        self.0.store(true, Ordering::Release)
    }
}
struct GateEnv(Arc<std::sync::atomic::AtomicBool>);
impl envexec::Environment for GateEnv {
    fn execve(&self, _: envexec::ExecveParam) -> io::Result<Box<dyn envexec::Process>> {
        Ok(Box::new(GateProcess(self.0.clone())))
    }
    fn open(&self, _: &[envexec::OpenParam]) -> io::Result<Vec<envexec::OpenResult>> {
        Ok(vec![])
    }
    fn symlink(&self, _: &[envexec::SymlinkParam]) -> io::Result<Vec<Option<String>>> {
        Ok(vec![])
    }
}
struct CancelProbeEnv {
    gate: Arc<AtomicBool>,
    process_started: std::sync::mpsc::SyncSender<()>,
}
impl envexec::Environment for CancelProbeEnv {
    fn execve(&self, _: envexec::ExecveParam) -> io::Result<Box<dyn envexec::Process>> {
        let process: Box<dyn envexec::Process> = Box::new(GateProcess(self.gate.clone()));
        let _ = self.process_started.send(());
        Ok(process)
    }
    fn open(&self, _: &[envexec::OpenParam]) -> io::Result<Vec<envexec::OpenResult>> {
        Ok(vec![])
    }
    fn symlink(&self, _: &[envexec::SymlinkParam]) -> io::Result<Vec<Option<String>>> {
        Ok(vec![])
    }
}
struct GatePool {
    env: Arc<dyn envexec::Environment>,
    destroyed: Arc<AtomicBool>,
}
impl EnvironmentPool for GatePool {
    fn get(&self) -> io::Result<Arc<dyn envexec::Environment>> {
        Ok(self.env.clone())
    }
    fn put(&self, _: Arc<dyn envexec::Environment>) {}
    fn destroy(&self) {
        self.destroyed.store(true, Ordering::Release)
    }
}
fn request(id: &str) -> Request {
    Request {
        request_id: id.into(),
        commands: vec![Command::default()],
        pipe_mapping: vec![],
    }
}

#[test]
fn async_worker_signals_start_enforces_queue_capacity_and_drains_on_shutdown() {
    let dir = std::env::temp_dir().join(format!("worker-queue-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let gate = Arc::new(AtomicBool::new(false));
    let destroyed = Arc::new(AtomicBool::new(false));
    let env: Arc<dyn envexec::Environment> = Arc::new(GateEnv(gate.clone()));
    let pool: Arc<dyn EnvironmentPool> = Arc::new(GatePool {
        env,
        destroyed: destroyed.clone(),
    });
    let mut cfg = WorkerConfig::new(LocalFileStore::new(&dir), pool);
    cfg.parallelism = 1;
    cfg.queue_capacity = 1;
    let worker = AsyncWorker::new(cfg);
    worker.start().unwrap();
    let (first, started) = worker.submit(request("first"), CancellationToken::default());
    started.recv_timeout(Duration::from_secs(1)).unwrap();
    let (second, second_started) = worker.submit(request("second"), CancellationToken::default());
    assert_eq!(worker.stat().queue, 1);
    assert_eq!(worker.stat().running, 1);
    let (full, full_started) = worker.submit(request("full"), CancellationToken::default());
    full_started.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(
        full.blocking_recv().unwrap().error.as_deref(),
        Some("worker queue is full")
    );
    gate.store(true, Ordering::Release);
    assert_eq!(first.blocking_recv().unwrap().request_id, "first");
    second_started.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(second.blocking_recv().unwrap().request_id, "second");
    worker.shutdown();
    assert!(destroyed.load(Ordering::Acquire));
    assert!(worker.start().is_err());
    let _ = std::fs::remove_dir_all(dir);
}
#[test]
fn async_worker_cancels_running_process_when_token_is_signaled() {
    let dir = std::env::temp_dir().join(format!("worker-cancel-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let gate = Arc::new(AtomicBool::new(false));
    let (process_started, process_started_rx) = std::sync::mpsc::sync_channel(1);
    let env: Arc<dyn envexec::Environment> = Arc::new(CancelProbeEnv {
        gate,
        process_started,
    });
    let pool: Arc<dyn EnvironmentPool> = Arc::new(GatePool {
        env,
        destroyed: Arc::new(AtomicBool::new(false)),
    });
    let worker = AsyncWorker::new(WorkerConfig::new(LocalFileStore::new(&dir), pool));
    worker.start().unwrap();
    let token = CancellationToken::default();
    let (response, started) = worker.submit(request("running-cancel"), token.clone());
    started.recv_timeout(Duration::from_secs(1)).unwrap();
    process_started_rx
        .recv_timeout(Duration::from_secs(1))
        .unwrap();
    token.cancel();
    let result = response.blocking_recv().unwrap();
    assert_eq!(result.results[0].status, JudgeStatus::InternalError);
    assert_eq!(result.results[0].error, "cancelled");
    worker.shutdown();
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn async_worker_rejects_unstarted_canceled_requests_and_runs_execute() {
    let dir = std::env::temp_dir().join(format!("worker-execute-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let gate = Arc::new(AtomicBool::new(true));
    let env: Arc<dyn envexec::Environment> = Arc::new(GateEnv(gate));
    let pool: Arc<dyn EnvironmentPool> = Arc::new(GatePool {
        env,
        destroyed: Arc::new(AtomicBool::new(false)),
    });
    let worker = AsyncWorker::new(WorkerConfig::new(LocalFileStore::new(&dir), pool));
    let (early, _) = worker.submit(request("early"), CancellationToken::default());
    assert_eq!(
        early.blocking_recv().unwrap().error.as_deref(),
        Some("worker is not started")
    );
    worker.start().unwrap();
    let token = CancellationToken::default();
    token.cancel();
    let (canceled, started) = worker.submit(request("cancelled"), token);
    started.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(
        canceled.blocking_recv().unwrap().error.as_deref(),
        Some("cancelled before execute")
    );
    let response = crate::tokio_runtime::runtime()
        .block_on(worker.execute(request("interactive"), CancellationToken::default()))
        .unwrap();
    assert_eq!(response.request_id, "interactive");
    assert_eq!(response.results[0].status, JudgeStatus::Accepted);
    worker.shutdown();
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn go_judge_status_names_and_cmd_file_debug_strings() {
    assert_eq!(JudgeStatus::Accepted as i32, 1);
    assert_eq!(JudgeStatus::InternalError as i32, 13);
    assert_eq!(
        JudgeStatus::MemoryLimitExceeded.to_string(),
        "Memory Limit Exceeded"
    );
    assert_eq!(CmdFile::Memory(vec![1, 2]).to_string(), "memory:(len:2)");
    assert_eq!(
        CmdFile::Cached("abc".into()).to_string(),
        "cached:(fileId:abc)"
    );
}
struct DummyProcess {
    usage: envexec::Usage,
}
impl envexec::Process for DummyProcess {
    fn done(&self) -> bool {
        false
    }
    fn result(&self) -> crate::runner::ResultInfo {
        Default::default()
    }
    fn usage(&self) -> envexec::Usage {
        self.usage
    }
    fn cancel(&self) {}
}
#[test]
fn waiter_detects_cpu_usage_and_treats_zero_clock_as_cpu_limit() {
    let p = DummyProcess {
        usage: envexec::Usage {
            time: Duration::from_millis(20),
            memory: Size(0),
        },
    };
    assert!(wait_for_limits(
        &p,
        Duration::from_millis(10),
        Duration::ZERO,
        Duration::from_millis(1),
        || false
    ));
    assert!(!wait_for_limits(
        &p,
        Duration::from_secs(1),
        Duration::ZERO,
        Duration::from_millis(1),
        || true
    ));
}

struct DummyEnv;
impl envexec::Environment for DummyEnv {
    fn execve(&self, _: envexec::ExecveParam) -> io::Result<Box<dyn envexec::Process>> {
        Err(io::Error::other("unused"))
    }
    fn open(&self, _: &[envexec::OpenParam]) -> io::Result<Vec<envexec::OpenResult>> {
        Ok(vec![])
    }
    fn symlink(&self, _: &[envexec::SymlinkParam]) -> io::Result<Vec<Option<String>>> {
        Ok(vec![])
    }
}
#[test]
fn prepare_command_applies_worker_defaults_and_pipe_output_filter() {
    let store = LocalFileStore::new("unused");
    let cmd = Command {
        cpu_limit: Duration::from_secs(2),
        memory_limit: Size(100),
        stack_limit: Size(200),
        output_limit: Size(0),
        open_file_limit: 0,
        cpu_set_limit: String::new(),
        copy_out: vec![
            CopyOutFile {
                name: "ordinary".into(),
                optional: false,
            },
            CopyOutFile {
                name: "pipe".into(),
                optional: true,
            },
        ],
        copy_out_cached: vec![],
        files: vec![CmdFile::Null, CmdFile::Memory(vec![1])],
        ..Default::default()
    };
    let defaults = ExecDefaults {
        extra_memory_limit: Size(50),
        output_limit: Size(7),
        copy_out_limit: Size(8),
        open_file_limit: 9,
        cpu_set: "2-3".into(),
    };
    let prepared = cmd
        .prepare_envexec(
            Arc::new(DummyEnv),
            &store,
            &defaults,
            &["pipe".to_string()].into_iter().collect(),
        )
        .unwrap();
    let p = prepared.execve_param(vec![]);
    assert_eq!(p.limit.memory, Size(150));
    assert_eq!(p.limit.stack, Size(150));
    assert_eq!(p.limit.output, Size(7));
    assert_eq!(p.limit.open_file, 9);
    assert_eq!(p.limit.cpu_set, "2-3");
    assert_eq!(prepared.copy_out.len(), 1);
    assert_eq!(prepared.copy_out[0].name, "ordinary");
    assert!(prepared.files[0].is_none());
    assert!(prepared.files[1].is_some());
}

#[test]
fn cached_outputs_are_added_to_store_and_removed_from_inline_files() {
    use std::io::Write;
    let dir = std::env::temp_dir().join(format!("rust-sandbox-worker-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let store = LocalFileStore::new(&dir);
    let (_, mut f) = store.new_file().unwrap();
    f.write_all(b"cached").unwrap();
    let mut files = std::collections::HashMap::new();
    files.insert("out".to_string(), f);
    let result = envexec::CmdResult {
        status: envexec::Status::Accepted,
        files,
        ..Default::default()
    };
    let cmd = Command {
        copy_out_cached: vec![CopyOutFile {
            name: "out".into(),
            optional: false,
        }],
        ..Default::default()
    };
    let converted = convert_result(result, &cmd, &store);
    assert_eq!(converted.status, JudgeStatus::Accepted);
    assert!(converted.files.is_empty());
    let id = &converted.file_ids["out"];
    let (_, mut cached) = store.get(id).unwrap();
    let mut data = String::new();
    std::io::Read::read_to_string(&mut cached, &mut data).unwrap();
    assert_eq!(data, "cached");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn partial_copy_out_files_survive_other_file_errors() {
    use std::io::Write;
    let dir = std::env::temp_dir().join(format!(
        "rust-sandbox-worker-partial-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let store = LocalFileStore::new(&dir);
    let (_, mut output) = store.new_file().unwrap();
    output.write_all(b"12345").unwrap();
    let result = envexec::CmdResult {
        status: envexec::Status::FileError,
        files: std::collections::HashMap::from([("stdout".to_owned(), output)]),
        ..Default::default()
    };
    let mut converted = convert_result(result, &Command::default(), &store);
    assert_eq!(converted.status, JudgeStatus::FileError);
    let mut stdout = converted.files.get_mut("stdout").unwrap();
    stdout.seek(SeekFrom::Start(0)).unwrap();
    let mut contents = String::new();
    std::io::Read::read_to_string(&mut stdout, &mut contents).unwrap();
    assert_eq!(contents, "12345");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn memory_command_file_opens_independent_reader() {
    let store = LocalFileStore::new("unused");
    let mut opened = CmdFile::Memory(b"abc".to_vec()).open_input(&store).unwrap();
    if let InputFile::Memory(ref mut c) = opened {
        use std::io::Read;
        let mut bytes = Vec::new();
        c.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"abc");
    } else {
        panic!("expected in-memory input");
    }
}
