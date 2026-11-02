use super::*;

use super::command::{CollectorJob, Prepared, prepare_files};
use super::group::with_cpu_affinity;
use std::io::Cursor;
use std::sync::Mutex;
struct CompletedProcess;
impl Process for CompletedProcess {
    fn done(&self) -> bool {
        true
    }
    fn result(&self) -> RunnerResult {
        RunnerResult {
            status: crate::runner::Status::Normal,
            ..Default::default()
        }
    }
    fn usage(&self) -> Usage {
        Usage::default()
    }
    fn cancel(&self) {}
}
#[derive(Default)]
struct FakeEnv {
    root: PathBuf,
    launched: Mutex<Vec<ExecveParam>>,
    links: Mutex<Vec<SymlinkParam>>,
    opened_batches: Mutex<Vec<usize>>,
}
impl Environment for FakeEnv {
    fn execve(&self, p: ExecveParam) -> io::Result<Box<dyn Process>> {
        if matches!(
            p.args.first().map(String::as_str),
            Some("write_output" | "write_output_to_stdout")
        ) {
            use std::os::fd::RawFd;
            let index =
                usize::from(p.args.first().map(String::as_str) == Some("write_output_to_stdout"));
            let fd =
                *p.files
                    .get(index)
                    .ok_or_else(|| io::Error::other("missing output fd"))? as RawFd;
            // SAFETY: the raw fd belongs to the prepared output pipe for this command.
            if unsafe { libc::write(fd, b"hello".as_ptr().cast(), 5) } < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        self.launched.lock().unwrap().push(p);
        Ok(Box::new(CompletedProcess))
    }
    fn open(&self, params: &[OpenParam]) -> io::Result<Vec<OpenResult>> {
        self.opened_batches.lock().unwrap().push(params.len());
        params
            .iter()
            .map(|p| {
                let path = self.root.join(&p.path);
                if p.mkdir_all
                    && let Some(parent) = path.parent()
                {
                    fs::create_dir_all(parent)?;
                }
                let f = open_host(path.to_str().unwrap(), p.flag, p.perm, p.mkdir_all)?;
                Ok(OpenResult {
                    file: Some(f),
                    error: None,
                })
            })
            .collect()
    }
    fn symlink(&self, params: &[SymlinkParam]) -> io::Result<Vec<Option<String>>> {
        self.links.lock().unwrap().extend_from_slice(params);
        Ok(vec![None; params.len()])
    }
}
fn test_store(dir: PathBuf) -> NewStoreFile {
    Arc::new(move || {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(dir.join(format!("store-{n}")))
    })
}

#[cfg(target_os = "linux")]
#[test]
fn proxy_cpu_affinity_pins_the_relay_thread_and_ignores_invalid_masks() {
    use nix::{sched, unistd::Pid};
    let allowed = sched::sched_getaffinity(Pid::from_raw(0)).unwrap();
    let cpu = (0..sched::CpuSet::count())
        .find(|cpu| allowed.is_set(*cpu).unwrap_or(false))
        .unwrap();
    std::thread::spawn(move || {
        with_cpu_affinity(&cpu.to_string(), || {
            let current = sched::sched_getaffinity(Pid::from_raw(0)).unwrap();
            assert!(current.is_set(cpu).unwrap());
            assert_eq!(
                (0..sched::CpuSet::count())
                    .filter(|candidate| current.is_set(*candidate).unwrap_or(false))
                    .count(),
                1
            );
        });
        with_cpu_affinity("not-a-cpu", || {
            let current = sched::sched_getaffinity(Pid::from_raw(0)).unwrap();
            assert!(current.is_set(cpu).unwrap());
        });
    })
    .join()
    .unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn reader_inputs_use_seekable_sealed_memfd_with_pipe_fallback() {
    use std::io::{Cursor, Read, Seek, SeekFrom};

    let mut threads = Vec::new();
    let mut memfd = reader_to_host_file(
        Box::new(Cursor::new(b"seekable input".to_vec())),
        &mut threads,
        true,
    )
    .unwrap();
    assert!(memfd.metadata().unwrap().file_type().is_file());
    memfd.seek(SeekFrom::Start(9)).unwrap();
    let mut tail = String::new();
    memfd.read_to_string(&mut tail).unwrap();
    assert_eq!(tail, "input");
    assert!(memfd.write_all(b"x").is_err());

    let mut pipe_threads = Vec::new();
    let mut pipe = reader_to_host_file(
        Box::new(Cursor::new(b"pipe fallback".to_vec())),
        &mut pipe_threads,
        false,
    )
    .unwrap();
    assert!(!pipe.metadata().unwrap().file_type().is_file());
    let mut content = Vec::new();
    pipe.read_to_end(&mut content).unwrap();
    for thread in pipe_threads {
        thread.recv().unwrap();
    }
    assert_eq!(content, b"pipe fallback");
}

#[cfg(unix)]
#[test]
fn non_pipe_collectors_use_one_batched_environment_open() {
    let root = std::env::temp_dir().join(format!("envexec-collector-batch-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let env = Arc::new(FakeEnv {
        root: root.clone(),
        ..Default::default()
    });
    let mut cmd = unsafe_cmd_defaults(env.clone());
    cmd.files = vec![
        Some(File::collector("stdout", Size(1024), false)),
        Some(File::collector("stderr", Size(1024), false)),
    ];
    let prepared = prepare_files(&mut cmd, &test_store(root.clone())).unwrap();
    assert_eq!(*env.opened_batches.lock().unwrap(), [4]);
    assert_eq!(prepared.fds.len(), 2);
    drop(prepared);
    fs::remove_dir_all(root).unwrap();
}
struct Env {
    root: PathBuf,
    fail: bool,
}
impl Environment for Env {
    fn execve(&self, _: ExecveParam) -> io::Result<Box<dyn Process>> {
        Err(io::Error::other("execve is unused by this collector test"))
    }
    fn open(&self, p: &[OpenParam]) -> io::Result<Vec<OpenResult>> {
        if self.fail {
            return Err(io::Error::other("open failed"));
        }
        assert!(
            p.iter()
                .all(|x| x.flag == 577 && x.perm == 0o777 && x.mkdir_all)
        );
        p.iter()
            .map(|x| {
                let path = self.root.join(&x.path);
                fs::create_dir_all(path.parent().unwrap())?;
                Ok(OpenResult {
                    file: Some(
                        OpenOptions::new()
                            .write(true)
                            .create(true)
                            .truncate(true)
                            .open(path)?,
                    ),
                    error: None,
                })
            })
            .collect()
    }
    fn symlink(&self, _: &[SymlinkParam]) -> io::Result<Vec<Option<String>>> {
        Ok(vec![])
    }
}
#[tokio::test]
async fn single_async_runs_copyin_symlink_exec_and_copyout() {
    let root = std::env::temp_dir().join(format!("envexec-single-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("output.txt"), b"captured").unwrap();
    let env = Arc::new(FakeEnv {
        root: root.clone(),
        ..Default::default()
    });
    let cmd = Cmd {
        environment: env.clone(),
        copy_in: HashMap::from([(
            "input.txt".into(),
            File::reader(Cursor::new(b"input".to_vec())),
        )]),
        symlinks: HashMap::from([("alias".into(), "input.txt".into())]),
        args: vec!["/bin/true".into()],
        files: vec![Some(File::opened(HostFile::open("/dev/null").unwrap()))],
        copy_out: vec![CmdCopyOutFile {
            name: "output.txt".into(),
            optional: false,
        }],
        ..unsafe_cmd_defaults(env.clone())
    };
    let store_dir = root.join("store");
    fs::create_dir_all(&store_dir).unwrap();
    let result = Single {
        cmd,
        new_store_file: test_store(store_dir.clone()),
    }
    .run_with_cancel_async(|| false)
    .await
    .unwrap();
    assert_eq!(result.status, Status::Accepted);
    assert_eq!(fs::read(root.join("input.txt")).unwrap(), b"input");
    assert!(result.files.contains_key("output.txt"));
    assert_eq!(env.launched.lock().unwrap()[0].args, ["/bin/true"]);
    assert_eq!(env.links.lock().unwrap().len(), 1);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn async_single_wait_does_not_block_tokio_worker() {
    struct DelayedProcess(Arc<AtomicBool>);
    impl Process for DelayedProcess {
        fn done(&self) -> bool {
            self.0.load(Ordering::Acquire)
        }
        fn result(&self) -> RunnerResult {
            RunnerResult {
                status: crate::runner::Status::Normal,
                ..Default::default()
            }
        }
        fn usage(&self) -> Usage {
            Usage::default()
        }
        fn wait_timeout_async<'a>(
            &'a self,
            _: Duration,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
            let done = self.0.clone();
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(30)).await;
                done.store(true, Ordering::Release);
            })
        }
        fn cancel(&self) {
            self.0.store(true, Ordering::Release);
        }
    }
    struct DelayedEnvironment(Arc<AtomicBool>);
    impl Environment for DelayedEnvironment {
        fn execve(&self, _: ExecveParam) -> io::Result<Box<dyn Process>> {
            Ok(Box::new(DelayedProcess(self.0.clone())))
        }
        fn open(&self, _: &[OpenParam]) -> io::Result<Vec<OpenResult>> {
            Ok(vec![])
        }
        fn symlink(&self, _: &[SymlinkParam]) -> io::Result<Vec<Option<String>>> {
            Ok(vec![])
        }
    }

    let root = std::env::temp_dir().join(format!(
        "envexec-async-wait-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&root).unwrap();
    let done = Arc::new(AtomicBool::new(false));
    let env: Arc<dyn Environment> = Arc::new(DelayedEnvironment(done.clone()));
    let mut cmd = unsafe_cmd_defaults(env.clone());
    cmd.args = vec!["/bin/true".into()];
    cmd.files = vec![Some(File::opened(HostFile::open("/dev/null").unwrap()))];
    let store = test_store(root.clone());

    let ticked = Arc::new(AtomicBool::new(false));
    let ticked_task = ticked.clone();
    let timer = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(5)).await;
        ticked_task.store(true, Ordering::Release);
    });
    let result = Single {
        cmd,
        new_store_file: store,
    }
    .run_with_cancel_async(|| false)
    .await
    .unwrap();
    timer.await.unwrap();
    assert_eq!(result.status, Status::Accepted);
    assert!(ticked.load(Ordering::Acquire));
    assert!(done.load(Ordering::Acquire));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn copyout_truncate_returns_bytes_from_start_of_store_file() {
    let root =
        std::env::temp_dir().join(format!("envexec-copyout-truncate-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("output.txt"), b"1234567890").unwrap();
    let env = Arc::new(FakeEnv {
        root: root.clone(),
        ..Default::default()
    });
    let mut cmd = unsafe_cmd_defaults(env.clone());
    cmd.args = vec!["/bin/true".into()];
    cmd.copy_out = vec![CmdCopyOutFile {
        name: "output.txt".into(),
        optional: false,
    }];
    cmd.copy_out_max = Size(5);
    cmd.copy_out_truncate = true;
    cmd.files = vec![Some(File::opened(HostFile::open("/dev/null").unwrap()))];
    let store_dir = root.join("store");
    fs::create_dir_all(&store_dir).unwrap();
    let result = Single {
        cmd,
        new_store_file: test_store(store_dir.clone()),
    }
    .run()
    .unwrap();
    assert_eq!(result.status, Status::FileError);
    let mut output = result.files.get("output.txt").unwrap().try_clone().unwrap();
    output.seek(SeekFrom::Start(0)).unwrap();
    let mut contents = Vec::new();
    output.read_to_end(&mut contents).unwrap();
    assert_eq!(contents, b"12345");
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn tty_collects_merged_output_from_a_shared_pty() {
    let root = std::env::temp_dir().join(format!("envexec-tty-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let env = Arc::new(FakeEnv {
        root: root.clone(),
        ..Default::default()
    });
    let cmd = Cmd {
        environment: env.clone(),
        args: vec!["write_output_to_stdout".into()],
        tty: true,
        files: vec![
            Some(File::reader(Cursor::new(b"input".to_vec()))),
            Some(File::collector("stdout", Size(1024), false)),
        ],
        ..unsafe_cmd_defaults(env)
    };
    let store_dir = root.join("store");
    fs::create_dir_all(&store_dir).unwrap();
    let result = Single {
        cmd,
        new_store_file: test_store(store_dir.clone()),
    }
    .run()
    .unwrap();
    assert_eq!(result.status, Status::Accepted);
    let mut output_file = result.files.get("stdout").unwrap().try_clone().unwrap();
    std::io::Seek::seek(&mut output_file, std::io::SeekFrom::Start(0)).unwrap();
    let mut output = Vec::new();
    output_file.read_to_end(&mut output).unwrap();
    // PTY input is echoed concurrently with the fake workload's output,
    // so either ordering is valid while both streams must be captured.
    assert!(output.windows(5).any(|part| part == b"input"));
    assert!(output.windows(5).any(|part| part == b"hello"));
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn pty_resize_updates_window_size_with_tiocswinsz() {
    let pair = nix::pty::openpty(None, None).unwrap();
    let master = HostFile::from(pair.master);
    let slave = HostFile::from(pair.slave);
    set_pty_window_size(
        master.as_raw_fd(),
        TerminalSize {
            rows: 37,
            cols: 119,
            x: 951,
            y: 681,
        },
    )
    .unwrap();
    let mut actual = unsafe { std::mem::zeroed::<libc::winsize>() };
    assert_eq!(
        unsafe { libc::ioctl(slave.as_raw_fd(), libc::TIOCGWINSZ, &mut actual) },
        0
    );
    assert_eq!(
        (
            actual.ws_row,
            actual.ws_col,
            actual.ws_xpixel,
            actual.ws_ypixel
        ),
        (37, 119, 951, 681)
    );
}

#[cfg(unix)]
#[test]
fn tty_resize_listener_stops_when_command_finishes_with_sender_alive() {
    let root = std::env::temp_dir().join(format!("envexec-tty-resize-stop-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let env = Arc::new(FakeEnv {
        root: root.clone(),
        ..Default::default()
    });
    let (resize_tx, resize_rx) = std::sync::mpsc::channel();
    let mut cmd = unsafe_cmd_defaults(env.clone());
    cmd.args = vec!["write_output".into()];
    cmd.tty = true;
    cmd.terminal_resize = Some(Arc::new(Mutex::new(resize_rx)));
    cmd.files = vec![Some(File::collector("stdout", Size(1024), false))];
    let result = Single {
        cmd,
        new_store_file: test_store(root.clone()),
    }
    .run()
    .unwrap();
    assert_eq!(result.status, Status::Accepted, "{}", result.error);
    drop(resize_tx);
    fs::remove_dir_all(root).unwrap();
}
fn unsafe_cmd_defaults(env: Arc<dyn Environment>) -> Cmd {
    Cmd {
        environment: env,
        copy_in: HashMap::new(),
        symlinks: HashMap::new(),
        args: vec![],
        env: vec![],
        files: vec![],
        tty: false,
        terminal_resize: None,
        time_limit: Duration::ZERO,
        clock_limit: Duration::ZERO,
        memory_limit: Size(0),
        stack_limit: Size(0),
        extra_memory_limit: Size(0),
        output_limit: Size(0),
        proc_limit: 0,
        open_file_limit: 0,
        cpu_rate_limit: 0,
        cpu_set_limit: String::new(),
        copy_out: vec![],
        copy_out_max: Size(0),
        copy_out_truncate: false,
        address_space_limit: false,
        data_segment_limit: false,
    }
}

#[cfg(unix)]
#[test]
fn single_writer_pipe_finishes_after_command_fds_close() {
    struct SharedWriter(Arc<Mutex<Vec<u8>>>);
    impl Write for SharedWriter {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let root = std::env::temp_dir().join(format!("envexec-writer-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let output = Arc::new(Mutex::new(Vec::new()));
    let env = Arc::new(FakeEnv {
        root: root.clone(),
        ..Default::default()
    });
    let mut cmd = unsafe_cmd_defaults(env);
    cmd.args = vec!["write_output".into()];
    cmd.files = vec![Some(File::writer(SharedWriter(output.clone()), Size(5)))];
    let result = Single {
        cmd,
        new_store_file: test_store(root.clone()),
    }
    .run()
    .unwrap();
    assert_eq!(result.status, Status::Accepted);
    assert_eq!(*output.lock().unwrap(), b"hello");
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn async_group_connects_command_descriptors_with_a_direct_pipe() {
    use std::sync::Mutex;
    struct PipeEnv(Arc<Mutex<Vec<u8>>>);
    impl Environment for PipeEnv {
        fn execve(&self, p: ExecveParam) -> io::Result<Box<dyn Process>> {
            use std::os::fd::RawFd;
            let fd = *p
                .files
                .first()
                .ok_or_else(|| io::Error::other("missing fd"))? as RawFd;
            if p.args.first().map(String::as_str) == Some("write") {
                let data = b"hello";
                // SAFETY: fd is the held writer end supplied in ExecveParam and data is valid.
                let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
                if n < 0 {
                    return Err(io::Error::last_os_error());
                }
            } else {
                let mut data = [0u8; 5];
                // SAFETY: fd is the held reader end supplied in ExecveParam and data is writable.
                let n = unsafe { libc::read(fd, data.as_mut_ptr().cast(), data.len()) };
                if n < 0 {
                    return Err(io::Error::last_os_error());
                }
                self.0
                    .lock()
                    .unwrap()
                    .extend_from_slice(&data[..n as usize]);
            }
            Ok(Box::new(CompletedProcess))
        }
        fn open(&self, _: &[OpenParam]) -> io::Result<Vec<OpenResult>> {
            Ok(vec![])
        }
        fn symlink(&self, _: &[SymlinkParam]) -> io::Result<Vec<Option<String>>> {
            Ok(vec![])
        }
    }
    fn make_cmd(env: Arc<dyn Environment>, arg: &str) -> Cmd {
        let mut c = unsafe_cmd_defaults(env);
        c.args = vec![arg.into()];
        c.files = vec![None];
        c
    }
    let root = std::env::temp_dir().join(format!("envexec-group-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let observed = Arc::new(Mutex::new(Vec::new()));
    let env = Arc::new(PipeEnv(observed.clone()));
    let group = Group {
        commands: vec![make_cmd(env.clone(), "write"), make_cmd(env, "read")],
        pipes: vec![PipeMapping {
            input: PipeIndex { index: 0, fd: 0 },
            output: PipeIndex { index: 1, fd: 0 },
            ..Default::default()
        }],
        new_store_file: test_store(root.clone()),
    };
    let results = group.run_with_cancel_async(|| false).await.unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(*observed.lock().unwrap(), b"hello");
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn async_group_proxy_pipe_relays_data_in_copy_and_splice_modes() {
    use std::sync::Mutex;
    const DATA_LEN: usize = 256 * 1024;
    struct ProxyEnv(Arc<Mutex<Vec<u8>>>);
    impl Environment for ProxyEnv {
        fn execve(&self, p: ExecveParam) -> io::Result<Box<dyn Process>> {
            use std::os::fd::RawFd;
            let fd = *p
                .files
                .first()
                .ok_or_else(|| io::Error::other("missing fd"))? as RawFd;
            if p.args.first().map(String::as_str) == Some("write") {
                let data = vec![b'x'; DATA_LEN];
                let mut offset = 0;
                while offset < data.len() {
                    let n = unsafe {
                        libc::write(fd, data[offset..].as_ptr().cast(), data.len() - offset)
                    };
                    if n < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    offset += n as usize;
                }
            } else {
                let mut data = vec![0u8; 8192];
                loop {
                    let n = unsafe { libc::read(fd, data.as_mut_ptr().cast(), data.len()) };
                    if n < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    if n == 0 {
                        break;
                    }
                    self.0
                        .lock()
                        .unwrap()
                        .extend_from_slice(&data[..n as usize]);
                }
            }
            Ok(Box::new(CompletedProcess))
        }
        fn open(&self, _: &[OpenParam]) -> io::Result<Vec<OpenResult>> {
            Ok(vec![])
        }
        fn symlink(&self, _: &[SymlinkParam]) -> io::Result<Vec<Option<String>>> {
            Ok(vec![])
        }
    }
    fn cmd(env: Arc<dyn Environment>, arg: &str) -> Cmd {
        let mut command = unsafe_cmd_defaults(env);
        command.args = vec![arg.into()];
        command.files = vec![None];
        command
    }
    let root = std::env::temp_dir().join(format!("envexec-proxy-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    for disable_zero_copy in [true, false] {
        let received = Arc::new(Mutex::new(Vec::new()));
        let env: Arc<dyn Environment> = Arc::new(ProxyEnv(received.clone()));
        let results = Group {
            commands: vec![cmd(env.clone(), "write"), cmd(env, "read")],
            pipes: vec![PipeMapping {
                input: PipeIndex { index: 0, fd: 0 },
                output: PipeIndex { index: 1, fd: 0 },
                proxy: true,
                disable_zero_copy,
                ..Default::default()
            }],
            new_store_file: test_store(root.clone()),
        }
        .run_with_cancel_async(|| false)
        .await
        .unwrap();
        assert!(
            results
                .iter()
                .all(|result| result.status == Status::Accepted)
        );
        assert_eq!(received.lock().unwrap().len(), DATA_LEN);
        assert!(received.lock().unwrap().iter().all(|byte| *byte == b'x'));
    }
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn output_pipe_limits_collection_and_drains_to_eof() {
    let relay = new_pipe(Vec::<u8>::new(), Size(3)).unwrap();
    let mut child = relay.write_end.as_ref().unwrap().try_clone().unwrap();
    child.write_all(b"abcde").unwrap();
    drop(child);
    assert_eq!(relay.wait().unwrap(), 3);
}

#[test]
fn statuses_match_go_ordinals_and_names() {
    assert_eq!(Status::InternalError as i32, 13);
    assert_eq!(
        Status::from_name("Dangerous Syscall").unwrap(),
        Status::DangerousSyscall
    );
    assert!(Status::from_name("unknown").is_err());
}
#[test]
fn file_errors_preserve_json_names() {
    assert_eq!(FileErrorType::Symlink.as_str(), "Symlink");
    assert_eq!(FileErrorType::CopyOutSizeExceeded as i32, 6);
}
#[test]
fn copyin_copies_reader_content_into_container_file() {
    let root = std::env::temp_dir().join(format!("rust-sandbox-copyin-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let env = Env {
        root: root.clone(),
        fail: false,
    };
    let input = [(
        "nested/data.txt".to_string(),
        File::reader(Cursor::new(b"payload".to_vec())),
    )]
    .into_iter()
    .collect();
    let (errors, result) = copy_in(&env, input);
    assert!(result.is_ok());
    assert!(errors.is_empty());
    assert_eq!(fs::read(root.join("nested/data.txt")).unwrap(), b"payload");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn copyin_batch_failure_returns_one_error_per_path() {
    let e = Env {
        root: std::env::temp_dir(),
        fail: true,
    };
    let input = [
        ("a", File::reader(Cursor::new(b"a".to_vec()))),
        ("b", File::reader(Cursor::new(b"b".to_vec()))),
    ]
    .into_iter()
    .map(|(n, f)| (n.to_string(), f))
    .collect();
    let (errors, err) = copy_in(&e, input);
    assert!(err.is_err());
    assert_eq!(errors.len(), 2);
    assert!(
        errors
            .iter()
            .all(|x| x.kind == FileErrorType::CopyInCreateFile && x.message == "open failed")
    );
}

#[test]
fn copyin_missing_source_is_classified_as_open_error() {
    let root = std::env::temp_dir().join(format!(
        "rust-sandbox-copyin-missing-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let env = Env {
        root: root.clone(),
        fail: false,
    };
    let input = [("missing".to_string(), File::input(root.join("not-present")))]
        .into_iter()
        .collect();
    let (errors, result) = copy_in(&env, input);
    assert!(result.is_err());
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].name, "missing");
    assert_eq!(errors[0].kind, FileErrorType::CopyInOpenFile);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn over_limit_collector_reports_collect_size_file_error() {
    let root = std::env::temp_dir().join(format!(
        "rust-sandbox-collector-limit-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let buffer_path = root.join("buffer");
    fs::write(&buffer_path, b"12345").unwrap();
    let buffer = OpenOptions::new()
        .read(true)
        .write(true)
        .open(buffer_path)
        .unwrap();
    let env: Arc<dyn Environment> = Arc::new(FakeEnv {
        root: root.clone(),
        ..Default::default()
    });
    let cmd = unsafe_cmd_defaults(env);
    let mut prepared = Prepared {
        fds: Vec::new(),
        relays: Vec::new(),
        collectors: vec![CollectorJob {
            name: "stdout".into(),
            limit: Size(3),
            buffer,
            relay: None,
        }],
        reader_threads: Vec::new(),
        resize_stop: None,
    };
    let mut result = CmdResult {
        status: Status::Accepted,
        ..Default::default()
    };
    collect_outputs(&cmd, &test_store(root.clone()), &mut prepared, &mut result).unwrap();
    assert_eq!(result.status, Status::OutputLimitExceeded);
    let error = result.file_errors.first().unwrap();
    assert_eq!(error.name, "stdout");
    assert_eq!(error.kind, FileErrorType::CollectSizeExceeded);
    assert_eq!(error.message, Status::OutputLimitExceeded.to_string());
    assert_eq!(result.files["stdout"].metadata().unwrap().len(), 4);
    fs::remove_dir_all(root).unwrap();
}
