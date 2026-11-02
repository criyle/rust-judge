use super::*;

pub(super) struct Prepared {
    pub(super) fds: Vec<HostFile>,
    pub(super) relays: Vec<PipeRelay>,
    pub(super) collectors: Vec<CollectorJob>,
    pub(super) reader_threads: Vec<std::sync::mpsc::Receiver<()>>,
    pub(super) resize_stop: Option<Arc<AtomicBool>>,
}
impl Drop for Prepared {
    fn drop(&mut self) {
        if let Some(stop) = &self.resize_stop {
            stop.store(true, Ordering::Release);
        }
    }
}
pub(super) struct CollectorJob {
    pub(super) name: String,
    pub(super) limit: Size,
    pub(super) buffer: HostFile,
    pub(super) relay: Option<PipeRelay>,
}
pub(super) fn run_command(
    cmd: Cmd,
    store: &NewStoreFile,
    cancelled: &dyn Fn() -> bool,
) -> io::Result<CmdResult> {
    let running = match start_command(cmd, store) {
        CommandStart::Finished(result) => return Ok(result),
        CommandStart::Running(running) => running,
    };
    let mut limit_hit = None;
    let mut was_cancelled = false;
    while !running.process.done() {
        if cancelled() && !was_cancelled {
            was_cancelled = true;
            running.process.cancel();
        }
        update_limits(
            running.process.as_ref(),
            running.start,
            &running.cmd,
            &mut limit_hit,
        );
        if limit_hit.is_some() {
            running.process.cancel();
        }
        // Match Go's 100ms resource-check tick. Backends with an eventable
        // process handle wake early when the child exits.
        running.process.wait_timeout(Duration::from_millis(100));
    }
    if limit_hit.is_none()
        && running.cmd.clock_limit > Duration::ZERO
        && running.start.elapsed() > running.cmd.clock_limit
    {
        limit_hit = Some(Status::TimeLimitExceeded);
    }
    finish_command(running, limit_hit, was_cancelled)
}

pub(super) struct RunningCommand {
    cmd: Cmd,
    store: NewStoreFile,
    prepared: Prepared,
    process: Box<dyn Process>,
    file_errors: Vec<FileError>,
    start: std::time::Instant,
}

// This state is short lived on the hot command path. Boxing RunningCommand
// would add an allocation for every launched command.
#[allow(clippy::large_enum_variant)]
pub(super) enum CommandStart {
    Finished(CmdResult),
    Running(RunningCommand),
}

pub(super) fn start_command(mut cmd: Cmd, store: &NewStoreFile) -> CommandStart {
    let prepared = match prepare_files(&mut cmd, store) {
        Ok(v) => v,
        Err(e) => {
            return CommandStart::Finished(CmdResult {
                status: Status::InternalError,
                error: e.to_string(),
                ..Default::default()
            });
        }
    };
    let (file_errors, copy_err) =
        copy_in(cmd.environment.as_ref(), std::mem::take(&mut cmd.copy_in));
    if let Err(e) = copy_err {
        drop(prepared);
        return CommandStart::Finished(CmdResult {
            status: Status::FileError,
            error: e.to_string(),
            file_errors,
            ..Default::default()
        });
    }
    if !cmd.symlinks.is_empty() {
        let batch: Vec<_> = cmd
            .symlinks
            .iter()
            .map(|(link, target)| SymlinkParam {
                link_path: link.clone(),
                target: target.clone(),
            })
            .collect();
        match cmd.environment.symlink(&batch) {
            Err(e) => {
                drop(prepared);
                return CommandStart::Finished(CmdResult {
                    status: Status::FileError,
                    error: e.to_string(),
                    file_errors,
                    ..Default::default()
                });
            }
            Ok(results) => {
                let errors: Vec<_> = results
                    .into_iter()
                    .enumerate()
                    .filter_map(|(i, e)| {
                        e.map(|message| FileError {
                            name: batch
                                .get(i)
                                .map(|v| v.link_path.clone())
                                .unwrap_or_default(),
                            kind: FileErrorType::Symlink,
                            message,
                        })
                    })
                    .collect();
                if !errors.is_empty() {
                    drop(prepared);
                    return CommandStart::Finished(CmdResult {
                        status: Status::FileError,
                        error: format!("symlink: {} operations failed", errors.len()),
                        file_errors: errors,
                        ..Default::default()
                    });
                }
            }
        }
    }
    let param = cmd.execve_param(prepared.fds.iter().map(|f| f.as_raw_fd() as u64).collect());
    let process = match cmd.environment.execve(param) {
        Ok(p) => p,
        Err(e) => {
            drop(prepared);
            return CommandStart::Finished(CmdResult {
                status: Status::InternalError,
                error: e.to_string(),
                file_errors,
                ..Default::default()
            });
        }
    };
    CommandStart::Running(RunningCommand {
        cmd,
        store: store.clone(),
        prepared,
        process,
        file_errors,
        start: std::time::Instant::now(),
    })
}

pub(super) fn update_limits(
    process: &dyn Process,
    start: std::time::Instant,
    cmd: &Cmd,
    limit_hit: &mut Option<Status>,
) {
    let usage = process.usage();
    if (cmd.time_limit > Duration::ZERO && usage.time > cmd.time_limit)
        || (cmd.clock_limit > Duration::ZERO && start.elapsed() > cmd.clock_limit)
    {
        *limit_hit = Some(Status::TimeLimitExceeded);
    }
    if cmd.memory_limit.0 > 0 && usage.memory > cmd.memory_limit {
        *limit_hit = Some(Status::MemoryLimitExceeded);
    }
}

pub(super) async fn run_command_async(
    cmd: Cmd,
    store: NewStoreFile,
    cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
) -> io::Result<CmdResult> {
    let running = tokio::task::spawn_blocking(move || start_command(cmd, &store))
        .await
        .map_err(|error| io::Error::other(format!("command setup task failed: {error}")))?;
    let running = match running {
        CommandStart::Finished(result) => return Ok(result),
        CommandStart::Running(running) => running,
    };
    let mut limit_hit = None;
    let mut was_cancelled = false;
    while !running.process.done() {
        if cancelled() && !was_cancelled {
            was_cancelled = true;
            running.process.cancel();
        }
        update_limits(
            running.process.as_ref(),
            running.start,
            &running.cmd,
            &mut limit_hit,
        );
        if limit_hit.is_some() {
            running.process.cancel();
        }
        running
            .process
            .wait_timeout_async(Duration::from_millis(100))
            .await;
    }
    if limit_hit.is_none()
        && running.cmd.clock_limit > Duration::ZERO
        && running.start.elapsed() > running.cmd.clock_limit
    {
        limit_hit = Some(Status::TimeLimitExceeded);
    }
    tokio::task::spawn_blocking(move || finish_command(running, limit_hit, was_cancelled))
        .await
        .map_err(|error| io::Error::other(format!("command cleanup task failed: {error}")))?
}

pub(super) fn finish_command(
    running: RunningCommand,
    limit_hit: Option<Status>,
    was_cancelled: bool,
) -> io::Result<CmdResult> {
    let RunningCommand {
        cmd,
        store,
        mut prepared,
        process,
        file_errors,
        start,
    } = running;
    let runner = process.result();
    let mut result = CmdResult {
        status: map_status(runner.status),
        finished_at: process.finished_at().or_else(monotonic_time_ns),
        exit_status: runner.exit_status,
        error: runner.error,
        time: runner.time,
        run_time: start.elapsed(),
        memory: runner.memory,
        proc_peak: runner.proc_peak,
        files: HashMap::new(),
        file_errors,
        ..Default::default()
    };
    if let Some(status) = limit_hit {
        result.status = status;
    }
    if was_cancelled && result.status == Status::Accepted {
        result.status = Status::InternalError;
        result.error = "cancelled".into();
    }
    for fd in prepared.fds.drain(..) {
        drop(fd);
    }
    if let Some(stop) = &prepared.resize_stop {
        stop.store(true, Ordering::Release);
    }
    for t in prepared.reader_threads.drain(..) {
        let _ = t.recv();
    }
    for relay in prepared.relays.drain(..) {
        let _ = relay.wait();
    }
    if let Err(e) = collect_outputs(&cmd, &store, &mut prepared, &mut result)
        && result.status == Status::Accepted
        && result.error.is_empty()
    {
        result.status = Status::FileError;
        result.error = e.to_string();
    }
    Ok(result)
}
pub(super) fn map_status(s: crate::runner::Status) -> Status {
    use crate::runner::Status as R;
    match s {
        R::Normal => Status::Accepted,
        R::TimeLimitExceeded => Status::TimeLimitExceeded,
        R::MemoryLimitExceeded => Status::MemoryLimitExceeded,
        R::OutputLimitExceeded => Status::OutputLimitExceeded,
        R::DisallowedSyscall => Status::DangerousSyscall,
        R::Signalled => Status::Signalled,
        R::NonzeroExitStatus => Status::NonzeroExitStatus,
        R::Invalid | R::RunnerError => Status::InternalError,
    }
}
pub(super) fn prepare_files(cmd: &mut Cmd, store: &NewStoreFile) -> io::Result<Prepared> {
    if cmd.tty {
        return prepare_tty_files(cmd, store);
    }
    let mut fds = Vec::with_capacity(cmd.files.len());
    let mut relays = Vec::new();
    let mut collectors = Vec::new();
    let mut reader_threads = Vec::new();
    let mut named = HashMap::<String, HostFile>::new();
    let mut collector_names = Vec::new();
    let mut seen_collectors = std::collections::HashSet::new();
    for file in cmd.files.iter().flatten() {
        if let File::Collector {
            name, pipe: false, ..
        } = file
            && seen_collectors.insert(name.clone())
        {
            collector_names.push(name.clone());
        }
    }
    let mut batched_collectors = HashMap::<String, (HostFile, HostFile)>::new();
    if !collector_names.is_empty() {
        let params: Vec<_> = collector_names
            .iter()
            .flat_map(|name| {
                [
                    OpenParam {
                        path: name.clone(),
                        flag: 1 | 64 | 512,
                        perm: 0o777,
                        mkdir_all: false,
                    },
                    OpenParam {
                        path: name.clone(),
                        flag: 2,
                        perm: 0o777,
                        mkdir_all: false,
                    },
                ]
            })
            .collect();
        let opened = cmd.environment.open(&params)?;
        if opened.len() != params.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "collector batch open returned wrong number of files",
            ));
        }
        let (pairs, remainder) = opened.as_chunks::<2>();
        debug_assert!(remainder.is_empty());
        for (name, pair) in collector_names.into_iter().zip(pairs) {
            if let Some(message) = pair.iter().find_map(|item| item.error.as_ref()) {
                return Err(io::Error::other(format!("container: {name}: {message}")));
            }
            let write = pair[0]
                .file
                .as_ref()
                .ok_or_else(|| io::Error::other("collector write open returned no file"))?
                .try_clone()?;
            let read = pair[1]
                .file
                .as_ref()
                .ok_or_else(|| io::Error::other("collector read open returned no file"))?
                .try_clone()?;
            batched_collectors.insert(name, (write, read));
        }
    }
    for slot in &mut cmd.files {
        let Some(file) = slot.take() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "null file descriptor",
            ));
        };
        let fd = match file {
            File::Opened(f) => f,
            File::Input(path) => HostFile::open(path)?,
            File::Reader(reader) => {
                reader_to_host_file(reader, &mut reader_threads, reader_memfd_enabled())?
            }
            File::StreamReader(mut reader) => {
                let (read, write) = os_pipe()?;
                reader_threads.push(crate::tokio_runtime::spawn_blocking(move || {
                    let mut write = write;
                    let _ = io::copy(&mut reader, &mut write);
                }));
                read
            }
            File::Writer { writer, limit } => {
                let mut relay = new_pipe(writer, limit)?;
                let w = relay.write_end.take().unwrap();
                relays.push(relay);
                w
            }
            File::Collector { name, limit, pipe } => {
                if let Some(existing) = named.get(&name) {
                    existing.try_clone()?
                } else if pipe {
                    let buffer = store()?;
                    let mut relay = new_pipe(buffer.try_clone()?, Size(limit.0.saturating_add(1)))?;
                    let w = relay.write_end.take().unwrap();
                    collectors.push(CollectorJob {
                        name: name.clone(),
                        limit,
                        buffer,
                        relay: Some(relay),
                    });
                    named.insert(name, w.try_clone()?);
                    w
                } else {
                    let (write, read) = batched_collectors.remove(&name).ok_or_else(|| {
                        io::Error::other("collector batch open did not include file")
                    })?;
                    collectors.push(CollectorJob {
                        name: name.clone(),
                        limit,
                        buffer: read,
                        relay: None,
                    });
                    named.insert(name, write.try_clone()?);
                    write
                }
            }
        };
        fds.push(fd);
    }
    Ok(Prepared {
        fds,
        relays,
        collectors,
        reader_threads,
        resize_stop: None,
    })
}

/// Prepare a shared PTY for the command's terminal-backed streams. This
/// mirrors go-judge's TTY behavior: all child descriptors use the slave, input
/// is written through the master, and the first output collector drains the
/// merged terminal stream.
pub(super) fn prepare_tty_files(cmd: &mut Cmd, store: &NewStoreFile) -> io::Result<Prepared> {
    let pair = nix::pty::openpty(None, None).map_err(io::Error::other)?;
    let master = HostFile::from(pair.master);
    let slave = HostFile::from(pair.slave);
    let mut fds = Vec::with_capacity(cmd.files.len());
    let relays = Vec::new();
    let mut collectors = Vec::new();
    let mut reader_threads = Vec::new();
    let mut has_input = false;
    let mut has_output = false;
    let resize_stop = cmd
        .terminal_resize
        .as_ref()
        .map(|_| Arc::new(AtomicBool::new(false)));

    if let Some(resize) = cmd.terminal_resize.take() {
        let resize_master = master.try_clone()?;
        let stop = resize_stop.as_ref().unwrap().clone();
        reader_threads.push(crate::tokio_runtime::spawn_blocking(move || {
            loop {
                if stop.load(Ordering::Acquire) {
                    break;
                }
                let next = resize
                    .lock()
                    .ok()
                    .map(|rx| rx.recv_timeout(Duration::from_millis(50)));
                match next {
                    Some(Ok(size)) => {
                        let _ = set_pty_window_size(resize_master.as_raw_fd(), size);
                    }
                    Some(Err(std::sync::mpsc::RecvTimeoutError::Disconnected)) | None => break,
                    Some(Err(std::sync::mpsc::RecvTimeoutError::Timeout)) => {}
                }
            }
        }));
    }

    for slot in &mut cmd.files {
        let Some(file) = slot.take() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "null file descriptor",
            ));
        };
        let fd = match file {
            File::Opened(file) => file,
            File::Input(path) => HostFile::open(path)?,
            File::Reader(mut reader) | File::StreamReader(mut reader) => {
                if has_input {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "tty: multiple input streams are not allowed",
                    ));
                }
                has_input = true;
                let mut master_write = master.try_clone()?;
                reader_threads.push(crate::tokio_runtime::spawn_blocking(move || {
                    let _ = io::copy(&mut reader, &mut master_write);
                }));
                slave.try_clone()?
            }
            File::Writer { mut writer, .. } => {
                let child_fd = slave.try_clone()?;
                if !has_output {
                    has_output = true;
                    let master_read = master.try_clone()?;
                    reader_threads.push(crate::tokio_runtime::spawn_blocking(move || {
                        let mut master_read = master_read;
                        if let Err(error) = io::copy(&mut master_read, &mut writer)
                            && error.raw_os_error() != Some(libc::EIO)
                        {}
                    }));
                }
                child_fd
            }
            File::Collector { name, limit, .. } => {
                let child_fd = slave.try_clone()?;
                if !has_output {
                    has_output = true;
                    let buffer = store()?;
                    let master_read = master.try_clone()?;
                    let thread_buffer = buffer.try_clone()?;
                    reader_threads.push(crate::tokio_runtime::spawn_blocking(move || {
                        let mut master_read = master_read;
                        let mut thread_buffer = thread_buffer;
                        let copied = io::copy(
                            &mut io::Read::by_ref(&mut master_read).take(limit.0.saturating_add(1)),
                            &mut thread_buffer,
                        );
                        if copied.is_err_and(|error| error.raw_os_error() != Some(libc::EIO)) {
                            return;
                        }
                        let _ = io::copy(&mut master_read, &mut io::sink());
                    }));
                    collectors.push(CollectorJob {
                        name,
                        limit,
                        buffer,
                        relay: None,
                    });
                }
                child_fd
            }
        };
        fds.push(fd);
    }
    // The master must be owned only by the relay threads. Keeping an extra
    // copy open here would prevent their reads from reaching PTY EOF.
    drop(master);
    drop(slave);
    Ok(Prepared {
        fds,
        relays,
        collectors,
        reader_threads,
        resize_stop,
    })
}

pub(super) fn set_pty_window_size(fd: std::os::fd::RawFd, size: TerminalSize) -> io::Result<()> {
    let winsize = libc::winsize {
        ws_row: size.rows,
        ws_col: size.cols,
        ws_xpixel: size.x,
        ws_ypixel: size.y,
    };
    if unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &winsize) } == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
pub(super) fn collect_outputs(
    cmd: &Cmd,
    store: &NewStoreFile,
    prepared: &mut Prepared,
    result: &mut CmdResult,
) -> io::Result<()> {
    for job in prepared.collectors.drain(..) {
        if let Some(relay) = job.relay {
            let _ = relay.wait();
        }
        let mut buffer = job.buffer;
        let size = buffer.metadata()?.len();
        if size > job.limit.0 {
            if result.status == Status::Accepted && result.error.is_empty() {
                result.status = Status::OutputLimitExceeded;
                result.error = Status::OutputLimitExceeded.to_string();
            }
            result.file_errors.push(FileError {
                name: job.name.clone(),
                kind: FileErrorType::CollectSizeExceeded,
                message: Status::OutputLimitExceeded.to_string(),
            });
            let _ = buffer.set_len(job.limit.0.saturating_add(1));
        }
        std::io::Seek::seek(&mut buffer, std::io::SeekFrom::Start(0))?;
        result.files.insert(job.name, buffer);
    }
    if cmd.copy_out.is_empty() {
        return Ok(());
    }
    let params: Vec<_> = cmd
        .copy_out
        .iter()
        .map(|n| OpenParam {
            path: n.name.clone(),
            flag: 0,
            perm: 0o777,
            mkdir_all: false,
        })
        .collect();
    let opened = match cmd.environment.open(&params) {
        Ok(opened) => opened,
        Err(error) => {
            for spec in &cmd.copy_out {
                let message = format!("batch open failed {}: {error}", spec.name);
                result.file_errors.push(FileError {
                    name: spec.name.clone(),
                    kind: FileErrorType::CopyOutOpen,
                    message,
                });
            }
            return Err(io::Error::other(format!(
                "copyout: batch open failed: {error}"
            )));
        }
    };
    if opened.len() != cmd.copy_out.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "copyout batch open returned wrong number of files",
        ));
    }
    let mut jobs = Vec::new();
    for (spec, item) in cmd.copy_out.iter().cloned().zip(opened) {
        if let Some(message) = item.error {
            if !spec.optional {
                result.file_errors.push(FileError {
                    name: spec.name.clone(),
                    kind: FileErrorType::CopyOutOpen,
                    message: message.clone(),
                });
                if result.status == Status::Accepted && result.error.is_empty() {
                    result.status = Status::FileError;
                    result.error = message;
                }
            }
            continue;
        }
        let Some(source) = item.file else {
            if !spec.optional {
                let message = "open returned no file".to_string();
                result.file_errors.push(FileError {
                    name: spec.name.clone(),
                    kind: FileErrorType::CopyOutOpen,
                    message: message.clone(),
                });
                if result.status == Status::Accepted && result.error.is_empty() {
                    result.status = Status::FileError;
                    result.error = message;
                }
            }
            continue;
        };
        jobs.push((spec, source));
    }
    let mut pending = jobs.into_iter();
    loop {
        let batch: Vec<_> = pending.by_ref().take(FILE_COPY_PARALLELISM).collect();
        if batch.is_empty() {
            break;
        }
        let store = Arc::clone(store);
        let joins: Vec<_> = batch
            .into_iter()
            .map(|(spec, source)| {
                let store = Arc::clone(&store);
                let copy_out_max = cmd.copy_out_max;
                let copy_out_truncate = cmd.copy_out_truncate;
                crate::tokio_runtime::spawn_blocking(move || {
                    copy_out_one(spec, source, &store, copy_out_max, copy_out_truncate)
                })
            })
            .collect();
        let outcomes: Vec<_> = joins
            .into_iter()
            .map(|join| {
                join.recv().unwrap_or_else(|_| CopyOutOutcome {
                    name: String::new(),
                    file: None,
                    file_error: Some(FileError {
                        name: String::new(),
                        kind: FileErrorType::CopyOutCopyContent,
                        message: "copyout worker panicked".into(),
                    }),
                    error: Some(io::Error::other("copyout worker panicked")),
                })
            })
            .collect();
        for outcome in outcomes {
            if let Some(file_error) = outcome.file_error {
                if result.status == Status::Accepted && result.error.is_empty() {
                    result.status = Status::FileError;
                    result.error = file_error.message.clone();
                }
                result.file_errors.push(file_error);
            }
            if let Some(error) = outcome.error
                && result.status == Status::Accepted
                && result.error.is_empty()
            {
                result.status = Status::FileError;
                result.error = error.to_string();
            }
            if let Some(file) = outcome.file {
                // Match Go's last-writer behavior when a collector and
                // copy-out entry use the same name.
                result.files.insert(outcome.name, file);
            }
        }
    }
    Ok(())
}

pub(super) struct CopyOutOutcome {
    name: String,
    file: Option<HostFile>,
    file_error: Option<FileError>,
    error: Option<io::Error>,
}

pub(super) fn copy_out_one(
    spec: CmdCopyOutFile,
    mut source: HostFile,
    store: &NewStoreFile,
    max: Size,
    truncate: bool,
) -> CopyOutOutcome {
    let name = spec.name.clone();
    let failed = |kind, message: String| CopyOutOutcome {
        name: name.clone(),
        file: None,
        file_error: Some(FileError {
            name: name.clone(),
            kind,
            message: message.clone(),
        }),
        error: Some(io::Error::other(message)),
    };
    let metadata = match source.metadata() {
        Ok(metadata) => metadata,
        Err(error) => {
            return failed(
                FileErrorType::CopyOutOpen,
                format!("copyout: stat {:?}: {error}", spec.name),
            );
        }
    };
    if !metadata.is_file() {
        return failed(
            FileErrorType::CopyOutNotRegularFile,
            format!("copyout: {:?} is not a regular file", spec.name),
        );
    }
    let mut amount = metadata.len();
    let mut exceeded = false;
    if max.0 > 0 && amount > max.0 {
        if !truncate {
            return failed(
                FileErrorType::CopyOutSizeExceeded,
                format!(
                    "copyout: {:?} size ({amount}) exceeds limit ({})",
                    spec.name, max.0
                ),
            );
        }
        amount = max.0;
        exceeded = true;
    }
    let mut target = match store() {
        Ok(file) => file,
        Err(error) => {
            return failed(
                FileErrorType::CopyOutCreateFile,
                format!(
                    "copyout: failed to create store file for {:?}: {error}",
                    spec.name
                ),
            );
        }
    };
    let copied = match io::copy(&mut Read::by_ref(&mut source).take(amount), &mut target) {
        Ok(copied) => copied,
        Err(error) => {
            return failed(
                FileErrorType::CopyOutCopyContent,
                format!(
                    "copyout: failed to copy content for {:?}: {error}",
                    spec.name
                ),
            );
        }
    };
    if let Err(error) = target.seek(SeekFrom::Start(0)) {
        return failed(
            FileErrorType::CopyOutCopyContent,
            format!(
                "copyout: failed to copy content for {:?}: {error}",
                spec.name
            ),
        );
    }
    if exceeded || (max.0 > 0 && copied > max.0) {
        let message = format!("copyout: {:?} size exceeds limit ({})", spec.name, max.0);
        return CopyOutOutcome {
            name: spec.name.clone(),
            file: Some(target),
            file_error: Some(FileError {
                name: spec.name,
                kind: FileErrorType::CopyOutSizeExceeded,
                message: message.clone(),
            }),
            error: Some(io::Error::other(message)),
        };
    }
    CopyOutOutcome {
        name: spec.name,
        file: Some(target),
        file_error: None,
        error: None,
    }
}
#[cfg(unix)]
pub(super) fn os_pipe() -> io::Result<(HostFile, HostFile)> {
    use std::os::fd::{FromRawFd, OwnedFd};
    let mut fds = [-1; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok((
        HostFile::from(unsafe { OwnedFd::from_raw_fd(fds[0]) }),
        HostFile::from(unsafe { OwnedFd::from_raw_fd(fds[1]) }),
    ))
}
