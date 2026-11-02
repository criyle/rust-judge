use super::command::run_command_async;
use super::*;

pub struct PipeRelay {
    pub write_end: Option<HostFile>,
    completion: std::sync::mpsc::Receiver<io::Result<u64>>,
}
impl PipeRelay {
    pub fn wait(self) -> io::Result<u64> {
        drop(self.write_end);
        self.completion
            .recv()
            .map_err(|_| io::Error::other("pipe relay stopped"))?
    }
}
#[cfg(unix)]
pub fn new_pipe<W: Write + Send + 'static>(sink: W, limit: Size) -> io::Result<PipeRelay> {
    use std::os::fd::{FromRawFd, OwnedFd};
    let mut fds = [-1; 2];
    // SAFETY: `fds` points to two writable integers; on success each descriptor is owned below.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pipe2 returned two fresh descriptors, each transferred into exactly one OwnedFd.
    let read_end = HostFile::from(unsafe { OwnedFd::from_raw_fd(fds[0]) });
    let write_end = HostFile::from(unsafe { OwnedFd::from_raw_fd(fds[1]) });
    let (tx, rx) = std::sync::mpsc::channel();
    let _task = crate::tokio_runtime::spawn_blocking(move || {
        let mut read_end = read_end;
        let mut sink = sink;
        let copied = io::copy(&mut Read::by_ref(&mut read_end).take(limit.0), &mut sink);
        let _ = tx.send(copied);
        io::copy(&mut read_end, &mut io::sink()).ok();
    });
    Ok(PipeRelay {
        write_end: Some(write_end),
        completion: rx,
    })
}

/// Open a host file through the same semantics as Go's FileToReader.
pub fn file_to_reader(file: File) -> io::Result<Box<dyn Read + Send>> {
    file.into_reader()
}
/// Open a host file for container copy-out, optionally creating parent directories.
pub fn open_host(path: &str, flags: i32, perm: u32, mkdir_all: bool) -> io::Result<HostFile> {
    if mkdir_all && let Some(parent) = PathBuf::from(path).parent() {
        fs::create_dir_all(parent)?;
    }
    let mut o = OpenOptions::new();
    o.read(flags & 0x3 == 0 || flags & 0x3 == 2)
        .write(flags & 0x3 == 1 || flags & 0x3 == 2)
        .create(flags & 64 != 0)
        .truncate(flags & 512 != 0)
        .mode(perm);
    o.open(path)
}

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

/// Run one command, including descriptor preparation, copy-in, symlink setup, waiting,
/// and copy-out. A copy/file operation failure is returned in `CmdResult` as `FileError`.
pub struct Single {
    pub cmd: Cmd,
    pub new_store_file: NewStoreFile,
}
impl Single {
    pub fn run(self) -> io::Result<CmdResult> {
        self.run_with_cancel(|| false)
    }
    pub fn run_with_cancel(
        self,
        cancelled: impl Fn() -> bool + Send + Sync,
    ) -> io::Result<CmdResult> {
        run_command(self.cmd, &self.new_store_file, &cancelled)
    }

    pub async fn run_with_cancel_async(
        self,
        cancelled: impl Fn() -> bool + Send + Sync + 'static,
    ) -> io::Result<CmdResult> {
        run_command_async(self.cmd, self.new_store_file, Arc::new(cancelled)).await
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PipeIndex {
    pub index: usize,
    pub fd: usize,
}
#[derive(Clone, Debug, Default)]
pub struct PipeMapping {
    pub input: PipeIndex,
    pub output: PipeIndex,
    pub cpu_set: String,
    pub proxy: bool,
    pub name: String,
    pub max: Size,
    pub disable_zero_copy: bool,
}
pub struct Group {
    pub commands: Vec<Cmd>,
    pub pipes: Vec<PipeMapping>,
    pub new_store_file: NewStoreFile,
}

pub(super) fn order_group_results(mut results: Vec<CmdResult>) -> Vec<CmdResult> {
    let mut completed: Vec<_> = results
        .iter()
        .enumerate()
        .filter_map(|(i, result)| result.finished_at.map(|at| (at, i)))
        .collect();
    completed.sort_by_key(|(at, i)| (*at, *i));
    for (order, (_, index)) in completed.into_iter().enumerate() {
        results[index].exit_order = order + 1;
    }
    results
}

impl Group {
    pub fn run(self) -> io::Result<Vec<CmdResult>> {
        self.run_with_cancel(|| false)
    }
    /// Run mapped commands concurrently, with direct or relayed proxy pipes.
    pub fn run_with_cancel(
        self,
        cancelled: impl Fn() -> bool + Send + Sync + 'static,
    ) -> io::Result<Vec<CmdResult>> {
        let group = prepare_group(self, Arc::new(cancelled))?;
        let mut slots: Vec<Option<io::Result<CmdResult>>> = std::iter::repeat_with(|| None)
            .take(group.commands.len())
            .collect();
        let joins: Vec<_> = group
            .commands
            .into_iter()
            .enumerate()
            .map(|(i, cmd)| {
                let factory = group.factory.clone();
                let cancelled = group.cancelled.clone();
                (
                    i,
                    crate::tokio_runtime::spawn_blocking(move || {
                        run_command(cmd, &factory, &*cancelled)
                    }),
                )
            })
            .collect();
        for (i, join) in joins {
            slots[i] = Some(
                join.recv()
                    .unwrap_or_else(|_| Err(io::Error::other("command worker thread panicked"))),
            );
        }
        for relay in group.relays {
            let _ = relay.recv();
        }
        Ok(order_group_results(
            slots
                .into_iter()
                .map(|value| value.unwrap())
                .collect::<io::Result<Vec<_>>>()?,
        ))
    }

    pub async fn run_with_cancel_async(
        self,
        cancelled: impl Fn() -> bool + Send + Sync + 'static,
    ) -> io::Result<Vec<CmdResult>> {
        let group = prepare_group(self, Arc::new(cancelled))?;
        let joins: Vec<_> = group
            .commands
            .into_iter()
            .map(|cmd| {
                let factory = group.factory.clone();
                let cancelled = group.cancelled.clone();
                tokio::spawn(async move { run_command_async(cmd, factory, cancelled).await })
            })
            .collect();
        let mut results = Vec::with_capacity(joins.len());
        for join in joins {
            results
                .push(join.await.map_err(|error| {
                    io::Error::other(format!("command task failed: {error}"))
                })??);
        }
        for relay in group.relays {
            let _ = tokio::task::spawn_blocking(move || relay.recv())
                .await
                .map_err(|error| io::Error::other(format!("proxy relay waiter failed: {error}")))?;
        }
        Ok(order_group_results(results))
    }
}

pub(super) struct PreparedGroup {
    commands: Vec<Cmd>,
    relays: Vec<std::sync::mpsc::Receiver<()>>,
    factory: NewStoreFile,
    cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
}

pub(super) fn prepare_group(
    mut group: Group,
    cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
) -> io::Result<PreparedGroup> {
    let mut relays = Vec::new();
    let mut fds: Vec<Vec<Option<File>>> = group
        .commands
        .iter_mut()
        .map(|cmd| std::mem::take(&mut cmd.files))
        .collect();
    for pipe in &group.pipes {
        if pipe.input.index >= fds.len() || pipe.output.index >= fds.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pipe: index out of range",
            ));
        }
        if pipe.input == pipe.output {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pipe: input and output must differ",
            ));
        }
        for endpoint in [pipe.output, pipe.input] {
            if endpoint.fd >= 1 << 20 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "pipe: descriptor index is too large",
                ));
            }
            if fds[endpoint.index].len() <= endpoint.fd {
                fds[endpoint.index].resize_with(endpoint.fd + 1, || None);
            }
            if fds[endpoint.index][endpoint.fd].is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "pipe: fd already occupied",
                ));
            }
        }
        if pipe.proxy {
            let (relay_source, child_output) = os_pipe()?;
            let (child_input, relay_destination) = os_pipe()?;
            fds[pipe.input.index][pipe.input.fd] = Some(File::opened(child_output));
            fds[pipe.output.index][pipe.output.fd] = Some(File::opened(child_input));
            let zero_copy = !pipe.disable_zero_copy;
            let cpu_set = pipe.cpu_set.clone();
            if crate::tokio_runtime::legacy_proxy_ablation_enabled() || zero_copy {
                relays.push(crate::tokio_runtime::spawn_blocking(move || {
                    with_cpu_affinity(&cpu_set, || {
                        if zero_copy {
                            relay_splice_or_copy(relay_source, relay_destination);
                        } else {
                            relay_copy_and_drain(relay_source, relay_destination);
                        }
                    });
                }));
            } else {
                let (done_tx, done_rx) = std::sync::mpsc::channel();
                crate::tokio_runtime::runtime().handle().spawn(async move {
                    let relay = async_relay(relay_source, relay_destination);
                    let _ = AffinityFuture {
                        cpu_set,
                        inner: relay,
                    }
                    .await;
                    let _ = done_tx.send(());
                });
                relays.push(done_rx);
            }
        } else {
            let (read, write) = os_pipe()?;
            fds[pipe.input.index][pipe.input.fd] = Some(File::opened(write));
            fds[pipe.output.index][pipe.output.fd] = Some(File::opened(read));
        }
    }
    for (cmd, files) in group.commands.iter_mut().zip(fds) {
        cmd.files = files;
    }
    Ok(PreparedGroup {
        commands: group.commands,
        relays,
        factory: group.new_store_file,
        cancelled,
    })
}

#[cfg(target_os = "linux")]
pub(super) fn with_cpu_affinity<T>(cpu_set: &str, run: impl FnOnce() -> T) -> T {
    use nix::{sched, unistd::Pid};
    if cpu_set.is_empty() {
        return run();
    }
    let Some(requested) = parse_cpu_affinity(cpu_set) else {
        return run();
    };
    let pid = Pid::from_raw(0);
    let Ok(previous) = sched::sched_getaffinity(pid) else {
        return run();
    };
    if sched::sched_setaffinity(pid, &requested).is_err() {
        return run();
    }
    let result = run();
    let _ = sched::sched_setaffinity(pid, &previous);
    result
}

pub(super) struct AffinityFuture<F> {
    cpu_set: String,
    inner: F,
}

impl<F: Future> Future for AffinityFuture<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // The future is never moved after pinning; only its poll is wrapped so
        // each Tokio worker thread is restricted while it performs relay work.
        let this = unsafe { self.get_unchecked_mut() };
        let mut inner = unsafe { Pin::new_unchecked(&mut this.inner) };
        let mut result = None;
        with_cpu_affinity(&this.cpu_set, || result = Some(inner.as_mut().poll(cx)));
        result.expect("affinity wrapper always polls its future")
    }
}

#[cfg(target_os = "linux")]
pub(super) async fn async_relay(source: HostFile, destination: HostFile) -> io::Result<()> {
    use tokio::io::unix::AsyncFd;

    set_nonblocking(&source)?;
    set_nonblocking(&destination)?;
    // SAFETY: both files own stable pipe descriptors and no code changes their
    // registrations while the AsyncFd values are alive.
    let source = unsafe { AsyncFd::register(source)? };
    // SAFETY: same ownership and descriptor-stability guarantee as above.
    let destination = unsafe { AsyncFd::register(destination)? };
    async_copy_relay(source, destination).await
}

#[cfg(not(target_os = "linux"))]
pub(super) async fn async_relay(source: HostFile, destination: HostFile) -> io::Result<()> {
    let mut source = tokio::fs::File::from_std(source);
    let mut destination = tokio::fs::File::from_std(destination);
    tokio::io::copy(&mut source, &mut destination).await?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn set_nonblocking(file: &HostFile) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let fd = file.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) async fn async_copy_relay(
    source: tokio::io::unix::AsyncFd<HostFile>,
    destination: tokio::io::unix::AsyncFd<HostFile>,
) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let n = loop {
            let mut readable = source.readable().await?;
            let n = readable.try_io(|inner| {
                let n = unsafe {
                    libc::read(
                        inner.get_ref().as_raw_fd(),
                        buffer.as_mut_ptr().cast(),
                        buffer.len(),
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match n {
                Err(_) => continue,
                Ok(Err(error)) => return Err(error),
                Ok(Ok(0)) => return Ok(()),
                Ok(Ok(n)) => break n,
            }
        };
        let mut offset = 0;
        while offset < n {
            let mut writable = destination.writable().await?;
            let written = writable.try_io(|inner| {
                let written = unsafe {
                    libc::write(
                        inner.get_ref().as_raw_fd(),
                        buffer[offset..n].as_ptr().cast(),
                        n - offset,
                    )
                };
                if written < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(written as usize)
                }
            });
            match written {
                Err(_) => continue,
                Ok(Err(error)) if error.raw_os_error() == Some(libc::EPIPE) => {
                    async_drain_relay_source(&source).await?;
                    return Ok(());
                }
                Ok(Err(error)) => return Err(error),
                Ok(Ok(0)) => return Err(io::Error::new(io::ErrorKind::WriteZero, "pipe relay")),
                Ok(Ok(written)) => offset += written,
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub(super) async fn async_drain_relay_source(
    source: &tokio::io::unix::AsyncFd<HostFile>,
) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let mut readable = source.readable().await?;
        let n = readable.try_io(|inner| {
            let n = unsafe {
                libc::read(
                    inner.get_ref().as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                )
            };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        });
        match n {
            Err(_) => continue,
            Ok(Err(error)) => return Err(error),
            Ok(Ok(0)) => return Ok(()),
            Ok(Ok(_)) => {}
        }
    }
}

#[cfg(target_os = "linux")]
pub(super) fn parse_cpu_affinity(value: &str) -> Option<nix::sched::CpuSet> {
    let mut set = nix::sched::CpuSet::new();
    for segment in value.split(',') {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        let (first, last) = match segment.split_once('-') {
            Some((first, last)) => (first.trim().parse().ok()?, last.trim().parse().ok()?),
            None => {
                let cpu = segment.parse().ok()?;
                (cpu, cpu)
            }
        };
        if first > last {
            return None;
        }
        for cpu in first..=last {
            set.set(cpu).ok()?;
        }
    }
    Some(set)
}

#[cfg(not(target_os = "linux"))]
pub(super) fn with_cpu_affinity<T>(_: &str, run: impl FnOnce() -> T) -> T {
    run()
}

pub(super) fn relay_copy_and_drain(source: HostFile, destination: HostFile) {
    // Go's `io.Copy` dispatches pipe-to-pipe `*os.File` transfers through
    // `os.File.ReadFrom`, which uses Linux splice when both endpoints support
    // it. Keep the Rust buffered fallback for filesystems/kernels where splice
    // is unavailable, but match that fast path for Go's DisableZeroCopy mode.
    #[cfg(target_os = "linux")]
    {
        relay_splice_or_copy(source, destination);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let mut source = source;
        let mut destination = destination;
        if io::copy(&mut source, &mut destination).is_err() {
            drop(destination);
            let _ = io::copy(&mut source, &mut io::sink());
        }
    }
}

pub(super) fn reader_to_host_file(
    mut reader: Box<dyn Read + Send>,
    reader_threads: &mut Vec<std::sync::mpsc::Receiver<()>>,
    try_memfd: bool,
) -> io::Result<HostFile> {
    #[cfg(target_os = "linux")]
    if try_memfd && READER_MEMFD_ENABLED.load(Ordering::Acquire) {
        match crate::container::memfd::dup_to_memfd_ref("input", &mut *reader) {
            Ok(file) => return Ok(file),
            Err(_) => READER_MEMFD_ENABLED.store(false, Ordering::Release),
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = try_memfd;

    let (read, write) = os_pipe()?;
    reader_threads.push(crate::tokio_runtime::spawn_blocking(move || {
        let mut write = write;
        let _ = io::copy(&mut reader, &mut write);
    }));
    Ok(read)
}

#[cfg(target_os = "linux")]
pub(super) fn relay_splice_or_copy(mut source: HostFile, mut destination: HostFile) {
    use nix::fcntl::{SpliceFFlags, splice};
    loop {
        match splice(
            &source,
            None,
            &destination,
            None,
            64 * 1024,
            SpliceFFlags::SPLICE_F_MOVE,
        ) {
            Ok(0) => return,
            Ok(_) => continue,
            Err(nix::errno::Errno::EPIPE) => {
                drop(destination);
                let _ = io::copy(&mut source, &mut io::sink());
                return;
            }
            Err(_) => {
                if io::copy(&mut source, &mut destination).is_err() {
                    drop(destination);
                    let _ = io::copy(&mut source, &mut io::sink());
                }
                return;
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn relay_splice_or_copy(source: HostFile, destination: HostFile) {
    relay_copy_and_drain(source, destination);
}
