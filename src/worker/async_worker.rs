use super::*;

struct QueuedRequest {
    request: Request,
    cancellation: CancellationToken,
    started: mpsc::Sender<()>,
    response: tokio::sync::oneshot::Sender<Response>,
}
struct WorkerInner {
    config: WorkerConfig,
    sender: Mutex<Option<tokio::sync::mpsc::Sender<QueuedRequest>>>,
    started: AtomicBool,
    stopped: AtomicBool,
    queued: AtomicUsize,
    running: AtomicUsize,
    completions: Mutex<Vec<mpsc::Receiver<()>>>,
}
/// Bounded asynchronous worker with bypass-queue `execute` for interactive requests.
#[derive(Clone)]
pub struct AsyncWorker {
    inner: Arc<WorkerInner>,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WorkerStat {
    pub queue: usize,
    pub running: usize,
}
impl AsyncWorker {
    pub fn new(config: WorkerConfig) -> Self {
        Self {
            inner: Arc::new(WorkerInner {
                config,
                sender: Mutex::new(None),
                started: AtomicBool::new(false),
                stopped: AtomicBool::new(false),
                queued: AtomicUsize::new(0),
                running: AtomicUsize::new(0),
                completions: Mutex::new(Vec::new()),
            }),
        }
    }
    pub fn start(&self) -> io::Result<()> {
        if self.inner.stopped.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "worker is shut down",
            ));
        }
        let mut sender = self.inner.sender.lock().unwrap();
        if self.inner.stopped.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "worker is shut down",
            ));
        }
        if self.inner.started.load(Ordering::Acquire) {
            return Ok(());
        }
        let capacity = self.inner.config.queue_capacity;
        let (tx, rx) = tokio::sync::mpsc::channel::<QueuedRequest>(capacity.max(1));
        *sender = Some(tx);
        self.inner.started.store(true, Ordering::Release);
        let count = if self.inner.config.cpu_sets.is_empty() {
            self.inner.config.parallelism
        } else {
            self.inner.config.cpu_sets.len()
        };
        let receiver = Arc::new(tokio::sync::Mutex::new(rx));
        for i in 0..count {
            let inner = self.inner.clone();
            let receiver = receiver.clone();
            let cpuset = self
                .inner
                .config
                .cpu_sets
                .get(i)
                .cloned()
                .unwrap_or_default();
            let (done_tx, done_rx) = mpsc::channel();
            crate::tokio_runtime::runtime().handle().spawn(async move {
                worker_loop(inner, receiver, cpuset).await;
                let _ = done_tx.send(());
            });
            self.inner.completions.lock().unwrap().push(done_rx);
        }
        Ok(())
    }
    pub fn submit(
        &self,
        request: Request,
        cancellation: CancellationToken,
    ) -> (tokio::sync::oneshot::Receiver<Response>, mpsc::Receiver<()>) {
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        let (started_tx, started_rx) = mpsc::channel();
        let sender = self.inner.sender.lock().unwrap();
        if !self.inner.started.load(Ordering::Acquire) {
            send_immediate(
                started_tx,
                response_tx,
                request.request_id,
                "worker is not started",
            );
            return (response_rx, started_rx);
        }
        if self.inner.stopped.load(Ordering::Acquire) {
            send_immediate(
                started_tx,
                response_tx,
                request.request_id,
                "worker is shutting down",
            );
            return (response_rx, started_rx);
        }
        let Some(tx) = sender.as_ref() else {
            send_immediate(
                started_tx,
                response_tx,
                request.request_id,
                "worker is shutting down",
            );
            return (response_rx, started_rx);
        };
        self.inner.queued.fetch_add(1, Ordering::AcqRel);
        let queued = QueuedRequest {
            request,
            cancellation,
            started: started_tx,
            response: response_tx,
        };
        if let Err(error) = tx.try_send(queued) {
            self.inner.queued.fetch_sub(1, Ordering::AcqRel);
            let queued = match error {
                tokio::sync::mpsc::error::TrySendError::Full(q)
                | tokio::sync::mpsc::error::TrySendError::Closed(q) => q,
            };
            let text = if self.inner.stopped.load(Ordering::Acquire) {
                "worker is shutting down"
            } else {
                "worker queue is full"
            };
            let _ = queued.started.send(());
            let _ = queued.response.send(Response {
                request_id: queued.request.request_id,
                results: vec![],
                error: Some(text.into()),
            });
        }
        (response_rx, started_rx)
    }
    /// Runs immediately as a Tokio task, bypassing queue saturation and
    /// configured worker parallelism for interactive requests.
    pub fn execute(
        &self,
        request: Request,
        cancellation: CancellationToken,
    ) -> tokio::sync::oneshot::Receiver<Response> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut completions = self.inner.completions.lock().unwrap();
        if self.inner.stopped.load(Ordering::Acquire) || !self.inner.started.load(Ordering::Acquire)
        {
            let _ = tx.send(Response {
                request_id: request.request_id,
                results: vec![],
                error: Some("worker is not available".into()),
            });
            return rx;
        }
        let inner = self.inner.clone();
        let (done_tx, done_rx) = mpsc::channel();
        let _task = crate::tokio_runtime::runtime().handle().spawn(async move {
            inner.running.fetch_add(1, Ordering::AcqRel);
            let response = work_do_running(&inner, request, cancellation, String::new()).await;
            let _ = tx.send(response);
            let _ = done_tx.send(());
        });
        completions.push(done_rx);
        rx
    }
    pub fn stat(&self) -> WorkerStat {
        WorkerStat {
            queue: self.inner.queued.load(Ordering::Acquire),
            running: self.inner.running.load(Ordering::Acquire),
        }
    }
    /// Stops accepting queued work, drains accepted work and Tokio blocking
    /// tasks, then destroys the environment pool.
    pub fn shutdown(&self) {
        if self.inner.stopped.swap(true, Ordering::AcqRel) {
            return;
        }
        self.inner.sender.lock().unwrap().take();
        let completions = std::mem::take(&mut *self.inner.completions.lock().unwrap());
        for done in completions {
            let _ = done.recv();
        }
        self.inner.config.environments.destroy();
    }
}

fn send_immediate(
    started: mpsc::Sender<()>,
    response: tokio::sync::oneshot::Sender<Response>,
    request_id: String,
    message: &str,
) {
    let _ = started.send(());
    let _ = response.send(Response {
        request_id,
        results: vec![],
        error: Some(message.to_owned()),
    });
}

async fn worker_loop(
    inner: Arc<WorkerInner>,
    receiver: Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<QueuedRequest>>>,
    cpuset: String,
) {
    loop {
        let work = receiver.lock().await.recv().await;
        let Some(work) = work else {
            break;
        };
        inner.queued.fetch_sub(1, Ordering::AcqRel);
        let QueuedRequest {
            request,
            cancellation,
            started,
            response: response_tx,
        } = work;
        let response = if cancellation.is_cancelled() {
            let _ = started.send(());
            Response {
                request_id: request.request_id,
                results: vec![],
                error: Some("cancelled before execute".into()),
            }
        } else {
            let inner = inner.clone();
            let worker_cpuset = cpuset.clone();
            inner.running.fetch_add(1, Ordering::AcqRel);
            let _ = started.send(());
            work_do_running(&inner, request, cancellation, worker_cpuset).await
        };
        let _ = response_tx.send(response);
    }
}
async fn work_do_running(
    inner: &Arc<WorkerInner>,
    request: Request,
    cancellation: CancellationToken,
    cpuset: String,
) -> Response {
    let _trace_span = crate::runtime_trace::SpanGuard::start("go-judge execute");
    let mut response = execute_request(inner, &request, cancellation, cpuset).await;
    response.request_id = request.request_id;
    if let Some(observer) = &inner.config.exec_observer {
        observer(&response);
    }
    inner.running.fetch_sub(1, Ordering::AcqRel);
    response
}
async fn execute_request(
    inner: &Arc<WorkerInner>,
    request: &Request,
    cancellation: CancellationToken,
    cpuset: String,
) -> Response {
    if cancellation.is_cancelled() {
        return Response {
            request_id: request.request_id.clone(),
            results: vec![],
            error: Some("cancelled before execute".into()),
        };
    }
    let mut commands = Vec::with_capacity(request.commands.len());
    let mut environments = Vec::new();
    let mut defaults = inner.config.defaults.clone();
    // Go's worker always supplies its assigned cpuset as the command default.
    // This keeps every command in a group aligned with its proxy relay; an
    // explicit per-command CPUSetLimit still takes precedence in
    // `prepare_envexec`.
    defaults.cpu_set = cpuset.clone();
    for command in &request.commands {
        let environment = match get_tracked_environment(inner.config.environments.clone()).await {
            Ok(e) => e,
            Err(e) => {
                for environment in environments.drain(..) {
                    put_tracked_environment(inner.config.environments.clone(), environment).await;
                }
                return Response {
                    request_id: request.request_id.clone(),
                    results: std::iter::repeat_with(|| ResultInfo {
                        status: JudgeStatus::InternalError,
                        error: format!("failed to get environment {e}"),
                        ..Default::default()
                    })
                    .take(request.commands.len())
                    .collect(),
                    error: None,
                };
            }
        };
        match command.prepare_envexec(
            environment.clone(),
            &inner.config.file_store,
            &defaults,
            &proxy_pipe_names(&request.pipe_mapping, request.commands.len()),
        ) {
            Ok(cmd) => {
                commands.push(cmd);
                environments.push(environment);
            }
            Err(e) => {
                put_tracked_environment(inner.config.environments.clone(), environment).await;
                for e in environments.drain(..) {
                    put_tracked_environment(inner.config.environments.clone(), e).await;
                }
                return Response {
                    request_id: request.request_id.clone(),
                    results: vec![],
                    error: Some(e.to_string()),
                };
            }
        }
    }
    let store = inner.config.file_store.clone();
    let new_store: envexec::NewStoreFile = Arc::new(move || store.new_file().map(|(_, f)| f));
    if commands.len() == 1 {
        let cmd = commands.pop().unwrap();
        let environment = environments.pop().unwrap();
        let token = cancellation.clone();
        let single = envexec::Single {
            cmd,
            new_store_file: new_store,
        };
        let output = if crate::tokio_runtime::sync_command_wait_ablation_enabled() {
            tokio::task::spawn_blocking(move || {
                single.run_with_cancel(move || token.is_cancelled())
            })
            .await
            .unwrap_or_else(|error| {
                Err(io::Error::other(format!(
                    "synchronous command worker failed: {error}"
                )))
            })
        } else {
            single
                .run_with_cancel_async(move || token.is_cancelled())
                .await
        };
        put_tracked_environment(inner.config.environments.clone(), environment).await;
        return match output {
            Ok(result) => Response {
                request_id: request.request_id.clone(),
                results: vec![convert_result(
                    result,
                    &request.commands[0],
                    &inner.config.file_store,
                )],
                error: None,
            },
            Err(e) => Response {
                request_id: request.request_id.clone(),
                results: vec![],
                error: Some(e.to_string()),
            },
        };
    }
    let pipes = request
        .pipe_mapping
        .iter()
        .map(|p| envexec::PipeMapping {
            input: envexec::PipeIndex {
                index: p.input.index,
                fd: p.input.fd,
            },
            output: envexec::PipeIndex {
                index: p.output.index,
                fd: p.output.fd,
            },
            // Go overwrites the pipe's affinity with the worker-assigned CPU
            // set for the whole request group.
            cpu_set: cpuset.clone(),
            proxy: p.proxy,
            name: p.name.clone(),
            max: p.limit,
            disable_zero_copy: p.disable_zero_copy,
        })
        .collect();
    let token = cancellation.clone();
    let group = envexec::Group {
        commands,
        pipes,
        new_store_file: new_store,
    };
    let output = if crate::tokio_runtime::sync_command_wait_ablation_enabled() {
        tokio::task::spawn_blocking(move || group.run_with_cancel(move || token.is_cancelled()))
            .await
            .unwrap_or_else(|error| {
                Err(io::Error::other(format!(
                    "group worker task failed: {error}"
                )))
            })
    } else {
        group
            .run_with_cancel_async(move || token.is_cancelled())
            .await
    };
    for e in environments {
        put_tracked_environment(inner.config.environments.clone(), e).await;
    }
    match output {
        Ok(results) => Response {
            request_id: request.request_id.clone(),
            results: results
                .into_iter()
                .zip(&request.commands)
                .map(|(r, c)| convert_result(r, c, &inner.config.file_store))
                .collect(),
            error: None,
        },
        Err(e) => Response {
            request_id: request.request_id.clone(),
            results: vec![],
            error: Some(e.to_string()),
        },
    }
}
fn proxy_pipe_names(pipes: &[PipeMap], count: usize) -> std::collections::HashSet<String> {
    pipes
        .iter()
        .filter(|p| p.proxy && p.input.index < count)
        .map(|p| p.name.clone())
        .collect()
}
