use super::*;

struct RemoteProcessState {
    result: Option<ResultInfo>,
    finished_at: Option<u64>,
    usage: Usage,
    started: Instant,
    cgroup: Option<Box<dyn Cgroup>>,
    cgroup_pool: Option<Arc<dyn CgroupPool>>,
}

pub(super) struct RemoteProcess {
    state: Arc<Mutex<RemoteProcessState>>,
    changed: Arc<Condvar>,
    async_changed: Arc<tokio::sync::Notify>,
    cancel: tokio::sync::watch::Sender<bool>,
}

impl RemoteProcess {
    pub(super) fn new(
        cgroup: Option<Box<dyn Cgroup>>,
        cgroup_pool: Option<Arc<dyn CgroupPool>>,
    ) -> (Self, tokio::sync::watch::Receiver<bool>) {
        let (cancel, receiver) = tokio::sync::watch::channel(false);
        (
            Self {
                state: Arc::new(Mutex::new(RemoteProcessState {
                    result: None,
                    finished_at: None,
                    usage: Usage::default(),
                    started: Instant::now(),
                    cgroup,
                    cgroup_pool,
                })),
                changed: Arc::new(Condvar::new()),
                async_changed: Arc::new(tokio::sync::Notify::new()),
                cancel,
            },
            receiver,
        )
    }

    pub(super) fn complete(&self, reply: io::Result<crate::container::protocol::Reply>) {
        let mut state = self.state.lock().unwrap();
        state.finished_at = reply
            .as_ref()
            .ok()
            .and_then(|reply| reply.exec_reply.as_ref())
            .map(|result| result.exit_time_ns)
            .filter(|timestamp| *timestamp != 0)
            .or_else(crate::envexec::monotonic_time_ns);
        let (result, reported_usage) = match reply {
            Ok(reply) if reply.error.is_none() => match reply.exec_reply {
                Some(result) => {
                    let status = match result.status {
                        0 => Status::Normal,
                        1 => Status::Normal,
                        2 => Status::TimeLimitExceeded,
                        3 => Status::MemoryLimitExceeded,
                        4 => Status::OutputLimitExceeded,
                        5 => Status::DisallowedSyscall,
                        6 => Status::Signalled,
                        7 => Status::NonzeroExitStatus,
                        _ => Status::RunnerError,
                    };
                    let usage = Usage {
                        time: Duration::from_nanos(result.time_ns.max(0) as u64),
                        memory: Size(result.memory_bytes),
                    };
                    (
                        ResultInfo {
                            status,
                            exit_status: result.exit_status,
                            time: usage.time,
                            memory: usage.memory,
                            proc_peak: 0,
                            running_time: state.started.elapsed(),
                            ..Default::default()
                        },
                        usage,
                    )
                }
                None => (
                    ResultInfo {
                        status: Status::RunnerError,
                        error: "container init returned no execution result".into(),
                        ..Default::default()
                    },
                    Usage::default(),
                ),
            },
            Ok(reply) => (
                ResultInfo {
                    status: Status::RunnerError,
                    error: reply.error.map_or_else(
                        || "container init execution failed".into(),
                        |error| error.message,
                    ),
                    ..Default::default()
                },
                Usage::default(),
            ),
            Err(error) => (
                ResultInfo {
                    status: Status::RunnerError,
                    error: error.to_string(),
                    ..Default::default()
                },
                Usage::default(),
            ),
        };
        state.usage.time = state.usage.time.max(reported_usage.time);
        state.usage.memory = state.usage.memory.max(reported_usage.memory);
        let mut result = result;
        if let Some(group) = state.cgroup.as_mut() {
            result.time = result.time.max(group.cpu_usage().unwrap_or_default());
            result.memory = Size(
                group
                    .max_memory()
                    .ok()
                    .filter(|value| *value > 0)
                    .unwrap_or(result.memory.0),
            );
            result.proc_peak = group.proc_peak().unwrap_or_default();
        }
        result.time = result.time.max(state.usage.time);
        result.memory = result.memory.max(state.usage.memory);
        state.usage.time = result.time;
        state.usage.memory = result.memory;
        state.result = Some(result);
        if let Some(group) = state.cgroup.take()
            && let Some(pool) = state.cgroup_pool.as_ref()
        {
            pool.put(group);
        }
        self.changed.notify_all();
        self.async_changed.notify_one();
    }

    fn update_usage(&self) {
        let mut state = self.state.lock().unwrap();
        if state.result.is_some() {
            return;
        }
        if let Some(group) = state.cgroup.as_mut() {
            let time = group.cpu_usage().ok();
            let memory = group.current_memory().ok();
            if let Some(time) = time {
                state.usage.time = state.usage.time.max(time);
            }
            if let Some(memory) = memory {
                state.usage.memory = state.usage.memory.max(Size(memory));
            }
        }
    }
}

impl Process for Arc<RemoteProcess> {
    fn done(&self) -> bool {
        self.update_usage();
        self.state.lock().unwrap().result.is_some()
    }

    fn result(&self) -> ResultInfo {
        let mut state = self.state.lock().unwrap();
        while state.result.is_none() {
            state = self.changed.wait(state).unwrap();
        }
        state.result.clone().unwrap_or_default()
    }

    fn finished_at(&self) -> Option<u64> {
        self.state.lock().unwrap().finished_at
    }

    fn usage(&self) -> Usage {
        self.update_usage();
        self.state.lock().unwrap().usage
    }

    fn wait_timeout(&self, timeout: Duration) {
        if self.done() {
            return;
        }
        let state = self.state.lock().unwrap();
        if state.result.is_none() {
            let _ = self.changed.wait_timeout(state, timeout);
        }
    }

    fn wait_timeout_async<'a>(
        &'a self,
        timeout: Duration,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        let process = self.clone();
        let changed = self.async_changed.clone();
        Box::pin(async move {
            let notified = changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if process.done() {
                return;
            }
            tokio::select! {
                _ = &mut notified => {},
                _ = tokio::time::sleep(timeout) => {},
            }
        })
    }

    fn cancel(&self) {
        let _ = self.cancel.send(true);
    }
}
