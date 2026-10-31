//! Shared Tokio runtime used by the server and synchronous compatibility paths.
//!
//! Synchronous sandbox internals sometimes need blocking file/process work.
//! Scheduling that work through this runtime lets Tokio reuse its blocking
//! pool instead of creating a fresh OS thread for each operation.

use std::sync::OnceLock;
use tokio::runtime::Runtime;

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

pub fn legacy_proxy_ablation_enabled() -> bool {
    std::env::var_os("RUST_SANDBOX_ABLATION_LEGACY_PROXY").is_some()
}

pub fn sync_command_wait_ablation_enabled() -> bool {
    std::env::var_os("RUST_SANDBOX_ABLATION_SYNC_COMMAND_WAIT").is_some()
}

pub fn runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        // A synchronous `Runner::start` may block one runtime worker while a
        // Tokio task completes its pre-exec parent/child synchronization.
        // Keep one other worker available even on single-CPU hosts so that
        // this callback cannot wait behind the worker blocked in spawn.
        let worker_threads = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1)
            .max(2);
        let mut builder = tokio::runtime::Builder::new_multi_thread();
        builder.worker_threads(worker_threads).enable_all();
        crate::runtime_trace::install_task_poll_hooks(&mut builder);
        builder.build().expect("create shared Tokio runtime")
    })
}

/// Run blocking work on Tokio's reusable blocking pool and return a synchronous
/// completion receiver for callers that still expose a blocking API.
pub fn spawn_blocking<F, T>(work: F) -> std::sync::mpsc::Receiver<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    runtime().handle().spawn_blocking(move || {
        let _ = tx.send(work());
    });
    rx
}
