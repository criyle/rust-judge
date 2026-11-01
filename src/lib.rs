#[global_allocator]
static GLOBAL_ALLOCATOR: rpprof::alloc::AllocProfiler = rpprof::alloc::AllocProfiler::system();

pub mod commands;
pub mod container;
pub mod env;
pub mod envexec;
pub mod filestore;
pub mod go_judge_config;
pub mod pb;
pub mod runner;
pub mod runtime_metrics;
pub mod runtime_trace;
pub mod seccomp_convert;
pub mod server;
pub mod tokio_runtime;
pub mod unixsocket;
pub mod worker;
