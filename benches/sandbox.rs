//! Criterion entry point for library, binary, ablation, and comparison benches.
//! Run with `cargo bench --bench sandbox`; filter by benchmark name as usual.

mod sandbox {
    mod ablation;
    mod binary;
    mod comparison;
    mod library;
    mod prelude;
    mod support;

    pub(crate) use ablation::{
        profile_sampler_blocking_pool_availability, tokio_task_poll_hook_overhead,
        worker_result_delivery,
    };
    pub(crate) use binary::container_exec_true;
    pub(crate) use comparison::forkexec_true;
    pub(crate) use library::{
        cgroup_v2, envexec_pipe_interactive, envexec_pipe_stream, memfd_copy,
        protobuf_encode_decode, socket_fd_batches, socket_ping, unixsocket_baselines,
    };
}

use criterion::{criterion_group, criterion_main};
use sandbox::*;

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
