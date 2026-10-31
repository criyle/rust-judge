# rust-judge

`rust-judge` is a Rust replication of [go-judge](https://github.com/criyle/go-judge), a service for executing programs in isolated, resource-limited environments. It reimplements go-judge's execution and service layers in Rust, including compatible REST, WebSocket, and gRPC APIs, along with its container protocol.

This project is intended for people studying or experimenting with a Rust implementation of go-judge. It is not currently a drop-in production replacement for upstream go-judge.

## What it includes

- A Linux execution environment using namespaces, mounts, seccomp, rlimits, and cgroups.
- A pool of reusable execution environments and a worker that manages execution requests.
- File storage and file transfer support.
- HTTP, WebSocket, and gRPC server code following go-judge's API surface.
- `runprog`, shell, container initialization, and seccomp conversion utilities.
- Runtime metrics, profiling hooks, and benchmarks.

The code is organized as a library and command-line binaries. The main server implementation is in `src/bin/go-judge.rs`; the container, runner, environment, worker, and API modules are exposed from `src/lib.rs`.

## Platform and maturity

The service entry point currently supports Linux only. Other platform-specific modules do not imply that the complete server works on those platforms. This is an ongoing replication, so check behavior against upstream go-judge before relying on it for production workloads.

## Comparison

| Project | Focus | How it relates |
| --- | --- | --- |
| [go-judge](https://github.com/criyle/go-judge) | Sandbox service with REST, WebSocket, and gRPC APIs, file management, and pooled environments | The upstream project `rust-judge` replicates. Go-judge currently has an optimized process launch path described below. |
| [`judger`](https://docs.rs/judger/latest/judger/) | Rust library for running untrusted code with resource limits and seccomp | A related Rust project focused on configuring and running individual programs. `rust-judge` focuses on a go-judge-style service, including its API surface, file management, and pooled environments. |
| [`crabpot`](https://docs.rs/crabpot/latest/crabpot/) | Native Rust command sandbox for AI agents, with platform-specific confinement backends | A related command-sandboxing project with a different focus: agent command policies and platform backends. `rust-judge` follows go-judge's online-judge service model. |

The intended value of `rust-judge` is to make go-judge's service and execution architecture available in Rust, including its API compatibility and the ability to develop the implementation as Rust code. It should not currently be presented as faster than upstream: the benchmark notes in [`BENCHMARKS.md`](BENCHMARKS.md) show that the Rust launch path does not use Go's optimized `clone3`/`vfork` path.

## Recommendation: use go-judge when launch performance matters

Upstream go-judge can use `clone3(CLONE_INTO_CGROUP)` and a `vfork`-style process launch on supported Linux kernels (kernel 5.7 or newer for the documented `clone3` cgroup placement path). The current Rust runner uses Rust's standard process-spawn path with setup hooks; those hooks prevent the same fast path from being used. The repository's benchmark notes document this difference.

If you need a mature service today, or want go-judge's optimized launch behavior, use [go-judge directly](https://github.com/criyle/go-judge). Choose `rust-judge` when the Rust implementation itself is useful to you and you can validate its current behavior for your workload.

## Build

Requires Rust 1.88 or newer. From this directory:

```sh
cargo build --release
```

The service binary is `go-judge` (`src/bin/go-judge.rs`). See the [upstream go-judge documentation](https://docs.goj.ac/) for the compatible API and configuration concepts; some details may differ in this implementation.

## License

See the upstream repository's license and retain its attribution when redistributing work derived from it. Add a repository-level `LICENSE` before publishing this project so its licensing terms are explicit.
