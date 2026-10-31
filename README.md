# rust-judge

`rust-judge` is a Rust implementation of [go-judge](https://github.com/criyle/go-judge), a service and library for running programs in isolated, resource-limited Linux environments. It provides REST, WebSocket, and gRPC service code, a reusable worker API, container and execution primitives, and command-line tools.

The project is still developing compatibility with upstream go-judge. It is useful for evaluation, integration work, and deployments that can validate the implementation against their own threat model. It is not currently a drop-in production replacement. Read [Security](SECURITY.md) before using it to execute untrusted programs.

## Install and run the server

The server executable is named `rust-judge`. From a checkout, build it with Rust 1.88 or newer:

```sh
cargo build --release --bin rust-judge
./target/release/rust-judge --help
```

For a local-only development server:

```sh
./target/release/rust-judge \
  --http-addr 127.0.0.1:5050 \
  --auth-token 'replace-with-a-long-random-secret'
```

HTTP API operations are available under `/run`, `/file`, and WebSocket endpoints. The token protects these HTTP routes; `/version` and `/config` remain public. Do not expose the service directly to an untrusted network. See [Security](SECURITY.md) for network, privilege, cgroup, and seccomp guidance.

The package also builds `runprog`, `rust-judge-init`, `rust-judge-shell`, `rust-judge-grpc-proxy`, `container-init`, and `seccomp-convert` binaries. Some are internal helpers or compatibility tools; the production server re-executes itself as the container init process.

## Embed the worker library

The library exposes `LinuxEnvironmentPool`, `AsyncWorker`, and request/result types for applications that want to run commands without starting the HTTP/gRPC server. The example at [`examples/embedded.rs`](examples/embedded.rs) builds a worker, submits `/bin/echo`, and reads captured output:

```sh
cargo run --release --example embedded
```

The example requires Linux namespace and mount capabilities and uses the built-in seccomp profile. Its default environment config does not configure a cgroup hierarchy, so do not treat its resource limits as a complete production resource-control policy. For production embedding, configure and delegate cgroups on the host, set `cgroup_root` or `cgroup_v1_roots`, set an appropriate container identity policy, and manage request concurrency and shutdown in the host application. See [`LinuxEnvironmentConfig`](src/env/linux_environment.rs) and [Security](SECURITY.md).

Use the library API as a building block: callers own service authentication, network exposure, lifecycle, storage permissions, cgroup setup, and observability. The API is not yet covered by a semver stability promise.

## Linux and kernel requirements

The service entry point and sandbox backend support Linux. Other platform-specific modules do not imply that the complete service builds or operates on those platforms. Container setup relies on Linux namespaces, mount operations, seccomp, rlimits, and optionally cgroups. Required capabilities and kernel features depend on the selected configuration and host policy.

## Seccomp profiles

Seccomp filtering is enabled by default. The built-in profile is [`resources/seccomp/default.yaml`](resources/seccomp/default.yaml). To use a custom profile, provide an architecture-aware policy file with `--seccomp-conf /path/to/policy.yaml`; this replaces the built-in profile. Convert a Docker/Moby-style JSON profile with:

```sh
seccomp-convert -input moby-profile.json -output policy.yaml
```

The YAML policy has a `default_action`, optional common rules under `base.syscalls`, and per-architecture rules under `architectures`. The selected architecture must be present. Test custom profiles against every workload and architecture you deploy: missing syscalls fail according to the profile's default action, and profiles that cannot be represented with equivalent kernel filter behavior are rejected.

Avoid `--no-seccomp` in production. It disables this syscall filter; it does not disable namespaces or other configured controls, and those controls are not substitutes for seccomp. See [Security](SECURITY.md) for profile review and rollout advice.

## Development and validation

```sh
cargo fmt --all -- --check
cargo clippy --all-targets
cargo test --lib --bins
cargo package --no-verify
```

The full test suite includes sandbox integration cases that require namespace and mount privileges. GitHub-hosted runners deny those operations, so CI skips only those cases listed in [`.github/namespace-test-skips.txt`](.github/namespace-test-skips.txt); run the complete suite on a Linux host that permits the required namespaces and mounts. CI checks formatting, linting, compilation, the remaining unit tests, and package contents, including compilation with the declared Rust 1.88 minimum version.

See [`BENCHMARKS.md`](BENCHMARKS.md) for benchmark methodology and current measurements. The Rust runner currently uses the standard process-spawn path with setup hooks and does not use Go's optimized `clone3`/`vfork` launch path. If you need a mature service today or depend on that optimized launch behavior, use [upstream go-judge](https://github.com/criyle/go-judge).

## License

Licensed under the MIT License. See [LICENSE](LICENSE). The seccomp resources retain their respective upstream notices where applicable.
