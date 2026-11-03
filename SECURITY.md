# Security and deployment guidance

`rust-judge` starts processes that may be controlled by remote users. Treat it as a security-sensitive sandbox component, not as a boundary that is safe to expose by default. The project is still developing and does not currently claim a production-grade security guarantee or complete go-judge parity. Validate the exact build, host kernel, configuration, and workload model before handling hostile code.

## Threat model and limits

The sandbox combines Linux namespaces, a private mount environment, syscall filtering, process resource limits, and optional cgroups. These mechanisms reduce access to the host; they do not make a kernel escape impossible. A kernel vulnerability, unsafe host mount, overly broad network access, or incorrect cgroup delegation can undermine isolation.

The service and embedded library have different responsibilities:

- The server supports an HTTP auth token for protected HTTP execution and file routes. `/version` and `/config` are public. Do not assume this token secures gRPC or the separate monitor listener.
- The embedded library does not provide an authentication or network boundary. The embedding application owns those controls, along with lifecycle, concurrency, storage permissions, and observability.
- The default `LinuxEnvironmentConfig` enables seccomp and configures namespaces, but leaves cgroup roots unset. Rlimits still apply, but cgroup CPU, memory, and process controls require a working cgroup hierarchy.
- Fallback behavior can leave cgroup enforcement unavailable for non-root service operation unless startup is configured to fail instead. For a service relying on cgroups, use `--no-fallback` and verify the resulting hierarchy and effective limits on the deployment host.
- When a memory cgroup is configured and its swap-accounting control is available, rust-judge sets swap to zero for memory-limited jobs. If the control is missing, startup warns and leaves swap unrestricted; `--no-fallback` makes startup fail instead. `/config` reports this as `runnerConfig.memorySwapLimitEnabled`.

## Network exposure

Bind the API to loopback or a private interface and place it behind a firewall or authenticated TLS proxy. Use a long random HTTP auth token. Do not expose gRPC or the monitor endpoint publicly unless a trusted proxy provides authentication, encryption, and access controls. Keep metrics and profiling endpoints private; profiling can reveal process and workload details and consumes resources.

The default server addresses are loopback for a normal process and wildcard addresses when it detects that it is PID 1. Review `--http-addr`, `--grpc-addr`, and `--monitor-addr` explicitly in containers and service managers. `--auth-token` protects selected HTTP routes only; it is not TLS and it is not a replacement for network policy.

## Seccomp setup

Seccomp is enabled by default and uses the bundled architecture-aware policy at [`resources/seccomp/default.yaml`](resources/seccomp/default.yaml). Its default action is `errno`; permitted syscall names and argument predicates are listed in the profile. A custom `--seccomp-conf` file replaces this policy, so a custom file must include a complete policy for the target architecture rather than assuming it is merged with the built-in profile.

To convert a Docker/Moby JSON profile into the policy format accepted by `--seccomp-conf`:

```sh
seccomp-convert -input moby-profile.json -output policy.yaml
```

Review converted output before deploying it. Test it with the actual compilers, interpreters, dynamic loaders, and programs you expect to run. Check every target architecture and kernel. A restrictive profile may break ordinary programs; an overly permissive profile weakens the boundary. The converter or assembler rejects some unsupported and order-sensitive policies rather than guaranteeing exact behavior for every source profile.

Do not use `--no-seccomp` as a compatibility workaround for untrusted workloads. If a workload requires a syscall outside the policy, identify the specific syscall, determine why it is needed, and make the smallest reviewed policy change possible. Roll changes out in a staging environment and retain the previous known-good policy for rollback.

## Host and cgroup setup

- Run on a supported Linux host with namespace and mount support. Grant only the capabilities and filesystem access needed for the selected configuration; avoid broad privileged-container settings when a narrower deployment works.
- Configure cgroups explicitly and verify that the service has delegated the required controllers. In cgroup v2, check CPU, memory, and pids controller availability and the resulting workload groups. For cgroup v1, verify all configured controller mounts and limits.
- Prefer startup failure over silently running without expected cgroup controls. `--no-fallback` is available for this purpose, but still verify limits after startup; configuration success alone is not proof that limits are effective.
- Keep sandbox roots, file storage, seccomp profiles, and mount configuration in directories writable only by trusted administrators and the service account as appropriate. Do not mount host secrets or writable host paths into the workload root.
- Use container credential mapping only after confirming the host UID/GID range is reserved and collision-free. The correct range depends on the host's user namespace and deployment setup.
- Apply host-level CPU, memory, process, disk, and network limits to the service itself. Workload limits do not protect the server from every denial-of-service path, including request volume, uploads, or bugs in the service process.

## Reporting security issues

Do not include exploit details, secrets, or sensitive workloads in a public issue. Contact the project maintainers through a private security channel associated with the repository when available; otherwise request a private reporting channel before sharing details.
