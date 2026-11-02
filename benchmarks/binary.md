# Binary benchmark notes

## Launch-path correction — 2026-10-30

Do not infer the production `Runner` clone mode from a plain
`std::process::Command` probe. On the tested toolchain, plain `Command` uses
`clone3(CLONE_VM | CLONE_VFORK | CLONE_CLEAR_SIGHAND)`, but `Runner` registers a
`pre_exec` hook and uses ordinary `clone` without `CLONE_VM` or `CLONE_VFORK`.
The Go `Runner` uses `clone` or `clone3` with `CLONE_VM | CLONE_VFORK` when
parent coordination is not needed. This was verified by tracing each launch
path.

Earlier benchmark notes that attribute most of the Rust/Go gap to Go's
`CLONE_INTO_CGROUP` placement are not established by that ablation. Disabling
Go's `clone3` cgroup placement still leaves Go's vfork path enabled, so that
test measures the cgroup-placement benefit within Go; it does not isolate the
Rust fork-versus-vfork difference. Treat these as separate optimizations.
Future launch comparisons should inspect the actual `Runner` clone flags and
keep `pre_exec` in the measured path.

## Warm container follow-up

The warm container benchmark initially measured about 1.58 ms per `/bin/true`
command. `Process::result()` was polling `Child::try_wait()` with a 1 ms sleep;
it now blocks in `Child::wait()` when no caller is monitoring resource limits.
A same-host rerun measured 0.63 ms per command (about 60% lower). Go's matching
container benchmark on this host measured about 228 µs/op, so Rust is still
roughly 2.8x slower in this microbenchmark. The full Go integration suite is
the end-to-end check; its elapsed time also includes compilation, HTTP, and
test setup.

That earlier 0.63 ms result was not reproduced with the current tree. With
`RUST_SANDBOX_CONTAINER_INIT` pointing at the release `rust-judge`, the warm
container benchmark measured 1.028 ms/op (100 samples; 95% interval 1.022–1.034
ms), then 1.049 ms/op in a shorter repeat. The standalone init alias measured
1.007 ms/op in the same short-run setup, so the production self-init path does
not show a material penalty against that control. Treat the older 0.63 ms
sample as historical; current measurements need a fresh paired Go run before
making a cross-version performance claim.

Privileged cgroup-controller and namespace/mount setup microbenchmarks have
not been reproduced. The crate now has cgroup v1 and v2 backends, but cgroup
v1 has only fixture-based unit coverage on this host. The Go container
benchmark also starts the full container init and is not equivalent to the
available process-only fork/exec benchmark.

## Production container init executable

The release `rust-judge` executable now re-executes itself as PID 1 with
`container_init`, matching Go's `/proc/self/exe` launch. The parent passes a
`SOCK_SEQPACKET` control socket as fd 3. PID 1 receives Configure, Exec, and
Kill requests over the Rust protobuf IPC and starts, monitors, and reaps
workloads itself. The host-side namespace executor and its per-environment OS
thread are no longer part of workload launch. The namespace launcher still
sets up the root mount tree; PID 1 completes proc mounts and path masks during
Configure. The production resolver follows Go's default by selecting the
current executable regardless of its filename. A standalone `container-init`
target remains for Cargo test harnesses and explicit
`--container-init-path` overrides.

I verified the production identity at runtime while a workload kept the
namespace alive: `/proc/<host-pid-of-container-init>/exe` and the server's
`/proc/<server-pid>/exe` had the same device and inode (`64539:2005690`). The
reported init path is `/.rust-sandbox-init`, the in-container bind-mount name
for that same running `rust-judge` executable.

Cleanup after each workload keeps Go's namespace-wide `waitAll` behavior when
the re-executed server is PID 1. Test-only in-process calls to the init
executor reap only that workload's process group, so parallel unit tests do not
consume one another's child statuses. The complete Rust suite passes with the
tests running concurrently, and the Go integration package passed against the
release server in 106.4 seconds after this change.

The official Go integration package covers HTTP only. I also started the
release server with gRPC enabled and called it from a Go client generated from
go-judge's protobuf package: `FileList` succeeded and unary `Exec` of
`/bin/true` returned `Accepted` with exit status 0.
The same client also round-tripped `FileAddStream`/`FileGetStream` and ran
`/bin/echo` through `ExecStream`, receiving the expected output and exit status.

After this architecture change, the complete Go integration package passed
against the final release server in 102.9 seconds (`go test -tags integration
-count=1 .`, 2026-10-30). An earlier build with the same PID 1 IPC path passed
in 97.0 seconds before removing the obsolete seccomp file mount. These single
samples are too noisy to establish a performance difference; the 95.7-second
run used the old host-side executor path and is not a matched comparison.
The latest rerun after verifying PID 1's executable identity also passed in
102.2 seconds with the release server listening on IPv6 loopback.
After implementing the parent/child fork-exec callback handshake, the release
server passed the full integration package again in 104.5 seconds. Those runs
do not exercise `Runner.sync_fn`; they confirm the production cgroup-FD path
and normal process launch remain intact.
The final rerun after hardening socket descriptor placement and ensuring a
second Tokio runtime worker passed in 111.4 seconds.

The production init Configure message now also carries Go's kernel-dependent
`unshareCgroup` setting. PID 1 applies `CLONE_NEWCGROUP` after placing each
workload in its cgroup, and ignores an unsupported/unauthorized unshare just
like Go. The full integration package passed again after this change in 100.9
seconds (`go test -tags integration -count=1 .`, 2026-10-30).

The Rust `/metrics` endpoint now exports Go's file-size histogram and
environment build/in-use counters as well as the existing worker, file-store,
and execution metrics. File and environment instrumentation is disabled unless
`--enable-metrics` is set. The complete Go integration package passed against
the release server after these changes in 106.7 seconds
(`go test -tags integration -count=1 .`, 2026-10-30).

HTTP scrape output now also includes the Gin request counter, request duration
histogram, and request/response size summaries. The gRPC families include
started and handled counters, stream message counts, and handling-time
histograms. The full Go integration package passed against the release server
with these API metrics and arbitrary Linux rlimit support in 107.5 seconds
(`go test -tags integration -count=1 .`, 2026-10-30).
The gRPC handled counter now uses grpc-prometheus' Go status names
(`ResourceExhausted`, `Canceled`, and so on), rather than tonic's snake-case
display strings. A focused unit test covers started/handled counts, status, and
latency series. HTTP streaming-body size summaries remain an approximation of
Gin's accounting because Axum may not know the final body size before sending.
After this status-label correction, the release server passed the full Go
integration package in 102.0 seconds (`go test -tags integration -count=1 .`,
2026-10-30).

Streaming RPC latency now covers consumption of the response stream for
`ExecStream` and `FileGetStream`, rather than ending when the handler first
returns its stream object. Stream errors are recorded with their gRPC status;
dropping an unfinished stream records cancellation. The stream-lifecycle unit
test verifies that a successful RPC is not counted as handled until stream
completion. The Go integration package passed against the release server
after this change in 111.1 seconds (`go test -tags integration -count=1 .`,
2026-10-30).

The pprof index now exposes the Go named profile routes. `heap` and `allocs`
use the Rust allocation sampler, enabled when `--enable-debug` is active;
`goroutine` and `threadcreate` report Linux thread snapshots because Tokio
tasks share runtime threads. `block` and `mutex` return valid empty profiles
when no contention sampler is configured. The Go 1.26 trace v2 writer now
backs `/debug/pprof/trace`; it records HTTP requests and sandbox executions as
balanced user-task spans. It also records real Tokio task poll intervals using
Tokio's unstable before/after-poll hooks, nested under task-lifetime spans from
Tokio's spawn/terminate hooks. Tokio 1.54.1 is pinned, and this
workspace enables `tokio_unstable` in `.cargo/config.toml` so production builds
include those hooks. `go tool trace -d=parsed` accepted a live capture that
contained both an HTTP request and Tokio task polls. These events describe real
poll activity and are not presented as Go goroutines. With `--enable-debug`,
Tokio's `schedule-latency` feature also records measured runnable-queue delay
as child spans under task lifetimes; it does not reconstruct wake relationships
or all scheduler state. The full Go integration package passed with these
profile routes in 105.1 seconds
(`go test -tags integration -count=1 .`, 2026-10-30).

After adding task lifetime hooks, `go tool trace -d=parsed` accepted a live
`/debug/pprof/trace` response containing an HTTP run, `go-judge execute`, Tokio
task lifetime spans, and poll intervals nested under their matching task IDs.
The capture verifies that each task lifetime ends after its last poll. The
complete Go integration package passed against that release server in 40.940
seconds; all 255 library tests, binary tests, and benchmark smoke cases passed.

A Criterion ablation measures one spawned task with a yield on a current-thread
runtime, with task-poll hooks disabled and with hooks installed but no active
trace. The medians were 11.920 µs and 12.662 µs respectively (20 samples,
1-second warm-up, 2-second measurement), a 6.2% / 0.742 µs cost for spawn,
poll, and terminate callbacks in this small operation. The hooks record spans
only while a capture is active; this baseline quantifies their always-on
dispatch cost.

The schedule-latency feature performs extra clock reads whenever Tokio
schedules and polls tasks, even when no trace capture is active. A three-way
Criterion ablation measured 11.983 µs with hooks disabled, 12.656 µs with task
hooks but schedule-latency measurement disabled, and 18.648 µs with both enabled
(20 samples, 1-second warm-up, 2-second measurement). Enabling schedule latency
added 47.3% to the hooks-only micro-operation, so production turns it on only
when `--enable-debug` is configured. The default runtime keeps task poll hooks
for trace captures without paying this scheduler timestamp cost.

With `--enable-debug`, a live trace parsed by `go tool trace -d=parsed` showed
14 runnable-queue delay spans alongside Tokio poll spans. The serial Rust test
suite passed all 255 library tests and 7 binary tests, and the full Go
integration package passed against the rebuilt release server in 38.008 seconds
with debug tracing disabled (`go test -tags integration -count=1
./integration_test`, 2026-10-30).

A container source audit found that Go's PID 1 opens paths under its chroot,
following symlinks in parent directories and clamping `..` at the container
root, while rejecting a symlink or non-regular file as the final open target.
Rust now matches that behavior with `openat2(RESOLVE_IN_ROOT | NO_MAGICLINKS)`
and a no-follow regular-file check. A unit test covers absolute parent
symlinks, `mkdir_all` through a symlink, chrooted `..` resolution after
symlink traversal, final symlink rejection, and procfs magic-link rejection.
The serial Rust suite and benchmark smoke harness passed, and the rebuilt
release server passed the full Go integration package in 39.056 seconds
(`go test -tags integration -count=1 ./integration_test`, 2026-10-30).
Newly created copy-in parent directories are also chmod'd to `0777` to match
Go PID 1's `umask(0)` plus `MkdirAll(..., 0777)`, independent of the service
umask. The focused unit test checks that mode. After this permission fix, all
Rust library and binary tests and the benchmark smoke harness passed again;
the full Go integration package passed in 39.480 seconds.
Host-side opened files now also keep the container init's mapped owner instead
of being reassigned to the workload UID. Newly created files are chmod'd to
the requested mode despite the service umask; existing files retain their
mode and owner when opened with `O_CREAT|O_TRUNC`. Focused tests cover both
cases. The full serial Rust suite, benchmark smoke harness, and Go integration
package passed again; the final release integration run took 37.634 seconds.

CPU profile sampling waits with `tokio::time::sleep` after starting the
process-wide sampler. Profiler setup and report encoding remain on Tokio's
blocking pool, but the requested sampling interval no longer occupies a
blocking worker. This is a resource-capacity improvement for saturated
blocking pools; it does not reduce the requested profile duration. The existing
monitor-route unit test decodes and validates the one-second CPU profile.

A Criterion ablation measured how long an unrelated `spawn_blocking` probe
waits while a 5 ms sampling interval runs with the blocking pool capped at one
thread. With an async timer, probe latency was 178.7 µs median; with the former
blocking sleep occupying that worker, it was 5.448 ms median (10 samples,
1 s warm-up and measurement). This isolated saturation case shows 96.7% lower
probe latency. It does not predict throughput on the production runtime's
larger blocking pool, nor change profile duration.

A focused Criterion smoke run after this change (`--sample-size 10
--warm-up-time 1 --measurement-time 1`) measured `std::process::Command`
`/bin/true` at 543.86 µs and `Runner` `/bin/true` with `pre_exec` at 1.42 ms.
Criterion compared these with older samples and reported the standard command
case as slower and the Runner case as faster. After adding the pprof allocator,
a later smoke run measured 558 µs and 1.466 ms respectively. These short,
unpaired samples do not isolate allocator overhead. The opt-in cgroup benchmark
was skipped because this host has no dedicated delegated cgroup v2 benchmark
root configured.

Two short Criterion runs after adding arbitrary Linux rlimit support reported
the standard command at about 545 µs/op in both runs, while the `Runner`
sample ranged from 796 µs/op to 1.49 ms/op. That spread is too large to
attribute to the empty raw-rlimit branch; repeat the benchmark under a stable,
otherwise idle host before making a launch-performance claim.

## clone3/vfork launch path — 2026-11-01

`Runner::start` now uses a raw Linux x86-64 `clone3(CLONE_VM | CLONE_VFORK)`
launcher for executions that do not need parent coordination. The child runs
on a separately mapped stack, uses prepared arguments and syscalls through
exec, reports setup/exec errno through a close-on-exec pipe, then immediately
calls `execve`. This path does not allocate, lock, unwind, or alter the parent's
`errno`. Modes needing a sync callback, user-namespace mapping, or namespace
helper keep the standard-library fork/exec path. Kernels or sandboxes that
reject clone3 use `clone(CLONE_VM | CLONE_VFORK)`; non-x86-64 targets use the
standard-library path.

When the caller supplies a cgroup v2 directory descriptor, clone3 adds
`CLONE_INTO_CGROUP`. If the kernel rejects that flag or descriptor, the child
retries without it and joins through the already-open `cgroup.procs` file.
Additional cgroup hierarchies continue to use `cgroup.procs`. A focused test
confirmed the child was in the requested cgroup before exec; `strace` showed
`clone3({flags=CLONE_VM|CLONE_VFORK|CLONE_INTO_CGROUP, ..., cgroup=3})` succeed.

The raw launcher returns rust-judge's command-style `Child` handle, with the
`id`, `kill`, `wait`, `try_wait`, and `wait_with_output` operations used by the
existing callers. The exact `std::process::Child` type cannot be constructed
outside `std` because its fields are private.

The local Criterion run used `cargo bench --bench sandbox --
forkexec/bin_true --sample-size 20 --warm-up-time 2 --measurement-time 3`:

| Path | Time/op |
| --- | ---: |
| `std::process::Command`, `/bin/true` | 392.35 µs |
| `Command` with no-op `pre_exec` | 1.159 ms |
| rust-judge `Runner`, fresh config | 437.96 µs |
| rust-judge `Runner`, reused config | 441.07 µs |
| Go-shaped simple fork runner | 502.40 µs |
| rust-judge `Runner` with parent sync callback | 1.745 ms |

The earlier short pre-change Runner baseline was 1.215 ms/op. The new reused
Runner result is about 64% lower on this host; the short baseline and these
sequential microbenchmarks are directional rather than a cross-host claim.
Go's HTTP integration concurrency benchmark against the release Rust server
reported 1.411 ms/op at parallelism 1, 848 µs at 2, 597 µs at 4, and 556 µs at
8, using `go test -tags integration -run '^$' -bench
'^BenchmarkGoJudge_Concurrency$' -cpu 1 -benchtime 3s` from
`go-judge/integration_test`. The full Go integration package passed against the
same release server in 22.455 seconds (`go test -tags integration -count=1
./integration_test`).
The serial Rust library suite passed all 261 tests, and all 7 binary tests
passed. The cgroup v2 configure/destroy Criterion case remained skipped because
this host had no dedicated delegated cgroup benchmark root configured.

## PID 1 child-exit readiness

PID 1 now waits for Linux child-exit readiness through a Tokio-registered
pidfd and retains the 5 ms `waitid`/procfs polling fallback when pidfds are
unavailable. This removes periodic polling on supported kernels and obtains
final resource usage with `wait4`. A pidfd unit test verifies exit readiness.
A same-host bidirectional proxy matrix measured 71.96 seconds before and
74.83 seconds after this change. The run-to-run variation and similar per-case
times show no performance improvement; the change is retained for event-driven
waiting and exact final usage, not as a throughput optimization.
The complete Go integration package passed against the rebuilt server in
106.9 seconds after this change.

## Standalone runprog container parity

The standalone `runprog -runner=container` backend now applies the mount list
from `go-sandbox/cmd/runprog` directly: read-only `/bin`, `/lib`, `/lib64`,
`/usr`, `/etc/alternatives`, `/etc/fpc.cfg`, and `/var/lib/ghc`; writable
`/dev/null`; read-only proc; and 8 MiB `/w` and `/tmp` tmpfs mounts. It no
longer inherits the broader go-judge server rootfs mount plan. The `-nucg`
option also disables creation of a cgroup namespace for runprog workloads.
Unit tests assert this mount plan and the `-nucg` setting. All 235 library
tests and binary tests passed after the change, and the full Go integration
package passed in 114.3 seconds against the rebuilt release server on
2026-10-30. That integration package exercises the server API, not the
standalone runprog CLI, so the runprog behavior is covered by its focused
container tests rather than counted as integration coverage.

The Rust `runprog` CLI defaults to its supported `container` backend. Go's
default is `ptrace`, but this port omits ptrace and the standalone namespace
runner as requested; retaining the ptrace default would make an invocation
without `-runner` fail immediately. Explicit unsupported backend selection
still returns a clear error.

`runprog -cgroup` now selects the host's cgroup v1 or v2 backend. It places
the `runprog` hierarchy below the current delegated membership, then creates
and removes a fresh cgroup for each execution. This preserves the Go command's
per-run isolation while respecting the service's delegated subtree. The cgroup
path selection is implemented for both versions; this host exposes v2 but not
a dedicated writable delegation, so privileged cgroup execution remains
unverified here. The existing v1 backend has fixture-based hierarchy coverage.
The `-cgroupfd` flag requires cgroup v2 when `-cgroup` is active, matching
Go's validation. Rust still enrolls the child by writing its PID to
`cgroup.procs`; `std::process::Command` does not expose Go's `clone3` cgroup-FD
placement flag, so the optimization is not reproduced.

After changing the default, `cargo run --bin runprog -- /bin/echo
default-container-runner` ran through the container backend and returned the
normal result row (`0 0 1984 0`). The expanded Rust suite passed 242 library
tests plus all binary tests. After the `-cgroupfd` validation change, the
release server was rebuilt and the full Go integration package passed in
116.5 seconds. It passed again after the configuration parser change, in
121.5 seconds on 2026-10-30. The suite exercises the server API; the CLI
behavior is covered by the no-flag smoke invocation above.

The server configuration parser now matches Go's `parallelism <= 0` fallback
for both CLI flags and `ES_PARALLELISM` values: zero or a negative value
selects the logical CPU count. The focused config unit test covers both input
paths. Compound Go-style durations also accept the leading `+` sign, and a
negative file timeout maps to disabled expiration as in Go. At this stage the
port also included a periodic glibc allocator-trimming task modeled on Go's
force-GC worker. That task and its force-GC options have since been removed:
Rust has no tracing garbage collector, and the allocator-specific monitor was
not retained. The release server passed the full Go integration package in
117.6 seconds after the original task was added; it passed again in 121.5
seconds after the negative file-timeout change.
