# Ablation benchmark notes

## 2026-10-30 std process creation baseline

An initial `strace` of a minimal `std::process::Command` spawn showed this
toolchain using `clone3(CLONE_VM | CLONE_VFORK | CLONE_CLEAR_SIGHAND)`. That
does not describe the production `Runner` path: registering its `pre_exec`
hook makes Rust's standard library use ordinary `clone` without
`CLONE_VM | CLONE_VFORK`. Go's custom fork/exec path keeps those flags when it
can use its raw child setup. Go additionally uses `CLONE_INTO_CGROUP` when a
cgroup FD is supplied; Rust currently enrolls through `cgroup.procs`.

The direct Criterion ablation (`cargo bench --bench sandbox --
forkexec/bin_true --sample-size 20 --warm-up-time 1 --measurement-time 2`)
measured:

| Path | Time/op |
| --- | ---: |
| `std::process::Command`, `/bin/true` | 546.44 µs |
| `Runner` with its `pre_exec` setup, `/bin/true` | 1.454 ms |
| `Runner` with parent sync callback, `/bin/true` | 1.888 ms |

The Go `pkg/forkexec` benchmarks measured 131.9 µs for `BenchmarkStdFork` and
319.0 µs for `BenchmarkSimpleFork`. These use `b.RunParallel`, while Rust's
Criterion case is sequential, so those figures are not a valid latency
comparison. The Rust warm-container benchmark could not initialize its helper
in this environment. The full Go integration package passed against the
unchanged Rust release server in 37.2 seconds on 2026-10-30.

## 2026-10-30 matched launch-path trace

The production spawn mismatch is the `pre_exec` hook, which disables Rust
`std::process::Command`'s vfork fast path. A one-child `strace` of Rust's
`Runner` showed `clone(... SIGCHLD)` with neither `CLONE_VM` nor `CLONE_VFORK`;
the Go `Runner` showed `clone(... CLONE_VM | CLONE_VFORK | SIGCHLD)`. The
Go child runs raw syscalls, which lets its parent remain suspended while the
child shares its address space until `execve`. Rust's hook is Rust code and
uses the standard-library fork-safe path.

Sequential loops measured the same launch patterns on this host. Both plain
standard-library paths ran `/bin/true`; both Runner paths ran `/bin/echo` with
`PATH=/bin`, cwd `/bin`, and all three standard descriptors redirected to the
same `/dev/null` file. Each Runner configuration was reused across 3,000
launches:

| Path | Time/op |
| --- | ---: |
| Go `syscall.ForkExec`, plain `/bin/true` | 561 µs |
| Rust `std::process::Command`, plain `/bin/true` | 520 µs |
| Go `forkexec.Runner`, sequential | 672 µs |
| Rust `Runner`, sequential | 802 µs |

This puts the matched Runner gap near 130 µs/op (about 19%). The new Criterion
ablations also measured Rust `std_command` at 527 µs, a no-op `pre_exec` at
723 µs, the reused Runner at 815 µs, and the Go-shaped Runner configuration at
844 µs. The no-op hook alone costs about 196 µs and confirms the fork-mode
fallback is material. Registering and rebuilding the Rust `Runner` in each
timed iteration raised that case to 1.45 ms; Go's existing benchmark reuses
its Runner, so that earlier comparison overstated the launch gap.

The Rust child also makes 12 explicit signal-action syscalls in the setup
hook, but Go resets signals too, so the trace does not point to signal setup as
the main cause. The strongest explanation for the remaining matched gap is
the ordinary fork required by Rust's `pre_exec` hook. Forking a larger server
process can amplify its page-table cost; the small standalone measurements
above do not quantify that production-scale effect. Rust's benchmark now has
`runner_pre_exec_reused_config`, `go_simplefork_matched`, and
`std_command_noop_pre_exec` cases to keep these comparisons visible.

Implementation parity work and benchmark analysis were assisted by OpenAI
Codex, in collaboration with the project maintainer.

The warm container benchmark must re-execute the production `rust-judge`
executable as PID 1. Build it and point the init override at that binary before
running the Criterion suite:

```sh
cargo build --release --bin rust-judge
export RUST_SANDBOX_CONTAINER_INIT="$PWD/target/release/rust-judge"
cargo bench --bench sandbox
```

The cgroup v2 benchmark is opt-in. To run it, set
`RUST_SANDBOX_CGROUP_V2_BENCH_ROOT` to an existing, dedicated cgroup v2
directory beneath `/sys/fs/cgroup` that has `cpu`, `cpuset`, `memory`, and
`pids` available and enabled in `cgroup.subtree_control`:

```sh
RUST_SANDBOX_CGROUP_V2_BENCH_ROOT=/sys/fs/cgroup/delegated/bench \
  cargo bench --bench sandbox -- cgroup_v2/configure_sample_destroy
```

The benchmark does not create or enable controllers on the supplied root. It
creates a uniquely named child there, creates and configures a `test` child per
iteration, samples CPU, current memory, and peak memory, then removes both
benchmark cgroups. It prints a skip message when the opt-in path or required
delegation is unavailable. This mirrors Go's `pkg/cgroup` benchmark while
avoiding changes to an unselected system cgroup.

The cgroup v2 backend now follows Go's `AddProcesses` file semantics by
opening `cgroup.procs` without truncation, and `Destroy` uses directory removal
without writing `cgroup.kill`. Container PID 1 is responsible for reaping
workloads; direct cgroup users receive the same nonempty-directory error as
Go. Fixture tests cover both behaviors. This host has no writable delegated
cgroup, so real controller writes remain unverified here.
After these parity fixes, the Go integration package passed against the release
server in 109.2 seconds.

The v1 backend now iterates controller hierarchies in go-sandbox's declared
order (`cpu`, `cpuset`, `cpuacct`, `memory`, `pids`) for group creation,
process enrollment, fd opening, and cleanup. A fixture with `/dev/full` verifies
that earlier memberships are written before the `cpuacct` error, as on the Go
path. The cgroup v1 implementation remains fixture-tested only on this host.
After this ordering change, all Go integration tests passed against the release
server in 110.3 seconds.

## Parent/child fork-exec synchronization

`Runner` now supports Go's pre-exec parent callback for direct child launches.
The child reports its PID over a Unix socketpair and waits; a Tokio async task
receives it, invokes the short synchronous callback, and acknowledges success
before exec. The runtime keeps at least two workers so a caller blocked in
`Command::spawn` cannot starve the callback task on a single-CPU host. Callback
mode is a one-shot handshake and therefore does not retry `ETXTBSY`; it is
unavailable when an external namespace helper is used, because that helper's
eventual PID 1 is not the direct `Command` child.

On Linux x86_64, Criterion (`--sample-size 10 --warm-up-time 1
--measurement-time 2`) most recently measured `/bin/true` at 1.594 ms for
`Runner` without the callback and 2.013 ms with a no-op callback. The extra
socket handshake and Tokio task cost about 419 µs in this process-launch
microbenchmark. An earlier sample measured 1.463 ms and 1.886 ms respectively;
both runs show similar callback overhead but have host-level variance. This
path is only used when callers need parent-side setup keyed by the child PID;
the production container path enrolls through pre-opened cgroup descriptors
instead.

## Same-host performance investigation

A later paired run used the same integration package and host for both servers.
The complete package passed against Rust release in 34.9 seconds and against Go
in 35.4 seconds. The parent timer for the 10,000-request copy-in/exec test
reported 0.22 seconds, but that excludes the parallel subtests' wall time. The
bidirectional proxy matrix accounted for 21.1 seconds on Rust and
22.4 seconds on Go, so its deliberate multi-second command workloads dominate
the suite wall time.

The same HTTP concurrency benchmark (`-benchtime=2s -count=1 -cpu 1`) measured:

| Parallelism | Rust release | Go |
| ---: | ---: | ---: |
| 1 | 2,111,893 ns/op | 1,699,428 ns/op |
| 2 | 1,203,282 ns/op | 972,848 ns/op |
| 4 | 962,237 ns/op | 732,333 ns/op |
| 8 | 892,897 ns/op | 734,008 ns/op |

This confirms a roughly 1.2–1.3x request-path overhead in this sample, while
the full integration run is comparable. A hand-built gRPC probe with no memory
limit returned SIGSEGV. With the default 16 KiB extra-memory allowance, a zero
command memory limit still creates a very small effective limit; Go's
`runSingleExecve` does the same. The integration and benchmark requests set a
larger memory limit and passed. Repeating the Go-generated gRPC request with
the same 64 MiB memory, 1 s CPU, and 50-process limits returned `Accepted` with
the expected stdout. Neither probe is part of the HTTP timing results.

## Follow-up on the launch-heavy race test

A paired rerun on the same host completed the full integration package in
45.5 seconds against Rust release and 34.1 seconds against Go. A fresh Rust
release rerun completed in 48.3 seconds. The isolated
10,000-request copy-in/exec test took 16.0 seconds against Rust and 7.9 seconds
against Go; a second Rust sample was 16.7 seconds. The Rust run is slower on
this process-heavy case, but neither server took multiple minutes.

The worker queue's `std::sync::mpsc::Receiver` mutex was considered as a source
of contention. A temporary crossbeam MPMC queue did not improve the isolated
result, so it was not retained. Process creation remains a likely contributor:
Go's Linux fork-exec path uses `vfork` and uses `clone3(CLONE_INTO_CGROUP)` when
available (`go-sandbox/pkg/forkexec/fork_child_linux.go`), while Rust's
`pre_exec` hook selects ordinary fork on the tested toolchain. The
10,000-request test launches one process per request, so this difference is
amplified there. The clone-mode trace supersedes the earlier assumption that
Rust's production `Runner` was already using the standard library's vfork
fast path.

## Focused proxy performance diagnosis

A fresh same-host run of `TestInteraction_Bidirectional_ProxyMatrix` took
39.7 seconds against Rust release and 22.4 seconds against Go. Rust's six
cases took 4.26–7.76 seconds each; Go's took 2.49–4.69 seconds. The cases
without a relay were also slower (4.26–4.69 seconds against Rust versus
2.49–2.55 seconds against Go), so relay copying is not the only source of the
gap. Rust's reported workload CPU time was about 2.0–2.25 seconds per Python
process; Go reported about 1.08–1.23 seconds for the same scripts.

The same matrix against Rust with `--no-seccomp` took 40.3 seconds, which rules
out the sandbox seccomp policy as the cause. The workload has no file copy-in
or copy-out and its no-relay case uses a direct pipe, so neither file transfer
nor the proxy relay explains the base-case slowdown. This narrows the problem
to workload scheduling or process execution behavior in the Rust container
path, but the available sampling profile did not collect enough samples to
identify the specific hot syscall or scheduling point. The known
`pre_exec`-forced fork versus Go's vfork launch difference remains relevant to
startup-heavy benchmarks, but does not by itself explain the elevated CPU time
inside this interactive workload. The launch-path difference is not a complete
diagnosis for this matrix.

I sampled the live workload cgroups as well. Both services gave the Python
processes CPUs `0-11`, an unlimited `cpu.max`, `cpu.weight=100`,
`memory.max=67125248`, and `pids.max=1`; neither cgroup reported CPU throttling.
Go places its container groups under `/system.slice/gojudge.scope`; Rust nests
its groups under the service's existing user-session cgroup. That hierarchy is
a remaining environmental difference, but the sampled ancestor CPU weights
were also 100 and the cgroup CPU-pressure readings were low. It does not yet
explain the measured 1.7x slowdown.

For a 300,000-roundtrip request, Rust's Python processes accumulated about
6.1 seconds of scheduler runtime each, with 37–44 ms queued as runnable. Go's
processes accumulated about 3.2 seconds of runtime each, with 8–11 ms runnable
wait. This rules out time spent waiting in the Rust worker queue or substantial
CPU run-queue contention. A same-script host pipe baseline took 4.4 seconds per
100,000 roundtrips, close to Rust's 4.3–4.4 seconds; Go took 2.5 seconds.

The namespace setup is aligned at the relevant boundary: Go creates the
namespaces while starting the persistent container init, and each workload
inherits them. Rust similarly starts a persistent namespace keeper and runs
workloads through an executor in those namespaces. Both may create a cgroup
namespace after cgroup placement. Namespace creation therefore does not explain
the measured workload slowdown.

## Tokio task and blocking-pool migration

On 2026-10-30, the server and synchronous compatibility paths were moved onto
one shared Tokio runtime. The bounded request workers are async tasks on a
Tokio channel. Single-command requests now await child completion as Tokio
tasks; synchronous setup, file operations, and cleanup use Tokio's reusable
blocking pool. Grouped pipeline requests launch command tasks together and
await each child without occupying blocking workers. Copy-in/out batches,
output pumps, buffer drains, and interactive shell input/signal handling no
longer create their own OS threads. File-store expiry uses Tokio timers and
dispatches its filesystem reaping to the blocking pool.

Buffered proxy relays use nonblocking pipe descriptors registered with
`AsyncFd`, so each relay is a Tokio task rather than a blocked thread. CPU
affinity is applied while each relay task is polled and restored before the
Tokio worker runs other tasks. The splice relay stays on Tokio's blocking pool:
an attempted async splice relay stalled on EAGAIN in the 100,000-roundtrip
integration cases and exceeded their 45-second request deadline. The focused
proxy matrix passed after routing splice through the blocking implementation;
its six cases completed in 56.3 seconds.

The persistent namespace executor thread was removed in the production init
refactor below. Linux namespace membership remains thread-specific, but workload
creation now runs inside the PID 1 container init process, which already owns
the namespaces. The UID/GID map handshake still uses Tokio's blocking pool.

The user-namespace mapper performs blocking pipe I/O for the synchronous
`std::process::Command` parent/child UID/GID mapping handshake. It now runs on
Tokio's reusable blocking pool, rather than creating a fresh named OS thread
for every mapped command. Turning that handshake into an async task would
require converting command startup and its `pre_exec` handshake to an async
process API together. `RUST_SANDBOX_ABLATION_STD_USERNS_MAPPER=1` restores the
per-command thread for comparison. Production single and grouped request paths
wait for child completion as Tokio tasks; setup and final result collection
remain blocking boundaries around the synchronous environment and file APIs.
`RUST_SANDBOX_ABLATION_SYNC_COMMAND_WAIT=1` restores synchronous process waits
for single and grouped requests.

An initial blanket ablation that forced every blocking helper onto a fresh
standard thread caused several integration file-copy errors, so it was not a
valid performance comparison and was removed. The supported controlled
ablations are `RUST_SANDBOX_ABLATION_LEGACY_PROXY=1` for relay I/O,
`RUST_SANDBOX_ABLATION_STD_USERNS_MAPPER=1` for the UID/GID mapping worker, and
`RUST_SANDBOX_ABLATION_SYNC_COMMAND_WAIT=1` for the single-command wait.

The single-command Go `BenchmarkGoJudge_Concurrency` ran against the release
server with `-parallelism 12`, `-benchtime=2s -count=3 -cpu=1` on the same
Ryzen 5 5625U host. Each cell is the median of three samples:

| Client concurrency | Async process wait | Blocking wait ablation | Async change |
| ---: | ---: | ---: | ---: |
| 1 | 2.477 ms/op | 2.485 ms/op | 0.3% faster |
| 2 | 1.469 ms/op | 1.482 ms/op | 0.9% faster |
| 4 | 1.073 ms/op | 1.068 ms/op | 0.5% slower |
| 8 | 0.938 ms/op | 0.974 ms/op | 3.7% faster |

This paired sample is effectively throughput-neutral within observed run-to-run
variation. The async path frees a blocking-pool worker while the child runs;
the benchmark does not show a reliable request-latency improvement.

The 100,000-roundtrip `TestInteraction_Bidirectional_ProxyMatrix` also passed
in async and synchronous-wait-ablation modes. Wall times were nearly identical:

| Proxy mode / placement | Async wait | Blocking wait ablation |
| --- | ---: | ---: |
| none / worker CPU | 2.488 s | 2.491 s |
| std / worker CPU | 5.180 s | 5.168 s |
| splice / worker CPU | 4.068 s | 4.103 s |
| none / split CPUs | 2.570 s | 2.568 s |
| std / split CPUs | 5.162 s | 5.202 s |
| splice / split CPUs | 4.017 s | 4.000 s |

Each matrix run took about 23.5 seconds for all six cases. The differences
range from 0.1% to 0.9%, so this comparison also shows no throughput change.
The complete Go integration package passed on the default async mode in 36.9
seconds.

| Measurement | Async buffered relay | Legacy blocking relay |
| --- | ---: | ---: |
| 1 MiB stream, 64 KiB blocks | 3.60 ms | 3.69 ms |
| 256 interactive roundtrips, 8-byte messages | 33.62 ms | 32.33 ms |
| Full Go integration package | 95.8 s | 98.2 s |

Criterion used ten samples per microbenchmark. The stream result is within
noise; the interactive microbenchmark favors the blocking relay by about 4%.
The full integration suite passed in both modes, with the async run about 2.4%
faster in this single paired sample. Treat the full-suite difference as
directional rather than stable. The Tokio relay reduces blocked pool threads
when many buffered proxies run concurrently, while the legacy path remains
slightly faster for this small-message microbenchmark.
