# Benchmarks

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

## Go cgroup sibling layout correction

The source audit found that go-judge calls `Nest("api")` and then calls
`New("containers")` on the original cgroup handle. Those directories are
siblings under the configured prefix; the execution groups are in
`<prefix>/containers`, not `<prefix>/api/containers`. Rust's default v1/v2
roots and v2 hierarchy preparation now follow that layout, while retaining
the empty `api` sibling created by Go. For v1, the configured prefix is now
resolved directly below each controller mount, matching go-judge's
`/sys/fs/cgroup/<controller>/<prefix>` paths instead of nesting below the
server's current membership. Fixture tests cover both path rules. The full
Rust suite passed (248 library tests,
4 rust-judge binary tests, and 1 shell binary test), and the Go integration
package passed against the rebuilt release server. This host
has no writable delegated cgroup, so runtime placement into that hierarchy
still requires validation on a host with writable delegation.

The v1 startup path also prepares Go's `api` sibling, migrates any processes
already in the prefix into it in controller order, and creates the `containers`
sibling before building the environment pool. A fixture test verifies the
layout and migration for all supported controllers. Live v1 cgroup setup
cannot be exercised on this cgroup v2 host. After this change, the complete
Go integration package passed against the rebuilt release server in 111.2
seconds. Standalone `runprog` now uses the same mount-root-relative v1 resolver
as Go's `cgroup.New("runprog")`, rather than nesting below the current
membership.

For a shorter local smoke run:

```sh
cargo bench --bench sandbox -- --sample-size 10 --warm-up-time 1 --measurement-time 1
```

The envexec pipe benchmarks use the production `envexec::Group` and
`PipeMapping` implementation. Their stdio adapter launches ordinary host
processes with `std::process::Command`, leaving namespace and cgroup setup out
of the sample. Each stream iteration transfers 1 MiB from `dd` to `cat` using
1 KiB, 64 KiB, or 1 MiB blocks through a direct pipe, the Go `io.Copy`
compatible relay, or the explicit splice relay. On Linux, Go's `io.Copy` on
`*os.File` pipe endpoints can itself use splice; Rust now uses the same fast
path and falls back to buffered copying when splice is unavailable. Interactive
cases run a shell writer and echo process over two mapped pipes and exchange
256 messages at 8, 64, 256, or 1024 bytes.

These results are relay-path measurements, not direct numeric equivalents of
Go's pipe microbenchmarks: Go writes and drains its pipes in benchmark
goroutines and keeps the interactive goroutines alive across iterations,
whereas the Rust `Group` API owns process launch and a fresh pair of child
processes is included in each Criterion iteration. Both use the same pipe
topology and compare direct pipes, Go-compatible proxy behavior, and explicit
splice relay behavior. Filter the benchmark to keep runs short:

```sh
cargo bench --bench sandbox -- envexec/pipe_stream_1mib/user_copy/block_65536b
cargo bench --bench sandbox -- envexec/pipe_interactive_256_roundtrips/splice/message_8b
```

Each envexec benchmark uses 10 samples, a 1-second warm-up, and a 1-second
measurement window. The stream benchmark requires `/bin/dd` and `/bin/cat`; the
interactive benchmark requires `/bin/sh`.

Criterion writes estimates and raw samples under `target/criterion/`. Compare runs on the same machine and toolchain; kernel, CPU, filesystem, and privilege setup strongly affect process and socket results. Re-run the Go benchmark with `go test -bench=. -benchmem` from the corresponding package when a same-host comparison is needed. The Go and Rust protocol payload encodings are intentionally different, so compare transport/framing costs only when payload sizes match.

The suite currently covers:

- Unix `SOCK_SEQPACKET` ping round trips, small-packet send/drain, and 10/100/200 descriptor batches.
- Rust unbounded and bounded (capacity 1 and 4) MPSC send/drain baselines, corresponding to Go channel baselines.
- Prost request encoding and decoding at 1 KiB, 32 KiB, 64 KiB, and 128 KiB, spanning the Go framing boundary.
- Standard-library `Command` versus the sandbox `Runner` for `/bin/true`, without namespace creation, plus the parent/child pre-exec synchronization callback path.
- Production `envexec::Group` direct pipes, buffered proxy relays, splice relays, and bidirectional interactive proxy traffic.
- `memfd` copy-and-seal at 4 KiB and 1 MiB.
- Cgroup v2 child creation, cpuset/memory/process limits, CPU and memory
  sampling, and teardown (opt-in on a dedicated delegated cgroup path).

## Smoke performance run

One run used `--sample-size 10 --warm-up-time 1 --measurement-time 1` on Linux x86_64. These are short-run medians, not release thresholds; Criterion reported substantial variation from its prior sample, so use repeated same-host runs for comparisons:

| Case | Estimated time |
| --- | ---: |
| Seqpacket ping round trip | 21.45 µs |
| FD batch 10 / 100 / 200 | 26.11 / 78.28 / 158.67 µs |
| Prost encode / decode, 1 KiB | 149.90 / 285.44 ns |
| Prost encode / decode, 32 KiB | 722.94 ns / 1.48 µs |
| Prost encode / decode, 64 KiB | 1.34 / 2.63 µs |
| Prost encode / decode, 128 KiB | 2.62 / 5.99 µs |
| `std::process::Command` `/bin/true` | 459.33 µs |
| Sandbox `Runner` `/bin/true` with `pre_exec` | 1.95 ms |
| Memfd copy-and-seal, 4 KiB / 1 MiB | 11.31 / 688 µs |

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

## Integration throughput investigation

The Go integration suite initially took about 320 seconds against Rust, while
the Go server completed it in about 36 seconds. Profiling showed that the HTTP
and unary gRPC handlers used `AsyncWorker::execute`, which created one OS thread
per request and retained every join handle until shutdown. The 10,000-request
copy-in race test therefore accumulated thousands of threads. Those request
handlers now use the bounded worker pool; interactive stream handlers continue
to use direct execution.

Using the Go integration package's `BenchmarkGoJudge_Concurrency` against each
server (`-benchtime=2s -count=1 -cpu 1`) produced these `ns/op` samples:

| Parallelism | Rust before worker-pool fix | Rust after fix | Go |
| ---: | ---: | ---: | ---: |
| 1 | 7,248,227 | 2,749,668 | 1,691,472 |
| 2 | 7,718,955 | 1,596,385 | 1,155,325 |
| 4 | 8,917,762 | 1,268,549 | 887,524 |
| 8 | 10,443,597 | 1,213,329 | 856,170 |

After the worker-pool fix, the full Go integration suite passed against Rust in
41.9 seconds. The first post-fix run found intermittent `ETXTBSY` failures in
the same 10,000-request copy-in race test. Go's fork/exec implementation retries
that transient `execve` error with a 1 ms delay; Rust's `Runner` now uses a
bounded retry for the same errno. The complete suite passed on rerun.

## Clean-host rerun and keeper lifecycle

After clearing stale processes, the full suite took 39.0 seconds against a Rust
debug server and 38.0 seconds against a Rust release server; Go took 34.6
seconds on the same host. The release build did not materially change runtime.
The isolated 10,000-request copy-in race test took 12.5 seconds against Rust
release and 7.6 seconds against Go. These measurements show a remaining hot-path
gap, but the full suite is below 40 seconds rather than minutes.

The clean-up audit found that dropping a `LinuxEnvironment` killed the outer
`unshare` launcher but could leave its PID-namespace init alive. Repeated server
starts and forced shutdowns had accumulated 919 orphan keepalives, degrading
subsequent runs. Environment teardown now kills the namespace init before
waiting for the launcher, and the server handles SIGTERM as a graceful shutdown
signal. A focused pool teardown test verifies that the namespace init is gone;
the test and a live SIGTERM shutdown both leave zero keepalives.

## Current performance recheck

On 2026-10-30, the full Go integration package completed in 36.0 seconds against
the rebuilt Rust release server and 34.2 seconds against the Go server, using
`go test -tags integration -count=1 .`. The concurrency benchmark was also
repeated with `-benchtime=2s -count=1 -cpu 1`:

| Parallelism | Rust release | Go |
| ---: | ---: | ---: |
| 1 | 2,136,254 ns/op | 1,612,281 ns/op |
| 2 | 1,217,175 ns/op | 952,899 ns/op |
| 4 | 989,905 ns/op | 713,898 ns/op |
| 8 | 1,032,115 ns/op | 666,048 ns/op |

This reproduces the expected small full-suite gap and the known 1.3–1.5x
request-path gap, but not a multi-minute slowdown. Both server shutdowns left no
`unshare` or namespace-init processes behind.

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

## 2026-10-30 current-tree performance audit

With one server active at a time and default seccomp enabled, the full Go
integration package passed in 51.5 seconds against Rust and 34.6 seconds
against Go. The largest measured difference came from two tests:

| Test | Rust | Go | Difference |
| --- | ---: | ---: | ---: |
| 10,000 copy-in-and-exec requests (isolated command wall time) | 18.3 s | 8.7 s | 9.6 s |
| Bidirectional proxy matrix | 29.4 s | 22.5 s | 6.9 s |

Together these account for essentially the full-suite gap. The 10,000-request
case launches a fresh tiny executable for every request, amplifying process
setup cost. Rust uses `std::process::Command` with `pre_exec`, which takes the
ordinary fork path on the tested toolchain; Go uses its Linux vfork path and
uses `clone3` when cgroup-FD placement is requested. This is a launch-path
difference in addition to the cgroup-placement difference.
The proxy matrix also remains slower in both direct-pipe and relay modes.

I checked the worker-count hypothesis as well. Go defaults to
`runtime.NumCPU()` (the process affinity mask); Rust now uses the same
affinity-mask count rather than `available_parallelism()`'s quota-aware count.
On this host both report 12 CPUs, and explicitly increasing Rust parallelism
to 64 made the isolated race test slower (22.5 s), so worker count is not the
cause of this host's gap. An earlier timing run used `--no-seccomp` and failed
two seccomp tests; it is excluded from the comparison above. That run also
left its server alive and consuming CPU, so the prior contaminated timings
should not be used.

## 2026-10-30 parallel request recheck

The copy-in-and-exec race test has 10,000 parallel subtests. Go's parent test
elapsed value only measures the time spent registering those children, so the
previous 0.22-second figure was misleading. Measuring the full test command
isolated gives 13.8 seconds against Rust release and 8.9 seconds against Go.
The full integration package passed in 44.9 seconds against Rust and 34.4
seconds against Go on the same host.

HTTP and unary gRPC handlers previously waited on a standard-library channel
from Tokio `spawn_blocking` tasks. They now await a Tokio one-shot response
channel, avoiding a blocking-pool waiter per queued request. The isolated
10,000-request case still runs about 1.55x slower than Go; the full suite runs
about 1.30x slower. A concurrent HTTP benchmark run measured Rust at 3.24,
2.07, 1.63, and 1.63 ms/op versus Go at 1.69, 1.09, 0.79, and 0.79 ms/op for
parallelism 1, 2, 4, and 8. These short samples varied from earlier results,
so repeat them before treating the ratios as stable. Both full runs completed
in under one minute here.

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

## 2026-10-30 current-tree recheck

After the file-timeout, pre-fork, cgroup API, monitor, and custom init-path
updates, the release server passed the complete Go integration package in
58.5 seconds. A paired focused run of the six-case bidirectional proxy matrix
took 32.5 seconds against Rust and 22.4 seconds against Go. Disabling seccomp
on both servers produced 33.0 seconds against Rust and 22.5 seconds against
Go, so seccomp is not responsible for that gap. The matrix is the slowest
suite component and still exercises 100,000 interactive round trips per case.

The Criterion warm-container `/bin/true` benchmark measured 742 and 752
microseconds in two consecutive filtered runs (`--sample-size 20`, 1-second
warm-up, 2-second measurement). A full short smoke run had one noisy 1.61 ms
sample for the same case, demonstrating that short runs can be contaminated;
the repeated filtered runs were stable. The Go container benchmark previously
measured about 228 microseconds per operation on this host. Rust remains
roughly 3.3 times slower on that microbenchmark under the required standard
library launch path, while the full integration suite remains under one
minute.

The new production relay-path benchmark (`envexec::Group`/`PipeMapping`) moved
1 MiB in 1 KiB blocks in these short samples:

| Mode | Time/op | Throughput |
| --- | ---: | ---: |
| Direct pipe | 3.60 ms | 278 MiB/s |
| User-space relay | 4.66 ms | 215 MiB/s |
| Splice relay | 4.61 ms | 217 MiB/s |

The splice case had substantial sample variation, so the 0.05 ms difference
from user-space relay is not conclusive. An 8-byte interactive splice sample
with 256 round trips per operation measured about 19.9 ms/op. These benchmarks
include process startup and use a standard-library command adapter without the
container namespace setup; use the full integration proxy matrix for the
end-to-end comparison.

## Current performance issue recheck

Rebuilt the current release and reran the complete Go integration package after
vendoring its protobuf schemas and adding monitor profiling/shutdown parity: it
passed in 67.6 seconds. A fresh Go server completed the same package in 35.1
seconds immediately beforehand.
The current Rust run's largest top-level test was the bidirectional proxy
matrix (36.4 seconds versus 22.35 seconds for Go). The isolated 10,000-request
copy-in/exec test took 19.7 seconds against Rust release and 10.7 seconds
against Go; Go's JSON parent-test elapsed field is misleading for its parallel
subtests, so these figures use the complete `go test` command wall time.

I repeated the isolated test with seccomp disabled on both servers. Rust took
18.6 seconds and Go took 8.2 seconds. This points to two distinct costs:
process-heavy requests remain about 2x slower with seccomp disabled, and the
proxy matrix remains slower independently. The process-heavy gap is consistent
with Rust's `pre_exec`-forced fork path versus Go's Linux vfork path (with
`clone3` for cgroup-FD placement). Seccomp is not the main source of the
gap. These are single-run timings and should be treated as directional, but
the complete suite is well below two minutes and passed with the current tree.

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

## Worker CPU-list parsing correction

A paired run on 2026-10-30 exposed a configuration mismatch in the earlier
proxy comparison. Go's `StringSlice` flag parses `-cpuset 0,1,2,3` as four
worker CPU sets. Rust parsed the same CLI value as one worker set containing
four CPUs, allowing paired workloads to run on separate cores.
Rust now splits comma-separated CLI values for both `--cpuset` and
`--src-prefix`, matching Go's flag behavior, with a config unit test for the
CLI form.

With the Rust server configured using `--cpuset 0,1,2,3`, the worker-allocated
direct-pipe case improved from 4.57 seconds before the fix to 3.13 seconds
after it. A matched Go run measured 2.21 seconds. The complete six-case Rust
proxy matrix took 38.6 seconds after the fix, compared with 43.0 seconds
before it. The namespace audit confirmed the launch boundaries match; the
earlier suspected per-workload namespace mismatch was incorrect. With the same
`0,1,2,3` worker configuration, the full Go
integration package passed in 37.2 seconds; it passed against the rebuilt Rust
server in 70.1 seconds. Both are below two minutes, though Rust remains about
1.9 times slower overall. The config mismatch explained a substantial part of
the direct-pipe slowdown; the remaining per-workload launch and proxy gap is
still visible in focused timings.

## Generated container credential validation

The `--container-cred-start` path now assigns a distinct host UID/GID to each
new environment and maps both container root and the configured workload ID in
the keeper user namespace. Workloads inherit that namespace. Pipe and newly
created collector-file ownership is translated through the mapping so a
workload can reopen `/proc/self/fd/N`, including the `/dev/stdout` symlink
case. The full Go integration package passed with
`--container-cred-start 1000 --no-fallback` in 68.1 seconds; this includes the
C++ cached-executable symlink test that had exposed the missing ownership
translation.

## Matched integration rerun after API cancellation changes

On the same host, using release Rust and Go servers configured with
`--no-fallback --cpuset 0,1,2,3`, the complete Go integration package passed in
69.1 seconds against Rust and 35.7 seconds against Go. Rust remains below two
minutes, but is about 1.9x slower on this host. The API cancellation change did
not affect correctness or move the suite outside that range.

The proxy matrix and process-heavy tests remain the largest known contributors.
Rust starts native OS threads for command workers and each proxy relay on every
group execution; Go uses goroutines for those tasks. This is a source-level
candidate for extra setup cost, but it does not yet explain the measured
workload CPU-time gap by itself. The direct-pipe matrix also remains slower,
and earlier same-script host-pipe measurements were close to Rust's direct
case. More targeted syscall and scheduling profiles are needed before
attributing the remaining slowdown to thread startup or changing the execution
model.

### Paired proxy-matrix profile

A fresh paired run on the same host completed the full integration package in
77.0 seconds against Rust release and 37.2 seconds against Go. The focused
`TestInteraction_Bidirectional_ProxyMatrix` took 46.6 seconds against Rust and
24.2 seconds against Go. The six Rust cases took 3.39, 8.52, 8.89, 6.07, 9.71,
and 10.01 seconds; the corresponding Go cases took 2.26, 5.28, 4.32, 2.65,
5.42, and 4.24 seconds. The no-relay and split-CPU cases are slower too, so
proxy copying alone does not account for the gap.

For `none/split-cpu-0-1`, Rust reported about 2.9 CPU seconds for each Python
process and Go about 1.2 seconds. Both children had the expected CPU affinity
(CPU 0 and CPU 1), `cpu.max=max`, and `cpu.weight=100`. Disabling Rust seccomp
left this case at about 6.1 seconds, ruling seccomp out as the primary cause.
The Rust command cgroups also reported much more kernel time than user time.
Short `strace -c` samples saw roughly 4,500 combined `read`/`write` calls for
Rust versus 6,500 for Go over the sampled interval, with higher average syscall
time in the Rust sample. These traced samples perturb timing and are not a
final attribution, but they localize the remaining cost to the workload's
pipe/syscall path rather than HTTP request handling or cgroup throttling. The
specific syscall or kernel-path difference remains unresolved.

The Rust Linux `DisableZeroCopy` relay now matches Go's `io.Copy` behavior for
pipe endpoints: it tries splice and falls back to buffered copying when splice
is unavailable. This is a fidelity fix based on Go's `os.File.ReadFrom` fast
path, but not a performance fix in this sample: the matrix reran in 47.0
seconds (46.6 seconds before), and the full Rust integration package passed in
77.9 seconds. The direct-pipe slowdown is unchanged.

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

### User-namespace mapper ablation

The complete Go integration package passed in 95.7 seconds with the Tokio
blocking-pool mapper and 101.8 seconds with the legacy per-command thread. That
default integration configuration does not request generated container
credentials, so it does not exercise the mapper; those full-suite timings are
correctness checks, not mapper performance evidence.

For a focused comparison, I restarted the release server with
`--container-cred-start 1000` so every workload uses a generated UID/GID map,
then ran the Go integration concurrency benchmark using
`-benchtime=2s -count=3 -cpu 1`. The table reports the median of the three
samples in each mode:

| Parallelism | Tokio blocking pool | Per-command OS thread | Change with pool |
| ---: | ---: | ---: | ---: |
| 1 | 3.91 ms/op | 4.38 ms/op | 10.7% faster |
| 2 | 2.90 ms/op | 3.06 ms/op | 5.0% slower |
| 4 | 2.66 ms/op | 2.81 ms/op | 5.3% faster |
| 8 | 3.03 ms/op | 2.96 ms/op | 2.3% slower |

The direction changes with concurrency and the differences are small relative
to run-to-run spread. Pooling removes a fresh OS-thread creation per mapped
command, but this benchmark does not show a consistent throughput improvement.
The change is retained to avoid needless thread churn; the direct performance
claim is reduced thread creation, not faster requests.

The PID 1 control loop now also follows Go's exec completion handshake: after
an execution result, the host sends `Kill`, and init consumes that command
before accepting the next request. Cancellation `Kill` commands received
while the payload is running remain part of the in-flight execution. An idle
`Ok` or `Kill` command is rejected as an unknown command, matching Go's
dispatcher. The Rust unit suite passed (232 library tests), and the Go
integration package passed against the release self-init server in 110.2
seconds after this protocol alignment (`go test -tags integration -count=1 .`,
2026-10-30).

The production `rust-judge` PID 1 dispatch now always enters the persistent
container control server; standalone helper flags cannot divert it to the
`container-init` CLI. A live smoke request returned `Accepted`, and the init
process's executable device/inode matched the running release `rust-judge` binary.
Go's systemd cgroup path moves the server into `gojudge.scope/api` and keeps
`containers` as its sibling; only the no-systemd fallback uses the nested
`init` child. Rust now follows both paths, requests a delegated transient scope
through Tokio-enabled zbus, and writes each PID to `cgroup.procs` as one
record. Live checks matched Go's process placement, controller list, and
subtree controls. A full `/config` comparison from identical working
directories showed matching keys and runner fields except `clone3` (true in
Go, false in Rust's `std::process::Command` runner). `/version` now falls back
to the Cargo package version for `buildVersion` and reports the build's actual
`rustc` version in its runtime-version field. The Go integration package
passed in 36.9 seconds after these changes
(`go test -tags integration -count=1 ./integration_test`, 2026-10-30).

Revalidated the production init path with the rebuilt release binary. During
the Go integration run, namespace PID 1 had argv `/.rust-sandbox-init
container_init` and its `/proc/<host-pid>/exe` had the same device, inode, and
SHA-256 as `target/release/rust-judge`; no standalone init executable was used.
The full Go integration package passed in 37.5 seconds, and the serial Rust
test suite passed (252 library tests plus all binary and doc tests). One
parallel Rust test run had a transient Unix-socket reset in the executable-fd
test; that test passed alone and in the serial suite.

Container PID 1 now waits with `waitid(WNOWAIT)` polling and reaps the command
with `wait4`, using the kernel's final user CPU time and peak RSS in its result.
This replaces the prior final-value estimate from procfs sampling. A focused
unit test confirms both values are populated from a CPU-using child. The full
Go integration package passed against the release server in 115.3 seconds
after this change (`go test -tags integration -count=1 .`, 2026-10-30).

### Interactive worker result delivery

Interactive worker execution now returns a Tokio one-shot receiver. WebSocket
and gRPC handlers await it directly instead of scheduling another blocking task
just to call `std::sync::mpsc::Receiver::recv`. A focused Criterion ablation
measured one Tokio blocking producer plus one-shot delivery at 59.4 µs median;
the former producer plus blocking-channel consumer shape measured 71.5 µs
median (20 samples, 1 s warm-up, 2 s measurement). This synthetic comparison
isolates delivery and scheduling overhead; it does not imply a 17% end-to-end
request improvement. The full integration package passed in 114.9 seconds
after this change, compared with 111.1 seconds immediately before it; that
small difference is within the observed run-to-run spread and gives no
end-to-end improvement signal (`go test -tags integration -count=1 .`,
2026-10-30).

Remaining production `spawn_blocking` work is on synchronous boundaries:
command setup still uses the synchronous `envexec::Environment` and
`std::process::Command` contract, while final file collection uses blocking
`Read`/`Write` adapters. The production resource-limit loop calls
`Process::wait_timeout_async` and is a Tokio task; only the synchronous
compatibility API uses `Process::wait_timeout`. The standalone `runprog` CLI
is synchronous by design. Making setup async requires an async environment
trait and an async launch path, including the `pre_exec` UID/GID mapping
handshake. Generic file, pipe, PTY, splice, and copy-out adapters accept
blocking `Read`/`Write` implementations; file expiry and pprof serialization
perform blocking filesystem or CPU work. These run through Tokio's reusable
blocking pool, not one newly created thread per operation. The parent-sync
callback's socket wait and dispatch are Tokio tasks; the callback itself is
synchronous and must be short. Buffered proxy relay I/O and request/response
handling are Tokio tasks.
The only production
`std::thread::Builder` path is the opt-in
`RUST_SANDBOX_ABLATION_STD_USERNS_MAPPER=1` control; other direct standard
threads found by the source audit are test/benchmark harnesses.

### PID 1 child-exit readiness

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

### Standalone runprog container parity

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
negative file timeout maps to disabled expiration as in Go. A zero force-GC
interval now fails server startup instead of silently disabling the task.

The configured force-GC interval and target now drive a periodic Tokio task
on Linux/glibc. Rust reclaims values at drop time rather than tracing them;
the task checks the glibc allocator footprint and calls `malloc_trim` through
Tokio's blocking pool when the target is exceeded. This returns already-free
pages, but cannot collect live values or reproduce Go's heap profile. Targets
without glibc have no allocator trimming equivalent in this build and skip
the task. The allocator checks have focused unit coverage. After wiring the
task, the release server passed the full Go integration package in 117.6
seconds on 2026-10-30.
The release server also passed the full integration package in 121.5 seconds
after the negative file-timeout and zero force-GC interval parity fixes.

### Current concurrency benchmark against Go

I rebuilt the Go server from the current source and ran the Go integration
`BenchmarkGoJudge_Concurrency` six times against each release server
(`-benchtime=1s -count=3`, two runs per server, one server active at a time).
Both servers used parallelism 12 on the same AMD Ryzen 5 5625U host. The table
shows the median across all six samples at each test concurrency:

| Benchmark concurrency | Go median | Rust median | Rust overhead |
| ---: | ---: | ---: | ---: |
| 1 | 0.795 ms/op | 0.851 ms/op | 7.1% |
| 2 | 0.725 ms/op | 0.862 ms/op | 18.9% |
| 4 | 0.735 ms/op | 0.895 ms/op | 21.7% |
| 8 | 0.737 ms/op | 0.876 ms/op | 18.8% |

This run confirms a repeatable request-path gap once concurrency exceeds one.
After the benchmark and ablation, the complete Go integration package passed
against the release Rust server in 37.6 seconds (`go test -tags integration
-count=1 ./integration_test`, 2026-10-30). Go's startup log confirms it selected
`clone3(CLONE_INTO_CGROUP)` on this kernel, while Rust enrolls the child through
cgroup membership files and its `pre_exec` hook uses ordinary fork. A
controlled ablation shows that cgroup placement helps Go. In a temporary Go
worktree with `tryClone3` disabled,
the same benchmark measured fallback
medians of 0.942, 0.917, 0.932, and 0.931 ms/op at concurrency 1, 2, 4, and 8.
Rust's medians were 0.851, 0.862, 0.895, and 0.876 ms/op, respectively, 4–10%
faster than Go's fallback in that server benchmark. Disabling Go's clone3
cgroup placement increased its median latency by 19–27%; it did not disable
vfork. Those results therefore do not show that cgroup placement explains most
of the Rust/Go gap. The `pre_exec`-forced fork is a separate measured
difference.

After the production-init verification, the serial Rust test run passed all
255 library tests and 7 binary tests; `cargo fmt --check` and the Criterion
benchmark smoke harness also passed. The full Go integration package passed
against the production-default release server in 36.834 seconds. During that
run, each inspected namespace PID 1 had `NSpid` ending in `1`, argv beginning
`/.rust-sandbox-init container_init`, and the same executable device/inode as
the server (`64539:2100577`).

After adding the trace writer, all 253 library tests, 7 binary tests, and doc
tests passed serially. The rebuilt release server's Go integration package
passed in 37.5 seconds (`go test -tags integration -count=1 ./integration_test`,
2026-10-30). Live trace files with empty and concurrent HTTP/workload spans
were accepted by Go 1.27.3's `go tool trace -d=parsed`.

The Go container init calls `chdir(WorkDir)` before executing the init command.
Rust PID 1 now does the same after configuring `/w`, which also preserves the
base directory for relative control operations such as Open, Delete, and
Symlink. A live `/proc` inspection during integration testing confirmed each
inspected production `rust-judge` process had namespace PID 1 and a host-visible
cwd ending in its container's `/w`. The default-seccomp full Go integration
package passed again in 37.2 seconds on 2026-10-30. `cargo fmt --check`, the
serial Rust unit/binary tests (255 library and 7 binary tests), the release
build, and the Criterion benchmark smoke harness also passed after this
change. A separate initial run with `--no-seccomp` failed the seccomp-specific
integration cases as expected and is not counted as a valid suite result.

The subsequent parity audit preserved every Go `syscall.Rlimit` entry in
order, including resource IDs and separate soft/hard values; missing optional
cgroup controllers no longer discard limits from available controllers, and
real controller write errors now propagate. REST file errors, JSON collector
validation, source-path errors, and gRPC file errors were aligned with Go and
covered by focused tests. Seccomp installation now happens once during PID 1
configuration, after the init command, and workloads inherit the filter; the
workload launch no longer performs a redundant `chroot("/")` that the inherited
filter denies. Go's symlink behavior is also preserved: creating a symlink
doesn't implicitly create its missing parent directory. With these changes,
`cargo fmt --check` and the serial Rust suite passed (262 library tests, 7
binary tests), the release build and Criterion smoke harness passed, and the
default-seccomp Go integration package passed in 37.3 seconds on 2026-10-30.

Environment-pool acquisition and return now run through Tokio's reusable
blocking pool. The pool API is synchronous and may create namespaces, prepare
mounts, or clear container filesystems, so invoking it directly from a request
task could stall a Tokio worker. The `runprog` container backend sends its
allowlist as an Exec-level seccomp filter, matching go-sandbox; go-judge's
shared container filter remains installed once in PID 1. The initial combined
unit run caught the distinction because installing runprog's narrower
workload-only allowlist in PID 1 killed its control-socket reply. After the
fix, `cargo fmt --check`, all 262 library and 7 binary tests, release build,
and Criterion smoke harness passed. The full default-seccomp Go integration
package passed in 36.5 seconds on 2026-10-30. This single before/after suite
pair is too small to claim a throughput improvement from moving pool operations
off Tokio workers.
