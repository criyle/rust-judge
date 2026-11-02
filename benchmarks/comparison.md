# Comparison benchmark notes

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

## 2026-11-01 go-judge HTTP concurrency comparison

Ran go-judge's `BenchmarkGoJudge_Concurrency` against each release server on
the same AMD Ryzen 5 5625U host, with one server running at a time. Both
servers used parallelism 12 and `-net-share`. The Go benchmark used
`go test -tags integration -run '^$' -bench
'^BenchmarkGoJudge_Concurrency$' -cpu 1 -benchtime=1s -count=3`; `-cpu 1`
lets the benchmark's explicit `Parallel-1/2/4/8` subtests set the concurrency.
The Go server ran first, followed by Rust. The table reports the median of each
server's three `ns/op` samples and the corresponding request throughput
(`1 / median seconds`):

| Benchmark concurrency | Go median | Go TPS | Rust median | Rust TPS | Rust TPS difference |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 1.290 ms/op | 775 | 1.229 ms/op | 814 | +5.0% |
| 2 | 0.788 ms/op | 1,269 | 0.740 ms/op | 1,351 | +6.5% |
| 4 | 0.546 ms/op | 1,833 | 0.507 ms/op | 1,973 | +7.7% |
| 8 | 0.512 ms/op | 1,955 | 0.475 ms/op | 2,106 | +7.8% |

Rust was faster at all four concurrency levels in this run. This is a short,
single-host run; the differences are modest and should not be generalized to
other hardware or request mixes. The raw Go samples were 1.291/1.273/1.290,
0.777/0.788/0.817, 0.546/0.547/0.543, and 0.505/0.520/0.512 ms/op. The raw
Rust samples were 1.256/1.229/1.228, 0.723/0.740/0.743, 0.506/0.508/0.507,
and 0.475/0.474/0.484 ms/op, respectively.

The Criterion suite is split by purpose under `benches/sandbox/`: `library.rs`
contains library API measurements, `binary.rs` contains warm container command
execution, `ablation.rs` contains controlled runtime/result-delivery variants,
and `comparison.rs` contains process-launch path comparisons. Shared fixtures
and helpers live in `support.rs`. Run the suite with `cargo bench --bench
sandbox`; existing Criterion benchmark names and filters remain unchanged.

## Current concurrency benchmark against Go

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

## 2026-11-01 asynchronous fresh-cgroup pool experiment

When cgroups are configured, Rust's production environment pool now
pre-creates one fresh cgroup per configured worker and destroys each
returned cgroup on a background thread before that worker creates its
replacement. The pool is shared across the service's environments, and
`cgroup_pool_size` follows `--parallelism`. It preserves fresh per-command
accounting and does not reuse cgroup state.

Compared release go-judge with release rust-judge on the same Ryzen 5 5625U
host, parallelism 12, and `-net-share`. I ran the Go integration
`BenchmarkGoJudge_Concurrency` twice against each server (`-cpu 1
-benchtime=1s -count=3`), reversing which server ran first on the second pair.
The table uses the median of six samples per server:

| Concurrency | Go median | Go TPS | Rust async-pool median | Rust TPS | Rust TPS difference |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 1.334 ms/op | 749 | 1.044 ms/op | 958 | +27.9% |
| 2 | 0.791 ms/op | 1,264 | 0.652 ms/op | 1,535 | +21.4% |
| 4 | 0.587 ms/op | 1,703 | 0.519 ms/op | 1,927 | +13.2% |
| 8 | 0.513 ms/op | 1,949 | 0.501 ms/op | 1,996 | +2.4% |

The order-balanced run favors the async-pool Rust build at all four
concurrency levels, with a much smaller gain at 8. An earlier no-pool Rust
comparison on this host measured 1.229, 0.740, 0.507, and 0.475 ms/op. Against
that separate run, the async pool improved latency at 1 and 2, while 4 and 8
were slightly slower; the cross-run difference is small enough at higher
concurrency that it needs a stable-host A/B run before claiming a pool-only
throughput gain.

The Rust pool lifecycle unit test, all 262 library tests, all 7 binary tests,
format check, release build, and full Go integration run passed with the pool
enabled. A later rerun failed at the helper executable's read-only bind
remount. The benchmark harness had copied the server into `/tmp`, which is a
separate `tmpfs` mount with `nosuid,nodev`; inside the new user and mount
namespace those inherited mount flags are locked, so the raw
`MS_REMOUNT|MS_BIND|MS_RDONLY` call returns `EPERM`. This matches the Linux
`mount(2)`/`mount_setattr(2)` locked-mount rules. The same release binary from
the repository's `/`-backed ext4 mount passed the full integration suite, while
copying that binary to `/tmp` reproduced the focused failure. The fresh-on-
demand control binary copied to `/tmp` failed the same way, confirming it was
the launch path used for testing rather than the cgroup pool. The final pool
shutdown path uses explicit worker stop messages instead of timed polling;
this changes idle shutdown behavior, not the benchmark execution path.

## 2026-11-02 cgroup warm-pool size sweep

I held the service parallelism at 12 and swept the Rust warm-pool size across
1, 4, and 12. For Go, the cached-pool channel capacity was swept across the
same values while keeping its 12 creator workers fixed; the Go pool may hold
up to `workers + channel capacity` cgroups (13, 16, and 24 respectively).
The Go integration benchmark ran against each server at request concurrency
1, 4, and 8 (`-cpu 1 -benchtime=1s -count=3`). Values below are medians of
three samples in this run, so treat small differences as directional rather
than statistically conclusive.

| Implementation / warm size | Concurrency 1 | Concurrency 4 | Concurrency 8 |
| --- | ---: | ---: | ---: |
| Go uncached | 1.272 ms/op | 0.525 ms/op | 0.497 ms/op |
| Go cached, channel capacity 1 | 1.188 ms/op | 0.494 ms/op | 0.480 ms/op |
| Go cached, channel capacity 4 | 1.202 ms/op | 0.487 ms/op | 0.481 ms/op |
| Go cached, channel capacity 12 | 1.225 ms/op | 0.494 ms/op | 0.563 ms/op |
| Rust warm pool 1 | 1.022 ms/op | 0.480 ms/op | 0.512 ms/op |
| Rust warm pool 4 | 1.032 ms/op | 0.509 ms/op | 0.487 ms/op |
| Rust warm pool 12 (default) | 1.032 ms/op | 0.486 ms/op | 0.500 ms/op |

The Rust default is 12 ready/replenished cgroups, one per configured service
parallelism slot; it has no separate channel-capacity setting. When all warm
Rust slots are leased, additional concurrent requests get one-off cgroups,
which are destroyed on return. This avoids blocking grouped requests whose
command count exceeds the warm-pool size. Thus a smaller Rust pool is not a
strict maximum on concurrent cgroup demand.

Across this sweep, the three Rust pool sizes are within roughly 5% at each
concurrency and the direction changes between points. Go capacities 1 and 4
were about 3–7% faster than its uncached pool in this run; capacity 12 was
noisy at concurrency 8 and showed no reliable advantage. These results suggest
that keeping a modest number of cgroups ready helps Go, while increasing the
pool to 12 does not show a repeatable gain here. Rust's async replenishment and
overflow path make warm-pool size less visible in this short request benchmark.
This is a single sweep on one host, and the Go and Rust samples are not an
order-balanced A/B series; do not interpret their small cross-implementation
differences as a precise speedup estimate.

## 2026-11-02 Go cgroup-cache worker/capacity matrix

To separate Go's cache buffer capacity from its cgroup-creation worker count, I
ran the Go integration concurrency benchmark against a temporary cached-pool
build at service parallelism 12. The 3x3 matrix uses creator-worker counts
1/4/12 and cache channel capacities 1/4/12. Each point is the median of three
one-second samples (`-cpu 1 -benchtime=1s -count=3`); latencies are ms/op.

| Creator workers | Cache capacity | Request concurrency 1 | Request concurrency 4 | Request concurrency 8 |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 1 | 1.246 | 0.509 | 0.463 |
| 1 | 4 | 1.264 | 0.507 | 0.473 |
| 1 | 12 | 1.263 | 0.532 | 0.467 |
| 4 | 1 | 1.287 | 0.531 | 0.504 |
| 4 | 4 | 1.291 | 0.525 | 0.490 |
| 4 | 12 | 1.279 | 0.540 | 0.493 |
| 12 | 1 | 1.289 | 0.532 | 0.541 |
| 12 | 4 | 1.281 | 0.555 | 0.541 |
| 12 | 12 | 1.385 | 0.600 | 0.579 |

Go's cached pool has one cgroup under construction per worker and a buffered
channel for ready cgroups, so it can retain approximately `workers + capacity`
cgroups. For example, workers=1/capacity=1 produced two child cgroups in a
live server; workers=12/capacity=12 can produce up to 24. The matrix shows no
reliable benefit from enlarging the channel. Increasing the worker count to 12
was slower at every tested concurrency, especially with capacity 12. This is
consistent with extra background cgroup creation and a larger ready set adding
kernel and memory-management work, though this benchmark alone does not isolate
that cause. The lowest measured point was workers=1/capacity=1 at concurrency
8; its result should be confirmed with an order-balanced repeat before tuning
production defaults.

Rust does use background creator workers. In `AsyncFreshCgroupPool`, each
configured pool slot has a dedicated thread that creates one fresh cgroup,
marks the slot ready, then creates a replacement after the leased cgroup is
returned. Rust has no independent buffer-capacity knob: `cgroup_pool_size`
sets both the number of background creator threads and the maximum warm slots.
If every slot is leased, Rust creates an overflow cgroup synchronously and
destroys it on return, so the warm-slot count does not cap concurrent demand.
The earlier Rust size sweep therefore varied worker count and warm capacity
together; it did not test them as independent axes. Separating those axes in
Rust would require redesigning its slot/replenishment model, and this Go matrix
does not by itself establish a reason to do that.

## 2026-11-02 Go cached pool vs Rust at parallelism 8

I compared release servers on the Ryzen 5 5625U with `--net-share`, service
parallelism 8, and the Go integration benchmark at request concurrency 8. Go
used the temporary cached-pool build with one creator worker and cache capacity
8; Rust used its default eight warm slots (eight creator threads). Each server
had three benchmark runs, each with three 2-second samples (`-cpu 1
-benchtime=2s -count=3`). I ran the servers in alternating order. The nine
samples per implementation give these medians:

| Server | Median latency | Median throughput | Sample range |
| --- | ---: | ---: | ---: |
| Go, cached pool (1 worker, capacity 8) | 0.495 ms/op | 2,021 requests/s | 0.461–0.530 ms/op |
| Rust (8 warm slots) | 0.537 ms/op | 1,864 requests/s | 0.518–0.598 ms/op |

In this run Rust was 8.5% slower by median latency, or about 7.8% lower by
median throughput. The ranges overlap and samples vary, so this is a measured
result for these builds and settings, not a definitive general ranking.

For memory, I reset and read `memory.peak` on the service's parent cgroup
scope after pool startup and before the benchmark. This scope includes the
server process, namespace init processes, command processes, and kernel memory
charged to their cgroups. The median of three runs was 99.0 MiB for Go and
36.3 MiB for Rust, about 63% lower for Rust. In one additional sampled run,
the sum of process RSS across the service scope peaked at 251.6 MiB for Go and
137.2 MiB for Rust. Summed RSS counts shared mapped pages once per process, so
it overstates unique physical memory; the hierarchical cgroup `memory.peak` is
the better whole-service comparison. The cgroup peak also includes kernel
charges, so it is broader than process RSS.

The Go cache implementation and pool-size overrides were built in a temporary
worktree for measurement and were removed afterward; this is not a benchmark of
a merged Go change. The benchmark harness was the go-judge integration
`BenchmarkGoJudge_Concurrency` run against both servers.

### Main process and container-init memory breakdown

I separately sampled each service's main process and the processes whose command
line contains `container_init` during the same parallelism-8 workload. RSS and
PSS were read from `/proc/<pid>/smaps_rollup` at 20 ms intervals. The values are
peaks for each role; init totals sum all init processes observed at the sample
where that role's aggregate peaked.

| Server | Main RSS peak | Main PSS peak | Container-inits at aggregate peak | Init RSS sum peak | Init PSS sum peak |
| --- | ---: | ---: | ---: | ---: | ---: |
| Go, cached pool (1 worker, capacity 8) | 37.1 MiB | 19.7 MiB | 8 | 213.3 MiB | 74.9 MiB |
| Rust (8 warm slots) | 21.1 MiB | 14.8 MiB | 16 | 63.2 MiB | 10.0 MiB |

Summed RSS can count shared executable and library pages once for each init;
PSS apportions those shared pages across processes. The PSS figures are therefore
more meaningful for comparing process memory, while the earlier cgroup
`memory.peak` also includes kernel charges and command processes. The 20 ms
sampling can miss brief process peaks, but the long-lived server and init
processes were present throughout the benchmark.
