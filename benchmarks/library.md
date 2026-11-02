# Library benchmark notes

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
