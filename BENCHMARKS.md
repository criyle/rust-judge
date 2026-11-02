# Benchmarks

Benchmark notes are split by the kind of work they measure:

- [Library benchmarks](benchmarks/library.md): IPC, protobuf, cgroup, envexec, and other library behavior.
- [Binary benchmarks](benchmarks/binary.md): process launch, warm container execution, and container-init behavior.
- [Ablations](benchmarks/ablation.md): controlled comparisons that isolate implementation costs.
- [Go comparisons](benchmarks/comparison.md): go-judge integration throughput and same-host comparisons.

The Criterion harness is split in parallel under `benches/sandbox/`. Run the
suite with `cargo bench --bench sandbox`; filter using existing benchmark
names, for example `cargo bench --bench sandbox -- forkexec/bin_true`.
