use super::prelude::*;

pub(crate) fn container_exec_true(c: &mut Criterion) {
    // Construct the namespace, mounts, and keeper once so this measures the
    // repeated per-command helper path used by a warm environment.
    let root_parent =
        std::env::temp_dir().join(format!("rust-sandbox-bench-{}", std::process::id()));
    let environment = LinuxEnvironment::build(LinuxEnvironmentConfig {
        root_parent,
        no_seccomp: true,
        ..LinuxEnvironmentConfig::default()
    })
    .expect("build warm Linux environment");
    c.bench_function("container_exec/warm_bin_true_non_tty", |b| {
        b.iter(|| {
            let process = environment
                .execve(ExecveParam {
                    args: vec!["/bin/true".into()],
                    env: vec!["PATH=/usr/bin:/bin".into()],
                    ..ExecveParam::default()
                })
                .expect("spawn /bin/true");
            black_box(process.result());
        });
    });
}
