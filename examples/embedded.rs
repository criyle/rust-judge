//! Minimal library example: run one command through the sandbox worker.
//!
//! This needs Linux namespace support and the privileges required to create
//! the configured namespaces and mounts. Configure cgroups separately when
//! you need cgroup-enforced resource limits.

use rust_judge::{
    env::linux_environment::{LinuxEnvironmentConfig, LinuxEnvironmentPool},
    filestore::LocalFileStore,
    runner::Size,
    tokio_runtime,
    worker::{AsyncWorker, CancellationToken, CmdFile, Command, Request, WorkerConfig},
};
use std::{io::Read, path::PathBuf, sync::Arc, time::Duration};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = PathBuf::from("/tmp/rust-judge-example");
    std::fs::create_dir_all(&data_dir)?;

    let files = LocalFileStore::new(data_dir.join("files"));
    std::fs::create_dir_all(data_dir.join("files"))?;
    let mut environment_config = LinuxEnvironmentConfig::default();
    environment_config.root_parent = data_dir.join("roots");
    let environments = Arc::new(LinuxEnvironmentPool::new(environment_config)?);

    let mut config = WorkerConfig::new(files, environments);
    config.parallelism = 1;
    let worker = AsyncWorker::new(config);
    worker.start()?;

    let request = Request {
        request_id: "example".into(),
        commands: vec![Command {
            args: vec!["/bin/echo".into(), "hello from rust-judge".into()],
            files: vec![
                CmdFile::Null,
                CmdFile::Collector {
                    name: "stdout".into(),
                    max: Size(64 * 1024),
                    pipe: false,
                },
                CmdFile::Collector {
                    name: "stderr".into(),
                    max: Size(64 * 1024),
                    pipe: false,
                },
            ],
            clock_limit: Duration::from_secs(2),
            memory_limit: Size(64 * 1024 * 1024),
            ..Command::default()
        }],
        pipe_mapping: vec![],
    };

    let (response_rx, _started_rx) = worker.submit(request, CancellationToken::default());
    let mut response = tokio_runtime::runtime().block_on(response_rx)?;
    worker.shutdown();

    if let Some(error) = response.error {
        return Err(error.into());
    }
    let result = response
        .results
        .first_mut()
        .ok_or("sandbox returned no command result")?;
    if let Some(mut stdout) = result.files.remove("stdout") {
        let mut output = String::new();
        stdout.read_to_string(&mut output)?;
        print!("{output}");
    }
    Ok(())
}
