use super::*;

/// Batch copy-in with Go-compatible flags, permissions, per-file errors, and file diagnostics.
pub fn copy_in(
    env: &dyn Environment,
    sources: HashMap<String, File>,
) -> (Vec<FileError>, io::Result<()>) {
    if sources.is_empty() {
        return (Vec::new(), Ok(()));
    }
    let entries: Vec<_> = sources.into_iter().collect();
    let opens: Vec<_> = entries
        .iter()
        .map(|(name, _)| OpenParam {
            path: name.clone(),
            flag: 1 | 64 | 512,
            perm: 0o777,
            mkdir_all: true,
        })
        .collect();
    let results = match env.open(&opens) {
        Ok(r) => r,
        Err(e) => {
            return (
                entries
                    .iter()
                    .map(|(n, _)| FileError {
                        name: n.clone(),
                        kind: FileErrorType::CopyInCreateFile,
                        message: e.to_string(),
                    })
                    .collect(),
                Err(io::Error::new(
                    e.kind(),
                    format!("copyin: batch open failed: {e}"),
                )),
            );
        }
    };
    let mut jobs = entries
        .into_iter()
        .zip(results)
        .collect::<Vec<_>>()
        .into_iter();
    let mut errors = Vec::new();
    let mut first = None;
    loop {
        let batch: Vec<_> = jobs.by_ref().take(FILE_COPY_PARALLELISM).collect();
        if batch.is_empty() {
            break;
        }
        let joins: Vec<_> = batch
            .into_iter()
            .map(|((name, source), opened)| {
                crate::tokio_runtime::spawn_blocking(move || {
                    if let Some(message) = opened.error {
                        return Some((
                            FileError {
                                name,
                                kind: FileErrorType::CopyInCreateFile,
                                message,
                            },
                            None,
                        ));
                    }
                    let Some(mut destination) = opened.file else {
                        return Some((
                            FileError {
                                name,
                                kind: FileErrorType::CopyInCreateFile,
                                message: "open returned no file".into(),
                            },
                            None,
                        ));
                    };
                    let copied = match source.into_reader() {
                        Err(error) => Err((FileErrorType::CopyInOpenFile, error)),
                        Ok(mut source) => io::copy(&mut source, &mut destination)
                            .map(|_| ())
                            .map_err(|error| (FileErrorType::CopyInCopyContent, error)),
                    };
                    copied.err().map(|(kind, error)| {
                        (
                            FileError {
                                name,
                                kind,
                                message: error.to_string(),
                            },
                            Some(error),
                        )
                    })
                })
            })
            .collect();
        let outcomes: Vec<_> = joins
            .into_iter()
            .map(|join| {
                join.recv().unwrap_or_else(|_| {
                    Some((
                        FileError {
                            name: String::new(),
                            kind: FileErrorType::CopyInCopyContent,
                            message: "copy-in worker panicked".into(),
                        },
                        Some(io::Error::other("copy-in worker panicked")),
                    ))
                })
            })
            .collect();
        for outcome in outcomes.into_iter().flatten() {
            errors.push(outcome.0);
            if first.is_none() {
                first = outcome.1;
            }
        }
    }
    match first {
        Some(e) => (errors, Err(e)),
        None => (errors, Ok(())),
    }
}
