use super::*;

pub(super) async fn debug_index() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        "<html><head><title>/debug/pprof/</title></head><body>/debug/pprof/<br><p>Set debug=1 as a query parameter to export in legacy text format</p><p>Types of profiles available:</p><table><thead><tr><td>Profile</td><td>Description</td></tr></thead><tbody><tr><td><a href='allocs?debug=1'>allocs</a></td><td>A sampling of all past memory allocations</td></tr><tr><td><a href='block?debug=1'>block</a></td><td>Stacks that led to blocking on synchronization primitives</td></tr><tr><td><a href='cmdline?debug=1'>cmdline</a></td><td>The command line invocation of the current program</td></tr><tr><td><a href='goroutine?debug=1'>goroutine</a></td><td>Operating system thread snapshots; Rust async tasks share these threads</td></tr><tr><td><a href='heap?debug=1'>heap</a></td><td>A sampling of live heap allocations</td></tr><tr><td><a href='mutex?debug=1'>mutex</a></td><td>Contended mutex profiles</td></tr><tr><td><a href='profile?debug=1'>profile</a></td><td>CPU profile</td></tr><tr><td><a href='symbol?debug=1'>symbol</a></td><td>Program counter symbol lookup</td></tr><tr><td><a href='threadcreate?debug=1'>threadcreate</a></td><td>Operating system thread snapshots</td></tr><tr><td><a href='trace?debug=1'>trace</a></td><td>Go runtime execution trace</td></tr></tbody></table><a href='goroutine?debug=2'>full thread snapshot</a></body></html>",
    )
}

pub(super) async fn debug_cmdline() -> impl IntoResponse {
    // Match net/http/pprof.Cmdline: arguments are separated by NUL bytes.
    // This is the portable part of the
    // Go endpoint and does not require platform-specific process inspection.
    let mut args = std::env::args_os();
    let mut body = Vec::new();
    if let Some(arg) = args.next() {
        body.extend_from_slice(arg.to_string_lossy().as_bytes());
    }
    for arg in args {
        body.push(0);
        body.extend_from_slice(arg.to_string_lossy().as_bytes());
    }
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        body,
    )
}

pub(super) async fn debug_profile(
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let seconds = query
        .get("seconds")
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(30) as u64;

    // SIGPROF and its timer are process-wide, so only one request may collect
    // a profile at a time. Keep profiler setup and report encoding off the
    // Tokio executor, but let Tokio's timer wait for the sampling interval so
    // the blocking pool does not need to hold a thread for the whole profile.
    let _profile_guard = CPU_PROFILE_LOCK.lock().await;
    let guard = tokio::task::spawn_blocking(|| {
        rpprof::ProfilerGuardBuilder::default()
            .frequency(100)
            .blocklist(&["libc", "libgcc", "pthread", "vdso"])
            .build()
    })
    .await;
    let guard = match guard {
        Ok(Ok(guard)) => guard,
        Ok(Err(error)) => return profile_error(error.to_string()),
        Err(error) => return profile_error(error.to_string()),
    };
    tokio::time::sleep(Duration::from_secs(seconds)).await;
    let profile = tokio::task::spawn_blocking(move || encode_cpu_profile(guard)).await;

    match profile {
        Ok(Ok(body)) => (
            StatusCode::OK,
            [
                ("x-content-type-options", "nosniff"),
                (header::CONTENT_TYPE.as_str(), "application/octet-stream"),
                (
                    header::CONTENT_DISPOSITION.as_str(),
                    "attachment; filename=\"profile\"",
                ),
            ],
            body,
        )
            .into_response(),
        Ok(Err(error)) => profile_error(error),
        Err(error) => profile_error(error.to_string()),
    }
}

fn encode_cpu_profile(guard: rpprof::ProfilerGuard<'static>) -> Result<Vec<u8>, String> {
    use rpprof::protos::Message;

    let report = guard.report().build().map_err(|error| error.to_string())?;
    let profile = report.pprof().map_err(|error| error.to_string())?;
    let mut protobuf = Vec::new();
    profile
        .encode(&mut protobuf)
        .map_err(|error| error.to_string())?;
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(&protobuf)
        .map_err(|error| error.to_string())?;
    gzip.finish().map_err(|error| error.to_string())
}

pub(super) async fn debug_named_profile(
    Path(name): Path<String>,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let supported = [
        "allocs",
        "block",
        "goroutine",
        "heap",
        "mutex",
        "threadcreate",
    ];
    if !supported.contains(&name.as_str()) {
        return named_profile_error(StatusCode::NOT_FOUND, "Unknown profile");
    }
    let debug = query
        .get("debug")
        .and_then(|value| value.parse::<i32>().ok())
        .unwrap_or_default();
    let seconds = match query.get("seconds") {
        None => None,
        Some(value) => match value.parse::<u64>() {
            Ok(seconds) if seconds > 0 => Some(seconds),
            _ => {
                return named_profile_error(
                    StatusCode::BAD_REQUEST,
                    "invalid value for \"seconds\" - must be a positive integer",
                );
            }
        },
    };
    if seconds.is_some() && debug != 0 {
        return named_profile_error(
            StatusCode::BAD_REQUEST,
            "seconds and debug params are incompatible",
        );
    }
    if let Some(seconds) = seconds {
        tokio::time::sleep(Duration::from_secs(seconds)).await;
    }
    let _heap_profile_guard = if name == "heap" || name == "allocs" {
        Some(HEAP_PROFILE_LOCK.lock().await)
    } else {
        None
    };
    if debug != 0 {
        let text = tokio::task::spawn_blocking(move || named_profile_text(&name, debug)).await;
        return match text {
            Ok(text) => (
                StatusCode::OK,
                [
                    ("x-content-type-options", "nosniff"),
                    (header::CONTENT_TYPE.as_str(), "text/plain; charset=utf-8"),
                ],
                text,
            )
                .into_response(),
            Err(error) => profile_error(error.to_string()),
        };
    }
    let disposition_name = name.clone();
    let profile = tokio::task::spawn_blocking(move || named_profile(&name)).await;
    match profile {
        Ok(Ok(body)) => {
            let mut response = (
                StatusCode::OK,
                [
                    ("x-content-type-options", "nosniff"),
                    (header::CONTENT_TYPE.as_str(), "application/octet-stream"),
                ],
                body,
            )
                .into_response();
            if let Ok(value) =
                HeaderValue::from_str(&format!("attachment; filename=\"{disposition_name}\""))
            {
                response
                    .headers_mut()
                    .insert(header::CONTENT_DISPOSITION, value);
            }
            response
        }
        Ok(Err(error)) => profile_error(error),
        Err(error) => profile_error(error.to_string()),
    }
}

fn named_profile(name: &str) -> Result<Vec<u8>, String> {
    use rpprof::protos::Message;

    let profile = match name {
        "heap" | "allocs" => {
            let was_active = rpprof::alloc::is_active();
            if !was_active {
                rpprof::alloc::start();
            }
            // Add a sampled allocation when the endpoint is used outside the
            // production debug-enabled server, such as in tests.
            let sample = vec![0u8; rpprof::alloc::DEFAULT_SAMPLE_RATE * 2];
            std::hint::black_box(&sample);
            rpprof::alloc::stop();
            let report = rpprof::alloc::heap_report().map_err(|error| error.to_string());
            if was_active {
                rpprof::alloc::start();
            }
            drop(sample);
            let report = report?;
            let report = if name == "heap" {
                report.to_inuse_report()
            } else {
                report.to_alloc_report()
            };
            report.pprof().map_err(|error| error.to_string())?
        }
        "goroutine" | "threadcreate" => thread_profile(name),
        "block" | "mutex" => empty_profile(name),
        _ => return Err(format!("unknown profile {name}")),
    };
    let mut protobuf = Vec::new();
    profile
        .encode(&mut protobuf)
        .map_err(|error| error.to_string())?;
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(&protobuf)
        .map_err(|error| error.to_string())?;
    gzip.finish().map_err(|error| error.to_string())
}

fn empty_profile(name: &str) -> rpprof::protos::Profile {
    use rpprof::protos::{Profile, ValueType};
    let (sample_name, sample_unit) = match name {
        "block" => ("contentions", "count"),
        "mutex" => ("contentions", "count"),
        _ => ("samples", "count"),
    };
    Profile {
        sample_type: vec![ValueType { ty: 1, unit: 2 }],
        string_table: vec![String::new(), sample_name.into(), sample_unit.into()],
        time_nanos: unix_time_nanos(),
        ..Default::default()
    }
}

fn thread_profile(name: &str) -> rpprof::protos::Profile {
    use rpprof::protos::{Label, Profile, Sample, ValueType};
    let (sample_name, sample_unit) = if name == "goroutine" {
        ("goroutine", "count")
    } else {
        ("threadcreate", "count")
    };
    let mut profile = Profile {
        sample_type: vec![ValueType { ty: 1, unit: 2 }],
        string_table: vec![
            String::new(),
            sample_name.into(),
            sample_unit.into(),
            "thread_id".into(),
            "threads".into(),
        ],
        time_nanos: unix_time_nanos(),
        ..Default::default()
    };
    for (thread_id, _) in system_threads() {
        profile.sample.push(Sample {
            location_id: Vec::new(),
            value: vec![1],
            label: vec![Label {
                key: 3,
                num: thread_id as i64,
                num_unit: 4,
                ..Default::default()
            }],
        });
    }
    profile
}

fn system_threads() -> Vec<(u64, String)> {
    let Ok(tasks) = std::fs::read_dir("/proc/self/task") else {
        return Vec::new();
    };
    tasks
        .flatten()
        .filter_map(|entry| {
            let id = entry.file_name().to_string_lossy().parse::<u64>().ok()?;
            let name = std::fs::read_to_string(entry.path().join("comm"))
                .unwrap_or_default()
                .trim()
                .to_owned();
            Some((id, name))
        })
        .collect()
}

fn named_profile_text(name: &str, debug: i32) -> String {
    let mut output = format!("profile: {name}\n");
    if name == "heap" || name == "allocs" {
        let was_active = rpprof::alloc::is_active();
        if !was_active {
            rpprof::alloc::start();
        }
        let sample = vec![0u8; rpprof::alloc::DEFAULT_SAMPLE_RATE * 2];
        std::hint::black_box(&sample);
        rpprof::alloc::stop();
        let report = rpprof::alloc::heap_report();
        if was_active {
            rpprof::alloc::start();
        }
        drop(sample);
        match report {
            Ok(report) => output.push_str(&format!(
                "samples: {}\nalloc_bytes: {}\ninuse_bytes: {}\n",
                report.records.len(),
                report.total_alloc_bytes(),
                report.total_inuse_bytes(),
            )),
            Err(error) => output.push_str(&format!("profile error: {error}\n")),
        }
    } else {
        let threads = system_threads();
        output.push_str(&format!("threads: {}\n", threads.len()));
        if debug > 1 {
            for (id, name) in threads {
                output.push_str(&format!("thread {id}: {name}\n"));
            }
        }
    }
    output
}

fn unix_time_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos().min(i64::MAX as u128) as i64)
        .unwrap_or_default()
}

fn named_profile_error(status: StatusCode, message: &str) -> Response {
    (
        status,
        [
            ("x-go-pprof", "1"),
            (header::CONTENT_TYPE.as_str(), "text/plain; charset=utf-8"),
        ],
        format!("{message}\n"),
    )
        .into_response()
}

pub(super) async fn debug_symbol(request: AxumRequest) -> Response {
    let input = if request.method() == axum::http::Method::POST {
        match axum::body::to_bytes(request.into_body(), usize::MAX).await {
            Ok(body) => String::from_utf8_lossy(&body).into_owned(),
            Err(error) => {
                return (
                    StatusCode::BAD_REQUEST,
                    [("x-content-type-options", "nosniff")],
                    format!("reading request: {error}\n"),
                )
                    .into_response();
            }
        }
    } else {
        request.uri().query().unwrap_or_default().to_owned()
    };

    // Match net/http/pprof.Symbol's text protocol. Program counters are
    // separated with '+', and unknown addresses simply have no row.
    let mut body = b"num_symbols: 1\n".to_vec();
    for word in input.split('+') {
        let Some(pc) = parse_symbol_pc(word) else {
            continue;
        };
        if let Some(name) = executable_symbol(pc) {
            body.extend_from_slice(format!("{pc:#x} {name}\n").as_bytes());
        }
    }
    (
        StatusCode::OK,
        [
            ("x-content-type-options", "nosniff"),
            (header::CONTENT_TYPE.as_str(), "text/plain; charset=utf-8"),
        ],
        body,
    )
        .into_response()
}

pub(super) async fn debug_trace(
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let seconds = query
        .get("seconds")
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|seconds| seconds.is_finite() && *seconds > 0.0)
        .unwrap_or(1.0);
    let duration = Duration::from_secs_f64(seconds.min(86_400.0));
    let _profile_guard = match TRACE_PROFILE_LOCK.try_lock() {
        Ok(guard) => guard,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [
                    ("x-content-type-options", "nosniff"),
                    (header::CONTENT_TYPE.as_str(), "text/plain; charset=utf-8"),
                    (
                        header::CONTENT_DISPOSITION.as_str(),
                        "attachment; filename=\"trace\"",
                    ),
                ],
                "Could not enable tracing: another trace is active\n",
            )
                .into_response();
        }
    };
    let Some(capture) = crate::runtime_trace::CaptureGuard::start() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            [
                ("x-content-type-options", "nosniff"),
                (header::CONTENT_TYPE.as_str(), "text/plain; charset=utf-8"),
                (
                    header::CONTENT_DISPOSITION.as_str(),
                    "attachment; filename=\"trace\"",
                ),
            ],
            "Could not enable tracing: another trace is active\n",
        )
            .into_response();
    };
    tokio::time::sleep(duration).await;
    let trace = capture.finish();
    (
        StatusCode::OK,
        [
            ("x-content-type-options", "nosniff"),
            (header::CONTENT_TYPE.as_str(), "application/octet-stream"),
            (
                header::CONTENT_DISPOSITION.as_str(),
                "attachment; filename=\"trace\"",
            ),
        ],
        trace,
    )
        .into_response()
}

fn profile_error(error: String) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        [
            ("x-go-pprof", "1"),
            (header::CONTENT_TYPE.as_str(), "text/plain; charset=utf-8"),
        ],
        format!("Could not enable CPU profiling: {error}\n"),
    )
        .into_response()
}

fn parse_symbol_pc(value: &str) -> Option<u64> {
    let value = value.trim();
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).ok()
    } else if value.len() > 1 && value.starts_with('0') {
        u64::from_str_radix(&value[1..], 8).ok()
    } else {
        value.parse().ok()
    }
}

struct ExecutableSymbol {
    address: u64,
    end: u64,
    name: String,
}

static EXECUTABLE_SYMBOLS: LazyLock<Vec<ExecutableSymbol>> = LazyLock::new(load_executable_symbols);

fn executable_symbol(pc: u64) -> Option<&'static str> {
    let index = EXECUTABLE_SYMBOLS
        .partition_point(|symbol| symbol.address <= pc)
        .checked_sub(1)?;
    let symbol = &EXECUTABLE_SYMBOLS[index];
    (pc < symbol.end).then_some(symbol.name.as_str())
}

fn load_executable_symbols() -> Vec<ExecutableSymbol> {
    use object::{Object, ObjectSymbol};

    let Ok(path) = std::env::current_exe().and_then(std::fs::canonicalize) else {
        return Vec::new();
    };
    let Ok(bytes) = std::fs::read(&path) else {
        return Vec::new();
    };
    let Ok(file) = object::File::parse(bytes.as_slice()) else {
        return Vec::new();
    };
    let Some(load_bias) = executable_load_bias(&file, &path) else {
        return Vec::new();
    };

    let mut symbols = file
        .symbols()
        .chain(file.dynamic_symbols())
        .filter(|symbol| symbol.is_definition() && symbol.kind() == object::SymbolKind::Text)
        .filter_map(|symbol| {
            let raw_name = symbol.name().ok()?;
            if raw_name.is_empty() {
                return None;
            }
            let address = load_bias.checked_add(symbol.address())?;
            let name = rustc_demangle::try_demangle(raw_name)
                .map(|name| name.to_string())
                .unwrap_or_else(|_| raw_name.to_owned());
            Some((address, symbol.size(), name))
        })
        .collect::<Vec<_>>();
    symbols.sort_by_key(|symbol| symbol.0);
    symbols.dedup_by(|right, left| {
        if right.0 == left.0 {
            if left.2.len() < right.2.len() {
                left.2 = right.2.clone();
            }
            true
        } else {
            false
        }
    });

    symbols
        .iter()
        .enumerate()
        .map(|(index, (address, size, name))| {
            let next_address = symbols.get(index + 1).map_or(u64::MAX, |next| next.0);
            let end = if *size > 0 {
                address.saturating_add(*size).min(next_address)
            } else {
                next_address
            };
            ExecutableSymbol {
                address: *address,
                end,
                name: name.clone(),
            }
        })
        .collect()
}

fn executable_load_bias(file: &object::File<'_>, path: &std::path::Path) -> Option<u64> {
    use object::{Object, ObjectSegment};

    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let range = fields.next()?;
        let _permissions = fields.next()?;
        let offset = u64::from_str_radix(fields.next()?, 16).ok()?;
        let _device = fields.next()?;
        let _inode = fields.next()?;
        let mapped_path = fields.collect::<Vec<_>>().join(" ");
        if std::path::Path::new(&mapped_path) != path {
            continue;
        }
        let start = u64::from_str_radix(range.split_once('-')?.0, 16).ok()?;
        for segment in file.segments() {
            let (file_offset, file_size) = segment.file_range();
            if file_offset <= offset && offset < file_offset.saturating_add(file_size) {
                let image_address = segment
                    .address()
                    .checked_add(offset.checked_sub(file_offset)?)?;
                return start.checked_sub(image_address);
            }
        }
    }
    None
}
