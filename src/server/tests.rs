use super::grpc::{GrpcApi, authenticate_grpc, proto_file, store_file_stream};
use super::*;
use crate::worker::{EnvironmentPool, WorkerConfig};
use futures_util::StreamExt;
use std::{fs, io};
use tower::ServiceExt;

#[tokio::test]
async fn grpc_stream_measurement_lives_until_stream_completion() {
    let measurement = GrpcCallMeasurement::start("server_stream", "metric-test");
    let mut stream = InstrumentedGrpcStream::new(
        futures_util::stream::iter(vec![Ok::<_, tonic::Status>(7)]),
        measurement,
    );
    assert!(!stream.measurement.finished);
    assert_eq!(stream.next().await.unwrap().unwrap(), 7);
    assert!(!stream.measurement.finished);
    assert!(stream.next().await.is_none());
    assert!(stream.measurement.finished);
}

struct CancellationProbeProcess(Arc<std::sync::atomic::AtomicBool>);
impl crate::envexec::Process for CancellationProbeProcess {
    fn done(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Acquire)
    }
    fn result(&self) -> crate::runner::ResultInfo {
        crate::runner::ResultInfo {
            status: crate::runner::Status::Signalled,
            exit_status: libc::SIGKILL,
            ..Default::default()
        }
    }
    fn usage(&self) -> crate::envexec::Usage {
        crate::envexec::Usage::default()
    }
    fn cancel(&self) {
        self.0.store(true, std::sync::atomic::Ordering::Release);
    }
}

struct CancellationProbeEnvironment {
    cancelled: Arc<std::sync::atomic::AtomicBool>,
    started: std::sync::mpsc::SyncSender<()>,
}
impl crate::envexec::Environment for CancellationProbeEnvironment {
    fn execve(
        &self,
        _: crate::envexec::ExecveParam,
    ) -> io::Result<Box<dyn crate::envexec::Process>> {
        let _ = self.started.send(());
        Ok(Box::new(CancellationProbeProcess(self.cancelled.clone())))
    }
    fn open(&self, _: &[crate::envexec::OpenParam]) -> io::Result<Vec<crate::envexec::OpenResult>> {
        Ok(vec![])
    }
    fn symlink(&self, _: &[crate::envexec::SymlinkParam]) -> io::Result<Vec<Option<String>>> {
        Ok(vec![])
    }
}

struct CancellationProbePool(Arc<dyn crate::envexec::Environment>);
impl EnvironmentPool for CancellationProbePool {
    fn get(&self) -> io::Result<Arc<dyn crate::envexec::Environment>> {
        Ok(self.0.clone())
    }
    fn put(&self, _: Arc<dyn crate::envexec::Environment>) {}
}

fn cancellation_probe_state() -> (
    ServerState,
    AsyncWorker,
    std::path::PathBuf,
    Arc<std::sync::atomic::AtomicBool>,
    std::sync::mpsc::Receiver<()>,
) {
    let dir = std::env::temp_dir().join(format!(
        "rust-sandbox-cancel-api-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    let store = LocalFileStore::new(&dir);
    let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
    let env: Arc<dyn crate::envexec::Environment> = Arc::new(CancellationProbeEnvironment {
        cancelled: cancelled.clone(),
        started: started_tx,
    });
    let worker = AsyncWorker::new(WorkerConfig::new(
        store.clone(),
        Arc::new(CancellationProbePool(env)),
    ));
    worker.start().unwrap();
    let state = ServerState {
        worker: worker.clone(),
        files: store,
        config: Arc::new(Config::defaults(2, 1)),
        runner_config: json!({}),
        version: "test".into(),
    };
    (state, worker, dir, cancelled, started_rx)
}

#[inline(never)]
fn pprof_test_symbol_marker() {}

#[test]
fn request_cancellation_guard_cancels_only_abandoned_work() {
    let abandoned = CancellationToken::default();
    drop(CancelOnDrop::new(abandoned.clone()));
    assert!(abandoned.is_cancelled());

    let completed = CancellationToken::default();
    let mut guard = CancelOnDrop::new(completed.clone());
    guard.disarm();
    drop(guard);
    assert!(!completed.is_cancelled());
}

fn state() -> (ServerState, std::path::PathBuf) {
    static NEXT_TEST_DIR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "rust-sandbox-api-{}-{}",
        std::process::id(),
        NEXT_TEST_DIR.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = fs::create_dir_all(&dir);
    let store = LocalFileStore::new(&dir);
    struct NoEnvironment;
    impl EnvironmentPool for NoEnvironment {
        fn get(&self) -> io::Result<Arc<dyn crate::envexec::Environment>> {
            Err(io::Error::other("test backend"))
        }
        fn put(&self, _: Arc<dyn crate::envexec::Environment>) {}
    }
    let worker = AsyncWorker::new(WorkerConfig::new(store.clone(), Arc::new(NoEnvironment)));
    (
        ServerState {
            worker,
            files: store,
            config: Arc::new(Config::defaults(2, 1)),
            runner_config: json!({}),
            version: "test".into(),
        },
        dir,
    )
}

#[tokio::test]
async fn http_metrics_record_route_status_latency_and_sizes() {
    let (mut state, dir) = state();
    let mut config = (*state.config).clone();
    config.enable_metrics = true;
    state.config = Arc::new(config);
    let response = http_router(state)
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/version")
                .header(header::HOST, "metrics.test")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut metrics = String::new();
    append_http_metrics(&mut metrics);
    assert!(metrics.contains("gin_requests_total"));
    assert!(metrics.contains("url=\"/version\""));
    assert!(metrics.contains("gin_request_duration_seconds_count"));
    assert!(metrics.contains("gin_request_size_bytes_count "));
    assert!(metrics.contains("gin_response_size_bytes_count "));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn grpc_metrics_record_started_handled_code_and_latency() {
    let metrics_were_enabled = crate::runtime_metrics::is_enabled();
    crate::runtime_metrics::set_enabled(true);
    let mut measurement = GrpcCallMeasurement::start("unary", "MetricsUnitTest");
    measurement.finish(tonic::Code::ResourceExhausted);

    let mut metrics = String::new();
    append_grpc_metrics(&mut metrics);
    assert!(metrics.contains(
            "grpc_server_started_total{grpc_method=\"MetricsUnitTest\",grpc_service=\"pb.Executor\",grpc_type=\"unary\"} 1"
        ));
    assert!(metrics.contains(
            "grpc_server_handled_total{grpc_code=\"ResourceExhausted\",grpc_method=\"MetricsUnitTest\",grpc_service=\"pb.Executor\",grpc_type=\"unary\"} 1"
        ));
    assert!(metrics.contains(
            "grpc_server_handling_seconds_count{grpc_method=\"MetricsUnitTest\",grpc_service=\"pb.Executor\",grpc_type=\"unary\"} 1"
        ));
    crate::runtime_metrics::set_enabled(metrics_were_enabled);
}

#[tokio::test]
async fn monitor_routes_follow_metrics_and_debug_flags() {
    let (mut state, dir) = state();
    let disabled = monitor_router(state.clone());
    for uri in [
        "/metrics",
        "/debug/pprof/",
        "/debug/pprof/cmdline",
        "/debug/pprof/profile",
        "/debug/pprof/symbol",
        "/debug/pprof/trace",
        "/debug/pprof/heap",
        "/debug/pprof/goroutine",
    ] {
        let response = disabled
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri(uri)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
    }

    let mut config = (*state.config).clone();
    config.enable_metrics = true;
    config.enable_debug = true;
    state.config = Arc::new(config);
    let enabled = monitor_router(state);
    let metrics = enabled
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/metrics")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(metrics.status(), StatusCode::OK);
    assert!(
        metrics.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/plain")
    );
    let metrics = axum::body::to_bytes(metrics.into_body(), usize::MAX)
        .await
        .unwrap();
    let metrics = String::from_utf8(metrics.to_vec()).unwrap();
    assert!(metrics.contains("go_judge_worker_queue_count"));
    assert!(metrics.contains("go_judge_file_size_bytes_bucket"));
    assert!(metrics.contains("go_judge_environment_count"));
    assert!(metrics.contains("go_judge_environment_current_count"));
    assert!(metrics.contains("gin_requests_total"));
    assert!(metrics.contains("gin_request_duration_seconds"));
    assert!(metrics.contains("grpc_server_started_total"));
    assert!(metrics.contains("grpc_server_handled_total"));
    assert!(metrics.contains("grpc_server_handling_seconds"));

    let debug = enabled
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/debug/pprof/")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(debug.status(), StatusCode::OK);
    let debug = axum::body::to_bytes(debug.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(
        String::from_utf8(debug.to_vec())
            .unwrap()
            .contains("href='profile?debug=1'")
    );
    let index = String::from_utf8(debug.to_vec()).unwrap();
    for entry in [
        "/debug/pprof/",
        "allocs",
        "block",
        "cmdline",
        "goroutine",
        "heap",
        "mutex",
        "profile",
        "symbol",
        "threadcreate",
        "trace",
    ] {
        assert!(index.contains(entry), "missing pprof index entry {entry}");
    }

    for name in [
        "allocs",
        "block",
        "goroutine",
        "heap",
        "mutex",
        "threadcreate",
    ] {
        let response = enabled
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri(format!("/debug/pprof/{name}?debug=1"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{name}");
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/plain; charset=utf-8"
        );
    }
    let unknown = enabled
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/debug/pprof/not-a-profile")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);

    let heap = enabled
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/debug/pprof/heap")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(heap.status(), StatusCode::OK);
    assert_eq!(
        heap.headers()[header::CONTENT_TYPE],
        "application/octet-stream"
    );
    assert_eq!(
        heap.headers()[header::CONTENT_DISPOSITION],
        "attachment; filename=\"heap\""
    );
    let compressed = axum::body::to_bytes(heap.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(compressed.starts_with(&[0x1f, 0x8b]));
    let mut decoded_heap = Vec::new();
    flate2::read::GzDecoder::new(compressed.as_ref())
        .read_to_end(&mut decoded_heap)
        .unwrap();
    let heap_profile = rpprof::protos::Profile::decode(decoded_heap.as_slice()).unwrap();
    assert!(!heap_profile.sample_type.is_empty());

    let cmdline = enabled
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/debug/pprof/cmdline")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cmdline.status(), StatusCode::OK);
    let cmdline = axum::body::to_bytes(cmdline.into_body(), usize::MAX)
        .await
        .unwrap();
    let expected = std::env::args_os()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("\0");
    assert_eq!(cmdline.as_ref(), expected.as_bytes());

    let profile = enabled
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/debug/pprof/profile?seconds=1")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(profile.status(), StatusCode::OK);
    assert_eq!(
        profile.headers()[header::CONTENT_TYPE],
        "application/octet-stream"
    );
    let compressed = axum::body::to_bytes(profile.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(compressed.starts_with(&[0x1f, 0x8b]));
    let mut decoded = Vec::new();
    flate2::read::GzDecoder::new(compressed.as_ref())
        .read_to_end(&mut decoded)
        .unwrap();
    use rpprof::protos::Message;
    let profile = rpprof::protos::Profile::decode(decoded.as_slice()).unwrap();
    assert_eq!(profile.sample_type.len(), 2);

    let symbol_pc = pprof_test_symbol_marker as *const () as usize;
    let symbol = enabled
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri(format!("/debug/pprof/symbol?{symbol_pc:#x}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(symbol.status(), StatusCode::OK);
    let symbol = axum::body::to_bytes(symbol.into_body(), usize::MAX)
        .await
        .unwrap();
    let symbol = String::from_utf8(symbol.to_vec()).unwrap();
    assert!(symbol.starts_with("num_symbols: 1\n"));
    assert!(symbol.contains("pprof_test_symbol_marker"), "{symbol}");

    let symbol = enabled
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method(axum::http::Method::POST)
                .uri("/debug/pprof/symbol")
                .body(axum::body::Body::from(format!("{symbol_pc:#x}")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(symbol.status(), StatusCode::OK);
    let symbol = axum::body::to_bytes(symbol.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(
        String::from_utf8(symbol.to_vec())
            .unwrap()
            .contains("pprof_test_symbol_marker")
    );

    let trace = enabled
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/debug/pprof/trace?seconds=0.001")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(trace.status(), StatusCode::OK);
    assert_eq!(
        trace.headers()[header::CONTENT_TYPE],
        "application/octet-stream"
    );
    assert_eq!(
        trace.headers()[header::CONTENT_DISPOSITION],
        "attachment; filename=\"trace\""
    );
    let trace = axum::body::to_bytes(trace.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(trace.starts_with(b"go 1.26 trace\0\0\0"));

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn execution_metrics_observe_error_time_and_memory() {
    let response = crate::worker::Response {
        error: Some("failed to prepare command".into()),
        results: vec![crate::worker::ResultInfo {
            status: crate::worker::JudgeStatus::Accepted,
            time: Duration::from_millis(12),
            memory: Size(8192),
            ..Default::default()
        }],
        ..Default::default()
    };
    observe_execution(&response);
    let mut text = String::new();
    append_execution_metrics(&mut text);
    assert!(text.contains("go_judge_exec_error_count "));
    assert!(text.contains("go_judge_exec_time_seconds_bucket{status=\"Accepted\",le=\"0.025\"} 1"));
    assert!(text.contains("go_judge_exec_time_seconds_count{status=\"Accepted\"} 1"));
    assert!(text.contains("go_judge_exec_memory_bytes_bucket{status=\"Accepted\",le=\"8192\"} 1"));
    assert!(text.contains("go_judge_exec_memory_bytes_sum{status=\"Accepted\"} 8192"));
}

#[tokio::test]
async fn version_and_file_routes_follow_contract() {
    let (s, dir) = state();
    let app = http_router(s);
    let r = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/version")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body = axum::body::to_bytes(r.into_body(), usize::MAX)
        .await
        .unwrap();
    let version: Value = serde_json::from_slice(&body).unwrap();
    assert!(version["buildVersion"].is_string());
    assert_eq!(version["goVersion"], env!("RUSTC_VERSION"));
    assert!(version["copyOutOptional"].as_bool().unwrap());
    assert!(version["platform"].is_string());
    let r = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/config")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body = axum::body::to_bytes(r.into_body(), usize::MAX)
        .await
        .unwrap();
    let config: Value = serde_json::from_slice(&body).unwrap();
    assert!(config["runnerConfig"].is_object());
    assert_eq!(config["fileStorePath"], "");
    assert!(config.get("authToken").is_none());

    let r = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/file/missing")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    let _ = fs::remove_dir_all(dir);
}

#[tokio::test]
async fn http_auth_matches_go_public_metadata_routes() {
    let (mut state, dir) = state();
    let mut config = (*state.config).clone();
    config.auth_token = "secret".into();
    state.config = Arc::new(config);
    let app = http_router(state);

    for uri in ["/version", "/config"] {
        let response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri(uri)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    for authorization in [None, Some("Bearer wrong")] {
        let mut request = axum::http::Request::builder().uri("/run");
        if let Some(value) = authorization {
            request = request.header(header::AUTHORIZATION, value);
        }
        let response = app
            .clone()
            .oneshot(request.body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/run")
                .header(header::AUTHORIZATION, "Bearer secret")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(response.status(), StatusCode::UNAUTHORIZED);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn grpc_auth_requires_the_configured_bearer_token() {
    let missing = authenticate_grpc(tonic::Request::new(()), "secret").unwrap_err();
    assert_eq!(missing.code(), tonic::Code::Unauthenticated);

    let mut request = tonic::Request::new(());
    request
        .metadata_mut()
        .insert("authorization", "Bearer wrong".parse().unwrap());
    assert_eq!(
        authenticate_grpc(request, "secret").unwrap_err().code(),
        tonic::Code::Unauthenticated
    );

    let mut request = tonic::Request::new(());
    request
        .metadata_mut()
        .insert("authorization", "Bearer secret".parse().unwrap());
    assert!(authenticate_grpc(request, "secret").is_ok());
}

#[tokio::test]
async fn grpc_file_add_get_and_delete_follow_contract() {
    use grpc_proto::executor_server::Executor;
    let (state, dir) = state();
    let api = GrpcApi(state);
    let id = api
        .file_add(tonic::Request::new(grpc_proto::FileContent {
            name: "payload.txt".into(),
            content: b"hello".to_vec(),
        }))
        .await
        .unwrap()
        .into_inner();
    let file = api
        .file_get(tonic::Request::new(grpc_proto::FileId {
            file_id: id.file_id.clone(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(file.name, "payload.txt");
    assert_eq!(file.content, b"hello");
    api.file_delete(tonic::Request::new(id.clone()))
        .await
        .unwrap();
    let missing = api
        .file_get(tonic::Request::new(id.clone()))
        .await
        .unwrap_err();
    assert_eq!(missing.code(), tonic::Code::NotFound);
    assert_eq!(
        missing.message(),
        format!("file not found: {:?}", id.file_id)
    );
    let missing_delete = api
        .file_delete(tonic::Request::new(id.clone()))
        .await
        .unwrap_err();
    assert_eq!(missing_delete.code(), tonic::Code::NotFound);
    assert_eq!(
        missing_delete.message(),
        format!("file id does not exist: {:?}", id.file_id)
    );
    let _ = fs::remove_dir_all(dir);
}

#[tokio::test]
async fn grpc_exec_maps_worker_rejection_to_internal_status() {
    use grpc_proto::executor_server::Executor;
    let (state, dir) = state();
    let api = GrpcApi(state);
    let error = api
        .exec(tonic::Request::new(grpc_proto::Request {
            cmd: vec![grpc_proto::request::CmdType {
                args: vec!["/bin/true".into()],
                ..Default::default()
            }],
            ..Default::default()
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::Internal);
    assert_eq!(error.message(), "worker is not started");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn worker_file_not_found_errors_preserve_http_and_grpc_statuses() {
    let error = "file does not exist with id \"cached-id\"";
    assert_eq!(worker_http_error_status(error), StatusCode::NOT_FOUND);
    assert_eq!(
        worker_grpc_error_status(error).code(),
        tonic::Code::NotFound
    );

    let other = "worker is not started";
    assert_eq!(
        worker_http_error_status(other),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        worker_grpc_error_status(other).code(),
        tonic::Code::Internal
    );
}

#[tokio::test]
async fn grpc_file_streams_keep_metadata_on_first_chunk_and_validate_upload_name() {
    use futures_util::StreamExt;
    use grpc_proto::executor_server::Executor;
    let (state, dir) = state();
    let api = GrpcApi(state.clone());
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tx.send(Ok(grpc_proto::FileContent {
        name: "stream.txt".into(),
        content: b"hello ".to_vec(),
    }))
    .await
    .unwrap();
    tx.send(Ok(grpc_proto::FileContent {
        name: String::new(),
        content: b"world".to_vec(),
    }))
    .await
    .unwrap();
    drop(tx);
    let id = store_file_stream(
        &state.files,
        tokio_stream::wrappers::ReceiverStream::new(rx),
    )
    .await
    .unwrap();

    let mut stream = api
        .file_get_stream(tonic::Request::new(id.clone()))
        .await
        .unwrap()
        .into_inner();
    let mut name = String::new();
    let mut content = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.unwrap();
        if !chunk.name.is_empty() {
            assert!(name.is_empty(), "name repeated after first chunk");
            name = chunk.name;
        }
        content.extend(chunk.content);
    }
    assert_eq!(name, "stream.txt");
    assert_eq!(content, b"hello world");

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<grpc_proto::FileContent, tonic::Status>>(1);
    drop(tx);
    let empty = store_file_stream(
        &state.files,
        tokio_stream::wrappers::ReceiverStream::new(rx),
    )
    .await
    .unwrap_err();
    assert_eq!(empty.code(), tonic::Code::InvalidArgument);
    assert_eq!(empty.message(), "file upload stream is empty");

    let (tx, rx) = tokio::sync::mpsc::channel(2);
    tx.send(Ok(grpc_proto::FileContent {
        name: "first.txt".into(),
        content: b"x".to_vec(),
    }))
    .await
    .unwrap();
    tx.send(Ok(grpc_proto::FileContent {
        name: "changed.txt".into(),
        content: b"y".to_vec(),
    }))
    .await
    .unwrap();
    drop(tx);
    let error = store_file_stream(
        &state.files,
        tokio_stream::wrappers::ReceiverStream::new(rx),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    assert_eq!(state.files.list().unwrap().len(), 1);
    assert!(state.files.get(&id.file_id).is_some());
    let _ = fs::remove_dir_all(dir);
}

#[tokio::test]
async fn grpc_exec_stream_accepts_exec_request_and_returns_final_response() {
    let (state, dir) = state();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let server_state = state.clone();
    let server = tokio::spawn(async move { serve_grpc(address, server_state).await });
    let mut client = loop {
        match grpc_proto::executor_client::ExecutorClient::connect(format!("http://{address}"))
            .await
        {
            Ok(client) => break client,
            Err(_) => tokio::task::yield_now().await,
        }
    };
    let request = grpc_proto::StreamRequest {
        request: Some(grpc_proto::stream_request::Request::ExecRequest(
            grpc_proto::Request {
                request_id: "stream-test".into(),
                cmd: vec![grpc_proto::request::CmdType {
                    args: vec!["/bin/true".into()],
                    ..Default::default()
                }],
                ..Default::default()
            },
        )),
    };
    let mut response = client
        .exec_stream(tokio_stream::iter([request]))
        .await
        .unwrap()
        .into_inner();
    let final_message = response.message().await.unwrap().unwrap();
    assert!(matches!(
        final_message.response,
        Some(grpc_proto::stream_response::Response::ExecResponse(_))
    ));
    assert!(response.message().await.unwrap().is_none());
    server.abort();
    let _ = fs::remove_dir_all(dir);
}

#[tokio::test]
async fn grpc_exec_stream_uses_go_internal_status_for_invalid_first_message() {
    let (state, dir) = state();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let server = tokio::spawn(async move { serve_grpc(address, state).await });
    let mut client = loop {
        match grpc_proto::executor_client::ExecutorClient::connect(format!("http://{address}"))
            .await
        {
            Ok(client) => break client,
            Err(_) => tokio::task::yield_now().await,
        }
    };

    let empty = client
        .exec_stream(tokio_stream::iter(Vec::<grpc_proto::StreamRequest>::new()))
        .await
        .unwrap_err();
    assert_eq!(empty.code(), tonic::Code::Internal);

    let wrong_first_message = grpc_proto::StreamRequest {
        request: Some(grpc_proto::stream_request::Request::ExecCancel(())),
    };
    let error = client
        .exec_stream(tokio_stream::iter([wrong_first_message]))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::Internal);

    server.abort();
    let _ = fs::remove_dir_all(dir);
}

#[tokio::test]
async fn grpc_exec_stream_rejects_missing_input_and_cancels_execution() {
    use std::sync::atomic::{AtomicBool, Ordering};

    struct RunningProcess(Arc<AtomicBool>);
    impl crate::envexec::Process for RunningProcess {
        fn done(&self) -> bool {
            self.0.load(Ordering::Acquire)
        }
        fn result(&self) -> crate::runner::ResultInfo {
            crate::runner::ResultInfo {
                status: crate::runner::Status::Normal,
                ..Default::default()
            }
        }
        fn usage(&self) -> crate::envexec::Usage {
            Default::default()
        }
        fn cancel(&self) {
            self.0.store(true, Ordering::Release);
        }
    }
    struct RunningEnvironment {
        started: Arc<AtomicBool>,
        cancelled: Arc<AtomicBool>,
    }
    impl crate::envexec::Environment for RunningEnvironment {
        fn execve(
            &self,
            _: crate::envexec::ExecveParam,
        ) -> io::Result<Box<dyn crate::envexec::Process>> {
            self.started.store(true, Ordering::Release);
            Ok(Box::new(RunningProcess(self.cancelled.clone())))
        }
        fn open(
            &self,
            params: &[crate::envexec::OpenParam],
        ) -> io::Result<Vec<crate::envexec::OpenResult>> {
            Ok(params
                .iter()
                .map(|_| crate::envexec::OpenResult {
                    file: None,
                    error: None,
                })
                .collect())
        }
        fn symlink(
            &self,
            params: &[crate::envexec::SymlinkParam],
        ) -> io::Result<Vec<Option<String>>> {
            Ok(vec![None; params.len()])
        }
    }
    struct RunningPool(Arc<RunningEnvironment>);
    impl EnvironmentPool for RunningPool {
        fn get(&self) -> io::Result<Arc<dyn crate::envexec::Environment>> {
            Ok(self.0.clone())
        }
        fn put(&self, _: Arc<dyn crate::envexec::Environment>) {}
    }

    let dir = std::env::temp_dir().join(format!(
        "rust-sandbox-stream-invalid-input-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let files = LocalFileStore::new(&dir);
    let started = Arc::new(AtomicBool::new(false));
    let cancelled = Arc::new(AtomicBool::new(false));
    let worker = AsyncWorker::new(WorkerConfig::new(
        files.clone(),
        Arc::new(RunningPool(Arc::new(RunningEnvironment {
            started: started.clone(),
            cancelled: cancelled.clone(),
        }))),
    ));
    worker.start().unwrap();
    let state = ServerState {
        worker,
        files,
        config: Arc::new(Config::defaults(2, 1)),
        runner_config: json!({}),
        version: "test".into(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let server = tokio::spawn(async move { serve_grpc(address, state).await });
    let mut client = loop {
        match grpc_proto::executor_client::ExecutorClient::connect(format!("http://{address}"))
            .await
        {
            Ok(client) => break client,
            Err(_) => tokio::task::yield_now().await,
        }
    };
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tx.send(grpc_proto::StreamRequest {
        request: Some(grpc_proto::stream_request::Request::ExecRequest(
            grpc_proto::Request {
                cmd: vec![grpc_proto::request::CmdType {
                    files: vec![grpc_proto::request::File {
                        file: Some(grpc_proto::request::file::File::StreamIn(())),
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            },
        )),
    })
    .await
    .unwrap();
    let mut response = client
        .exec_stream(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !started.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    tx.send(grpc_proto::StreamRequest {
        request: Some(grpc_proto::stream_request::Request::ExecInput(
            grpc_proto::stream_request::Input {
                index: 0,
                fd: 3,
                content: b"unexpected".to_vec(),
            },
        )),
    })
    .await
    .unwrap();
    let error = tokio::time::timeout(Duration::from_secs(2), response.message())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::Internal);
    tokio::time::timeout(Duration::from_secs(2), async {
        while !cancelled.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    server.abort();
    let _ = fs::remove_dir_all(dir);
}

#[tokio::test]
async fn grpc_exec_stream_resize_reaches_running_pty() {
    use std::os::fd::RawFd;
    struct ResizeEnv(Arc<std::sync::atomic::AtomicBool>);
    struct Finished;
    impl crate::envexec::Process for Finished {
        fn done(&self) -> bool {
            true
        }
        fn result(&self) -> crate::runner::ResultInfo {
            crate::runner::ResultInfo {
                status: crate::runner::Status::Normal,
                ..Default::default()
            }
        }
        fn usage(&self) -> crate::envexec::Usage {
            Default::default()
        }
        fn cancel(&self) {}
    }
    impl crate::envexec::Environment for ResizeEnv {
        fn execve(
            &self,
            param: crate::envexec::ExecveParam,
        ) -> io::Result<Box<dyn crate::envexec::Process>> {
            let fd = *param
                .files
                .first()
                .ok_or_else(|| io::Error::other("missing pty fd"))? as RawFd;
            for _ in 0..100 {
                let mut size = unsafe { std::mem::zeroed::<libc::winsize>() };
                if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut size) } == 0
                    && size.ws_row == 43
                    && size.ws_col == 121
                {
                    self.0.store(true, std::sync::atomic::Ordering::Release);
                    return Ok(Box::new(Finished));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(io::Error::other("PTY resize was not applied before exec"))
        }
        fn open(
            &self,
            params: &[crate::envexec::OpenParam],
        ) -> io::Result<Vec<crate::envexec::OpenResult>> {
            Ok(params
                .iter()
                .map(|_| crate::envexec::OpenResult {
                    file: None,
                    error: None,
                })
                .collect())
        }
        fn symlink(
            &self,
            params: &[crate::envexec::SymlinkParam],
        ) -> io::Result<Vec<Option<String>>> {
            Ok(vec![None; params.len()])
        }
    }
    struct Pool(Arc<ResizeEnv>);
    impl EnvironmentPool for Pool {
        fn get(&self) -> io::Result<Arc<dyn crate::envexec::Environment>> {
            Ok(self.0.clone())
        }
        fn put(&self, _: Arc<dyn crate::envexec::Environment>) {}
    }

    let dir = std::env::temp_dir().join(format!("rust-sandbox-resize-grpc-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let files = LocalFileStore::new(&dir);
    let observed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let worker = AsyncWorker::new(WorkerConfig::new(
        files.clone(),
        Arc::new(Pool(Arc::new(ResizeEnv(observed.clone())))),
    ));
    worker.start().unwrap();
    let state = ServerState {
        worker,
        files,
        config: Arc::new(Config::defaults(2, 1)),
        runner_config: json!({}),
        version: "test".into(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let server = tokio::spawn(async move { serve_grpc(address, state).await });
    let mut client = loop {
        match grpc_proto::executor_client::ExecutorClient::connect(format!("http://{address}"))
            .await
        {
            Ok(client) => break client,
            Err(_) => tokio::task::yield_now().await,
        }
    };
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tx.send(grpc_proto::StreamRequest {
        request: Some(grpc_proto::stream_request::Request::ExecRequest(
            grpc_proto::Request {
                cmd: vec![grpc_proto::request::CmdType {
                    tty: true,
                    files: vec![
                        grpc_proto::request::File {
                            file: Some(grpc_proto::request::file::File::StreamIn(())),
                        },
                        grpc_proto::request::File {
                            file: Some(grpc_proto::request::file::File::StreamOut(())),
                        },
                        grpc_proto::request::File {
                            file: Some(grpc_proto::request::file::File::StreamOut(())),
                        },
                    ],
                    ..Default::default()
                }],
                ..Default::default()
            },
        )),
    })
    .await
    .unwrap();
    tx.send(grpc_proto::StreamRequest {
        request: Some(grpc_proto::stream_request::Request::ExecResize(
            grpc_proto::stream_request::Resize {
                index: 0,
                fd: 0,
                rows: 43,
                cols: 121,
                x: 960,
                y: 720,
            },
        )),
    })
    .await
    .unwrap();
    drop(tx);
    let mut response = client
        .exec_stream(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    loop {
        let Some(message) = response.message().await.unwrap() else {
            break;
        };
        if let Some(grpc_proto::stream_response::Response::ExecResponse(result)) = message.response
        {
            assert!(
                result
                    .results
                    .first()
                    .is_some_and(|r| r.status == crate::envexec::Status::Accepted as i32),
                "{result:?}"
            );
            break;
        }
    }
    assert!(
        observed.load(std::sync::atomic::Ordering::Acquire),
        "resize was not observed by environment"
    );
    server.abort();
    let _ = fs::remove_dir_all(dir);
}

#[tokio::test]
async fn websocket_run_and_stream_use_go_message_framing() {
    use futures_util::{SinkExt, StreamExt};
    let (state, dir) = state();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, http_router(state)).await });
    let (mut run, _) = tokio_tungstenite::connect_async(format!("ws://{address}/ws"))
        .await
        .unwrap();
    run.send(tokio_tungstenite::tungstenite::Message::Text(
        json!({"requestId":"ws-test","cmd":[{"args":["/bin/true"]}]})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let run_message = run.next().await.unwrap().unwrap().into_text().unwrap();
    let run_response: Value = serde_json::from_str(&run_message).unwrap();
    assert_eq!(run_response["requestId"], "ws-test");

    let (mut stream, _) = tokio_tungstenite::connect_async(format!("ws://{address}/stream"))
        .await
        .unwrap();
    let request = json!({"requestId":"stream-ws-test","cmd":[{"args":["/bin/true"]}]});
    let mut frame = vec![1];
    frame.extend(serde_json::to_vec(&request).unwrap());
    stream
        .send(tokio_tungstenite::tungstenite::Message::Binary(
            frame.into(),
        ))
        .await
        .unwrap();
    let response = stream.next().await.unwrap().unwrap().into_data();
    assert_eq!(response[0], 1);
    let response: Value = serde_json::from_slice(&response[1..]).unwrap();
    assert_eq!(response["requestId"], "stream-ws-test");
    server.abort();
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn rest_run_response_is_top_level_result_array() {
    let response = crate::worker::Response {
        request_id: "req".into(),
        results: vec![],
        error: None,
    };
    assert_eq!(response_results(response), Vec::<Value>::new());
    let response = crate::worker::Response {
        request_id: "req".into(),
        results: vec![],
        error: None,
    };
    let websocket = response_json(response);
    assert_eq!(websocket["requestId"], "req");
    assert!(websocket.get("error").is_none());
}

#[test]
fn grpc_stream_final_response_drops_worker_top_level_error_like_go() {
    let response = grpc_response(crate::worker::Response {
        request_id: "stream-id".into(),
        error: Some("worker is not available".into()),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(response.request_id, "stream-id");
    assert!(response.error.is_empty());
    assert!(response.results.is_empty());
}

#[test]
fn grpc_response_maps_copy_in_directory_error_to_go_proto_enum() {
    let response = grpc_response(crate::worker::Response {
        results: vec![crate::worker::ResultInfo {
            file_errors: vec![crate::envexec::FileError {
                name: "dir/file".into(),
                kind: crate::envexec::FileErrorType::CopyInCreateDir,
                message: "permission denied".into(),
            }],
            ..Default::default()
        }],
        ..Default::default()
    })
    .unwrap();
    assert_eq!(response.results[0].file_error[0].r#type, 2);
}

#[tokio::test]
async fn rest_run_maps_worker_rejection_to_http_500() {
    let (state, dir) = state();
    let response = http_router(state)
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/run")
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    r#"{"cmd":[{"args":["/bin/true"]}]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap(),
        "worker is not started"
    );
    let _ = fs::remove_dir_all(dir);
}

async fn wait_for_probe_cancellation(cancelled: &std::sync::atomic::AtomicBool) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !cancelled.load(std::sync::atomic::Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("worker did not cancel the abandoned request");
}

#[tokio::test]
async fn rest_run_cancels_work_when_handler_is_dropped() {
    let (state, worker, dir, cancelled, started) = cancellation_probe_state();
    let task = tokio::spawn(
        http_router(state).oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/run")
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(r#"{"cmd":[{"args":["probe"]}]}"#))
                .unwrap(),
        ),
    );
    tokio::task::spawn_blocking(move || started.recv_timeout(Duration::from_secs(2)))
        .await
        .unwrap()
        .expect("worker did not start request");
    task.abort();
    wait_for_probe_cancellation(&cancelled).await;
    worker.shutdown();
    let _ = fs::remove_dir_all(dir);
}

#[tokio::test]
async fn grpc_exec_cancels_work_when_rpc_future_is_dropped() {
    let (state, worker, dir, cancelled, started) = cancellation_probe_state();
    let api = GrpcApi(state);
    let request = grpc_proto::Request {
        cmd: vec![grpc_proto::request::CmdType {
            args: vec!["probe".into()],
            ..Default::default()
        }],
        ..Default::default()
    };
    let task = tokio::spawn(async move {
        grpc_proto::executor_server::Executor::exec(&api, tonic::Request::new(request)).await
    });
    tokio::task::spawn_blocking(move || started.recv_timeout(Duration::from_secs(2)))
        .await
        .unwrap()
        .expect("worker did not start request");
    task.abort();
    wait_for_probe_cancellation(&cancelled).await;
    worker.shutdown();
    let _ = fs::remove_dir_all(dir);
}

#[tokio::test]
async fn websocket_stream_resize_rejects_an_unmapped_input_fd() {
    use futures_util::{SinkExt, StreamExt};

    let (state, worker, dir, cancelled, started) = cancellation_probe_state();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, http_router(state)).await });
    let (mut stream, _) = tokio_tungstenite::connect_async(format!("ws://{address}/stream"))
        .await
        .unwrap();
    let request = json!({
        "requestId": "resize-invalid-fd",
        "cmd": [{"args": ["probe"], "tty": true, "files": [{"streamIn": true}] }]
    });
    let mut frame = vec![1];
    frame.extend(serde_json::to_vec(&request).unwrap());
    stream
        .send(tokio_tungstenite::tungstenite::Message::Binary(
            frame.into(),
        ))
        .await
        .unwrap();
    tokio::task::spawn_blocking(move || started.recv_timeout(Duration::from_secs(2)))
        .await
        .unwrap()
        .expect("worker did not start request");
    let mut resize = vec![2];
    resize.extend(
        serde_json::to_vec(&json!({
            "index": 0,
            "fd": 1,
            "rows": 24,
            "cols": 80
        }))
        .unwrap(),
    );
    stream
        .send(tokio_tungstenite::tungstenite::Message::Binary(
            resize.into(),
        ))
        .await
        .unwrap();

    wait_for_probe_cancellation(&cancelled).await;
    let after_invalid_resize = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .expect("websocket did not close after invalid resize");
    assert!(!matches!(
        after_invalid_resize,
        Some(Ok(tokio_tungstenite::tungstenite::Message::Binary(bytes)))
            if bytes.first() == Some(&1)
    ));
    worker.shutdown();
    server.abort();
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn rest_response_output_bytes_are_plain_utf8_strings() {
    let dir = std::env::temp_dir().join(format!("rust-sandbox-rest-output-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("stdout");
    fs::write(&path, b"hello\n").unwrap();
    let response = crate::worker::Response {
        results: vec![crate::worker::ResultInfo {
            files: std::collections::HashMap::from([(
                "stdout".into(),
                fs::File::open(&path).unwrap(),
            )]),
            ..Default::default()
        }],
        ..Default::default()
    };
    let result = response_results(response);
    assert_eq!(result[0]["files"]["stdout"], "hello\n");
    assert!(result[0].get("error").is_none());
    assert!(result[0].get("fileIds").is_none());
    assert!(result[0].get("fileError").is_none());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rest_file_error_uses_go_integer_type_and_omits_empty_message() {
    let response = crate::worker::Response {
        results: vec![crate::worker::ResultInfo {
            file_errors: vec![
                crate::envexec::FileError {
                    name: "input".into(),
                    kind: crate::envexec::FileErrorType::CopyInOpenFile,
                    message: String::new(),
                },
                crate::envexec::FileError {
                    name: "output".into(),
                    kind: crate::envexec::FileErrorType::CopyOutSizeExceeded,
                    message: "limit exceeded".into(),
                },
            ],
            ..Default::default()
        }],
        ..Default::default()
    };

    let result = response_results(response);
    assert_eq!(result[0]["fileError"][0]["type"], 0);
    assert!(result[0]["fileError"][0].get("message").is_none());
    assert_eq!(result[0]["fileError"][1]["type"], 6);
    assert_eq!(result[0]["fileError"][1]["message"], "limit exceeded");
}

#[test]
fn json_collector_requires_name_and_max_and_casts_signed_max_like_go() {
    let (state, dir) = state();
    let missing_max = convert_cmd_file(&json!({"name":"collector"}), &state);
    assert!(missing_max.is_err());

    let collector = convert_cmd_file(&json!({"name":"collector","max":-1}), &state).unwrap();
    assert!(matches!(
        collector,
        CmdFile::Collector { name, max: Size(u64::MAX), pipe: false } if name == "collector"
    ));

    let request = convert_json_request(
        &json!({
            "cmd": [{"args":["/bin/cat"], "files":[{"name":"collector","max":-1}]}],
            "pipeMapping": [{"in":{"index":0,"fd":1},"out":{"index":1,"fd":0},"max":-2}]
        }),
        &state,
    )
    .unwrap();
    assert_eq!(request.pipe_mapping[0].limit, Size((-2i64) as u64));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn stream_json_request_maps_live_stream_descriptors() {
    let (state, dir) = state();
    let (output_tx, _output_rx) = tokio::sync::mpsc::channel(32);
    let value = json!({
        "requestId":"interactive",
        "cmd":[{"args":["/bin/cat"],"tty":true,"files":[{"streamIn":true},{"streamOut":true}]}]
    });
    let (request, inputs, resizes) =
        convert_json_request_with_stream(&value, &state, Some(output_tx)).unwrap();
    assert!(inputs.contains_key(&(0, 0)));
    assert!(matches!(request.commands[0].files[0], CmdFile::StreamIn(_)));
    assert!(matches!(
        request.commands[0].files[1],
        CmdFile::StreamOut {
            index: 0,
            fd: 1,
            ..
        }
    ));
    let size = crate::worker::TerminalSize {
        rows: 41,
        cols: 120,
        x: 900,
        y: 700,
    };
    resizes[&0].send(size).unwrap();
    assert_eq!(
        request.commands[0]
            .terminal_resize
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .try_recv()
            .unwrap(),
        size
    );
    drop(request);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn json_request_accepts_null_pipe_slots_and_copyin_symlinks() {
    let (state, dir) = state();
    let value = json!({
        "cmd": [{
            "args": ["/bin/cat"],
            "files": [null, {"name":"stdout","max":1024}, {"name":"stderr","max":1024}],
            "copyIn": {"input.txt": {"symlink":"/dev/stdin"}}
        }],
        "pipeMapping": [{"in":{"index":0,"fd":0},"out":{"index":0,"fd":1}}]
    });
    let request = convert_json_request(&value, &state).unwrap();
    assert!(matches!(request.commands[0].files[0], CmdFile::Null));
    assert_eq!(
        request.commands[0]
            .symlinks
            .get("input.txt")
            .map(String::as_str),
        Some("/dev/stdin")
    );
    assert_eq!(request.pipe_mapping.len(), 1);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn json_request_requires_at_least_one_command_like_go() {
    let (state, dir) = state();
    for request in [json!({}), json!({"cmd": null}), json!({"cmd": []})] {
        let error = convert_json_request(&request, &state).unwrap_err();
        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert_eq!(error.1, "no cmd provided");
    }
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn json_request_rejects_wrong_field_types_like_go_json_binding() {
    let (state, dir) = state();
    for request in [
        json!({"cmd": [{"args": ["/bin/true", 1]}]}),
        json!({"cmd": [{"args": ["/bin/true"], "cpuLimit": 1.5}]}),
    ] {
        let error = convert_json_request(&request, &state).unwrap_err();
        assert_eq!(error.0, StatusCode::BAD_REQUEST, "{request}: {error:?}");
    }
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn json_request_returns_not_found_for_missing_local_source() {
    let (state, dir) = state();
    let value = json!({
        "cmd": [{
            "args": ["/bin/cat"],
            "copyIn": {"input.txt": {"src":"/definitely/missing/rust-sandbox-input"}}
        }]
    });
    let error = convert_json_request(&value, &state).unwrap_err();
    assert_eq!(error.0, StatusCode::NOT_FOUND);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn json_request_real_cpu_limit_overrides_clock_limit() {
    let (state, dir) = state();
    let request = json!({
        "cmd": [{"args": ["/bin/true"], "realCpuLimit": 50, "clockLimit": 100}]
    });
    let converted = convert_json_request(&request, &state).unwrap();
    assert_eq!(converted.commands[0].clock_limit, Duration::from_nanos(50));

    let request = json!({
        "cmd": [{"args": ["/bin/true"], "clockLimit": 100}]
    });
    let converted = convert_json_request(&request, &state).unwrap();
    assert_eq!(converted.commands[0].clock_limit, Duration::from_nanos(100));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn source_prefix_validation_resolves_symlinks_and_path_boundaries() {
    let temp = std::env::temp_dir().join(format!("rust-sandbox-prefix-{}", std::process::id()));
    let allowed = temp.join("allowed");
    let outside = temp.join("allowed-other");
    fs::create_dir_all(&allowed).unwrap();
    fs::create_dir_all(&outside).unwrap();
    let target = outside.join("secret");
    fs::write(&target, b"secret").unwrap();
    let link = allowed.join("escape");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    assert!(source_path_allowed(
        &allowed.join("missing"),
        &[allowed.to_string_lossy().into_owned()]
    ));
    assert!(!source_path_allowed(
        &link,
        &[allowed.to_string_lossy().into_owned()]
    ));
    assert!(!source_path_allowed(
        &target,
        &[allowed.to_string_lossy().into_owned()]
    ));
    fs::remove_dir_all(temp).unwrap();
}

#[test]
fn source_path_errors_keep_go_validation_status_and_messages() {
    let no_prefix = Vec::new();
    assert_eq!(
        source_path_error(std::path::Path::new(""), &no_prefix),
        Some((StatusCode::BAD_REQUEST, "source path is empty".into()))
    );

    let prefix = std::env::temp_dir().join(format!("rust-sandbox-source-{}", std::process::id()));
    fs::create_dir_all(&prefix).unwrap();
    let prefixes = vec![prefix.to_string_lossy().into_owned()];
    let outside = std::env::temp_dir().join("rust-sandbox-outside-prefix");
    assert_eq!(
        source_path_error(&outside, &prefixes),
        Some((
            StatusCode::BAD_REQUEST,
            format!(
                "file ({}) does not under ([{}])",
                outside.display(),
                prefixes[0]
            )
        ))
    );
    let missing = prefix.join("missing");
    assert_eq!(
        source_path_error(&missing, &prefixes),
        Some((
            StatusCode::NOT_FOUND,
            format!(
                "source file does not exist {:?}: file not found",
                missing.display()
            )
        ))
    );
    fs::remove_dir_all(prefix).unwrap();
}

#[test]
fn grpc_local_file_respects_source_prefix() {
    let (mut state, dir) = state();
    let prefix = dir.join("allowed");
    let outside = dir.join("outside");
    fs::create_dir_all(&prefix).unwrap();
    fs::write(&outside, b"x").unwrap();
    let mut config = (*state.config).clone();
    config.src_prefix = vec![prefix.to_string_lossy().into_owned()];
    state.config = Arc::new(config);
    let file = grpc_proto::request::File {
        file: Some(grpc_proto::request::file::File::Local(
            grpc_proto::request::LocalFile {
                src: outside.to_string_lossy().into_owned(),
            },
        )),
    };
    let error = proto_file(&file, &state).unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    let _ = fs::remove_dir_all(dir);
}
