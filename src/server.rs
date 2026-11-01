//! Native HTTP and gRPC server surface for go-judge.
use crate::{
    filestore::LocalFileStore,
    go_judge_config::Config,
    runner::Size,
    worker::{
        AsyncWorker, CancellationToken, CmdFile, Command, CopyOutFile, PipeIndex, PipeMap, Request,
    },
};
use axum::{
    Json, Router,
    extract::{
        Multipart, Path, Query, Request as AxumRequest, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use futures_util::Stream;
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::SocketAddr,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, LazyLock, Mutex},
    task::{Context, Poll},
    time::Duration,
};

pub mod grpc_proto {
    tonic::include_proto!("pb");
}

const WS_WRITE_WAIT: Duration = Duration::from_secs(10);
const WS_PONG_WAIT: Duration = Duration::from_secs(60);
const WS_PING_PERIOD: Duration = Duration::from_secs(50);

const EXEC_TIME_BUCKETS: [f64; 17] = [
    0.001, 0.002, 0.005, 0.010, 0.025, 0.050, 0.1, 0.2, 0.4, 0.8, 1.0, 2.0, 5.0, 10.0, 20.0, 50.0,
    100.0,
];
const HTTP_DURATION_BUCKETS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];
const GRPC_DURATION_BUCKETS: [f64; 11] = HTTP_DURATION_BUCKETS;

#[derive(Default)]
struct Histogram {
    buckets: Vec<u64>,
    count: u64,
    sum: f64,
}

impl Histogram {
    fn observe(&mut self, value: f64, bounds: &[f64]) {
        if self.buckets.is_empty() {
            self.buckets.resize(bounds.len(), 0);
        }
        if let Some(index) = bounds.iter().position(|bound| value <= *bound) {
            self.buckets[index] += 1;
        }
        self.count += 1;
        self.sum += value;
    }
}

#[derive(Default)]
struct ExecutionMetrics {
    errors: u64,
    time: std::collections::BTreeMap<String, Histogram>,
    memory: std::collections::BTreeMap<String, Histogram>,
}

static EXECUTION_METRICS: LazyLock<Mutex<ExecutionMetrics>> =
    LazyLock::new(|| Mutex::new(ExecutionMetrics::default()));
static HTTP_REQUEST_METRICS: LazyLock<Mutex<HttpRequestMetrics>> =
    LazyLock::new(|| Mutex::new(HttpRequestMetrics::default()));
static GRPC_REQUEST_METRICS: LazyLock<Mutex<GrpcRequestMetrics>> =
    LazyLock::new(|| Mutex::new(GrpcRequestMetrics::default()));
static CPU_PROFILE_LOCK: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));
static HEAP_PROFILE_LOCK: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));
static TRACE_PROFILE_LOCK: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));

struct CancelOnDrop {
    token: CancellationToken,
    armed: bool,
}

impl CancelOnDrop {
    fn new(token: CancellationToken) -> Self {
        Self { token, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if self.armed {
            self.token.cancel();
        }
    }
}

#[derive(Clone)]
pub struct ServerState {
    pub worker: AsyncWorker,
    pub files: LocalFileStore,
    pub config: Arc<Config>,
    pub runner_config: Value,
    pub version: String,
}

#[derive(Default)]
struct HttpRequestMetrics {
    count: std::collections::BTreeMap<(String, String, String, String, String), u64>,
    duration: std::collections::BTreeMap<(String, String, String), Histogram>,
    request_size: Summary,
    response_size: Summary,
}

#[derive(Default)]
struct Summary {
    count: u64,
    sum: f64,
}

#[derive(Default)]
struct GrpcRequestMetrics {
    started: std::collections::BTreeMap<(String, String, String), u64>,
    handled: std::collections::BTreeMap<(String, String, String, String), u64>,
    duration: std::collections::BTreeMap<(String, String, String), Histogram>,
    received: std::collections::BTreeMap<(String, String, String), u64>,
    sent: std::collections::BTreeMap<(String, String, String), u64>,
}

impl Summary {
    fn observe(&mut self, value: u64) {
        self.count += 1;
        self.sum += value as f64;
    }
}

pub fn http_router(state: ServerState) -> Router {
    let auth_token = state.config.auth_token.clone();
    let enable_metrics = state.config.enable_metrics;
    let state = Arc::new(state);
    let public = Router::new()
        .route("/version", get(version))
        .route("/config", get(config))
        .with_state(state.clone());
    let protected = Router::new()
        .route("/file", get(file_list).post(file_upload))
        .route("/file/{fid}", get(file_get).delete(file_delete))
        .route("/run", post(run))
        .route("/ws", get(websocket_run))
        .route("/stream", get(websocket_stream))
        .with_state(state);
    let router = if auth_token.is_empty() {
        public.merge(protected)
    } else {
        public.merge(protected.layer(middleware::from_fn_with_state(auth_token, authorize_http)))
    };
    if enable_metrics {
        router.layer(middleware::from_fn(record_http_request))
    } else {
        router
    }
    .layer(middleware::from_fn(record_trace_request))
}

async fn record_trace_request(request: AxumRequest, next: Next) -> Response {
    let name = format!("HTTP {} {}", request.method(), request.uri().path());
    let span = crate::runtime_trace::SpanGuard::start(name);
    let response = next.run(request).await;
    drop(span);
    response
}

pub fn monitor_router(state: ServerState) -> Router {
    crate::runtime_metrics::set_enabled(state.config.enable_metrics);
    let state = Arc::new(state);
    let mut router = Router::new();
    if state.config.enable_metrics {
        router = router.route("/metrics", get(metrics));
    }
    if state.config.enable_debug {
        router = router
            .route("/debug/pprof/", get(debug_index))
            .route("/debug/pprof/cmdline", get(debug_cmdline))
            .route("/debug/pprof/profile", get(debug_profile))
            .route("/debug/pprof/symbol", get(debug_symbol).post(debug_symbol))
            .route("/debug/pprof/trace", get(debug_trace))
            .route("/debug/pprof/{profile}", get(debug_named_profile));
    }
    router.with_state(state)
}

async fn metrics(State(state): State<Arc<ServerState>>) -> impl IntoResponse {
    let worker = state.worker.stat();
    let (file_count, file_bytes) = match state.files.list() {
        Ok(files) => {
            let mut bytes = 0u64;
            for id in files.keys() {
                if let Some((_, file)) = state.files.get(id) {
                    bytes = bytes.saturating_add(file.metadata().map_or(0, |m| m.len()));
                }
            }
            (files.len(), bytes)
        }
        Err(_) => (0, 0),
    };
    let mut body = format!(
        "# HELP go_judge_worker_queue_count Number of requests waiting in worker queue.\n# TYPE go_judge_worker_queue_count gauge\ngo_judge_worker_queue_count {}\n# HELP go_judge_worker_running_count Number of requests running by workers.\n# TYPE go_judge_worker_running_count gauge\ngo_judge_worker_running_count {}\n# HELP go_judge_file_current_bytes_count Number of files currently in the file store.\n# TYPE go_judge_file_current_bytes_count gauge\ngo_judge_file_current_bytes_count {}\n# HELP go_judge_file_current_bytes_sum Total bytes currently in the file store.\n# TYPE go_judge_file_current_bytes_sum gauge\ngo_judge_file_current_bytes_sum {}\n",
        worker.queue, worker.running, file_count, file_bytes
    );
    let (environment_count, environment_in_use) = crate::runtime_metrics::environment_counts();
    body.push_str(&format!(
        "# HELP go_judge_environment_count Total number of environments built by the environment builder.\n# TYPE go_judge_environment_count counter\ngo_judge_environment_count {environment_count}\n# HELP go_judge_environment_current_count Total number of environments currently in use.\n# TYPE go_judge_environment_current_count gauge\ngo_judge_environment_current_count {environment_in_use}\n"
    ));
    append_file_size_metrics(&mut body);
    append_execution_metrics(&mut body);
    append_http_metrics(&mut body);
    append_grpc_metrics(&mut body);
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

async fn record_http_request(request: AxumRequest, next: Next) -> Response {
    let started = std::time::Instant::now();
    let method = request.method().as_str().to_owned();
    let path = request.uri().path().to_owned();
    let url = http_route_label(&path);
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let request_size = request
        .headers()
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
        .sum::<usize>()
        .saturating_add(method.len())
        .saturating_add(path.len())
        .saturating_add(8) // HTTP/1.1
        .saturating_add(
            request
                .headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or_default(),
        ) as u64;
    let response = next.run(request).await;
    let code = response.status().as_u16().to_string();
    let handler = url.clone();
    let response_size = http_body::Body::size_hint(response.body())
        .exact()
        .and_then(|size| u64::try_from(size).ok())
        .or_else(|| {
            response
                .headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
        })
        .unwrap_or_default();
    observe_http_request(
        code,
        method,
        handler,
        host,
        url,
        started.elapsed().as_secs_f64(),
        request_size,
        response_size,
    );
    response
}

fn http_route_label(path: &str) -> String {
    match path {
        "/version" | "/config" | "/file" | "/run" | "/ws" | "/stream" => path.to_owned(),
        path if path.starts_with("/file/") => "/file/{fid}".into(),
        _ => path.to_owned(),
    }
}

fn observe_http_request(
    code: String,
    method: String,
    handler: String,
    host: String,
    url: String,
    duration: f64,
    request_size: u64,
    response_size: u64,
) {
    let Ok(mut metrics) = HTTP_REQUEST_METRICS.lock() else {
        return;
    };
    *metrics
        .count
        .entry((code.clone(), method.clone(), handler, host, url.clone()))
        .or_default() += 1;
    metrics
        .duration
        .entry((code, method, url))
        .or_default()
        .observe(duration, &HTTP_DURATION_BUCKETS);
    metrics.request_size.observe(request_size);
    metrics.response_size.observe(response_size);
}

fn append_http_metrics(body: &mut String) {
    let Ok(metrics) = HTTP_REQUEST_METRICS.lock() else {
        return;
    };
    body.push_str("# HELP gin_requests_total How many HTTP requests processed, partitioned by status code and HTTP method.\n# TYPE gin_requests_total counter\n");
    for ((code, method, handler, host, url), count) in &metrics.count {
        body.push_str(&format!(
            "gin_requests_total{{code=\"{}\",handler=\"{}\",host=\"{}\",method=\"{}\",url=\"{}\"}} {count}\n",
            prometheus_label(code),
            prometheus_label(handler),
            prometheus_label(host),
            prometheus_label(method),
            prometheus_label(url),
        ));
    }
    body.push_str("# HELP gin_request_duration_seconds The HTTP request latencies in seconds.\n# TYPE gin_request_duration_seconds histogram\n");
    append_http_duration_histograms(body, &metrics.duration);
    body.push_str("# HELP gin_request_size_bytes The HTTP request sizes in bytes.\n# TYPE gin_request_size_bytes summary\n");
    body.push_str(&format!(
        "gin_request_size_bytes_sum {}\ngin_request_size_bytes_count {}\n",
        metrics.request_size.sum, metrics.request_size.count
    ));
    body.push_str("# HELP gin_response_size_bytes The HTTP response sizes in bytes.\n# TYPE gin_response_size_bytes summary\n");
    body.push_str(&format!(
        "gin_response_size_bytes_sum {}\ngin_response_size_bytes_count {}\n",
        metrics.response_size.sum, metrics.response_size.count
    ));
}

fn append_http_duration_histograms(
    body: &mut String,
    histograms: &std::collections::BTreeMap<(String, String, String), Histogram>,
) {
    for ((code, method, url), histogram) in histograms {
        let mut cumulative = 0u64;
        for (index, bound) in HTTP_DURATION_BUCKETS.iter().enumerate() {
            cumulative += histogram.buckets.get(index).copied().unwrap_or(0);
            body.push_str(&format!(
                "gin_request_duration_seconds_bucket{{code=\"{}\",method=\"{}\",url=\"{}\",le=\"{bound}\"}} {cumulative}\n",
                prometheus_label(code),
                prometheus_label(method),
                prometheus_label(url),
            ));
        }
        body.push_str(&format!(
            "gin_request_duration_seconds_bucket{{code=\"{}\",method=\"{}\",url=\"{}\",le=\"+Inf\"}} {}\ngin_request_duration_seconds_sum{{code=\"{}\",method=\"{}\",url=\"{}\"}} {}\ngin_request_duration_seconds_count{{code=\"{}\",method=\"{}\",url=\"{}\"}} {}\n",
            prometheus_label(code), prometheus_label(method), prometheus_label(url), histogram.count,
            prometheus_label(code), prometheus_label(method), prometheus_label(url), histogram.sum,
            prometheus_label(code), prometheus_label(method), prometheus_label(url), histogram.count,
        ));
    }
}

fn prometheus_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

async fn instrument_grpc<T>(
    rpc_type: &'static str,
    method: &'static str,
    call: impl std::future::Future<Output = Result<T, tonic::Status>>,
) -> Result<T, tonic::Status> {
    let mut measurement = GrpcCallMeasurement::start(rpc_type, method);
    let result = call.await;
    measurement.finish(
        result
            .as_ref()
            .map(|_| tonic::Code::Ok)
            .unwrap_or_else(|status| status.code()),
    );
    result
}

/// Tracks an RPC from request arrival through completion. For streaming RPCs
/// the handler only creates the response stream; the measurement is moved into
/// that stream and finished when it ends or the client drops it.
struct GrpcCallMeasurement {
    rpc_type: &'static str,
    method: &'static str,
    started: std::time::Instant,
    enabled: bool,
    finished: bool,
}

impl GrpcCallMeasurement {
    fn start(rpc_type: &'static str, method: &'static str) -> Self {
        let enabled = crate::runtime_metrics::is_enabled();
        if enabled && let Ok(mut metrics) = GRPC_REQUEST_METRICS.lock() {
            *metrics
                .started
                .entry((rpc_type.into(), "pb.Executor".into(), method.into()))
                .or_default() += 1;
        }
        Self {
            rpc_type,
            method,
            started: std::time::Instant::now(),
            enabled,
            finished: false,
        }
    }

    fn finish(&mut self, code: tonic::Code) {
        if self.finished {
            return;
        }
        self.finished = true;
        if self.enabled
            && let Ok(mut metrics) = GRPC_REQUEST_METRICS.lock()
        {
            *metrics
                .handled
                .entry((
                    self.rpc_type.into(),
                    "pb.Executor".into(),
                    self.method.into(),
                    grpc_code_label(code).into(),
                ))
                .or_default() += 1;
            metrics
                .duration
                .entry((
                    self.rpc_type.into(),
                    "pb.Executor".into(),
                    self.method.into(),
                ))
                .or_default()
                .observe(self.started.elapsed().as_secs_f64(), &GRPC_DURATION_BUCKETS);
        }
    }
}

fn grpc_code_label(code: tonic::Code) -> &'static str {
    match code {
        tonic::Code::Ok => "OK",
        tonic::Code::Cancelled => "Canceled",
        tonic::Code::Unknown => "Unknown",
        tonic::Code::InvalidArgument => "InvalidArgument",
        tonic::Code::DeadlineExceeded => "DeadlineExceeded",
        tonic::Code::NotFound => "NotFound",
        tonic::Code::AlreadyExists => "AlreadyExists",
        tonic::Code::PermissionDenied => "PermissionDenied",
        tonic::Code::ResourceExhausted => "ResourceExhausted",
        tonic::Code::FailedPrecondition => "FailedPrecondition",
        tonic::Code::Aborted => "Aborted",
        tonic::Code::OutOfRange => "OutOfRange",
        tonic::Code::Unimplemented => "Unimplemented",
        tonic::Code::Internal => "Internal",
        tonic::Code::Unavailable => "Unavailable",
        tonic::Code::DataLoss => "DataLoss",
        tonic::Code::Unauthenticated => "Unauthenticated",
    }
}

impl Drop for GrpcCallMeasurement {
    fn drop(&mut self) {
        // A dropped response stream represents a client cancellation or
        // transport failure that prevented normal stream completion.
        self.finish(tonic::Code::Cancelled);
    }
}

struct InstrumentedGrpcStream<S> {
    inner: S,
    measurement: GrpcCallMeasurement,
}

impl<S> InstrumentedGrpcStream<S> {
    fn new(inner: S, measurement: GrpcCallMeasurement) -> Self {
        Self { inner, measurement }
    }
}

impl<S, T> Stream for InstrumentedGrpcStream<S>
where
    S: Stream<Item = Result<T, tonic::Status>> + Unpin,
{
    type Item = Result<T, tonic::Status>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(None) => {
                this.measurement.finish(tonic::Code::Ok);
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(status))) => {
                this.measurement.finish(status.code());
                Poll::Ready(Some(Err(status)))
            }
            other => other,
        }
    }
}

async fn instrument_grpc_stream<S, T>(
    rpc_type: &'static str,
    method: &'static str,
    call: impl std::future::Future<Output = Result<tonic::Response<S>, tonic::Status>>,
) -> Result<tonic::Response<InstrumentedGrpcStream<S>>, tonic::Status>
where
    S: Stream<Item = Result<T, tonic::Status>> + Unpin,
{
    let mut measurement = GrpcCallMeasurement::start(rpc_type, method);
    match call.await {
        Ok(response) => {
            let (metadata, stream, extensions) = response.into_parts();
            Ok(tonic::Response::from_parts(
                metadata,
                InstrumentedGrpcStream::new(stream, measurement),
                extensions,
            ))
        }
        Err(status) => {
            measurement.finish(status.code());
            Err(status)
        }
    }
}

fn observe_grpc_message(rpc_type: &str, method: &str, sent: bool) {
    if !crate::runtime_metrics::is_enabled() {
        return;
    }
    let Ok(mut metrics) = GRPC_REQUEST_METRICS.lock() else {
        return;
    };
    let series = (rpc_type.into(), "pb.Executor".into(), method.into());
    let counters = if sent {
        &mut metrics.sent
    } else {
        &mut metrics.received
    };
    *counters.entry(series).or_default() += 1;
}

fn append_grpc_metrics(body: &mut String) {
    let Ok(metrics) = GRPC_REQUEST_METRICS.lock() else {
        return;
    };
    body.push_str("# HELP grpc_server_started_total Total number of RPCs started on the server.\n# TYPE grpc_server_started_total counter\n");
    for ((rpc_type, service, method), count) in &metrics.started {
        body.push_str(&format!(
            "grpc_server_started_total{{grpc_method=\"{}\",grpc_service=\"{}\",grpc_type=\"{}\"}} {count}\n",
            prometheus_label(method), prometheus_label(service), prometheus_label(rpc_type)
        ));
    }
    body.push_str("# HELP grpc_server_msg_received_total Total number of stream messages received on the server.\n# TYPE grpc_server_msg_received_total counter\n");
    for ((rpc_type, service, method), count) in &metrics.received {
        body.push_str(&format!(
            "grpc_server_msg_received_total{{grpc_method=\"{}\",grpc_service=\"{}\",grpc_type=\"{}\"}} {count}\n",
            prometheus_label(method), prometheus_label(service), prometheus_label(rpc_type)
        ));
    }
    body.push_str("# HELP grpc_server_msg_sent_total Total number of stream messages sent on the server.\n# TYPE grpc_server_msg_sent_total counter\n");
    for ((rpc_type, service, method), count) in &metrics.sent {
        body.push_str(&format!(
            "grpc_server_msg_sent_total{{grpc_method=\"{}\",grpc_service=\"{}\",grpc_type=\"{}\"}} {count}\n",
            prometheus_label(method), prometheus_label(service), prometheus_label(rpc_type)
        ));
    }
    body.push_str("# HELP grpc_server_handled_total Total number of RPCs completed on the server, regardless of success or failure.\n# TYPE grpc_server_handled_total counter\n");
    for ((rpc_type, service, method, code), count) in &metrics.handled {
        body.push_str(&format!(
            "grpc_server_handled_total{{grpc_code=\"{}\",grpc_method=\"{}\",grpc_service=\"{}\",grpc_type=\"{}\"}} {count}\n",
            prometheus_label(code), prometheus_label(method), prometheus_label(service), prometheus_label(rpc_type)
        ));
    }
    body.push_str("# HELP grpc_server_handling_seconds Histogram of response latency (seconds) of gRPC that had been application-level handled by the server.\n# TYPE grpc_server_handling_seconds histogram\n");
    for ((rpc_type, service, method), histogram) in &metrics.duration {
        let mut cumulative = 0u64;
        for (index, bound) in GRPC_DURATION_BUCKETS.iter().enumerate() {
            cumulative += histogram.buckets.get(index).copied().unwrap_or(0);
            body.push_str(&format!(
                "grpc_server_handling_seconds_bucket{{grpc_method=\"{}\",grpc_service=\"{}\",grpc_type=\"{}\",le=\"{bound}\"}} {cumulative}\n",
                prometheus_label(method), prometheus_label(service), prometheus_label(rpc_type)
            ));
        }
        body.push_str(&format!(
            "grpc_server_handling_seconds_bucket{{grpc_method=\"{}\",grpc_service=\"{}\",grpc_type=\"{}\",le=\"+Inf\"}} {}\ngrpc_server_handling_seconds_sum{{grpc_method=\"{}\",grpc_service=\"{}\",grpc_type=\"{}\"}} {}\ngrpc_server_handling_seconds_count{{grpc_method=\"{}\",grpc_service=\"{}\",grpc_type=\"{}\"}} {}\n",
            prometheus_label(method), prometheus_label(service), prometheus_label(rpc_type), histogram.count,
            prometheus_label(method), prometheus_label(service), prometheus_label(rpc_type), histogram.sum,
            prometheus_label(method), prometheus_label(service), prometheus_label(rpc_type), histogram.count,
        ));
    }
}

fn append_file_size_metrics(body: &mut String) {
    let (buckets, count, sum) = crate::runtime_metrics::file_size_histogram();
    body.push_str("# HELP go_judge_file_size_bytes Histogram for the file size created in the file store.\n# TYPE go_judge_file_size_bytes histogram\n");
    let mut cumulative = 0u64;
    for (index, bucket) in buckets.iter().enumerate() {
        cumulative += bucket;
        let bound = 1u64 << (8 + index);
        body.push_str(&format!(
            "go_judge_file_size_bytes_bucket{{le=\"{bound}\"}} {cumulative}\n"
        ));
    }
    body.push_str(&format!(
        "go_judge_file_size_bytes_bucket{{le=\"+Inf\"}} {count}\ngo_judge_file_size_bytes_sum {sum}\ngo_judge_file_size_bytes_count {count}\n"
    ));
}

async fn debug_index() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        "<html><head><title>/debug/pprof/</title></head><body>/debug/pprof/<br><p>Set debug=1 as a query parameter to export in legacy text format</p><p>Types of profiles available:</p><table><thead><tr><td>Profile</td><td>Description</td></tr></thead><tbody><tr><td><a href='allocs?debug=1'>allocs</a></td><td>A sampling of all past memory allocations</td></tr><tr><td><a href='block?debug=1'>block</a></td><td>Stacks that led to blocking on synchronization primitives</td></tr><tr><td><a href='cmdline?debug=1'>cmdline</a></td><td>The command line invocation of the current program</td></tr><tr><td><a href='goroutine?debug=1'>goroutine</a></td><td>Operating system thread snapshots; Rust async tasks share these threads</td></tr><tr><td><a href='heap?debug=1'>heap</a></td><td>A sampling of live heap allocations</td></tr><tr><td><a href='mutex?debug=1'>mutex</a></td><td>Contended mutex profiles</td></tr><tr><td><a href='profile?debug=1'>profile</a></td><td>CPU profile</td></tr><tr><td><a href='symbol?debug=1'>symbol</a></td><td>Program counter symbol lookup</td></tr><tr><td><a href='threadcreate?debug=1'>threadcreate</a></td><td>Operating system thread snapshots</td></tr><tr><td><a href='trace?debug=1'>trace</a></td><td>Go runtime execution trace</td></tr></tbody></table><a href='goroutine?debug=2'>full thread snapshot</a></body></html>",
    )
}

async fn debug_cmdline() -> impl IntoResponse {
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

async fn debug_profile(Query(query): Query<std::collections::HashMap<String, String>>) -> Response {
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

async fn debug_named_profile(
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

async fn debug_symbol(request: AxumRequest) -> Response {
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

async fn debug_trace(Query(query): Query<std::collections::HashMap<String, String>>) -> Response {
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

    let Ok(path) = std::env::current_exe().and_then(|path| std::fs::canonicalize(path)) else {
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

pub fn observe_execution(response: &crate::worker::Response) {
    let Ok(mut metrics) = EXECUTION_METRICS.lock() else {
        return;
    };
    if response.error.is_some() {
        metrics.errors += 1;
    }
    let memory_bounds: Vec<f64> = (0..21).map(|index| (1u64 << 12 << index) as f64).collect();
    for result in &response.results {
        let status = result.status.as_str().to_owned();
        metrics
            .time
            .entry(status.clone())
            .or_default()
            .observe(result.time.as_secs_f64(), &EXEC_TIME_BUCKETS);
        metrics
            .memory
            .entry(status)
            .or_default()
            .observe(result.memory.0 as f64, &memory_bounds);
    }
}

fn append_execution_metrics(body: &mut String) {
    let Ok(metrics) = EXECUTION_METRICS.lock() else {
        return;
    };
    body.push_str("# HELP go_judge_exec_error_count Number of exec query returns error.\n# TYPE go_judge_exec_error_count counter\n");
    body.push_str(&format!("go_judge_exec_error_count {}\n", metrics.errors));
    body.push_str("# HELP go_judge_exec_time_seconds Histogram for the command execution time.\n# TYPE go_judge_exec_time_seconds histogram\n");
    append_histograms(
        body,
        "go_judge_exec_time_seconds",
        &metrics.time,
        &EXEC_TIME_BUCKETS,
    );
    let memory_bounds: Vec<f64> = (0..21).map(|index| (1u64 << 12 << index) as f64).collect();
    body.push_str("# HELP go_judge_exec_memory_bytes Histogram for the command execution max memory.\n# TYPE go_judge_exec_memory_bytes histogram\n");
    append_histograms(
        body,
        "go_judge_exec_memory_bytes",
        &metrics.memory,
        &memory_bounds,
    );
}

fn append_histograms(
    body: &mut String,
    name: &str,
    histograms: &std::collections::BTreeMap<String, Histogram>,
    bounds: &[f64],
) {
    for (status, histogram) in histograms {
        let status = status
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n");
        let mut cumulative = 0u64;
        for (index, bound) in bounds.iter().enumerate() {
            cumulative += histogram.buckets.get(index).copied().unwrap_or(0);
            body.push_str(&format!(
                "{name}_bucket{{status=\"{status}\",le=\"{bound}\"}} {cumulative}\n"
            ));
        }
        body.push_str(&format!(
            "{name}_bucket{{status=\"{status}\",le=\"+Inf\"}} {}\n{name}_sum{{status=\"{status}\"}} {}\n{name}_count{{status=\"{status}\"}} {}\n",
            histogram.count, histogram.sum, histogram.count
        ));
    }
}

async fn authorize_http(State(token): State<String>, request: AxumRequest, next: Next) -> Response {
    let authorized = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        == Some(token.as_str());
    if authorized {
        next.run(request).await
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

async fn version(State(s): State<Arc<ServerState>>) -> impl IntoResponse {
    Json(json!({
        "buildVersion": s.version,
        "goVersion": env!("RUSTC_VERSION"),
        "platform": go_architecture(),
        "os": std::env::consts::OS,
        "copyOutOptional": true,
        "pipeProxy": true,
        "symlink": true,
        "addressSpaceLimit": true,
        "stream": true,
        "procPeak": true,
        "copyOutTruncate": true,
        "pipeProxyZeroCopy": true,
        "fixSymlinkEscape": true,
        "exitOrder": true,
    }))
}

fn go_architecture() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "386",
        "powerpc64" => "ppc64",
        "powerpc64le" => "ppc64le",
        "s390x" => "s390x",
        other => other,
    }
}

async fn config(State(s): State<Arc<ServerState>>) -> impl IntoResponse {
    Json(json!({
        "copyOutOptional": true,
        "pipeProxy": true,
        "symlink": true,
        "addressSpaceLimit": true,
        "stream": true,
        "procPeak": true,
        "copyOutTruncate": true,
        "pipeProxyZeroCopy": true,
        "fixSymlinkEscape": true,
        "exitOrder": true,
        // The server resolves Go's default directory before constructing
        // `ServerState`, so this reports the effective file-store path.
        "fileStorePath": s.config.dir,
        "runnerConfig": s.runner_config,
    }))
}
async fn file_list(State(s): State<Arc<ServerState>>) -> impl IntoResponse {
    match s.files.list() {
        Ok(x) => (StatusCode::OK, Json(x)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
async fn file_upload(
    State(s): State<Arc<ServerState>>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    while let Ok(Some(field)) = multipart.next_field().await {
        if field.name() != Some("file") {
            continue;
        }
        let name = field.file_name().unwrap_or("file").to_owned();
        let data = match field.bytes().await {
            Ok(b) => b,
            Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
        };
        let (id, mut file) = match s.files.new_file() {
            Ok(x) => x,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        };
        if let Err(e) = file
            .write_all(&data)
            .and_then(|_| s.files.set_name(&id, name))
        {
            s.files.remove(&id);
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
        return Json(id).into_response();
    }
    (StatusCode::BAD_REQUEST, "missing multipart file field").into_response()
}
async fn file_get(State(s): State<Arc<ServerState>>, Path(id): Path<String>) -> impl IntoResponse {
    let Some((name, mut file)) = s.files.get(&id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mut bytes = Vec::new();
    if file.read_to_end(&mut bytes).is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let mime = mime_guess(&name);
    let mut response = bytes.into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(mime));
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!(
            "attachment; filename=\"{}\"",
            name.replace('"', "")
        ))
        .unwrap_or(HeaderValue::from_static("attachment")),
    );
    response
}
async fn file_delete(State(s): State<Arc<ServerState>>, Path(id): Path<String>) -> StatusCode {
    if s.files.remove(&id) {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}
async fn run(State(s): State<Arc<ServerState>>, body: axum::body::Bytes) -> impl IntoResponse {
    let value: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!(e.to_string()))).into_response(),
    };
    let request = match convert_json_request(&value, &s) {
        Ok(v) => v,
        Err((status, e)) => return (status, Json(json!(e))).into_response(),
    };
    let cancellation = CancellationToken::default();
    let mut cancel_on_drop = CancelOnDrop::new(cancellation.clone());
    let (rx, _started) = s.worker.submit(request, cancellation);
    let response = rx.await;
    cancel_on_drop.disarm();
    match response {
        Ok(r) if r.error.is_some() => {
            let error = r.error.unwrap_or_default();
            (worker_http_error_status(&error), Json(json!(error))).into_response()
        }
        Ok(r) => Json(response_results(r)).into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!("worker response channel closed")),
        )
            .into_response(),
    }
}

fn response_results(r: crate::worker::Response) -> Vec<Value> {
    let results: Vec<Value> = r
        .results
        .into_iter()
        .map(|mut x| {
            let mut files = serde_json::Map::new();
            for (name, mut file) in x.files.drain() {
                let mut bytes = Vec::new();
                if file.read_to_end(&mut bytes).is_ok() {
                    files.insert(
                        name,
                        Value::String(String::from_utf8_lossy(&bytes).into_owned()),
                    );
                }
            }
            let file_errors: Vec<Value> = x
                .file_errors
                .into_iter()
                .map(|e| {
                    let mut error = json!({
                        "name": e.name,
                        // Go's FileErrorType is an integer enum in the REST
                        // response; its String method is only for logs.
                        "type": e.kind as i32,
                    });
                    if !e.message.is_empty() {
                        error["message"] = json!(e.message);
                    }
                    error
                })
                .collect();
            let mut result = json!({
                "status": x.status.as_str(),
                "exitStatus": x.exit_status,
                "time": x.time.as_nanos() as u64,
                "runTime": x.run_time.as_nanos() as u64,
                "memory": x.memory.0,
            });
            let object = result.as_object_mut().expect("JSON result object");
            if x.exit_order != 0 {
                object.insert("exitOrder".into(), json!(x.exit_order));
            }
            if !x.error.is_empty() {
                object.insert("error".into(), Value::String(x.error));
            }
            if x.proc_peak != 0 {
                object.insert("procPeak".into(), json!(x.proc_peak));
            }
            if !files.is_empty() {
                object.insert("files".into(), Value::Object(files));
            }
            if !x.file_ids.is_empty() {
                object.insert("fileIds".into(), json!(x.file_ids));
            }
            if !file_errors.is_empty() {
                object.insert("fileError".into(), Value::Array(file_errors));
            }
            result
        })
        .collect();
    results
}

fn response_json(r: crate::worker::Response) -> Value {
    let request_id = r.request_id.clone();
    let error = r.error.clone();
    let results = response_results(r);
    if let Some(error) = error {
        json!({"requestId": request_id, "results": results, "error": error})
    } else {
        json!({"requestId": request_id, "results": results})
    }
}

fn is_missing_cached_file_error(message: &str) -> bool {
    // worker::CmdFile::Cached preserves Go's ErrFileNotFound wording when a
    // cached file disappears after request conversion but before preparation.
    message.starts_with("file does not exist with id ")
}

fn worker_http_error_status(message: &str) -> StatusCode {
    if is_missing_cached_file_error(message) {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

fn worker_grpc_error_status(message: &str) -> tonic::Status {
    if is_missing_cached_file_error(message) {
        tonic::Status::not_found(message.to_owned())
    } else {
        tonic::Status::internal(message.to_owned())
    }
}

fn grpc_response(result: crate::worker::Response) -> Result<grpc_proto::Response, tonic::Status> {
    let results = result
        .results
        .into_iter()
        .map(|mut r| {
            let mut files = std::collections::HashMap::new();
            for (name, mut file) in r.files.drain() {
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes)
                    .map_err(|e| tonic::Status::internal(e.to_string()))?;
                files.insert(name, bytes);
            }
            Ok(grpc_proto::response::Result {
                status: r.status as i32,
                exit_status: r.exit_status,
                error: r.error,
                time: r.time.as_nanos() as u64,
                run_time: r.run_time.as_nanos() as u64,
                proc_peak: r.proc_peak,
                exit_order: r.exit_order as i32,
                memory: r.memory.0,
                files,
                file_i_ds: r.file_ids,
                file_error: r
                    .file_errors
                    .into_iter()
                    .map(|e| grpc_proto::response::FileError {
                        name: e.name,
                        r#type: grpc_file_error_type(e.kind),
                        message: e.message,
                    })
                    .collect(),
            })
        })
        .collect::<Result<Vec<_>, tonic::Status>>()?;
    Ok(grpc_proto::Response {
        request_id: result.request_id,
        results,
        // Go's ExecStream returns the converted result list but discards the
        // worker's top-level execution error in its final stream response.
        error: String::new(),
    })
}

fn grpc_file_error_type(kind: crate::envexec::FileErrorType) -> i32 {
    match kind {
        // Go's grpc executor intentionally maps both directory and file
        // creation failures to the protobuf CopyInCreateFile enum.
        crate::envexec::FileErrorType::CopyInCreateDir
        | crate::envexec::FileErrorType::CopyInCreateFile => 2,
        _ => kind as i32,
    }
}

async fn websocket_run(
    State(state): State<Arc<ServerState>>,
    upgrade: WebSocketUpgrade,
) -> impl IntoResponse {
    upgrade.on_upgrade(move |socket| websocket_loop(socket, state))
}

async fn websocket_stream(
    State(state): State<Arc<ServerState>>,
    upgrade: WebSocketUpgrade,
) -> impl IntoResponse {
    upgrade.on_upgrade(move |socket| websocket_stream_loop(socket, state))
}

async fn websocket_stream_loop(mut socket: WebSocket, state: Arc<ServerState>) {
    use axum::extract::ws::Message;
    use futures_util::{SinkExt, StreamExt};
    let Some(Ok(Message::Binary(first))) = socket.next().await else {
        return;
    };
    if first.first() != Some(&1) {
        let _ = socket.close().await;
        return;
    }
    let request: Value = match serde_json::from_slice(&first[1..]) {
        Ok(request) => request,
        Err(_) => {
            let _ = socket.close().await;
            return;
        }
    };
    let (output_tx, mut output_rx) = tokio::sync::mpsc::channel::<crate::worker::StreamOutput>(32);
    let (request, input_tx, resize_tx) =
        match convert_json_request_with_stream(&request, &state, Some(output_tx)) {
            Ok(pair) => pair,
            Err(_) => {
                let _ = socket.close().await;
                return;
            }
        };
    for (index, command) in request.commands.iter().enumerate() {
        if index > 15
            && command
                .files
                .iter()
                .any(|f| matches!(f, CmdFile::StreamIn(_) | CmdFile::StreamOut { .. }))
        {
            let _ = socket.close().await;
            return;
        }
        for (fd, file) in command.files.iter().enumerate() {
            if fd > 15 && matches!(file, CmdFile::StreamIn(_) | CmdFile::StreamOut { .. }) {
                let _ = socket.close().await;
                return;
            }
        }
    }
    let cancellation = CancellationToken::default();
    let response_task = state.worker.execute(request, cancellation.clone());
    tokio::pin!(response_task);
    let mut input_tx = input_tx;
    let mut input_open = true;
    let mut output_open = true;
    let mut ping =
        tokio::time::interval_at(tokio::time::Instant::now() + WS_PING_PERIOD, WS_PING_PERIOD);
    let mut last_pong = tokio::time::Instant::now();
    let pong_deadline = tokio::time::sleep_until(last_pong + WS_PONG_WAIT);
    tokio::pin!(pong_deadline);
    loop {
        tokio::select! {
            _ = &mut pong_deadline => {
                cancellation.cancel();
                break;
            }
            _ = ping.tick() => {
                if tokio::time::timeout(WS_WRITE_WAIT, socket.send(Message::Ping(Vec::new().into())))
                    .await
                    .map_or(true, |result| result.is_err())
                {
                    cancellation.cancel();
                    break;
                }
            }
            incoming = socket.next(), if input_open => match incoming {
                Some(Ok(Message::Binary(bytes))) if !bytes.is_empty() => match bytes[0] {
                    3 if bytes.len() > 1 => {
                        let packed = bytes[1];
                        let key = ((packed >> 4) as u32, (packed & 0xf) as u32);
                        if let Some(sender) = input_tx.get(&key) { let _ = sender.send(bytes[2..].to_vec()).await; }
                    }
                    2 if bytes.len() > 1 => {
                        if let Ok(value) = serde_json::from_slice::<Value>(&bytes[1..]) {
                            let index = value.get("index").and_then(Value::as_u64).unwrap_or(0) as u32;
                            let fd = value.get("fd").and_then(Value::as_u64).unwrap_or(0) as u32;
                            let size = crate::worker::TerminalSize {
                                rows: value.get("rows").and_then(Value::as_u64).unwrap_or(0) as u16,
                                cols: value.get("cols").and_then(Value::as_u64).unwrap_or(0) as u16,
                                x: value.get("x").and_then(Value::as_u64).unwrap_or(0) as u16,
                                y: value.get("y").and_then(Value::as_u64).unwrap_or(0) as u16,
                            };
                            let key = (index, fd);
                            if input_tx.contains_key(&key) {
                                if let Some(sender) = resize_tx.get(&index) {
                                    let _ = sender.send(size);
                                } else {
                                    cancellation.cancel();
                                    break;
                                }
                            } else {
                                cancellation.cancel();
                                break;
                            }
                        }
                    }
                    2 => {}
                    4 => { cancellation.cancel(); input_tx.clear(); input_open = false; }
                    _ => { cancellation.cancel(); input_tx.clear(); input_open = false; }
                },
                Some(Ok(Message::Ping(bytes))) => {
                    if tokio::time::timeout(WS_WRITE_WAIT, socket.send(Message::Pong(bytes)))
                        .await
                        .map_or(true, |result| result.is_err())
                    {
                        cancellation.cancel();
                        break;
                    }
                }
                Some(Ok(Message::Pong(_))) => {
                    last_pong = tokio::time::Instant::now();
                    pong_deadline.as_mut().reset(last_pong + WS_PONG_WAIT);
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => { cancellation.cancel(); input_tx.clear(); input_open = false; }
                _ => {}
            },
            output = output_rx.recv(), if output_open => match output {
                Some(output) if output.index <= 15 && output.fd <= 15 => {
                    let mut bytes = vec![2, ((output.index as u8) << 4) | output.fd as u8];
                    bytes.extend_from_slice(&output.content);
                    if tokio::time::timeout(WS_WRITE_WAIT, socket.send(Message::Binary(bytes.into())))
                        .await
                        .map_or(true, |result| result.is_err())
                    { cancellation.cancel(); break; }
                }
                Some(_) => { cancellation.cancel(); break; }
                None => output_open = false,
            },
            result = &mut response_task => {
                input_tx.clear();
                let response = match result {
                    Ok(response) => response_json(response),
                    _ => json!({"results": [], "error": "worker response channel closed"}),
                };
                while let Some(output) = output_rx.recv().await {
                    if output.index > 15 || output.fd > 15 { break; }
                    let mut bytes = vec![2, ((output.index as u8) << 4) | output.fd as u8];
                    bytes.extend_from_slice(&output.content);
                    if tokio::time::timeout(WS_WRITE_WAIT, socket.send(Message::Binary(bytes.into())))
                        .await
                        .map_or(true, |result| result.is_err())
                    { return; }
                }
                let mut bytes = vec![1];
                if let Ok(encoded) = serde_json::to_vec(&response) { bytes.extend(encoded); }
                let _ = tokio::time::timeout(WS_WRITE_WAIT, socket.send(Message::Binary(bytes.into()))).await;
                let _ = socket.close().await;
                return;
            }
        }
    }
}

async fn websocket_loop(socket: WebSocket, state: Arc<ServerState>) {
    use futures_util::{SinkExt, StreamExt};
    use std::collections::HashMap;
    let (mut sink, mut source) = socket.split();
    let active = Arc::new(tokio::sync::Mutex::new(
        HashMap::<String, CancellationToken>::new(),
    ));
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Value>(128);
    let writer = tokio::spawn(async move {
        let mut ping =
            tokio::time::interval_at(tokio::time::Instant::now() + WS_PING_PERIOD, WS_PING_PERIOD);
        loop {
            tokio::select! {
                value = rx.recv() => {
                    let Some(value) = value else { break; };
                    let Ok(encoded) = serde_json::to_string(&value) else { break; };
                    if tokio::time::timeout(WS_WRITE_WAIT, sink.send(Message::Text(encoded.into())))
                        .await
                        .map_or(true, |result| result.is_err())
                    { break; }
                }
                _ = ping.tick() => {
                    if tokio::time::timeout(WS_WRITE_WAIT, sink.send(Message::Ping(Vec::new().into())))
                        .await
                        .map_or(true, |result| result.is_err())
                    { break; }
                }
            }
        }
    });
    let mut last_pong = tokio::time::Instant::now();
    let pong_deadline = tokio::time::sleep_until(last_pong + WS_PONG_WAIT);
    tokio::pin!(pong_deadline);
    loop {
        let incoming = tokio::select! {
            _ = &mut pong_deadline => break,
            incoming = source.next() => incoming,
        };
        let Some(Ok(message)) = incoming else {
            break;
        };
        let text = match message {
            Message::Text(text) => text.to_string(),
            Message::Binary(bytes) => match String::from_utf8(bytes.to_vec()) {
                Ok(text) => text,
                Err(error) => {
                    let _ = tx.send(json!({"error": error.to_string()})).await;
                    continue;
                }
            },
            Message::Close(_) => break,
            Message::Ping(_) => continue,
            Message::Pong(_) => {
                last_pong = tokio::time::Instant::now();
                pong_deadline.as_mut().reset(last_pong + WS_PONG_WAIT);
                continue;
            }
        };
        let mut request: Value = match serde_json::from_str(&text) {
            Ok(req) => req,
            Err(error) => {
                let _ = tx.send(json!({"error": error.to_string()})).await;
                continue;
            }
        };
        let cancel_request_id = request
            .get("cancelRequestId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        if !cancel_request_id.is_empty() {
            if let Some(token) = active.lock().await.remove(&cancel_request_id) {
                token.cancel();
            }
            continue;
        }
        if let Some(object) = request.as_object_mut() {
            object.remove("cancelRequestId");
        }
        let converted = match convert_json_request(&request, &state) {
            Ok(request) => request,
            Err((_, error)) => {
                let _ = tx.send(json!({"error": error})).await;
                continue;
            }
        };
        let request_id = converted.request_id.clone();
        let duplicate = active.lock().await.contains_key(&request_id);
        if request_id.is_empty() || duplicate {
            let error = if request_id.is_empty() {
                "empty request id".to_string()
            } else {
                format!("duplicated request id: {request_id:?}")
            };
            let _ = tx
                .send(json!({"requestId": request_id, "error": error}))
                .await;
            continue;
        }
        let cancellation = CancellationToken::default();
        active
            .lock()
            .await
            .insert(request_id.clone(), cancellation.clone());
        let worker = state.worker.clone();
        let tx = tx.clone();
        let active_task = active.clone();
        let id = request_id.clone();
        tokio::spawn(async move {
            let response = worker.execute(converted, cancellation).await;
            let payload = match response {
                Ok(response) => response_json(response),
                _ => {
                    json!({"requestId": id, "results": [], "error": "worker response channel closed"})
                }
            };
            let _ = tx.send(payload).await;
            active_task.lock().await.remove(&id);
        });
    }
    for token in active.lock().await.drain().map(|(_, token)| token) {
        token.cancel();
    }
    drop(tx);
    let _ = writer.await;
}

fn convert_json_request(v: &Value, state: &ServerState) -> Result<Request, (StatusCode, String)> {
    convert_json_request_with_stream(v, state, None).map(|(request, _, _)| request)
}
fn convert_json_request_with_stream(
    v: &Value,
    state: &ServerState,
    output: Option<tokio::sync::mpsc::Sender<crate::worker::StreamOutput>>,
) -> Result<
    (
        Request,
        std::collections::HashMap<(u32, u32), tokio::sync::mpsc::Sender<Vec<u8>>>,
        std::collections::HashMap<u32, std::sync::mpsc::Sender<crate::worker::TerminalSize>>,
    ),
    (StatusCode, String),
> {
    validate_json_request_types(v).map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    let cmds = match v.get("cmd") {
        Some(Value::Array(cmds)) => cmds,
        None | Some(Value::Null) => {
            return Err((StatusCode::BAD_REQUEST, "no cmd provided".into()));
        }
        Some(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                "invalid cmd: expected an array".into(),
            ));
        }
    };
    if cmds.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "no cmd provided".into()));
    }
    let mut req = Request {
        request_id: v
            .get("requestId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        ..Request::default()
    };
    let mut inputs = std::collections::HashMap::new();
    let mut resizes = std::collections::HashMap::new();
    for (index, c) in cmds.iter().enumerate() {
        let mut cmd = Command::default();
        cmd.args = strings(c, "args");
        cmd.env = strings(c, "env");
        cmd.cpu_limit = Duration::from_nanos(num(c, "cpuLimit"));
        let real_cpu_limit = num(c, "realCpuLimit");
        cmd.clock_limit = Duration::from_nanos(if real_cpu_limit > 0 {
            real_cpu_limit
        } else {
            num(c, "clockLimit")
        });
        cmd.memory_limit = Size(num(c, "memoryLimit"));
        cmd.stack_limit = Size(num(c, "stackLimit"));
        cmd.output_limit = Size(state.config.output_limit.0);
        cmd.proc_limit = num(c, "procLimit");
        cmd.cpu_rate_limit = num(c, "cpuRateLimit");
        cmd.cpu_set_limit = text(c, "cpuSetLimit");
        cmd.copy_out_max = num(c, "copyOutMax");
        cmd.copy_out_truncate = boolv(c, "copyOutTruncate");
        cmd.tty = boolv(c, "tty");
        if cmd.tty {
            let (tx, rx) = std::sync::mpsc::channel();
            cmd.terminal_resize = Some(Arc::new(std::sync::Mutex::new(rx)));
            resizes.insert(index as u32, tx);
        }
        cmd.data_segment_limit = boolv(c, "dataSegmentLimit") || boolv(c, "strictMemoryLimit");
        cmd.address_space_limit = boolv(c, "addressSpaceLimit");
        if let Some(fs) = c.get("files").and_then(Value::as_array) {
            for (fd, f) in fs.iter().enumerate() {
                if boolv(f, "streamIn") {
                    let (tx, rx) = tokio::sync::mpsc::channel(8);
                    inputs.insert((index as u32, fd as u32), tx);
                    cmd.files
                        .push(CmdFile::StreamIn(Arc::new(std::sync::Mutex::new(rx))));
                } else if boolv(f, "streamOut") {
                    let Some(output) = output.as_ref() else {
                        return Err((
                            StatusCode::BAD_REQUEST,
                            "streamOut is only valid on /stream".into(),
                        ));
                    };
                    cmd.files.push(CmdFile::StreamOut {
                        index: index as u32,
                        fd: fd as u32,
                        tx: output.clone(),
                    });
                } else {
                    cmd.files.push(convert_cmd_file(f, state)?);
                }
            }
        }
        if let Some(map) = c.get("copyIn").and_then(Value::as_object) {
            for (name, f) in map {
                if let Some(target) = f.get("symlink").and_then(Value::as_str) {
                    cmd.symlinks.insert(name.clone(), target.to_owned());
                    continue;
                }
                match convert_cmd_file(f, state)? {
                    CmdFile::Local(p) => {
                        cmd.copy_in.insert(name.clone(), CmdFile::Local(p));
                    }
                    CmdFile::Memory(b) => {
                        cmd.copy_in.insert(name.clone(), CmdFile::Memory(b));
                    }
                    CmdFile::Cached(id) => {
                        cmd.copy_in.insert(name.clone(), CmdFile::Cached(id));
                    }
                    other => {
                        return Err((
                            StatusCode::BAD_REQUEST,
                            format!("unsupported copyIn source {other}"),
                        ));
                    }
                }
            }
        }
        cmd.copy_out = copyouts(c, "copyOut");
        cmd.copy_out_cached = copyouts(c, "copyOutCached");
        req.commands.push(cmd);
    }
    if let Some(maps) = v.get("pipeMapping").and_then(Value::as_array) {
        for m in maps {
            let idx = |k: &str| {
                let x = &m[k];
                PipeIndex {
                    index: x["index"].as_u64().unwrap_or(0) as usize,
                    fd: x["fd"].as_u64().unwrap_or(0) as usize,
                }
            };
            req.pipe_mapping.push(PipeMap {
                input: idx("in"),
                output: idx("out"),
                cpu_set: text(m, "cpuSet"),
                name: text(m, "name"),
                // Go's JSON model decodes PipeMap.max as int64, then casts
                // it to the unsigned environment size type.
                limit: Size(signed_num(m, "max") as u64),
                proxy: boolv(m, "proxy"),
                disable_zero_copy: boolv(m, "disableZeroCopy"),
            });
        }
    }
    Ok((req, inputs, resizes))
}

fn validate_json_request_types(value: &Value) -> Result<(), String> {
    fn type_name(value: &Value) -> &'static str {
        match value {
            Value::Null => "null",
            Value::Bool(_) => "boolean",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        }
    }
    fn field<F>(object: &Value, key: &str, expected: &str, predicate: F) -> Result<(), String>
    where
        F: FnOnce(&Value) -> bool,
    {
        let Some(value) = object.get(key) else {
            return Ok(());
        };
        if value.is_null() || predicate(value) {
            Ok(())
        } else {
            Err(format!(
                "json: cannot unmarshal {} into Go struct field {key} of type {expected}",
                type_name(value)
            ))
        }
    }
    fn string_array(object: &Value, key: &str) -> Result<(), String> {
        field(object, key, "[]string", |value| {
            value
                .as_array()
                .is_some_and(|items| items.iter().all(Value::is_string))
        })
    }
    fn string_field(object: &Value, key: &str) -> Result<(), String> {
        field(object, key, "string", Value::is_string)
    }
    fn bool_field(object: &Value, key: &str) -> Result<(), String> {
        field(object, key, "bool", Value::is_boolean)
    }
    fn uint_field(object: &Value, key: &str) -> Result<(), String> {
        field(object, key, "uint64", |value| value.as_u64().is_some())
    }
    fn int_field(object: &Value, key: &str) -> Result<(), String> {
        field(object, key, "int64", |value| value.as_i64().is_some())
    }
    fn object_fields<F>(value: &Value, what: &str, validate: F) -> Result<(), String>
    where
        F: FnOnce(&Value) -> Result<(), String>,
    {
        if value.is_null() || value.is_object() {
            if value.is_object() {
                validate(value)
            } else {
                Ok(())
            }
        } else {
            Err(format!(
                "json: cannot unmarshal {} into Go struct field {what}",
                type_name(value)
            ))
        }
    }
    fn validate_file(file: &Value) -> Result<(), String> {
        object_fields(file, "CmdFile", |file| {
            for key in ["src", "content", "fileId", "name", "symlink"] {
                string_field(file, key)?;
            }
            int_field(file, "max")?;
            for key in ["streamIn", "streamOut", "pipe"] {
                bool_field(file, key)?;
            }
            Ok(())
        })
    }

    if !value.is_object() && !value.is_null() {
        return Err(format!(
            "json: cannot unmarshal {} into Go value of type model.Request",
            type_name(value)
        ));
    }
    string_field(value, "requestId")?;
    field(value, "cmd", "[]model.Cmd", Value::is_array)?;
    field(value, "pipeMapping", "[]model.PipeMap", Value::is_array)?;
    if let Some(commands) = value.get("cmd").and_then(Value::as_array) {
        for command in commands {
            object_fields(command, "Cmd", |command| {
                for key in ["args", "env", "copyOut", "copyOutCached"] {
                    string_array(command, key)?;
                }
                for key in [
                    "cpuLimit",
                    "realCpuLimit",
                    "clockLimit",
                    "memoryLimit",
                    "stackLimit",
                    "procLimit",
                    "cpuRateLimit",
                    "copyOutMax",
                ] {
                    uint_field(command, key)?;
                }
                for key in ["cpuSetLimit", "copyOutDir"] {
                    string_field(command, key)?;
                }
                for key in [
                    "copyOutTruncate",
                    "tty",
                    "strictMemoryLimit",
                    "dataSegmentLimit",
                    "addressSpaceLimit",
                ] {
                    bool_field(command, key)?;
                }
                if let Some(files) = command.get("files") {
                    field(command, "files", "[]*CmdFile", Value::is_array)?;
                    if let Some(files) = files.as_array() {
                        for file in files {
                            validate_file(file)?;
                        }
                    }
                }
                if let Some(copy_in) = command.get("copyIn") {
                    field(command, "copyIn", "map[string]CmdFile", Value::is_object)?;
                    if let Some(copy_in) = copy_in.as_object() {
                        for file in copy_in.values() {
                            validate_file(file)?;
                        }
                    }
                }
                Ok(())
            })?;
        }
    }
    if let Some(mappings) = value.get("pipeMapping").and_then(Value::as_array) {
        for mapping in mappings {
            object_fields(mapping, "PipeMap", |mapping| {
                for key in ["name"] {
                    string_field(mapping, key)?;
                }
                int_field(mapping, "max")?;
                for key in ["proxy", "disableZeroCopy"] {
                    bool_field(mapping, key)?;
                }
                for key in ["in", "out"] {
                    if let Some(index) = mapping.get(key) {
                        object_fields(index, "PipeIndex", |index| {
                            for component in ["index", "fd"] {
                                field(index, component, "int", |value| value.as_i64().is_some())?;
                            }
                            Ok(())
                        })?;
                    }
                }
                Ok(())
            })?;
        }
    }
    Ok(())
}

fn convert_cmd_file(v: &Value, state: &ServerState) -> Result<CmdFile, (StatusCode, String)> {
    if v.is_null() {
        return Ok(CmdFile::Null);
    }
    if let Some(s) = v.get("src").and_then(Value::as_str) {
        let p = PathBuf::from(s);
        if let Some(error) = source_path_error(&p, &state.config.src_prefix) {
            return Err(error);
        }
        return Ok(CmdFile::Local(p));
    }
    if let Some(s) = v.get("content").and_then(Value::as_str) {
        return Ok(CmdFile::Memory(s.as_bytes().to_vec()));
    }
    if let Some(s) = v.get("fileId").and_then(Value::as_str) {
        if state.files.get(s).is_none() {
            return Err((
                StatusCode::NOT_FOUND,
                format!("file does not exist with id {s:?}"),
            ));
        }
        return Ok(CmdFile::Cached(s.into()));
    }
    if let (Some(name), Some(max)) = (
        v.get("name").and_then(Value::as_str),
        v.get("max").and_then(Value::as_i64),
    ) {
        return Ok(CmdFile::Collector {
            name: name.to_owned(),
            // Match Go's int64-to-Size conversion for negative max values.
            max: Size(max as u64),
            pipe: boolv(v, "pipe"),
        });
    }
    if v.get("symlink").is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            "symlink entries require the copyIn map form".into(),
        ));
    }
    Err((StatusCode::BAD_REQUEST, "invalid command file".into()))
}

fn source_path_allowed(path: &std::path::Path, prefixes: &[String]) -> bool {
    if prefixes.is_empty() {
        return true;
    }
    let Some(source) = resolve_source_path(path) else {
        return false;
    };
    prefixes.iter().any(|prefix| {
        resolve_source_path(std::path::Path::new(prefix))
            .is_some_and(|prefix| source.starts_with(prefix))
    })
}

fn source_path_error(path: &std::path::Path, prefixes: &[String]) -> Option<(StatusCode, String)> {
    if path.as_os_str().is_empty() {
        return Some((StatusCode::BAD_REQUEST, "source path is empty".into()));
    }
    if !source_path_allowed(path, prefixes) {
        return Some((
            StatusCode::BAD_REQUEST,
            format!(
                "file ({}) does not under ([{}])",
                path.display(),
                prefixes.join(" ")
            ),
        ));
    }
    if !path.exists() {
        return Some((
            StatusCode::NOT_FOUND,
            format!(
                "source file does not exist {:?}: file not found",
                path.display()
            ),
        ));
    }
    None
}

/// Resolve existing symlinks and preserve a missing suffix, matching Go's
/// source-prefix check. This keeps missing files under an allowed prefix
/// distinguishable from missing paths outside it.
fn resolve_source_path(path: &std::path::Path) -> Option<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(path)
    };
    let mut cursor = absolute;
    let mut suffix = Vec::new();
    loop {
        if let Ok(mut resolved) = std::fs::canonicalize(&cursor) {
            for component in suffix.iter().rev() {
                resolved.push(component);
            }
            return Some(resolved);
        }
        let name = cursor.file_name()?.to_os_string();
        suffix.push(name);
        if !cursor.pop() {
            return None;
        }
    }
}

fn strings(v: &Value, k: &str) -> Vec<String> {
    v.get(k)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}
fn num(v: &Value, k: &str) -> u64 {
    v.get(k).and_then(Value::as_u64).unwrap_or(0)
}
fn signed_num(v: &Value, k: &str) -> i64 {
    v.get(k).and_then(Value::as_i64).unwrap_or(0)
}
fn boolv(v: &Value, k: &str) -> bool {
    v.get(k).and_then(Value::as_bool).unwrap_or(false)
}
fn text(v: &Value, k: &str) -> String {
    v.get(k)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}
fn copyouts(v: &Value, k: &str) -> Vec<CopyOutFile> {
    strings(v, k)
        .into_iter()
        .map(|n| {
            let optional = n.ends_with('?');
            CopyOutFile {
                name: if optional {
                    n[..n.len() - 1].to_owned()
                } else {
                    n
                },
                optional,
            }
        })
        .collect()
}
fn mime_guess(name: &str) -> &'static str {
    match name
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "txt" | "log" | "go" | "rs" | "c" | "cpp" | "h" => "text/plain; charset=utf-8",
        "json" => "application/json",
        "html" | "htm" => "text/html",
        _ => "application/octet-stream",
    }
}

pub async fn serve_http(addr: SocketAddr, state: ServerState) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, http_router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(std::io::Error::other)
}
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut terminate) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = terminate.recv() => {},
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
pub async fn serve_grpc(
    addr: SocketAddr,
    state: ServerState,
) -> Result<(), tonic::transport::Error> {
    let service = grpc_proto::executor_server::ExecutorServer::new(GrpcApi(state.clone()))
        .max_decoding_message_size(state.config.grpc_msg_size.0.min(usize::MAX as u64) as usize);
    let mut server = tonic::transport::Server::builder();
    if state.config.auth_token.is_empty() {
        server
            .add_service(service)
            .serve_with_shutdown(addr, shutdown_signal())
            .await
    } else {
        let token = state.config.auth_token.clone();
        server
            .add_service(tonic::service::interceptor::InterceptedService::new(
                service,
                move |request| authenticate_grpc(request, &token),
            ))
            .serve_with_shutdown(addr, shutdown_signal())
            .await
    }
}

fn authenticate_grpc<T>(
    request: tonic::Request<T>,
    token: &str,
) -> Result<tonic::Request<T>, tonic::Status> {
    let authorized = request
        .metadata()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        == Some(token);
    if authorized {
        Ok(request)
    } else {
        Err(tonic::Status::unauthenticated("invalid auth token"))
    }
}

struct GrpcApi(ServerState);

async fn store_file_stream<S>(
    files: &LocalFileStore,
    mut stream: S,
) -> Result<grpc_proto::FileId, tonic::Status>
where
    S: futures_util::Stream<Item = Result<grpc_proto::FileContent, tonic::Status>> + Unpin,
{
    use futures_util::StreamExt;
    let first = stream
        .next()
        .await
        .transpose()?
        .ok_or_else(|| tonic::Status::invalid_argument("file upload stream is empty"))?;
    observe_grpc_message("client_stream", "FileAddStream", false);
    let (id, mut file) = files
        .new_file()
        .map_err(|e| tonic::Status::internal(e.to_string()))?;
    let name = first.name;
    let upload_result = async {
        file.write_all(&first.content)
            .map_err(|e| tonic::Status::internal(e.to_string()))?;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            observe_grpc_message("client_stream", "FileAddStream", false);
            if !chunk.name.is_empty() && chunk.name != name {
                return Err(tonic::Status::invalid_argument(format!(
                    "file name changed during upload: {name:?} -> {:?}",
                    chunk.name
                )));
            }
            file.write_all(&chunk.content)
                .map_err(|e| tonic::Status::internal(e.to_string()))?;
        }
        Ok(())
    }
    .await;
    drop(file);
    if let Err(error) = upload_result {
        files.remove(&id);
        return Err(error);
    }
    if let Err(error) = files.set_name(&id, name) {
        files.remove(&id);
        return Err(tonic::Status::internal(error.to_string()));
    }
    Ok(grpc_proto::FileId { file_id: id })
}

fn proto_file(
    file: &grpc_proto::request::File,
    state: &ServerState,
) -> Result<CmdFile, tonic::Status> {
    use grpc_proto::request::file::File as F;
    match file
        .file
        .as_ref()
        .ok_or_else(|| tonic::Status::invalid_argument("missing command file source"))?
    {
        F::Local(f) => {
            let path = PathBuf::from(&f.src);
            if let Some((status, message)) = source_path_error(&path, &state.config.src_prefix) {
                return Err(if status == StatusCode::NOT_FOUND {
                    tonic::Status::not_found(message)
                } else {
                    tonic::Status::invalid_argument(message)
                });
            }
            Ok(CmdFile::Local(path))
        }
        F::Memory(f) => Ok(CmdFile::Memory(f.content.clone())),
        F::Cached(f) => {
            if state.files.get(&f.file_id).is_none() {
                Err(tonic::Status::not_found("file not found"))
            } else {
                Ok(CmdFile::Cached(f.file_id.clone()))
            }
        }
        F::Pipe(p) => Ok(CmdFile::Collector {
            name: p.name.clone(),
            max: Size(p.max.max(0) as u64),
            pipe: p.pipe,
        }),
        F::StreamIn(()) | F::StreamOut(()) => Err(tonic::Status::invalid_argument(
            "stream files require ExecStream",
        )),
    }
}

fn stream_conversion_error(error: tonic::Status) -> tonic::Status {
    tonic::Status::internal(format!("convert exec request: {error}"))
}

async fn send_exec_stream_message(
    sender: &tokio::sync::mpsc::Sender<Result<grpc_proto::StreamResponse, tonic::Status>>,
    message: Result<grpc_proto::StreamResponse, tonic::Status>,
) -> Result<
    (),
    tokio::sync::mpsc::error::SendError<Result<grpc_proto::StreamResponse, tonic::Status>>,
> {
    let sent = message.is_ok();
    sender.send(message).await?;
    if sent {
        observe_grpc_message("bidi_stream", "ExecStream", true);
    }
    Ok(())
}

#[tonic::async_trait]
impl grpc_proto::executor_server::Executor for GrpcApi {
    async fn exec(
        &self,
        req: tonic::Request<grpc_proto::Request>,
    ) -> Result<tonic::Response<grpc_proto::Response>, tonic::Status> {
        instrument_grpc("unary", "Exec", async {
            let cancellation = CancellationToken::default();
            let mut cancel_on_drop = CancelOnDrop::new(cancellation.clone());
            let input = req.into_inner();
            let mut request = Request {
                request_id: input.request_id.clone(),
                ..Request::default()
            };
            for c in input.cmd {
                let mut cmd = Command {
                    args: c.args,
                    env: c.env,
                    tty: c.tty,
                    cpu_limit: Duration::from_nanos(c.cpu_time_limit),
                    clock_limit: Duration::from_nanos(c.clock_time_limit),
                    memory_limit: Size(c.memory_limit),
                    stack_limit: Size(c.stack_limit),
                    proc_limit: c.proc_limit,
                    cpu_rate_limit: c.cpu_rate_limit,
                    cpu_set_limit: c.cpu_set_limit,
                    copy_out_max: c.copy_out_max,
                    copy_out_truncate: c.copy_out_truncate,
                    data_segment_limit: c.data_segment_limit,
                    address_space_limit: c.address_space_limit,
                    ..Command::default()
                };
                cmd.files = c
                    .files
                    .iter()
                    .map(|f| proto_file(f, &self.0))
                    .collect::<Result<_, _>>()?;
                for (n, f) in c.copy_in {
                    cmd.copy_in.insert(n, proto_file(&f, &self.0)?);
                }
                cmd.symlinks = c.symlinks;
                cmd.copy_out = c
                    .copy_out
                    .into_iter()
                    .map(|f| CopyOutFile {
                        name: f.name,
                        optional: f.optional,
                    })
                    .collect();
                cmd.copy_out_cached = c
                    .copy_out_cached
                    .into_iter()
                    .map(|f| CopyOutFile {
                        name: f.name,
                        optional: f.optional,
                    })
                    .collect();
                request.commands.push(cmd);
            }
            for m in input.pipe_mapping {
                let idx = |p: Option<grpc_proto::request::pipe_map::PipeIndex>| {
                    p.map(|x| PipeIndex {
                        index: x.index.max(0) as usize,
                        fd: x.fd.max(0) as usize,
                    })
                    .unwrap_or_default()
                };
                request.pipe_mapping.push(PipeMap {
                    input: idx(m.r#in),
                    output: idx(m.out),
                    name: m.name,
                    limit: Size(m.max),
                    proxy: m.proxy,
                    disable_zero_copy: m.disable_zero_copy,
                    ..PipeMap::default()
                });
            }
            let (rx, _started) = self.0.worker.submit(request, cancellation);
            let result = rx
                .await
                .map_err(|_| tonic::Status::internal("worker response channel closed"))?;
            cancel_on_drop.disarm();
            if let Some(error) = result.error.as_ref() {
                return Err(worker_grpc_error_status(error));
            }
            let results = result
                .results
                .into_iter()
                .map(|mut r| {
                    let mut files = std::collections::HashMap::new();
                    for (n, mut f) in r.files.drain() {
                        let mut b = Vec::new();
                        let _ = f.read_to_end(&mut b);
                        files.insert(n, b);
                    }
                    grpc_proto::response::Result {
                        status: r.status as i32,
                        exit_status: r.exit_status,
                        error: r.error,
                        time: r.time.as_nanos() as u64,
                        run_time: r.run_time.as_nanos() as u64,
                        proc_peak: r.proc_peak,
                        exit_order: r.exit_order as i32,
                        memory: r.memory.0,
                        files,
                        file_i_ds: r.file_ids,
                        file_error: r
                            .file_errors
                            .into_iter()
                            .map(|e| grpc_proto::response::FileError {
                                name: e.name,
                                r#type: grpc_file_error_type(e.kind),
                                message: e.message,
                            })
                            .collect(),
                    }
                })
                .collect();
            Ok(tonic::Response::new(grpc_proto::Response {
                request_id: result.request_id,
                results,
                error: result.error.unwrap_or_default(),
            }))
        })
        .await
    }
    type ExecStreamStream = InstrumentedGrpcStream<
        tokio_stream::wrappers::ReceiverStream<Result<grpc_proto::StreamResponse, tonic::Status>>,
    >;
    async fn exec_stream(
        &self,
        req: tonic::Request<tonic::Streaming<grpc_proto::StreamRequest>>,
    ) -> Result<tonic::Response<Self::ExecStreamStream>, tonic::Status> {
        instrument_grpc_stream("bidi_stream", "ExecStream", async {
        use grpc_proto::{stream_request, stream_response};
        let mut incoming = req.into_inner();
        let first = incoming
            .message()
            .await
            .map_err(|error| tonic::Status::internal(error.to_string()))?;
        if first.is_some() {
            observe_grpc_message("bidi_stream", "ExecStream", false);
        }
        let first = first.ok_or_else(|| tonic::Status::internal("missing exec request"))?;
        let Some(stream_request::Request::ExecRequest(input)) = first.request else {
            return Err(tonic::Status::internal(
                "the first stream request must be exec request",
            ));
        };
        let (output_tx, mut output_rx) =
            tokio::sync::mpsc::channel::<crate::worker::StreamOutput>(32);
        let mut input_tx =
            std::collections::HashMap::<(u32, u32), tokio::sync::mpsc::Sender<Vec<u8>>>::new();
        let mut resize_tx = std::collections::HashMap::<
            u32,
            std::sync::mpsc::Sender<crate::worker::TerminalSize>,
        >::new();
        let mut request = Request {
            request_id: input.request_id.clone(),
            ..Request::default()
        };
        for (index, c) in input.cmd.into_iter().enumerate() {
            let mut cmd = Command {
                args: c.args,
                env: c.env,
                tty: c.tty,
                cpu_limit: Duration::from_nanos(c.cpu_time_limit),
                clock_limit: Duration::from_nanos(c.clock_time_limit),
                memory_limit: Size(c.memory_limit),
                stack_limit: Size(c.stack_limit),
                proc_limit: c.proc_limit,
                cpu_rate_limit: c.cpu_rate_limit,
                cpu_set_limit: c.cpu_set_limit,
                copy_out_max: c.copy_out_max,
                copy_out_truncate: c.copy_out_truncate,
                data_segment_limit: c.data_segment_limit,
                address_space_limit: c.address_space_limit,
                ..Command::default()
            };
            if cmd.tty {
                let (tx, rx) = std::sync::mpsc::channel();
                cmd.terminal_resize = Some(Arc::new(std::sync::Mutex::new(rx)));
                resize_tx.insert(index as u32, tx);
            }
            for (fd, file) in c.files.into_iter().enumerate() {
                use grpc_proto::request::file::File as Source;
                let command_file = match file.file.as_ref() {
                    Some(Source::StreamIn(())) => {
                        let (tx, rx) = tokio::sync::mpsc::channel(8);
                        input_tx.insert((index as u32, fd as u32), tx);
                        CmdFile::StreamIn(Arc::new(std::sync::Mutex::new(rx)))
                    }
                    Some(Source::StreamOut(())) => CmdFile::StreamOut {
                        index: index as u32,
                        fd: fd as u32,
                        tx: output_tx.clone(),
                    },
                    _ => proto_file(&file, &self.0).map_err(stream_conversion_error)?,
                };
                cmd.files.push(command_file);
            }
            for (name, file) in c.copy_in {
                cmd.copy_in.insert(
                    name,
                    proto_file(&file, &self.0).map_err(stream_conversion_error)?,
                );
            }
            cmd.symlinks = c.symlinks;
            cmd.copy_out = c
                .copy_out
                .into_iter()
                .map(|f| CopyOutFile {
                    name: f.name,
                    optional: f.optional,
                })
                .collect();
            cmd.copy_out_cached = c
                .copy_out_cached
                .into_iter()
                .map(|f| CopyOutFile {
                    name: f.name,
                    optional: f.optional,
                })
                .collect();
            request.commands.push(cmd);
        }
        for mapping in input.pipe_mapping {
            let idx = |p: Option<grpc_proto::request::pipe_map::PipeIndex>| {
                p.map(|x| PipeIndex {
                    index: x.index.max(0) as usize,
                    fd: x.fd.max(0) as usize,
                })
                .unwrap_or_default()
            };
            request.pipe_mapping.push(PipeMap {
                input: idx(mapping.r#in),
                output: idx(mapping.out),
                name: mapping.name,
                limit: Size(mapping.max),
                proxy: mapping.proxy,
                disable_zero_copy: mapping.disable_zero_copy,
                ..PipeMap::default()
            });
        }
        let cancellation = CancellationToken::default();
        let response_task = self.0.worker.execute(request, cancellation.clone());
        let (send_tx, send_rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move {
            tokio::pin!(response_task);
            let mut input_open = true;
            let mut output_open = true;
            loop {
                tokio::select! {
                    message = incoming.message(), if input_open => match message {
                        Ok(Some(message)) => {
                            observe_grpc_message("bidi_stream", "ExecStream", false);
                            match message.request {
                            Some(stream_request::Request::ExecInput(input)) => {
                                let key = (input.index,input.fd);
                                if let Some(sender) = input_tx.get(&key) {
                                    if sender.send(input.content).await.is_err() {
                                        input_tx.remove(&key);
                                        input_open = false;
                                        input_tx.clear();
                                    }
                                } else {
                                    cancellation.cancel();
                                    let _ = send_tx
                                        .send(Err(tonic::Status::internal(format!(
                                            "input does not exist: {}/{}",
                                            input.index, input.fd
                                        ))))
                                        .await;
                                    break;
                                }
                            }
                            Some(stream_request::Request::ExecCancel(())) => {
                                cancellation.cancel();
                                input_tx.clear();
                                input_open = false;
                            }
                            Some(stream_request::Request::ExecResize(resize)) => {
                                let key = (resize.index, resize.fd);
                                if !input_tx.contains_key(&key) {
                                    cancellation.cancel();
                                    let _ = send_tx
                                        .send(Err(tonic::Status::internal(format!(
                                            "input does not exist: {}/{}",
                                            resize.index, resize.fd
                                        ))))
                                        .await;
                                    break;
                                }
                                let Some(sender) = resize_tx.get(&resize.index) else {
                                    cancellation.cancel();
                                    let _ = send_tx
                                        .send(Err(tonic::Status::internal(format!(
                                            "resize {}/{}: stream is not a tty",
                                            resize.index, resize.fd
                                        ))))
                                        .await;
                                    break;
                                };
                                let _ = sender.send(crate::worker::TerminalSize {
                                    rows: resize.rows.min(u16::MAX as u32) as u16,
                                    cols: resize.cols.min(u16::MAX as u32) as u16,
                                    x: resize.x.min(u16::MAX as u32) as u16,
                                    y: resize.y.min(u16::MAX as u32) as u16,
                                });
                            }
                            Some(stream_request::Request::ExecRequest(_)) | None => {
                                cancellation.cancel();
                                let _ = send_tx.send(Err(tonic::Status::internal("invalid stream request"))).await;
                                break;
                            }
                            }
                        },
                        Ok(None) => { input_tx.clear(); input_open = false; }
                        Err(error) => {
                            input_tx.clear();
                            cancellation.cancel();
                            let _ = send_tx.send(Err(tonic::Status::internal(error.to_string()))).await;
                            break;
                        }
                    },
                    output = output_rx.recv(), if output_open => match output {
                        Some(output) => {
                            if send_exec_stream_message(&send_tx, Ok(grpc_proto::StreamResponse { response: Some(stream_response::Response::ExecOutput(stream_response::Output { index: output.index, fd: output.fd, content: output.content })) })).await.is_err() { cancellation.cancel(); break; }
                        }
                        None => output_open = false,
                    },
                    result = &mut response_task => {
                        let response = match result {
                            Ok(response) => response,
                            _ => { let _ = send_tx.send(Err(tonic::Status::internal("worker response channel closed"))).await; break; }
                        };
                        drop(input_tx);
                        while let Some(output) = output_rx.recv().await {
                            if send_exec_stream_message(&send_tx, Ok(grpc_proto::StreamResponse { response: Some(stream_response::Response::ExecOutput(stream_response::Output { index: output.index, fd: output.fd, content: output.content })) })).await.is_err() { break; }
                        }
                        match grpc_response(response) {
                            Ok(response) => { let _ = send_exec_stream_message(&send_tx, Ok(grpc_proto::StreamResponse { response: Some(stream_response::Response::ExecResponse(response)) })).await; }
                            Err(error) => { let _ = send_tx.send(Err(error)).await; }
                        }
                        break;
                    }
                }
            }
        });
        Ok(tonic::Response::new(
            tokio_stream::wrappers::ReceiverStream::new(send_rx),
        ))
        })
        .await
    }
    async fn file_list(
        &self,
        _: tonic::Request<()>,
    ) -> Result<tonic::Response<grpc_proto::FileListType>, tonic::Status> {
        instrument_grpc("unary", "FileList", async {
            Ok(tonic::Response::new(grpc_proto::FileListType {
                file_i_ds: self
                    .0
                    .files
                    .list()
                    .map_err(|e| tonic::Status::internal(e.to_string()))?,
            }))
        })
        .await
    }
    async fn file_get(
        &self,
        req: tonic::Request<grpc_proto::FileId>,
    ) -> Result<tonic::Response<grpc_proto::FileContent>, tonic::Status> {
        instrument_grpc("unary", "FileGet", async {
            let id = req.into_inner().file_id;
            let (name, mut f) = self
                .0
                .files
                .get(&id)
                .ok_or_else(|| tonic::Status::not_found(format!("file not found: {id:?}")))?;
            let mut content = Vec::new();
            f.read_to_end(&mut content)
                .map_err(|e| tonic::Status::internal(e.to_string()))?;
            Ok(tonic::Response::new(grpc_proto::FileContent {
                name,
                content,
            }))
        })
        .await
    }
    type FileGetStreamStream = InstrumentedGrpcStream<
        tokio_stream::wrappers::ReceiverStream<Result<grpc_proto::FileContent, tonic::Status>>,
    >;
    async fn file_get_stream(
        &self,
        req: tonic::Request<grpc_proto::FileId>,
    ) -> Result<tonic::Response<Self::FileGetStreamStream>, tonic::Status> {
        instrument_grpc_stream("server_stream", "FileGetStream", async {
            let (tx, rx) = tokio::sync::mpsc::channel(2);
            let id = req.into_inner().file_id;
            let (name, file) = self
                .0
                .files
                .get(&id)
                .ok_or_else(|| tonic::Status::not_found(format!("file not found: {id:?}")))?;
            tokio::task::spawn_blocking(move || {
                let mut file = file;
                let mut buffer = vec![0; 1 << 20];
                let mut first = true;
                loop {
                    match file.read(&mut buffer) {
                        Ok(0) if first => {
                            observe_grpc_message("server_stream", "FileGetStream", true);
                            let _ = tx.blocking_send(Ok(grpc_proto::FileContent {
                                name: name.clone(),
                                content: Vec::new(),
                            }));
                            break;
                        }
                        Ok(0) => break,
                        Ok(count) => {
                            observe_grpc_message("server_stream", "FileGetStream", true);
                            let chunk_name = if first {
                                first = false;
                                name.clone()
                            } else {
                                String::new()
                            };
                            if tx
                                .blocking_send(Ok(grpc_proto::FileContent {
                                    name: chunk_name,
                                    content: buffer[..count].to_vec(),
                                }))
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(error) => {
                            let _ =
                                tx.blocking_send(Err(tonic::Status::internal(error.to_string())));
                            break;
                        }
                    }
                }
            });
            Ok(tonic::Response::new(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            ))
        })
        .await
    }
    async fn file_add(
        &self,
        req: tonic::Request<grpc_proto::FileContent>,
    ) -> Result<tonic::Response<grpc_proto::FileId>, tonic::Status> {
        instrument_grpc("unary", "FileAdd", async {
            let v = req.into_inner();
            let (id, mut f) = self
                .0
                .files
                .new_file()
                .map_err(|e| tonic::Status::internal(e.to_string()))?;
            f.write_all(&v.content)
                .map_err(|e| tonic::Status::internal(e.to_string()))?;
            self.0
                .files
                .set_name(&id, v.name)
                .map_err(|e| tonic::Status::internal(e.to_string()))?;
            Ok(tonic::Response::new(grpc_proto::FileId { file_id: id }))
        })
        .await
    }
    async fn file_add_stream(
        &self,
        req: tonic::Request<tonic::Streaming<grpc_proto::FileContent>>,
    ) -> Result<tonic::Response<grpc_proto::FileId>, tonic::Status> {
        instrument_grpc("client_stream", "FileAddStream", async {
            store_file_stream(&self.0.files, req.into_inner())
                .await
                .map(tonic::Response::new)
        })
        .await
    }
    async fn file_delete(
        &self,
        req: tonic::Request<grpc_proto::FileId>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        instrument_grpc("unary", "FileDelete", async {
            let id = req.into_inner().file_id;
            if self.0.files.remove(&id) {
                Ok(tonic::Response::new(()))
            } else {
                Err(tonic::Status::not_found(format!(
                    "file id does not exist: {id:?}"
                )))
            }
        })
        .await
    }
}
pub async fn serve(
    http: Option<SocketAddr>,
    grpc: Option<SocketAddr>,
    state: ServerState,
) -> std::io::Result<()> {
    serve_with_monitor(http, grpc, None, state).await
}

pub async fn serve_with_monitor(
    http: Option<SocketAddr>,
    grpc: Option<SocketAddr>,
    monitor: Option<SocketAddr>,
    state: ServerState,
) -> std::io::Result<()> {
    match (http, grpc) {
        (Some(h), Some(g)) => {
            let hs = state.clone();
            let gs = state;
            serve_servers(h, hs, Some(g), gs, monitor).await
        }
        (Some(h), None) => serve_servers(h, state.clone(), None, state, monitor).await,
        (None, Some(g)) => serve_servers_grpc_only(g, state, monitor).await,
        (None, None) => match monitor {
            Some(m) => serve_monitor(m, state).await,
            None => Ok(()),
        },
    }
}

async fn serve_servers(
    http: SocketAddr,
    http_state: ServerState,
    grpc: Option<SocketAddr>,
    grpc_state: ServerState,
    monitor: Option<SocketAddr>,
) -> std::io::Result<()> {
    match (grpc, monitor) {
        (Some(grpc), Some(monitor)) => {
            let monitor_state = grpc_state.clone();
            tokio::try_join!(
                serve_http(http, http_state),
                async move {
                    serve_grpc(grpc, grpc_state)
                        .await
                        .map_err(std::io::Error::other)
                },
                async move { serve_monitor(monitor, monitor_state).await },
            )?;
        }
        (Some(grpc), None) => {
            tokio::try_join!(serve_http(http, http_state), async move {
                serve_grpc(grpc, grpc_state)
                    .await
                    .map_err(std::io::Error::other)
            },)?;
        }
        (None, Some(monitor)) => {
            tokio::try_join!(
                serve_http(http, http_state),
                serve_monitor(monitor, grpc_state),
            )?;
        }
        (None, None) => serve_http(http, http_state).await?,
    }
    Ok(())
}

async fn serve_servers_grpc_only(
    grpc: SocketAddr,
    state: ServerState,
    monitor: Option<SocketAddr>,
) -> std::io::Result<()> {
    match monitor {
        Some(monitor) => {
            let monitor_state = state.clone();
            tokio::try_join!(
                async move { serve_grpc(grpc, state).await.map_err(std::io::Error::other) },
                serve_monitor(monitor, monitor_state),
            )?;
            Ok(())
        }
        None => serve_grpc(grpc, state).await.map_err(std::io::Error::other),
    }
}

async fn serve_monitor(addr: SocketAddr, state: ServerState) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, monitor_router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(std::io::Error::other)
}

#[cfg(test)]
mod tests {
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
        fn open(
            &self,
            _: &[crate::envexec::OpenParam],
        ) -> io::Result<Vec<crate::envexec::OpenResult>> {
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
        assert!(
            text.contains("go_judge_exec_time_seconds_bucket{status=\"Accepted\",le=\"0.025\"} 1")
        );
        assert!(text.contains("go_judge_exec_time_seconds_count{status=\"Accepted\"} 1"));
        assert!(
            text.contains("go_judge_exec_memory_bytes_bucket{status=\"Accepted\",le=\"8192\"} 1")
        );
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

        let (tx, rx) =
            tokio::sync::mpsc::channel::<Result<grpc_proto::FileContent, tonic::Status>>(1);
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
                    .ok_or_else(|| io::Error::other("missing pty fd"))?
                    as RawFd;
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

        let dir =
            std::env::temp_dir().join(format!("rust-sandbox-resize-grpc-{}", std::process::id()));
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
            if let Some(grpc_proto::stream_response::Response::ExecResponse(result)) =
                message.response
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
        let dir =
            std::env::temp_dir().join(format!("rust-sandbox-rest-output-{}", std::process::id()));
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

        let prefix =
            std::env::temp_dir().join(format!("rust-sandbox-source-{}", std::process::id()));
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
}
