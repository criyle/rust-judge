use super::*;

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

pub(super) async fn metrics(State(state): State<Arc<ServerState>>) -> impl IntoResponse {
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

pub(super) async fn record_http_request(request: AxumRequest, next: Next) -> Response {
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
        .or_else(|| {
            response
                .headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
        })
        .unwrap_or_default();
    observe_http_request(HttpRequestObservation {
        code,
        method,
        handler,
        host,
        url,
        duration: started.elapsed().as_secs_f64(),
        request_size,
        response_size,
    });
    response
}

fn http_route_label(path: &str) -> String {
    match path {
        "/version" | "/config" | "/file" | "/run" | "/ws" | "/stream" => path.to_owned(),
        path if path.starts_with("/file/") => "/file/{fid}".into(),
        _ => path.to_owned(),
    }
}

struct HttpRequestObservation {
    code: String,
    method: String,
    handler: String,
    host: String,
    url: String,
    duration: f64,
    request_size: u64,
    response_size: u64,
}

fn observe_http_request(observation: HttpRequestObservation) {
    let Ok(mut metrics) = HTTP_REQUEST_METRICS.lock() else {
        return;
    };
    *metrics
        .count
        .entry((
            observation.code.clone(),
            observation.method.clone(),
            observation.handler,
            observation.host,
            observation.url.clone(),
        ))
        .or_default() += 1;
    metrics
        .duration
        .entry((observation.code, observation.method, observation.url))
        .or_default()
        .observe(observation.duration, &HTTP_DURATION_BUCKETS);
    metrics.request_size.observe(observation.request_size);
    metrics.response_size.observe(observation.response_size);
}

pub(super) fn append_http_metrics(body: &mut String) {
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

pub(super) async fn instrument_grpc<T>(
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
pub(super) struct GrpcCallMeasurement {
    rpc_type: &'static str,
    method: &'static str,
    started: std::time::Instant,
    enabled: bool,
    pub(super) finished: bool,
}

impl GrpcCallMeasurement {
    pub(super) fn start(rpc_type: &'static str, method: &'static str) -> Self {
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

    pub(super) fn finish(&mut self, code: tonic::Code) {
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

pub(super) struct InstrumentedGrpcStream<S> {
    inner: S,
    pub(super) measurement: GrpcCallMeasurement,
}

impl<S> InstrumentedGrpcStream<S> {
    pub(super) fn new(inner: S, measurement: GrpcCallMeasurement) -> Self {
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

pub(super) async fn instrument_grpc_stream<S, T>(
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

pub(super) fn observe_grpc_message(rpc_type: &str, method: &str, sent: bool) {
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

pub(super) fn append_grpc_metrics(body: &mut String) {
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

pub(super) fn append_file_size_metrics(body: &mut String) {
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

pub(super) fn append_execution_metrics(body: &mut String) {
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
