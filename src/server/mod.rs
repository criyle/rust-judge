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

pub fn http_router(state: ServerState) -> Router {
    let auth_token = state.config.auth_token.clone();
    let enable_metrics = state.config.enable_metrics;
    let state = Arc::new(state);
    let public: Router = Router::new()
        .route("/version", get(version))
        .route("/config", get(config))
        .with_state(state.clone());
    let protected: Router = Router::new()
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
    let mut router: Router<Arc<ServerState>> = Router::new();
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

mod debug;
mod grpc;
mod json;
mod metrics;
mod websocket;
use debug::{
    debug_cmdline, debug_index, debug_named_profile, debug_profile, debug_symbol, debug_trace,
};
pub use grpc::serve_grpc;
use json::*;
pub use metrics::observe_execution;
#[cfg(test)]
use metrics::{
    GrpcCallMeasurement, append_execution_metrics, append_grpc_metrics, append_http_metrics,
};
use metrics::{
    InstrumentedGrpcStream, instrument_grpc, instrument_grpc_stream, metrics, observe_grpc_message,
    record_http_request,
};
use websocket::{websocket_run, websocket_stream};

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
mod tests;
