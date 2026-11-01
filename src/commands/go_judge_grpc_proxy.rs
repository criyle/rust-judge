//! REST-to-gRPC proxy matching `cmd/go-judge-grpc-proxy`.

use crate::server::grpc_proto as pb;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Multipart, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get as get_route, post},
};
use base64::Engine;
use serde_json::{Map, Value, json};
use std::fmt;
use tonic::{Request, Status, metadata::MetadataValue, transport::Channel};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyConfig {
    pub listen_addr: String,
    pub grpc_addr: String,
    pub token: String,
}
impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: ":7755".into(),
            grpc_addr: "localhost:5051".into(),
            token: String::new(),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ProxyConfigError {
    Help,
    MissingValue(String),
    UnknownOption(String),
}
impl fmt::Display for ProxyConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Help => f.write_str("help requested"),
            Self::MissingValue(n) => write!(f, "option {n} requires a value"),
            Self::UnknownOption(n) => write!(f, "unknown option {n}"),
        }
    }
}
impl std::error::Error for ProxyConfigError {}

impl ProxyConfig {
    pub fn parse<I, S>(args: I, token: impl Into<String>) -> Result<Self, ProxyConfigError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut args: Vec<String> = args.into_iter().map(Into::into).collect();
        if !args.is_empty() && !args[0].starts_with('-') {
            args.remove(0);
        }
        let mut config = Self {
            token: token.into(),
            ..Default::default()
        };
        let mut i = 0;
        while i < args.len() {
            if matches!(args[i].as_str(), "-h" | "--help" | "-help") {
                return Err(ProxyConfigError::Help);
            }
            if args[i] == "--" || !args[i].starts_with('-') {
                break;
            }
            let raw = args[i].trim_start_matches('-');
            let (name, inline) = raw
                .split_once('=')
                .map_or((raw, None), |(n, v)| (n, Some(v.to_owned())));
            if !matches!(name, "addr" | "srvaddr") {
                return Err(ProxyConfigError::UnknownOption(name.into()));
            }
            let value = if let Some(value) = inline {
                value
            } else {
                i += 1;
                args.get(i)
                    .cloned()
                    .ok_or_else(|| ProxyConfigError::MissingValue(name.into()))?
            };
            match name {
                "addr" => config.listen_addr = value,
                "srvaddr" => config.grpc_addr = value,
                _ => unreachable!(),
            }
            i += 1;
        }
        Ok(config)
    }
}

pub const USAGE: &str = "Usage: rust-judge-grpc-proxy [-addr=:7755] [-srvaddr=localhost:5051]\n";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum GrpcCode {
    Canceled = 1,
    InvalidArgument = 3,
    DeadlineExceeded = 4,
    NotFound = 5,
    PermissionDenied = 7,
    ResourceExhausted = 8,
    Unauthenticated = 16,
    Unavailable = 14,
    Other = 0,
}

pub fn grpc_http_status(code: GrpcCode) -> u16 {
    grpc_http_status_code(code as i32)
}

pub fn grpc_http_status_code(code: i32) -> u16 {
    match code {
        3 => 400,
        5 => 404,
        16 => 401,
        7 => 403,
        8 => 429,
        1 => 499,
        4 => 504,
        14 => 503,
        _ => 500,
    }
}

fn status_code(status: &Status) -> StatusCode {
    StatusCode::from_u16(grpc_http_status_code(status.code() as i32))
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
}

#[derive(Clone)]
struct ProxyState {
    client: pb::executor_client::ExecutorClient<Channel>,
    token: Option<MetadataValue<tonic::metadata::Ascii>>,
}

fn grpc_request<T>(value: T, token: &Option<MetadataValue<tonic::metadata::Ascii>>) -> Request<T> {
    let mut request = Request::new(value);
    if let Some(value) = token {
        request
            .metadata_mut()
            .insert("authorization", value.clone());
    }
    request
}

/// Build and run the REST listener. Tonic's lazy channel lets the HTTP server
/// bind before the upstream gRPC server becomes available, matching grpc.NewClient.
pub async fn serve(config: ProxyConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let grpc_uri = if config.grpc_addr.contains("://") {
        config.grpc_addr.clone()
    } else {
        format!("http://{}", config.grpc_addr)
    };
    let endpoint = tonic::transport::Endpoint::from_shared(grpc_uri)?;
    let client = pb::executor_client::ExecutorClient::new(endpoint.connect_lazy());
    let token = if config.token.is_empty() {
        None
    } else {
        Some(MetadataValue::try_from(format!("Bearer {}", config.token))?)
    };
    let state = ProxyState { client, token };
    let app = Router::new()
        .route("/exec", post(exec))
        .route("/file", get_route(file_list).post(file_add))
        .route("/file/{fid}", get_route(file_get).delete(file_delete))
        .with_state(state);
    let listen_addr = if config.listen_addr.starts_with(':') {
        format!("0.0.0.0{}", config.listen_addr)
    } else {
        config.listen_addr
    };
    let listener = tokio::net::TcpListener::bind(listen_addr.as_str()).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn exec(State(mut state): State<ProxyState>, body: Bytes) -> Response {
    let request = match decode_request(&body) {
        Ok(request) => request,
        Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
    };
    match state.client.exec(grpc_request(request, &state.token)).await {
        Ok(response) => json_response(proto_response(&response.into_inner())),
        Err(error) => grpc_error_response(error),
    }
}

async fn file_list(State(mut state): State<ProxyState>) -> Response {
    match state.client.file_list(grpc_request((), &state.token)).await {
        Ok(response) => {
            let map = response
                .into_inner()
                .file_i_ds
                .into_iter()
                .map(|(key, value)| (key, Value::String(value)))
                .collect::<Map<_, _>>();
            json_response(json!({ "fileIDs": map }))
        }
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            error.message().to_owned(),
        )
            .into_response(),
    }
}

async fn file_get(State(mut state): State<ProxyState>, Path(fid): Path<String>) -> Response {
    let request = pb::FileId { file_id: fid };
    match state
        .client
        .file_get(grpc_request(request, &state.token))
        .await
    {
        Ok(response) => json_response(proto_file_content(&response.into_inner())),
        Err(error) => grpc_error_response(error),
    }
}

async fn file_add(State(mut state): State<ProxyState>, mut multipart: Multipart) -> Response {
    let mut upload = None;
    loop {
        match multipart.next_field().await {
            Ok(Some(field)) if field.name() == Some("file") => {
                let name = field.file_name().unwrap_or_default().to_owned();
                match field.bytes().await {
                    Ok(content) => {
                        upload = Some(pb::FileContent {
                            name,
                            content: content.to_vec(),
                        });
                        break;
                    }
                    Err(error) => {
                        return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
                            .into_response();
                    }
                }
            }
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(error) => return (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
        }
    }
    let Some(upload) = upload else {
        return (StatusCode::BAD_REQUEST, "missing multipart file field").into_response();
    };
    match state
        .client
        .file_add(grpc_request(upload, &state.token))
        .await
    {
        Ok(response) => json_response(json!({ "fileID": response.into_inner().file_id })),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            error.message().to_owned(),
        )
            .into_response(),
    }
}

async fn file_delete(State(mut state): State<ProxyState>, Path(fid): Path<String>) -> Response {
    let request = pb::FileId { file_id: fid };
    match state
        .client
        .file_delete(grpc_request(request, &state.token))
        .await
    {
        Ok(_) => json_response(json!({})),
        Err(error) => grpc_error_response(error),
    }
}

fn grpc_error_response(error: Status) -> Response {
    (status_code(&error), error.message().to_owned()).into_response()
}

fn json_response(value: Value) -> Response {
    Json(value).into_response()
}

fn decode_request(bytes: &[u8]) -> Result<pb::Request, String> {
    let value: Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    let root = object(&value, "request")?;
    let mut request = pb::Request {
        // The Go protobuf schema spells this field `requestID`, so ProtoJSON
        // preserves that spelling. Also accept the Rust/proto field spelling.
        request_id: root
            .get("requestID")
            .or_else(|| root.get("requestId"))
            .or_else(|| root.get("request_id"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        ..Default::default()
    };
    if let Some(commands) = get(root, "cmd", "cmd") {
        for command in array(commands, "cmd")? {
            request.cmd.push(decode_command(command)?);
        }
    }
    if let Some(pipes) = get(root, "pipeMapping", "pipe_mapping") {
        for pipe in array(pipes, "pipeMapping")? {
            let pipe = object(pipe, "pipeMapping item")?;
            request.pipe_mapping.push(pb::request::PipeMap {
                r#in: get(pipe, "in", "in")
                    .map(|v| decode_pipe_index(v, "in"))
                    .transpose()?,
                out: get(pipe, "out", "out")
                    .map(|v| decode_pipe_index(v, "out"))
                    .transpose()?,
                proxy: boolean(pipe, "proxy", "proxy"),
                name: string(pipe, "name", "name"),
                max: uint(pipe, "max", "max")?,
                disable_zero_copy: boolean(pipe, "disableZeroCopy", "disable_zero_copy"),
            });
        }
    }
    Ok(request)
}

fn decode_command(value: &Value) -> Result<pb::request::CmdType, String> {
    let command = object(value, "cmd item")?;
    let mut result = pb::request::CmdType {
        args: string_array(command, "args")?,
        env: string_array(command, "env")?,
        cpu_time_limit: uint(command, "cpuTimeLimit", "cpu_time_limit")?,
        clock_time_limit: uint(command, "clockTimeLimit", "clock_time_limit")?,
        memory_limit: uint(command, "memoryLimit", "memory_limit")?,
        proc_limit: uint(command, "procLimit", "proc_limit")?,
        copy_out_dir: string(command, "copyOutDir", "copy_out_dir"),
        stack_limit: uint(command, "stackLimit", "stack_limit")?,
        tty: boolean(command, "tty", "tty"),
        copy_out_max: uint(command, "copyOutMax", "copy_out_max")?,
        cpu_rate_limit: uint(command, "cpuRateLimit", "cpu_rate_limit")?,
        data_segment_limit: boolean(command, "dataSegmentLimit", "data_segment_limit"),
        cpu_set_limit: string(command, "cpuSetLimit", "cpu_set_limit"),
        address_space_limit: boolean(command, "addressSpaceLimit", "address_space_limit"),
        copy_out_truncate: boolean(command, "copyOutTruncate", "copy_out_truncate"),
        ..Default::default()
    };
    if let Some(files) = get(command, "files", "files") {
        for file in array(files, "files")? {
            result.files.push(decode_file(file)?);
        }
    }
    if let Some(files) = get(command, "copyIn", "copy_in") {
        for (name, file) in object(files, "copyIn")? {
            result.copy_in.insert(name.clone(), decode_file(file)?);
        }
    }
    if let Some(links) = get(command, "symlinks", "symlinks") {
        for (name, value) in object(links, "symlinks")? {
            result.symlinks.insert(
                name.clone(),
                value
                    .as_str()
                    .ok_or_else(|| format!("symlinks.{name} must be a string"))?
                    .to_owned(),
            );
        }
    }
    result.copy_out = decode_copyouts(command, "copyOut", "copy_out")?;
    result.copy_out_cached = decode_copyouts(command, "copyOutCached", "copy_out_cached")?;
    Ok(result)
}

fn decode_file(value: &Value) -> Result<pb::request::File, String> {
    use pb::request::{CachedFile, LocalFile, MemoryFile, PipeCollector, file::File as FileKind};
    let fields = object(value, "file")?;
    let mut kinds = Vec::new();
    if let Some(value) = get(fields, "local", "local") {
        kinds.push(FileKind::Local(LocalFile {
            src: string(object(value, "local")?, "src", "src"),
        }));
    }
    if let Some(value) = get(fields, "memory", "memory") {
        let content = string(object(value, "memory")?, "content", "content");
        let content = base64::engine::general_purpose::STANDARD
            .decode(&content)
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(&content))
            .map_err(|e| format!("file memory content: {e}"))?;
        kinds.push(FileKind::Memory(MemoryFile { content }));
    }
    if let Some(value) = get(fields, "cached", "cached") {
        let cached = object(value, "cached")?;
        kinds.push(FileKind::Cached(CachedFile {
            file_id: string(cached, "fileID", "file_id"),
        }));
    }
    if let Some(value) = get(fields, "pipe", "pipe") {
        let pipe = object(value, "pipe")?;
        let max = int(pipe, "max", "max")?;
        kinds.push(FileKind::Pipe(PipeCollector {
            name: string(pipe, "name", "name"),
            max,
            pipe: boolean(pipe, "pipe", "pipe"),
        }));
    }
    if get(fields, "streamIn", "stream_in").is_some()
        || get(fields, "streamOut", "stream_out").is_some()
    {
        return Err("streamIn/streamOut are only valid with ExecStream".into());
    }
    if kinds.len() != 1 {
        return Err("file must contain exactly one source".into());
    }
    Ok(pb::request::File { file: kinds.pop() })
}

fn decode_pipe_index(
    value: &Value,
    name: &str,
) -> Result<pb::request::pipe_map::PipeIndex, String> {
    let index = object(value, name)?;
    Ok(pb::request::pipe_map::PipeIndex {
        index: signed32(index, "index", "index")?,
        fd: signed32(index, "fd", "fd")?,
    })
}

fn decode_copyouts(
    fields: &Map<String, Value>,
    json_name: &str,
    proto_name: &str,
) -> Result<Vec<pb::request::CmdCopyOutFile>, String> {
    let Some(values) = get(fields, json_name, proto_name) else {
        return Ok(Vec::new());
    };
    array(values, json_name)?
        .iter()
        .map(|v| {
            let item = object(v, json_name)?;
            Ok(pb::request::CmdCopyOutFile {
                name: string(item, "name", "name"),
                optional: boolean(item, "optional", "optional"),
            })
        })
        .collect()
}

fn proto_response(response: &pb::Response) -> Value {
    let mut root = Map::new();
    put_string(&mut root, "requestID", &response.request_id);
    if !response.results.is_empty() {
        root.insert(
            "results".into(),
            Value::Array(response.results.iter().map(proto_result).collect()),
        );
    }
    put_string(&mut root, "error", &response.error);
    Value::Object(root)
}

fn proto_result(result: &pb::response::Result) -> Value {
    let mut value = Map::new();
    if result.status != 0 {
        value.insert("status".into(), json!(status_name(result.status)));
    }
    if result.exit_status != 0 {
        value.insert("exitStatus".into(), json!(result.exit_status));
    }
    put_string(&mut value, "error", &result.error);
    put_u64(&mut value, "time", result.time);
    put_u64(&mut value, "runTime", result.run_time);
    put_u64(&mut value, "procPeak", result.proc_peak);
    if result.exit_order != 0 {
        value.insert("exitOrder".into(), json!(result.exit_order));
    }
    put_u64(&mut value, "memory", result.memory);
    if !result.files.is_empty() {
        value.insert(
            "files".into(),
            Value::Object(
                result
                    .files
                    .iter()
                    .map(|(name, bytes)| {
                        (
                            name.clone(),
                            json!(base64::engine::general_purpose::STANDARD.encode(bytes)),
                        )
                    })
                    .collect(),
            ),
        );
    }
    if !result.file_i_ds.is_empty() {
        value.insert(
            "fileIDs".into(),
            Value::Object(
                result
                    .file_i_ds
                    .iter()
                    .map(|(name, id)| (name.clone(), json!(id)))
                    .collect(),
            ),
        );
    }
    if !result.file_error.is_empty() {
        value.insert(
            "fileError".into(),
            Value::Array(result.file_error.iter().map(proto_file_error).collect()),
        );
    }
    Value::Object(value)
}

fn proto_file_error(error: &pb::response::FileError) -> Value {
    let mut value = Map::new();
    put_string(&mut value, "name", &error.name);
    if error.r#type != 0 {
        value.insert("type".into(), json!(file_error_name(error.r#type)));
    }
    put_string(&mut value, "message", &error.message);
    Value::Object(value)
}

fn proto_file_content(file: &pb::FileContent) -> Value {
    json!({
        "name": file.name,
        "content": base64::engine::general_purpose::STANDARD.encode(&file.content),
    })
}

fn status_name(value: i32) -> &'static str {
    use pb::response::result::StatusType as S;
    match S::try_from(value).ok() {
        Some(S::Invalid) => "Invalid",
        Some(S::Accepted) => "Accepted",
        Some(S::WrongAnswer) => "WrongAnswer",
        Some(S::PartiallyCorrect) => "PartiallyCorrect",
        Some(S::MemoryLimitExceeded) => "MemoryLimitExceeded",
        Some(S::TimeLimitExceeded) => "TimeLimitExceeded",
        Some(S::OutputLimitExceeded) => "OutputLimitExceeded",
        Some(S::FileError) => "FileError",
        Some(S::NonZeroExitStatus) => "NonZeroExitStatus",
        Some(S::Signalled) => "Signalled",
        Some(S::DangerousSyscall) => "DangerousSyscall",
        Some(S::JudgementFailed) => "JudgementFailed",
        Some(S::InvalidInteraction) => "InvalidInteraction",
        Some(S::InternalError) => "InternalError",
        None => "Invalid",
    }
}

fn file_error_name(value: i32) -> &'static str {
    use pb::response::file_error::ErrorType as E;
    match E::try_from(value).ok() {
        Some(E::CopyInOpenFile) => "CopyInOpenFile",
        Some(E::CopyInCreateFile) => "CopyInCreateFile",
        Some(E::CopyInCopyContent) => "CopyInCopyContent",
        Some(E::CopyOutOpen) => "CopyOutOpen",
        Some(E::CopyOutNotRegularFile) => "CopyOutNotRegularFile",
        Some(E::CopyOutSizeExceeded) => "CopyOutSizeExceeded",
        Some(E::CopyOutCreateFile) => "CopyOutCreateFile",
        Some(E::CopyOutCopyContent) => "CopyOutCopyContent",
        Some(E::CollectSizeExceeded) => "CollectSizeExceeded",
        Some(E::Symlink) => "Symlink",
        None => "CopyInOpenFile",
    }
}

fn put_string(map: &mut Map<String, Value>, key: &str, value: &str) {
    if !value.is_empty() {
        map.insert(key.into(), json!(value));
    }
}
fn put_u64(map: &mut Map<String, Value>, key: &str, value: u64) {
    if value != 0 {
        map.insert(key.into(), json!(value.to_string()));
    }
}
fn object<'a>(value: &'a Value, label: &str) -> Result<&'a Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{label} must be an object"))
}
fn array<'a>(value: &'a Value, label: &str) -> Result<&'a Vec<Value>, String> {
    value
        .as_array()
        .ok_or_else(|| format!("{label} must be an array"))
}
fn get<'a>(map: &'a Map<String, Value>, json_name: &str, proto_name: &str) -> Option<&'a Value> {
    map.get(json_name).or_else(|| map.get(proto_name))
}
fn string(map: &Map<String, Value>, json_name: &str, proto_name: &str) -> String {
    get(map, json_name, proto_name)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}
fn boolean(map: &Map<String, Value>, json_name: &str, proto_name: &str) -> bool {
    get(map, json_name, proto_name)
        .and_then(Value::as_bool)
        .unwrap_or(false)
}
fn uint(map: &Map<String, Value>, json_name: &str, proto_name: &str) -> Result<u64, String> {
    let Some(value) = get(map, json_name, proto_name) else {
        return Ok(0);
    };
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|v| v.parse().ok()))
        .ok_or_else(|| format!("{json_name} must be a non-negative integer or decimal string"))
}
fn int(map: &Map<String, Value>, json_name: &str, proto_name: &str) -> Result<i64, String> {
    let Some(value) = get(map, json_name, proto_name) else {
        return Ok(0);
    };
    value
        .as_i64()
        .or_else(|| value.as_str().and_then(|v| v.parse().ok()))
        .ok_or_else(|| format!("{json_name} must be an integer or decimal string"))
}
fn signed32(map: &Map<String, Value>, json_name: &str, proto_name: &str) -> Result<i32, String> {
    int(map, json_name, proto_name)?
        .try_into()
        .map_err(|_| format!("{json_name} is outside int32 range"))
}
fn string_array(map: &Map<String, Value>, key: &str) -> Result<Vec<String>, String> {
    let Some(value) = map.get(key) else {
        return Ok(Vec::new());
    };
    array(value, key)?
        .iter()
        .map(|v| {
            v.as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| format!("{key} values must be strings"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_defaults_flags_and_statuses_match_go() {
        let p = ProxyConfig::parse(["proxy", "-addr=:9000", "-srvaddr", "judge:5051"], "token")
            .unwrap();
        assert_eq!(p.listen_addr, ":9000");
        assert_eq!(p.grpc_addr, "judge:5051");
        assert_eq!(p.token, "token");
        assert_eq!(ProxyConfig::default().grpc_addr, "localhost:5051");
        assert!(matches!(
            ProxyConfig::parse(["--help"], ""),
            Err(ProxyConfigError::Help)
        ));
        assert_eq!(grpc_http_status(GrpcCode::Unauthenticated), 401);
        assert_eq!(grpc_http_status(GrpcCode::Canceled), 499);
        assert_eq!(grpc_http_status_code(2), 500);
    }

    #[test]
    fn request_protojson_decodes_command_files_and_pipe_maps() {
        let request = decode_request(
            br#"{"requestID":"r","cmd":[{"args":["/bin/echo","hi"],"cpuTimeLimit":"10","files":[{"memory":{"content":"aGk="}},{"pipe":{"name":"stdout","max":"50","pipe":true}}],"copyIn":{"input":{"cached":{"fileID":"id"}}},"copyOut":[{"name":"result","optional":true}]}],"pipeMapping":[{"in":{"index":0,"fd":3},"out":{"index":1,"fd":4},"disableZeroCopy":true}]}"#,
        )
        .unwrap();
        assert_eq!(request.request_id, "r");
        assert_eq!(request.cmd[0].cpu_time_limit, 10);
        assert_eq!(request.cmd[0].files.len(), 2);
        assert!(matches!(
            request.cmd[0].files[0].file,
            Some(pb::request::file::File::Memory(_))
        ));
        assert_eq!(request.cmd[0].copy_out[0].name, "result");
        assert_eq!(request.pipe_mapping[0].out.as_ref().unwrap().fd, 4);
        assert!(request.pipe_mapping[0].disable_zero_copy);
        assert_eq!(
            decode_request(br#"{"requestId":"alias"}"#)
                .unwrap()
                .request_id,
            "alias"
        );
    }

    #[test]
    fn request_rejects_bad_protojson_and_execstream_only_files() {
        assert!(decode_request(b"{").is_err());
        assert!(decode_request(br#"{"cmd":[{"files":[{"streamIn":{}}]}]}"#).is_err());
    }

    #[test]
    fn response_uses_protojson_names_enum_and_base64_bytes() {
        let response = pb::Response {
            request_id: "r".into(),
            results: vec![pb::response::Result {
                status: pb::response::result::StatusType::Accepted as i32,
                files: [("stdout".into(), b"ok".to_vec())].into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let json = proto_response(&response);
        assert_eq!(json["requestID"], "r");
        assert_eq!(json["results"][0]["status"], "Accepted");
        assert_eq!(json["results"][0]["files"]["stdout"], "b2s=");
    }

    #[test]
    fn grpc_auth_metadata_is_bearer_token() {
        let token = Some(MetadataValue::try_from("Bearer secret").unwrap());
        let request = grpc_request((), &token);
        assert_eq!(
            request
                .metadata()
                .get("authorization")
                .unwrap()
                .to_str()
                .unwrap(),
            "Bearer secret"
        );
        assert!(grpc_request((), &None).metadata().is_empty());
    }
}
