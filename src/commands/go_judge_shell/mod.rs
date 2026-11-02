//! Interactive shell client configuration and typed stream protocol.

use crate::envexec;
use crate::pb;
use crate::worker;
use futures_util::{SinkExt, StreamExt};
use prost::Message;
use std::collections::HashMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Transport {
    #[default]
    WebSocket,
    Grpc,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShellConfig {
    pub transport: Transport,
    pub websocket_url: String,
    pub grpc_addr: String,
    pub copy_in_dir: String,
    pub args: Vec<String>,
    pub token: String,
    pub term: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ShellConfigError {
    Help,
    MissingValue(String),
    InvalidTransport(String),
    UnknownOption(String),
}
impl fmt::Display for ShellConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Help => f.write_str("help requested"),
            Self::MissingValue(s) => write!(f, "option {s} requires a value"),
            Self::InvalidTransport(s) => {
                write!(f, "invalid transport {s:?}; expected websocket or grpc")
            }
            Self::UnknownOption(s) => write!(f, "unknown option {s}"),
        }
    }
}
impl std::error::Error for ShellConfigError {}

impl ShellConfig {
    pub fn parse<I, S>(
        args: I,
        token: impl Into<String>,
        term: impl Into<String>,
    ) -> Result<Self, ShellConfigError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut values: Vec<String> = args.into_iter().map(Into::into).collect();
        if !values.is_empty() && !values[0].starts_with('-') {
            values.remove(0);
        }
        let mut config = Self {
            transport: Transport::WebSocket,
            websocket_url: "ws://localhost:5050/stream".into(),
            grpc_addr: "localhost:5051".into(),
            copy_in_dir: String::new(),
            args: Vec::new(),
            token: token.into(),
            term: term.into(),
        };
        let mut i = 0;
        while i < values.len() {
            let arg = &values[i];
            if arg == "-h" || arg == "--help" || arg == "-help" {
                return Err(ShellConfigError::Help);
            }
            if arg == "--" {
                i += 1;
                config.args.extend(values[i..].iter().cloned());
                break;
            }
            if !arg.starts_with('-') || arg == "-" {
                config.args.extend(values[i..].iter().cloned());
                break;
            }
            let option = arg.trim_start_matches('-');
            let (name, inline) = option
                .split_once('=')
                .map_or((option, None), |(n, v)| (n, Some(v.to_string())));
            if !matches!(name, "transport" | "ws-url" | "grpc-addr" | "copy-in-dir") {
                return Err(ShellConfigError::UnknownOption(name.into()));
            }
            let value = if let Some(value) = inline {
                value
            } else {
                i += 1;
                values
                    .get(i)
                    .cloned()
                    .ok_or_else(|| ShellConfigError::MissingValue(name.into()))?
            };
            match name {
                "transport" => {
                    config.transport = match value.as_str() {
                        "websocket" => Transport::WebSocket,
                        "grpc" => Transport::Grpc,
                        _ => return Err(ShellConfigError::InvalidTransport(value)),
                    }
                }
                "ws-url" => config.websocket_url = value,
                "grpc-addr" => config.grpc_addr = value,
                "copy-in-dir" => config.copy_in_dir = value,
                _ => return Err(ShellConfigError::UnknownOption(name.into())),
            }
            i += 1;
        }
        if config.args.is_empty() {
            config.args.push("/bin/bash".into());
        }
        Ok(config)
    }

    pub fn execution_plan(&self) -> ShellExecutionPlan {
        ShellExecutionPlan {
            command: worker::Command {
                args: self.args.clone(),
                env: vec![
                    "PATH=/usr/local/bin:/usr/bin:/bin".into(),
                    "HOME=/tmp".into(),
                    format!("TERM={}", self.term),
                ],
                files: vec![
                    worker::CmdFile::Null,
                    worker::CmdFile::Null,
                    worker::CmdFile::Null,
                ],
                cpu_limit: Duration::from_secs(20),
                clock_limit: Duration::from_secs(30 * 60),
                memory_limit: crate::runner::Size(256 << 20),
                proc_limit: 50,
                tty: true,
                ..Default::default()
            },
            copy_in: self.copy_in_files(),
            stream_input_fds: vec![0],
            stream_output_fds: vec![1, 2],
        }
    }

    /// Mirrors Go's best-effort walk: only regular files are added, with
    /// relative target names and absolute host sources.
    pub fn copy_in_files(&self) -> HashMap<String, PathBuf> {
        let mut files = HashMap::new();
        if self.copy_in_dir.is_empty() {
            return files;
        }
        let root = Path::new(&self.copy_in_dir);
        let root_abs = if root.is_absolute() {
            root.to_path_buf()
        } else {
            let Ok(cwd) = std::env::current_dir() else {
                return files;
            };
            cwd.join(root)
        };
        let mut todo = vec![root_abs.clone()];
        while let Some(path) = todo.pop() {
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&path) {
                    todo.extend(entries.filter_map(Result::ok).map(|e| e.path()));
                }
            } else {
                if let Ok(relative) = path.strip_prefix(&root_abs) {
                    let target = if relative.as_os_str().is_empty() {
                        ".".to_string()
                    } else {
                        relative.to_string_lossy().into_owned()
                    };
                    files.insert(target, path);
                }
            }
        }
        files
    }
}

#[derive(Clone, Debug)]
pub struct ShellExecutionPlan {
    pub command: worker::Command,
    pub copy_in: HashMap<String, PathBuf>,
    pub stream_input_fds: Vec<usize>,
    pub stream_output_fds: Vec<usize>,
}

#[derive(Debug)]
pub enum ShellRequest {
    Exec(worker::Request),
    Input {
        index: usize,
        fd: usize,
        content: Vec<u8>,
    },
    Resize {
        index: usize,
        fd: usize,
        rows: u16,
        cols: u16,
        x: u16,
        y: u16,
    },
    Cancel,
}
#[derive(Debug)]
pub enum ShellResponse {
    Output {
        index: usize,
        fd: usize,
        content: Vec<u8>,
    },
    Exec(worker::Response),
}

pub trait ShellTransport: Send + Sync {
    fn send(&self, request: ShellRequest) -> io::Result<()>;
    fn recv(&self) -> io::Result<ShellResponse>;
}

pub fn connect(config: &ShellConfig) -> io::Result<Box<dyn ShellTransport>> {
    match config.transport {
        Transport::WebSocket => Ok(Box::new(WebSocketClient::connect(config)?)),
        Transport::Grpc => Ok(Box::new(GrpcClient::connect(config)?)),
    }
}

/// Build the initial interactive request with stdin/stdout/stderr stream descriptors.
pub fn exec_shell_request(config: &ShellConfig) -> worker::Request {
    let mut command = config.execution_plan().command;
    command.files = vec![
        worker::CmdFile::StreamIn(std::sync::Arc::new(std::sync::Mutex::new(
            tokio::sync::mpsc::channel(1).1,
        ))),
        worker::CmdFile::StreamOut {
            index: 0,
            fd: 1,
            tx: tokio::sync::mpsc::channel(1).0,
        },
        worker::CmdFile::StreamOut {
            index: 0,
            fd: 2,
            tx: tokio::sync::mpsc::channel(1).0,
        },
    ];
    command.copy_in = config
        .copy_in_files()
        .into_iter()
        .map(|(name, path)| (name, worker::CmdFile::Local(path)))
        .collect();
    worker::Request {
        commands: vec![command],
        ..Default::default()
    }
}

struct WebSocketClient {
    runtime: tokio::runtime::Runtime,
    socket: std::sync::Mutex<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
}
impl WebSocketClient {
    fn connect(config: &ShellConfig) -> io::Result<Self> {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let mut request = config
            .websocket_url
            .as_str()
            .into_client_request()
            .map_err(other_io)?;
        if !config.token.is_empty() {
            let value = format!("Bearer {}", config.token)
                .parse()
                .map_err(other_io)?;
            request.headers_mut().insert("authorization", value);
        }
        let (socket, _) = runtime
            .block_on(tokio_tungstenite::connect_async(request))
            .map_err(other_io)?;
        Ok(Self {
            runtime,
            socket: std::sync::Mutex::new(socket),
        })
    }
}
impl ShellTransport for WebSocketClient {
    fn send(&self, request: ShellRequest) -> io::Result<()> {
        use tokio_tungstenite::tungstenite::Message;
        let bytes = match request {
            ShellRequest::Exec(request) => {
                let mut bytes = vec![1];
                bytes.extend(serde_json::to_vec(&request_json(&request))?);
                bytes
            }
            ShellRequest::Resize {
                index,
                fd,
                rows,
                cols,
                x,
                y,
            } => {
                let mut bytes = vec![2];
                bytes.extend(serde_json::to_vec(
                    &serde_json::json!({"index":index,"fd":fd,"rows":rows,"cols":cols,"x":x,"y":y}),
                )?);
                bytes
            }
            ShellRequest::Input { index, fd, content } => {
                if index > 15 || fd > 15 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "WebSocket stream index and fd must fit in four bits",
                    ));
                }
                let mut bytes = vec![3, ((index as u8) << 4) | fd as u8];
                bytes.extend(content);
                bytes
            }
            ShellRequest::Cancel => vec![4],
        };
        let mut socket = self
            .socket
            .lock()
            .map_err(|_| other_io("websocket mutex poisoned"))?;
        self.runtime
            .block_on(socket.send(Message::Binary(bytes.into())))
            .map_err(other_io)
    }
    fn recv(&self) -> io::Result<ShellResponse> {
        use tokio_tungstenite::tungstenite::Message;
        let mut socket = self
            .socket
            .lock()
            .map_err(|_| other_io("websocket mutex poisoned"))?;
        loop {
            let message = self
                .runtime
                .block_on(socket.next())
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "websocket closed"))?
                .map_err(other_io)?;
            let Message::Binary(bytes) = message else {
                continue;
            };
            let Some(kind) = bytes.first().copied() else {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "empty WebSocket frame",
                ));
            };
            return match kind {
                1 => {
                    let value: serde_json::Value = serde_json::from_slice(&bytes[1..])?;
                    Ok(ShellResponse::Exec(json_response(value)?))
                }
                2 if bytes.len() >= 2 => Ok(ShellResponse::Output {
                    index: (bytes[1] >> 4) as usize,
                    fd: (bytes[1] & 15) as usize,
                    content: bytes[2..].to_vec(),
                }),
                2 => Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated WebSocket output",
                )),
                code => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid WebSocket response code {code}"),
                )),
            };
        }
    }
}

struct GrpcClient {
    runtime: tokio::runtime::Runtime,
    tx: tokio::sync::mpsc::Sender<crate::server::grpc_proto::StreamRequest>,
    rx: std::sync::Mutex<tonic::Streaming<crate::server::grpc_proto::StreamResponse>>,
}
impl GrpcClient {
    fn connect(config: &ShellConfig) -> io::Result<Self> {
        use crate::server::grpc_proto::{StreamRequest, executor_client::ExecutorClient};
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let addr = if config.grpc_addr.contains("://") {
            config.grpc_addr.clone()
        } else {
            format!("http://{}", config.grpc_addr)
        };
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let mut client = runtime
            .block_on(ExecutorClient::connect(addr))
            .map_err(other_io)?;
        let mut req = tonic::Request::new(tokio_stream::wrappers::ReceiverStream::new(rx));
        if !config.token.is_empty() {
            let value = format!("Bearer {}", config.token)
                .parse()
                .map_err(other_io)?;
            req.metadata_mut().insert("authorization", value);
        }
        let response = runtime
            .block_on(client.exec_stream(req))
            .map_err(other_io)?;
        let _: Option<StreamRequest> = None;
        Ok(Self {
            runtime,
            tx,
            rx: std::sync::Mutex::new(response.into_inner()),
        })
    }
}
impl ShellTransport for GrpcClient {
    fn send(&self, request: ShellRequest) -> io::Result<()> {
        use crate::server::grpc_proto::{StreamRequest, stream_request::Request as Kind};
        let req = match request {
            ShellRequest::Exec(r) => {
                let pb = request_to_pb(r);
                let wire = pb::StreamRequest {
                    kind: Some(pb::stream_request::Kind::ExecRequest(pb)),
                }
                .encode_to_vec();
                StreamRequest::decode(wire.as_slice()).map_err(other_io)?
            }
            ShellRequest::Input { index, fd, content } => StreamRequest {
                request: Some(Kind::ExecInput(
                    crate::server::grpc_proto::stream_request::Input {
                        index: index as u32,
                        fd: fd as u32,
                        content,
                    },
                )),
            },
            ShellRequest::Resize {
                index,
                fd,
                rows,
                cols,
                x,
                y,
            } => StreamRequest {
                request: Some(Kind::ExecResize(
                    crate::server::grpc_proto::stream_request::Resize {
                        index: index as u32,
                        fd: fd as u32,
                        rows: rows as u32,
                        cols: cols as u32,
                        x: x as u32,
                        y: y as u32,
                    },
                )),
            },
            ShellRequest::Cancel => StreamRequest {
                request: Some(Kind::ExecCancel(())),
            },
        };
        self.runtime.block_on(self.tx.send(req)).map_err(other_io)
    }
    fn recv(&self) -> io::Result<ShellResponse> {
        use crate::server::grpc_proto::stream_response::Response as Kind;
        let mut rx = self
            .rx
            .lock()
            .map_err(|_| other_io("gRPC response mutex poisoned"))?;
        let response = self
            .runtime
            .block_on(rx.message())
            .map_err(other_io)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "gRPC stream closed"))?;
        match response.response.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "empty gRPC stream response")
        })? {
            Kind::ExecOutput(o) => Ok(ShellResponse::Output {
                index: o.index as usize,
                fd: o.fd as usize,
                content: o.content,
            }),
            Kind::ExecResponse(r) => {
                let wire = r.encode_to_vec();
                let decoded = pb::Response::decode(wire.as_slice()).map_err(other_io)?;
                Ok(ShellResponse::Exec(pb_response(decoded)?))
            }
        }
    }
}

fn other_io(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

fn request_to_pb(request: worker::Request) -> pb::Request {
    let mut out = pb::Request {
        request_id: request.request_id,
        ..Default::default()
    };
    for cmd in request.commands {
        let file = |f: &worker::CmdFile| -> Option<pb::request::File> {
            use pb::request::{File, file::Kind};
            Some(File {
                kind: Some(match f {
                    worker::CmdFile::Local(p) => Kind::Local(pb::request::LocalFile {
                        src: p.to_string_lossy().into_owned(),
                    }),
                    worker::CmdFile::Memory(b) => {
                        Kind::Memory(pb::request::MemoryFile { content: b.clone() })
                    }
                    worker::CmdFile::Null => return Some(File { kind: None }),
                    worker::CmdFile::Cached(id) => Kind::Cached(pb::request::CachedFile {
                        file_id: id.clone(),
                    }),
                    worker::CmdFile::Collector { name, max, pipe } => {
                        Kind::Pipe(pb::request::PipeCollector {
                            name: name.clone(),
                            max: max.0 as i64,
                            pipe: *pipe,
                        })
                    }
                    worker::CmdFile::StreamIn(_) => Kind::StreamIn(pb::Empty {}),
                    worker::CmdFile::StreamOut { .. } => Kind::StreamOut(pb::Empty {}),
                }),
            })
        };
        let files = cmd.files.iter().filter_map(file).collect();
        let copy_in = cmd
            .copy_in
            .iter()
            .filter_map(|(n, f)| file(f).map(|f| (n.clone(), f)))
            .collect();
        let copy_out = cmd
            .copy_out
            .iter()
            .map(|f| pb::request::CmdCopyOutFile {
                name: f.name.clone(),
                optional: f.optional,
            })
            .collect();
        let copy_out_cached = cmd
            .copy_out_cached
            .iter()
            .map(|f| pb::request::CmdCopyOutFile {
                name: f.name.clone(),
                optional: f.optional,
            })
            .collect();
        out.cmd.push(pb::request::CmdType {
            args: cmd.args,
            env: cmd.env,
            files,
            cpu_time_limit: cmd.cpu_limit.as_nanos() as u64,
            clock_time_limit: cmd.clock_limit.as_nanos() as u64,
            memory_limit: cmd.memory_limit.0,
            proc_limit: cmd.proc_limit,
            copy_in,
            copy_out,
            copy_out_cached,
            copy_out_dir: String::new(),
            stack_limit: cmd.stack_limit.0,
            tty: cmd.tty,
            copy_out_max: cmd.copy_out_max,
            cpu_rate_limit: cmd.cpu_rate_limit,
            data_segment_limit: cmd.data_segment_limit,
            cpu_set_limit: cmd.cpu_set_limit,
            symlinks: cmd.symlinks,
            address_space_limit: cmd.address_space_limit,
            copy_out_truncate: cmd.copy_out_truncate,
        });
    }
    out.pipe_mapping = request
        .pipe_mapping
        .into_iter()
        .map(|m| pb::request::PipeMap {
            r#in: Some(pb::request::PipeIndex {
                index: m.input.index as i32,
                fd: m.input.fd as i32,
            }),
            out: Some(pb::request::PipeIndex {
                index: m.output.index as i32,
                fd: m.output.fd as i32,
            }),
            proxy: m.proxy,
            name: m.name,
            max: m.limit.0,
            disable_zero_copy: m.disable_zero_copy,
        })
        .collect();
    out
}

fn request_json(req: &worker::Request) -> serde_json::Value {
    use serde_json::{Map, Value, json};
    let file_json = |f: &worker::CmdFile| -> Value {
        match f {
            worker::CmdFile::Local(p) => json!({"src":p}),
            worker::CmdFile::Memory(b) => json!({"content":String::from_utf8_lossy(b)}),
            worker::CmdFile::Null => Value::Null,
            worker::CmdFile::Cached(id) => json!({"fileId":id}),
            worker::CmdFile::Collector { name, max, pipe } => {
                json!({"name":name,"max":max.0,"pipe":pipe})
            }
            worker::CmdFile::StreamIn(_) => json!({"streamIn":true}),
            worker::CmdFile::StreamOut { .. } => json!({"streamOut":true}),
        }
    };
    let cmds:Vec<Value> = req.commands.iter().map(|c| {
        let mut ci = Map::new(); for (k,v) in &c.copy_in { ci.insert(k.clone(),file_json(v)); }
        for (k,v) in &c.symlinks { ci.insert(k.clone(),json!({"symlink":v})); }
        json!({"args":c.args,"env":c.env,"files":c.files.iter().map(file_json).collect::<Vec<_>>(),"cpuLimit":c.cpu_limit.as_nanos() as u64,"clockLimit":c.clock_limit.as_nanos() as u64,"memoryLimit":c.memory_limit.0,"stackLimit":c.stack_limit.0,"procLimit":c.proc_limit,"cpuRateLimit":c.cpu_rate_limit,"cpuSetLimit":c.cpu_set_limit,"copyIn":ci,"copyOut":c.copy_out.iter().map(|f|json!({"name":f.name,"optional":f.optional})).collect::<Vec<_>>(),"copyOutCached":c.copy_out_cached.iter().map(|f|json!({"name":f.name,"optional":f.optional})).collect::<Vec<_>>(),"copyOutMax":c.copy_out_max,"copyOutTruncate":c.copy_out_truncate,"tty":c.tty,"dataSegmentLimit":c.data_segment_limit,"addressSpaceLimit":c.address_space_limit})
    }).collect();
    let maps:Vec<Value> = req.pipe_mapping.iter().map(|m|json!({"in":{"index":m.input.index,"fd":m.input.fd},"out":{"index":m.output.index,"fd":m.output.fd},"name":m.name,"max":m.limit.0,"proxy":m.proxy,"disableZeroCopy":m.disable_zero_copy})).collect();
    json!({"requestId":req.request_id,"cmd":cmds,"pipeMapping":maps})
}

fn pb_response(response: pb::Response) -> io::Result<worker::Response> {
    use pb::response::result::StatusType as S;
    let mut out = worker::Response {
        request_id: response.request_id,
        error: (!response.error.is_empty()).then_some(response.error),
        ..Default::default()
    };
    for r in response.results {
        let status = match S::try_from(r.status).unwrap_or(S::Invalid) {
            S::Accepted => worker::JudgeStatus::Accepted,
            S::WrongAnswer => worker::JudgeStatus::WrongAnswer,
            S::PartiallyCorrect => worker::JudgeStatus::PartiallyCorrect,
            S::MemoryLimitExceeded => worker::JudgeStatus::MemoryLimitExceeded,
            S::TimeLimitExceeded => worker::JudgeStatus::TimeLimitExceeded,
            S::OutputLimitExceeded => worker::JudgeStatus::OutputLimitExceeded,
            S::FileError => worker::JudgeStatus::FileError,
            S::NonZeroExitStatus => worker::JudgeStatus::NonzeroExitStatus,
            S::Signalled => worker::JudgeStatus::Signalled,
            S::DangerousSyscall => worker::JudgeStatus::DangerousSyscall,
            S::JudgementFailed => worker::JudgeStatus::JudgementFailed,
            S::InvalidInteraction => worker::JudgeStatus::InvalidInteraction,
            S::InternalError => worker::JudgeStatus::InternalError,
            S::Invalid => worker::JudgeStatus::Invalid,
        };
        let mut files = HashMap::new();
        for (name, bytes) in r.files {
            files.insert(
                name.clone(),
                crate::container::memfd::dup_to_memfd(&name, std::io::Cursor::new(bytes))?,
            );
        }
        out.results.push(worker::ResultInfo {
            status,
            exit_order: r.exit_order.max(0) as usize,
            exit_status: r.exit_status,
            error: r.error,
            time: Duration::from_nanos(r.time),
            run_time: Duration::from_nanos(r.run_time),
            memory: crate::runner::Size(r.memory),
            proc_peak: r.proc_peak,
            files,
            file_ids: r.file_ids,
            file_errors: r
                .file_error
                .into_iter()
                .map(|e| {
                    let kind = match pb::response::file_error::ErrorType::try_from(e.r#type) {
                        Ok(pb::response::file_error::ErrorType::CopyInOpenFile) => {
                            envexec::FileErrorType::CopyInOpenFile
                        }
                        Ok(pb::response::file_error::ErrorType::CopyInCreateFile) => {
                            envexec::FileErrorType::CopyInCreateFile
                        }
                        Ok(pb::response::file_error::ErrorType::CopyInCopyContent) => {
                            envexec::FileErrorType::CopyInCopyContent
                        }
                        Ok(pb::response::file_error::ErrorType::CopyOutOpen) => {
                            envexec::FileErrorType::CopyOutOpen
                        }
                        Ok(pb::response::file_error::ErrorType::CopyOutNotRegularFile) => {
                            envexec::FileErrorType::CopyOutNotRegularFile
                        }
                        Ok(pb::response::file_error::ErrorType::CopyOutSizeExceeded) => {
                            envexec::FileErrorType::CopyOutSizeExceeded
                        }
                        Ok(pb::response::file_error::ErrorType::CopyOutCreateFile) => {
                            envexec::FileErrorType::CopyOutCreateFile
                        }
                        Ok(pb::response::file_error::ErrorType::CopyOutCopyContent) => {
                            envexec::FileErrorType::CopyOutCopyContent
                        }
                        Ok(pb::response::file_error::ErrorType::CollectSizeExceeded) => {
                            envexec::FileErrorType::CollectSizeExceeded
                        }
                        Ok(pb::response::file_error::ErrorType::Symlink) => {
                            envexec::FileErrorType::Symlink
                        }
                        Err(_) => envexec::FileErrorType::CopyInOpenFile,
                    };
                    envexec::FileError {
                        name: e.name,
                        kind,
                        message: e.message,
                    }
                })
                .collect(),
        });
    }
    Ok(out)
}

fn json_response(v: serde_json::Value) -> io::Result<worker::Response> {
    let request_id = v
        .get("requestId")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();
    let error = v.get("error").and_then(|v| v.as_str()).map(str::to_owned);
    let mut response = worker::Response {
        request_id,
        error,
        ..Default::default()
    };
    for r in v
        .get("results")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        let status = match r.get("status").and_then(|x| x.as_str()).unwrap_or("") {
            "Accepted" => worker::JudgeStatus::Accepted,
            "Wrong Answer" => worker::JudgeStatus::WrongAnswer,
            "Partially Correct" => worker::JudgeStatus::PartiallyCorrect,
            "Memory Limit Exceeded" => worker::JudgeStatus::MemoryLimitExceeded,
            "Time Limit Exceeded" => worker::JudgeStatus::TimeLimitExceeded,
            "Output Limit Exceeded" => worker::JudgeStatus::OutputLimitExceeded,
            "File Error" => worker::JudgeStatus::FileError,
            "Nonzero Exit Status" => worker::JudgeStatus::NonzeroExitStatus,
            "Signalled" => worker::JudgeStatus::Signalled,
            "Dangerous Syscall" => worker::JudgeStatus::DangerousSyscall,
            "Judgement Failed" => worker::JudgeStatus::JudgementFailed,
            "Invalid Interaction" => worker::JudgeStatus::InvalidInteraction,
            "Internal Error" => worker::JudgeStatus::InternalError,
            _ => worker::JudgeStatus::Invalid,
        };
        let number = |k: &str| r.get(k).and_then(|x| x.as_u64()).unwrap_or(0);
        let mut files = HashMap::new();
        if let Some(fs) = r.get("files").and_then(|x| x.as_object()) {
            for (n, b) in fs {
                files.insert(
                    n.clone(),
                    crate::container::memfd::dup_to_memfd(
                        n,
                        std::io::Cursor::new(b.as_str().unwrap_or("").as_bytes()),
                    )?,
                );
            }
        }
        let file_ids = r
            .get("fileIds")
            .and_then(|x| x.as_object())
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
                    .collect()
            })
            .unwrap_or_default();
        response.results.push(worker::ResultInfo {
            status,
            exit_order: r.get("exitOrder").and_then(|x| x.as_u64()).unwrap_or(0) as usize,
            exit_status: r.get("exitStatus").and_then(|x| x.as_i64()).unwrap_or(0) as i32,
            error: r
                .get("error")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_owned(),
            time: Duration::from_nanos(number("time")),
            run_time: Duration::from_nanos(number("runTime")),
            memory: crate::runner::Size(number("memory")),
            proc_peak: number("procPeak"),
            files,
            file_ids,
            file_errors: r
                .get("fileError")
                .and_then(|x| x.as_array())
                .into_iter()
                .flatten()
                .filter_map(|e| {
                    let kind = match e.get("type").and_then(|x| x.as_str())? {
                        "CopyInOpenFile" => envexec::FileErrorType::CopyInOpenFile,
                        "CopyInCreateDir" => envexec::FileErrorType::CopyInCreateDir,
                        "CopyInCreateFile" => envexec::FileErrorType::CopyInCreateFile,
                        "CopyInCopyContent" => envexec::FileErrorType::CopyInCopyContent,
                        "CopyOutOpen" => envexec::FileErrorType::CopyOutOpen,
                        "CopyOutNotRegularFile" => envexec::FileErrorType::CopyOutNotRegularFile,
                        "CopyOutSizeExceeded" => envexec::FileErrorType::CopyOutSizeExceeded,
                        "CopyOutCreateFile" => envexec::FileErrorType::CopyOutCreateFile,
                        "CopyOutCopyContent" => envexec::FileErrorType::CopyOutCopyContent,
                        "CollectSizeExceeded" => envexec::FileErrorType::CollectSizeExceeded,
                        "Symlink" => envexec::FileErrorType::Symlink,
                        _ => return None,
                    };
                    Some(envexec::FileError {
                        name: e
                            .get("name")
                            .and_then(|x| x.as_str())
                            .unwrap_or_default()
                            .to_owned(),
                        kind,
                        message: e
                            .get("message")
                            .and_then(|x| x.as_str())
                            .unwrap_or_default()
                            .to_owned(),
                    })
                })
                .collect(),
        });
    }
    Ok(response)
}

pub const USAGE: &str = "Usage: rust-judge-shell [options] [command args...]\nOptions: -transport=websocket|grpc -ws-url URL -grpc-addr ADDR -copy-in-dir DIR\n";

/// Protobuf conversion surface used by the future gRPC transport.
pub fn exec_request(plan: ShellExecutionPlan) -> pb::Request {
    let cmd = plan.command;
    let copy_in = plan
        .copy_in
        .into_iter()
        .map(|(target, source)| {
            (
                target,
                pb::request::File {
                    kind: Some(pb::request::file::Kind::Local(pb::request::LocalFile {
                        src: source.to_string_lossy().into_owned(),
                    })),
                },
            )
        })
        .collect();
    let files = vec![
        pb::request::File {
            kind: Some(pb::request::file::Kind::StreamIn(pb::Empty {})),
        },
        pb::request::File {
            kind: Some(pb::request::file::Kind::StreamOut(pb::Empty {})),
        },
        pb::request::File {
            kind: Some(pb::request::file::Kind::StreamOut(pb::Empty {})),
        },
    ];
    pb::Request {
        request_id: String::new(),
        cmd: vec![pb::request::CmdType {
            args: cmd.args,
            env: cmd.env,
            files,
            cpu_time_limit: cmd.cpu_limit.as_nanos() as u64,
            clock_time_limit: cmd.clock_limit.as_nanos() as u64,
            memory_limit: cmd.memory_limit.0,
            proc_limit: cmd.proc_limit,
            copy_in,
            tty: true,
            ..Default::default()
        }],
        pipe_mapping: Vec::new(),
    }
}

#[cfg(test)]
mod tests;
