use super::*;

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

pub(super) fn authenticate_grpc<T>(
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

pub(super) struct GrpcApi(pub(super) ServerState);

pub(super) async fn store_file_stream<S>(
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

pub(super) fn proto_file(
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
