use super::*;

pub(super) async fn websocket_run(
    State(state): State<Arc<ServerState>>,
    upgrade: WebSocketUpgrade,
) -> impl IntoResponse {
    upgrade.on_upgrade(move |socket| websocket_loop(socket, state))
}

pub(super) async fn websocket_stream(
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
