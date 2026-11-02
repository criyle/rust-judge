use super::*;

#[test]
fn defaults_and_transport_options_match_go_shell() {
    let config = ShellConfig::parse(["rust-judge-shell"], "secret", "xterm").unwrap();
    assert_eq!(config.websocket_url, "ws://localhost:5050/stream");
    assert_eq!(config.grpc_addr, "localhost:5051");
    assert_eq!(config.args, ["/bin/bash"]);
    assert_eq!(config.token, "secret");
    assert_eq!(config.execution_plan().command.memory_limit.0, 256 << 20);
    assert!(matches!(
        ShellConfig::parse(["-transport=grpc", "sh"], "", "",)
            .unwrap()
            .transport,
        Transport::Grpc
    ));
}

#[test]
fn rejects_unknown_transport_and_missing_option_values() {
    assert!(matches!(
        ShellConfig::parse(["-transport=raw"], "", ""),
        Err(ShellConfigError::InvalidTransport(_))
    ));
    assert!(matches!(
        ShellConfig::parse(["-ws-url"], "", ""),
        Err(ShellConfigError::MissingValue(_))
    ));
    assert!(matches!(
        ShellConfig::parse(["-bad"], "", ""),
        Err(ShellConfigError::UnknownOption(_))
    ));
    assert!(matches!(
        ShellConfig::parse(["--help"], "", ""),
        Err(ShellConfigError::Help)
    ));
}

#[test]
fn copy_in_walk_maps_regular_files_by_relative_target() {
    let root = std::env::temp_dir().join(format!("judge-shell-copyin-{}", std::process::id()));
    let nested = root.join("sub");
    std::fs::create_dir_all(&nested).unwrap();
    let file = nested.join("program.txt");
    std::fs::write(&file, b"test").unwrap();
    let config = ShellConfig::parse(["-copy-in-dir", root.to_str().unwrap()], "", "").unwrap();
    let files = config.copy_in_files();
    assert_eq!(
        files.get("sub/program.txt"),
        Some(&std::fs::canonicalize(file).unwrap())
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn shell_request_converts_for_both_stream_wire_formats() {
    let request = worker::Request {
        request_id: "shell-1".into(),
        commands: vec![worker::Command {
            args: vec!["/bin/sh".into()],
            env: vec!["TERM=xterm".into()],
            files: vec![
                worker::CmdFile::StreamIn(std::sync::Arc::new(std::sync::Mutex::new(
                    tokio::sync::mpsc::channel(1).1,
                ))),
                worker::CmdFile::StreamOut {
                    index: 0,
                    fd: 1,
                    tx: tokio::sync::mpsc::channel(1).0,
                },
            ],
            tty: true,
            ..Default::default()
        }],
        ..Default::default()
    };
    let json = request_json(&request);
    assert_eq!(json["requestId"], "shell-1");
    assert_eq!(json["cmd"][0]["files"][0]["streamIn"], true);
    assert_eq!(json["cmd"][0]["files"][1]["streamOut"], true);
    let pb = request_to_pb(request);
    assert_eq!(pb.request_id, "shell-1");
    assert!(pb.cmd[0].tty);
    assert_eq!(pb.cmd[0].files.len(), 2);
    assert!(matches!(
        pb.cmd[0].files[0].kind,
        Some(pb::request::file::Kind::StreamIn(_))
    ));
}

#[test]
fn websocket_response_json_preserves_result_fields_and_files() {
    let response = json_response(serde_json::json!({
            "requestId":"r1", "results":[{"status":"Accepted","exitStatus":0,"time":17,"runTime":12,"memory":99,"procPeak":2,"files":{"out":"hello"}}]
        })).unwrap();
    assert_eq!(response.request_id, "r1");
    assert_eq!(response.results[0].status, worker::JudgeStatus::Accepted);
    assert_eq!(response.results[0].time, Duration::from_nanos(17));
    let mut file = response.results[0].files["out"].try_clone().unwrap();
    let mut contents = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut contents).unwrap();
    assert_eq!(contents, b"hello");
}

#[test]
fn shell_response_converters_preserve_file_error_details() {
    let json = json_response(serde_json::json!({
        "requestId":"json-fe", "results":[{"status":"File Error","fileError":[
            {"name":"out.txt","type":"CopyOutOpen","message":"permission denied"},
            {"name":"link","type":"Symlink","message":"invalid target"}
        ]}]
    }))
    .unwrap();
    assert_eq!(
        json.results[0].file_errors,
        [
            envexec::FileError {
                name: "out.txt".into(),
                kind: envexec::FileErrorType::CopyOutOpen,
                message: "permission denied".into()
            },
            envexec::FileError {
                name: "link".into(),
                kind: envexec::FileErrorType::Symlink,
                message: "invalid target".into()
            },
        ]
    );

    let grpc = pb_response(pb::Response {
        request_id: "grpc-fe".into(),
        results: vec![pb::response::Result {
            status: pb::response::result::StatusType::FileError as i32,
            file_error: vec![pb::response::FileError {
                name: "out.txt".into(),
                r#type: pb::response::file_error::ErrorType::CopyOutOpen as i32,
                message: "permission denied".into(),
            }],
            ..Default::default()
        }],
        ..Default::default()
    })
    .unwrap();
    assert_eq!(
        grpc.results[0].file_errors,
        [envexec::FileError {
            name: "out.txt".into(),
            kind: envexec::FileErrorType::CopyOutOpen,
            message: "permission denied".into(),
        }]
    );
}
