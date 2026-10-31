#![cfg(target_os = "linux")]

//! Manual end-to-end counterpart to go-judge's integration_test/sanity_test.go.
//! Run with `cargo test --test go_judge_sanity -- --ignored --nocapture` on a
//! Linux host that permits the sandbox's namespace and mount operations.

use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        unsafe {
            libc::kill(self.0.id() as i32, libc::SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if self.0.try_wait().ok().flatten().is_some() {
                return;
            }
            thread::sleep(Duration::from_millis(25));
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn post(address: SocketAddr, body: &Value) -> std::io::Result<(String, Value)> {
    let payload = serde_json::to_vec(body).expect("serialize sanity request");
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    write!(
        stream,
        "POST /run HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    )?;
    stream.write_all(&payload)?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| std::io::Error::other("HTTP response has no header terminator"))?;
    let headers = String::from_utf8_lossy(&response[..split]).into_owned();
    let value = serde_json::from_slice(&response[split + 4..])
        .map_err(|error| std::io::Error::other(format!("decode run response: {error}")))?;
    Ok((headers, value))
}

fn temporary_directory() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after the Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "rust-judge-go-sanity-{}-{nonce}",
        std::process::id()
    ))
}

#[test]
#[ignore = "requires Linux sandbox namespace and mount operations; run explicitly on a capable host"]
fn go_judge_basic_functionality_sanity_cases() {
    let reservation = TcpListener::bind("127.0.0.1:0").expect("reserve local port");
    let address = reservation.local_addr().unwrap();
    drop(reservation);

    let directory = temporary_directory();
    fs::create_dir_all(&directory).expect("create server data directory");
    let mut server = Server(
        Command::new(env!("CARGO_BIN_EXE_rust-judge"))
            .args([
                "--http-addr",
                &address.to_string(),
                "--dir",
                directory.to_str().unwrap(),
                "--pre-fork",
                "0",
                "--silent",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start rust-judge server"),
    );

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = server.0.try_wait().expect("check server process") {
            panic!("rust-judge exited before becoming ready: {status}");
        }
        match TcpStream::connect_timeout(&address, Duration::from_millis(100)) {
            Ok(_) => break,
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(50)),
            Err(error) => panic!("rust-judge did not become ready: {error}"),
        }
    }

    let base = json!({
        "env": ["PATH=/usr/bin:/bin"],
        "files": [
            { "src": "/dev/null" },
            { "name": "stdout", "max": 10240 },
            { "name": "stderr", "max": 10240 }
        ],
        "cpuLimit": 10_000_000_000u64,
        "realCpuLimit": 12_000_000_000u64,
        "memoryLimit": 104_857_600u64,
        "procLimit": 50
    });

    let cases = vec![
        (
            "Basic Hello World",
            json!({ "args": ["/bin/echo", "hello world"] }),
            "Accepted",
            Some(("stdout", "hello world")),
        ),
        (
            "Environment Variable Check",
            json!({ "args": ["/bin/sh", "-c", "echo $MY_VAR"], "env": ["PATH=/bin", "MY_VAR=integration_test"] }),
            "Accepted",
            Some(("stdout", "integration_test")),
        ),
        (
            "Copy in Sub Directory",
            json!({ "args": ["/bin/ls", "test_dir"], "copyIn": { "test_dir/test_file": { "content": "content" } } }),
            "Accepted",
            Some(("stdout", "test_file")),
        ),
        (
            "Copy in Temp Directory",
            json!({ "args": ["/bin/ls", "/tmp"], "copyIn": { "/tmp/test_file": { "content": "content" } } }),
            "Accepted",
            Some(("stdout", "test_file")),
        ),
        (
            "Copy out Optional File Accepted",
            json!({ "args": ["/bin/ls"], "copyOut": ["test?"] }),
            "Accepted",
            None,
        ),
        (
            "Copy out File Error",
            json!({ "args": ["/bin/ls"], "copyOut": ["test"] }),
            "File Error",
            None,
        ),
        (
            "Copy out max",
            json!({ "args": ["/bin/cat", "input.txt"], "copyIn": { "input.txt": { "content": "1234567890" } }, "copyOut": ["input.txt"], "copyOutMax": 5 }),
            "File Error",
            None,
        ),
        (
            "Copy out Truncate",
            json!({ "args": ["/bin/cat", "input.txt"], "copyIn": { "input.txt": { "content": "1234567890" } }, "copyOut": ["input.txt"], "copyOutMax": 5, "copyOutTruncate": true }),
            "File Error",
            Some(("input.txt", "12345")),
        ),
        (
            "Copy out Cached File",
            json!({ "args": ["/bin/sh", "-c", "printf hello > out && cat out"], "copyOutCached": ["out"] }),
            "Accepted",
            Some(("stdout", "hello")),
        ),
        (
            "Stack Limit",
            json!({ "args": ["/bin/bash", "-c", "ulimit -s"], "stackLimit": 102_400_000u64 }),
            "Accepted",
            Some(("stdout", "100000")),
        ),
        (
            "No Symlink Escape",
            json!({ "args": ["/bin/ln", "-s", "/etc/passwd", "out.txt"], "copyOut": ["out.txt"] }),
            "File Error",
            None,
        ),
        (
            "FIFO Creation Denied by Seccomp",
            json!({ "args": ["/usr/bin/mkfifo", "out"], "copyOut": ["out"] }),
            "Nonzero Exit Status",
            None,
        ),
        (
            "Signal Check",
            json!({ "args": ["/bin/bash", "-c", "kill -SIGINT 1"] }),
            "Accepted",
            None,
        ),
        (
            "Time Limit Exceeded",
            json!({ "args": ["/bin/sleep", "2"], "cpuLimit": 1_000_000_000u64, "realCpuLimit": 1_000_000_000u64 }),
            "Time Limit Exceeded",
            None,
        ),
        (
            "Symlink /dev/urandom CopyOut Failure",
            json!({ "args": ["/bin/ln", "-s", "/dev/urandom", "out"], "copyOut": ["out"] }),
            "File Error",
            None,
        ),
        (
            "Compile with TTY",
            json!({
                "args": ["/usr/bin/g++", "a.cc"],
                "env": ["PATH=/usr/bin:/bin", "TERM=xterm"],
                "tty": true,
                "files": [
                    { "content": "/dev/null" },
                    { "name": "stdout", "max": 10240 },
                    { "name": "stderr", "max": 10240 }
                ],
                "copyIn": { "a.cc": { "content": "int main(){int a}" } }
            }),
            "Nonzero Exit Status",
            Some(("stdout", "\u{1b}")),
        ),
    ];

    for (name, override_fields, expected_status, expected_file) in cases {
        let mut command = base.clone();
        for (key, value) in override_fields.as_object().unwrap() {
            command[key] = value.clone();
        }
        let (headers, response) = post(address, &json!({ "cmd": [command] }))
            .unwrap_or_else(|error| panic!("{name}: request failed: {error}"));
        assert!(headers.starts_with("HTTP/1.1 200"), "{name}: {headers}");
        let result = &response[0];
        if name == "Compile with TTY"
            && result["status"] == "Internal Error"
            && result["error"]
                .as_str()
                .is_some_and(|error| error.contains("input/output error"))
        {
            eprintln!("SKIP {name}: host cannot establish a controlling TTY");
            continue;
        }
        assert_eq!(
            result["status"].as_str(),
            Some(expected_status),
            "{name}: {result}"
        );
        if let Some((file, expected)) = expected_file {
            let actual = result["files"][file].as_str().unwrap_or_default();
            assert!(
                actual.contains(expected),
                "{name}: expected {expected:?} in {actual:?}"
            );
        }
        if name == "Copy out Cached File" {
            let file_id = result["fileIds"]["out"].as_str().expect("cached output ID");
            let (headers, _) = delete_file(address, file_id).expect("delete cached output");
            assert!(
                headers.starts_with("HTTP/1.1 200"),
                "cached file cleanup: {headers}"
            );
        }
        eprintln!("PASS {name}");
    }

    drop(server);
    fs::remove_dir_all(directory).expect("remove server data directory");
}

fn delete_file(address: SocketAddr, file_id: &str) -> std::io::Result<(String, Value)> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    write!(
        stream,
        "DELETE /file/{file_id} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
    )?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| std::io::Error::other("HTTP response has no header terminator"))?;
    Ok((
        String::from_utf8_lossy(&response[..split]).into_owned(),
        Value::Null,
    ))
}
