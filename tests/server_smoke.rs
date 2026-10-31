#![cfg(target_os = "linux")]

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
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn request(address: SocketAddr, path: &str, token: Option<&str>) -> std::io::Result<String> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(250))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n"
    )?;
    if let Some(token) = token {
        write!(stream, "Authorization: Bearer {token}\r\n")?;
    }
    write!(stream, "\r\n")?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

fn temporary_directory() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after the Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "rust-judge-server-smoke-{}-{nonce}",
        std::process::id()
    ))
}

#[test]
fn server_starts_serves_public_metadata_and_protects_file_routes() {
    let reservation = TcpListener::bind("127.0.0.1:0").expect("reserve local port");
    let address = reservation.local_addr().unwrap();
    drop(reservation);

    let directory = temporary_directory();
    fs::create_dir_all(&directory).expect("create server data directory");
    let child = Command::new(env!("CARGO_BIN_EXE_rust-judge"))
        .args([
            "--http-addr",
            &address.to_string(),
            "--dir",
            directory.to_str().unwrap(),
            "--pre-fork",
            "0",
            "--auth-token",
            "integration-test-token",
            "--silent",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start rust-judge server");
    let mut server = Server(child);

    let deadline = Instant::now() + Duration::from_secs(10);
    let version = loop {
        if let Some(status) = server.0.try_wait().expect("check server process") {
            panic!("rust-judge exited before becoming ready: {status}");
        }
        match request(address, "/version", None) {
            Ok(response) if response.starts_with("HTTP/1.1 200") => break response,
            _ if Instant::now() < deadline => thread::sleep(Duration::from_millis(50)),
            result => panic!("server did not become ready at {address}: {result:?}"),
        }
    };
    assert!(version.contains("\"buildVersion\""));
    assert!(version.contains("\"platform\""));

    let public_config = request(address, "/config", None).expect("read public config");
    assert!(public_config.starts_with("HTTP/1.1 200"));
    assert!(!public_config.contains("integration-test-token"));

    let unauthorized = request(address, "/file", None).expect("request protected file route");
    assert!(unauthorized.starts_with("HTTP/1.1 401"));

    let authorized = request(address, "/file", Some("integration-test-token"))
        .expect("request file route with bearer token");
    assert!(authorized.starts_with("HTTP/1.1 200"));

    drop(server);
    fs::remove_dir_all(directory).expect("remove server data directory");
}
