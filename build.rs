use std::{
    fs,
    path::PathBuf,
    process::{Command, Stdio},
};

fn main() {
    println!("cargo:rustc-check-cfg=cfg(tokio_unstable)");
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let rustc_version = Command::new(rustc)
        .arg("--version")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|version| {
            let parts = version.split_whitespace().take(2).collect::<Vec<_>>();
            (parts.len() == 2).then(|| parts.join(" "))
        })
        .unwrap_or_else(|| "rustc unknown".into());
    println!("cargo:rustc-env=RUSTC_VERSION={rustc_version}");
    println!("cargo:rerun-if-env-changed=RUSTC");

    // Keep the Go Judge wire schema beside this crate. The Rust build must not
    // depend on a sibling checkout being present at a machine-specific path.
    let source = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .join("proto")
        .join("go-judge");
    let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("proto");
    fs::create_dir_all(&out).unwrap();
    for name in [
        "judge.proto",
        "request.proto",
        "response.proto",
        "stream_request.proto",
        "stream_response.proto",
        "file.proto",
    ] {
        let input = fs::read_to_string(source.join(name)).unwrap();
        let clean = input
            .lines()
            .filter(|line| {
                let l = line.trim();
                !(l.starts_with("option ") || l.contains("google/protobuf/go_features.proto"))
            })
            .map(|line| line.replace("edition = \"2023\";", "syntax = \"proto3\";"))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(out.join(name), clean).unwrap();
        println!("cargo:rerun-if-changed={}", source.join(name).display());
    }
    let protoc = protoc_bin_vendored::protoc_bin_path().unwrap();
    unsafe {
        std::env::set_var("PROTOC", protoc);
    }
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&[out.join("judge.proto")], &[out])
        .unwrap();
}
