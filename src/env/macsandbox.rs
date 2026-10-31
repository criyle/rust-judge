//! macOS sandbox backend surface. The Go implementation creates a temporary
//! directory and a `sandbox-exec` profile; that native backend is not yet
//! available in this crate.

pub const DEFAULT_READ: &[&str] = &["/"];
pub const DEFAULT_WRITE: &[&str] = &["/tmp", "/dev/null", "/var/tmp"];

#[derive(Clone, Debug)]
pub struct Config {
    pub working_directory: String,
    pub readable_paths: Vec<String>,
    pub writable_paths: Vec<String>,
    pub network: bool,
}

pub fn build(_config: Config) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "macOS sandbox backend is not implemented",
    ))
}
