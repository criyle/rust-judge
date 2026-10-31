//! Windows Job Object/token backend surface. The Go backend lowers the token's
//! mandatory integrity level and applies a low-integrity security descriptor.
//! Those Windows-specific APIs are not implemented in this crate yet.

#[derive(Clone, Debug, Default)]
pub struct Config {
    pub root: String,
}

pub fn build(_config: Config) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Windows sandbox backend is not implemented",
    ))
}
