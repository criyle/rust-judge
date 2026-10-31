//! Memory backed anonymous files used to pass immutable content to a child.
use nix::fcntl::{FcntlArg, SealFlag, fcntl};
use nix::sys::memfd::{MFdFlags, memfd_create};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};

/// Create a close-on-exec memory file that permits later sealing.
pub fn new(name: &str) -> io::Result<File> {
    let fd = memfd_create(name, MFdFlags::MFD_CLOEXEC | MFdFlags::MFD_ALLOW_SEALING)
        .map_err(|e| io::Error::other(format!("memfd: memfd_create: {e}")))?;
    Ok(File::from(fd))
}

/// Copy reader contents into a memfd, seal it against writes and size changes,
/// then rewind it. The returned descriptor remains readable.
pub fn dup_to_memfd(name: &str, mut reader: impl Read) -> io::Result<File> {
    dup_to_memfd_ref(name, &mut reader)
}

/// Copy from a borrowed reader so callers can fall back to a pipe if memfd
/// creation, copying, or sealing fails.
pub fn dup_to_memfd_ref(name: &str, reader: &mut dyn Read) -> io::Result<File> {
    let mut file = new(name).map_err(|e| io::Error::other(format!("memfd: dup: {e}")))?;
    io::copy(reader, &mut file).map_err(|e| io::Error::other(format!("memfd: read from: {e}")))?;
    let seals = SealFlag::F_SEAL_SEAL
        | SealFlag::F_SEAL_SHRINK
        | SealFlag::F_SEAL_GROW
        | SealFlag::F_SEAL_WRITE;
    fcntl(&file, FcntlArg::F_ADD_SEALS(seals))
        .map_err(|e| io::Error::other(format!("memfd: seal: {e}")))?;
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read, Write};

    #[test]
    fn new_memfd_is_readable_and_writable() {
        let mut file = new("rust-sandbox-test").unwrap();
        file.write_all(b"hello").unwrap();
        file.rewind().unwrap();
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();
        assert_eq!(content, "hello");
    }

    #[test]
    fn duplicate_is_rewound_and_sealed_read_only() {
        let mut file = dup_to_memfd("rust-sandbox-sealed-test", Cursor::new(b"immutable")).unwrap();
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();
        assert_eq!(content, "immutable");
        assert!(file.write_all(b"x").is_err());
    }

    #[test]
    fn propagates_reader_error() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::InvalidData, "broken reader"))
            }
        }
        assert!(dup_to_memfd("rust-sandbox-error-test", Broken).is_err());
    }
}
