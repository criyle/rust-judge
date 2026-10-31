//! Bounded output capture from an operating system pipe.
use std::fs::File;
use std::io::{self, Read};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};

/// A pipe whose reader retains at most `max + 1` bytes and then drains the
/// remainder so writers can finish without a full pipe causing a deadlock.
pub struct Buffer {
    writer: Option<File>,
    captured: Arc<Mutex<Vec<u8>>>,
    done: Receiver<()>,
    drain_thread: Option<Receiver<()>>,
    pub max: i64,
}

impl Buffer {
    pub fn new(max: i64) -> io::Result<Self> {
        let (read_fd, write_fd) = nix::unistd::pipe().map_err(io::Error::other)?;
        let reader = File::from(read_fd);
        let writer = File::from(write_fd);
        let captured = Arc::new(Mutex::new(Vec::new()));
        let output = Arc::clone(&captured);
        let (done_tx, done) = mpsc::channel();
        // Match Go's sentinel byte: retain one byte beyond the configured cap.
        let limit = max.saturating_add(1).max(0) as usize;
        let drain_thread = crate::tokio_runtime::spawn_blocking(move || {
            let mut reader = reader;
            let mut remaining = limit;
            let mut chunk = [0; 8192];
            while remaining > 0 {
                let want = remaining.min(chunk.len());
                match reader.read(&mut chunk[..want]) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        output
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .extend_from_slice(&chunk[..n]);
                        remaining -= n;
                    }
                }
            }
            let _ = done_tx.send(());
            // Continue draining until the owner closes the write end.
            io::copy(&mut reader, &mut io::sink()).ok();
        });
        Ok(Self {
            writer: Some(writer),
            captured,
            done,
            drain_thread: Some(drain_thread),
            max,
        })
    }

    pub fn writer(&self) -> &File {
        self.writer.as_ref().expect("pipe writer has been closed")
    }

    /// Close this end to let the reader finish draining after its bounded copy.
    pub fn close_writer(&mut self) {
        self.writer.take();
    }

    /// Wait until the bounded part has arrived. Close the writer first when
    /// no further writes are expected; this also lets the drain thread exit.
    pub fn wait(&mut self) -> io::Result<Vec<u8>> {
        self.done.recv().map_err(io::Error::other)?;
        if self.writer.is_none()
            && let Some(thread) = self.drain_thread.take()
        {
            thread
                .recv()
                .map_err(|_| io::Error::other("pipe drain task panicked"))?;
        }
        Ok(self
            .captured
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone())
    }

    pub fn output(&self) -> Vec<u8> {
        self.captured
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

impl std::fmt::Display for Buffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let len = self
            .captured
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len();
        write!(f, "Buffer[{len}/{}]", self.max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn captures_all_below_limit() {
        let mut b = Buffer::new(10).unwrap();
        b.writer().write_all(b"hello").unwrap();
        b.close_writer();
        assert_eq!(b.wait().unwrap(), b"hello");
        assert_eq!(b.to_string(), "Buffer[5/10]");
    }

    #[test]
    fn keeps_limit_plus_sentinel_then_drains() {
        let mut b = Buffer::new(5).unwrap();
        b.writer().write_all(b"toolonginput").unwrap();
        b.close_writer();
        assert_eq!(b.wait().unwrap(), b"toolon");
    }
}
