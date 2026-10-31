//! Periodically return free glibc allocator pages to the operating system.
//!
//! Rust has no tracing garbage collector to force. Values are reclaimed when
//! dropped; on glibc, `malloc_trim` provides the closest equivalent to Go's
//! `debug.FreeOSMemory` for returning already-free allocator pages. The
//! configured threshold uses the allocator's arena plus mmap footprint as a
//! coarse analogue of Go's in-use heap size.

use std::time::Duration;
use std::{io, io::ErrorKind};
use tokio::task::JoinHandle;

/// Spawn the periodic allocator reclamation task on the shared Tokio runtime.
/// Blocking allocator inspection and trimming run on Tokio's blocking pool.
/// Returns `None` on platforms without the glibc allocator API or for a zero
/// interval, which cannot drive a Tokio timer.
pub fn spawn(interval: Duration, target_bytes: u64) -> io::Result<Option<JoinHandle<()>>> {
    if interval.is_zero() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "force-gc-interval must be positive",
        ));
    }
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        return Ok(Some(crate::tokio_runtime::runtime().handle().spawn(
            async move {
                let mut ticker = tokio::time::interval(interval);
                loop {
                    ticker.tick().await;
                    let _ = tokio::task::spawn_blocking(move || {
                        reclaim_if_over_target(target_bytes);
                    })
                    .await;
                }
            },
        )));
    }
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    {
        let _ = (interval, target_bytes);
        Ok(None)
    }
}

/// Trim free allocator pages only when the glibc arena footprint exceeds the
/// configured threshold. Returns true if `malloc_trim` released pages.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub fn reclaim_if_over_target(target_bytes: u64) -> bool {
    // SAFETY: mallinfo2 has no pointer arguments and only reads allocator
    // bookkeeping maintained by the process's glibc allocator.
    let stats = unsafe { libc::mallinfo2() };
    let footprint = stats.arena.saturating_add(stats.hblkhd) as u64;
    if footprint < target_bytes {
        return false;
    }
    // SAFETY: malloc_trim accepts a scalar padding value and is thread-safe in
    // glibc. A zero pad allows release of all complete free pages.
    unsafe { libc::malloc_trim(0) != 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[test]
    fn allocator_footprint_below_maximum_target_is_not_trimmed() {
        assert!(!reclaim_if_over_target(u64::MAX));
    }

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[test]
    fn zero_target_runs_allocator_trim_without_panicking() {
        let _ = reclaim_if_over_target(0);
    }

    #[test]
    fn zero_interval_does_not_spawn_a_busy_reclaimer() {
        assert_eq!(
            spawn(Duration::ZERO, 20 << 20).unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
    }
}
