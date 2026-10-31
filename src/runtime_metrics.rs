//! Process-wide metrics shared by the worker, environment builder, and file store.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

static METRICS_ENABLED: AtomicBool = AtomicBool::new(false);
static ENVIRONMENTS_BUILT: AtomicU64 = AtomicU64::new(0);
static ENVIRONMENTS_IN_USE: AtomicU64 = AtomicU64::new(0);
static FILE_SIZE: LazyLock<Mutex<FileSizeHistogram>> =
    LazyLock::new(|| Mutex::new(FileSizeHistogram::default()));

#[derive(Default)]
struct FileSizeHistogram {
    buckets: [u64; 20],
    count: u64,
    sum: f64,
}

pub fn set_enabled(enabled: bool) {
    METRICS_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn is_enabled() -> bool {
    METRICS_ENABLED.load(Ordering::Relaxed)
}

pub fn environment_built() {
    if !is_enabled() {
        return;
    }
    ENVIRONMENTS_BUILT.fetch_add(1, Ordering::Relaxed);
}

pub fn environment_acquired() {
    if !is_enabled() {
        return;
    }
    ENVIRONMENTS_IN_USE.fetch_add(1, Ordering::Relaxed);
}

pub fn environment_released() {
    if !is_enabled() {
        return;
    }
    let mut current = ENVIRONMENTS_IN_USE.load(Ordering::Relaxed);
    while current > 0 {
        match ENVIRONMENTS_IN_USE.compare_exchange_weak(
            current,
            current - 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(actual) => current = actual,
        }
    }
}

pub fn environment_counts() -> (u64, u64) {
    (
        ENVIRONMENTS_BUILT.load(Ordering::Relaxed),
        ENVIRONMENTS_IN_USE.load(Ordering::Relaxed),
    )
}

pub fn observe_file_size(size: u64) {
    if !is_enabled() {
        return;
    }
    let Ok(mut histogram) = FILE_SIZE.lock() else {
        return;
    };
    record_file_size(&mut histogram, size);
}

fn record_file_size(histogram: &mut FileSizeHistogram, size: u64) {
    if let Some(index) = (0..20).find(|index| size <= (1u64 << (8 + index))) {
        histogram.buckets[index] += 1;
    }
    histogram.count += 1;
    histogram.sum += size as f64;
}

pub fn file_size_histogram() -> ([u64; 20], u64, f64) {
    FILE_SIZE
        .lock()
        .map(|histogram| (histogram.buckets, histogram.count, histogram.sum))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_size_observation_updates_bucket_count_and_sum() {
        let mut histogram = FileSizeHistogram::default();
        record_file_size(&mut histogram, 513);
        assert_eq!(histogram.buckets[2], 1);
        assert_eq!(histogram.count, 1);
        assert_eq!(histogram.sum, 513.0);
    }
}
