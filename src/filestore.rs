//! Local file storage matching the file ID behavior used by go-judge.
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

/// A filesystem backed file store. Returned IDs are basenames within `dir`.
#[derive(Clone)]
pub struct LocalFileStore {
    dir: PathBuf,
    names: Arc<Mutex<HashMap<String, String>>>,
    timeout: Option<Arc<LocalTimeout>>,
}

struct LocalTimeout {
    accessed: Arc<Mutex<HashMap<String, Instant>>>,
    lifecycle: Arc<TimeoutLifecycle>,
}

impl LocalFileStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        if crate::runtime_metrics::is_enabled()
            && let Ok(entries) = fs::read_dir(&dir)
        {
            for entry in entries.flatten() {
                if let Ok(metadata) = entry.metadata()
                    && metadata.is_file()
                {
                    crate::runtime_metrics::observe_file_size(metadata.len());
                }
            }
        }
        Self {
            dir,
            names: Arc::new(Mutex::new(HashMap::new())),
            timeout: None,
        }
    }

    /// Create a local file store with Go's sliding file TTL behavior.
    ///
    /// A successful `add` starts the TTL, `get` refreshes it, and a background
    /// reaper removes expired files. A zero timeout disables expiration.
    pub fn with_timeout(
        dir: impl Into<PathBuf>,
        timeout: Duration,
        check_interval: Duration,
    ) -> Self {
        let mut store = Self::new(dir);
        if !timeout.is_zero() {
            store.timeout = Some(Arc::new(LocalTimeout::new(
                store.dir.clone(),
                Arc::clone(&store.names),
                timeout,
                check_interval,
            )));
        }
        store
    }

    pub fn add(&self, name: impl Into<String>, path: impl AsRef<Path>) -> io::Result<String> {
        let path = path.as_ref();
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        if clean_path(parent) != clean_path(&self.dir) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "add: {} does not have prefix {}",
                    path.display(),
                    self.dir.display()
                ),
            ));
        }
        let id = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "path has no valid file name")
            })?
            .to_owned();
        self.names.lock().unwrap().insert(id.clone(), name.into());
        if crate::runtime_metrics::is_enabled()
            && let Ok(metadata) = fs::metadata(path)
        {
            crate::runtime_metrics::observe_file_size(metadata.len());
        }
        if let Some(timeout) = &self.timeout {
            timeout.touch(&id);
        }
        Ok(id)
    }

    /// Copy an output file into the store and preserve its client-visible name.
    pub fn add_reader(&self, name: impl Into<String>, mut source: impl Read) -> io::Result<String> {
        let name = name.into();
        let (id, mut destination) = self.new_file()?;
        if let Err(error) =
            io::copy(&mut source, &mut destination).and_then(|_| destination.flush())
        {
            let _ = self.remove(&id);
            return Err(error);
        }
        if let Err(error) = self.set_name(&id, name) {
            let _ = self.remove(&id);
            return Err(error);
        }
        if crate::runtime_metrics::is_enabled()
            && let Ok(metadata) = fs::metadata(self.dir.join(&id))
        {
            crate::runtime_metrics::observe_file_size(metadata.len());
        }
        Ok(id)
    }

    pub fn get(&self, id: &str) -> Option<(String, File)> {
        if !valid_id(id) {
            return None;
        }
        let file = File::open(self.dir.join(id)).ok()?;
        let name = self
            .names
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .unwrap_or_else(|| id.to_owned());
        if let Some(timeout) = &self.timeout {
            timeout.touch(id);
        }
        Some((name, file))
    }

    /// Preserve the client supplied filename for a file already created in this store.
    pub fn set_name(&self, id: &str, name: impl Into<String>) -> io::Result<()> {
        if !valid_id(id) || !self.dir.join(id).is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "file does not exist",
            ));
        }
        self.names
            .lock()
            .unwrap()
            .insert(id.to_owned(), name.into());
        if let Some(timeout) = &self.timeout {
            timeout.touch(id);
        }
        Ok(())
    }

    pub fn remove(&self, id: &str) -> bool {
        if !valid_id(id) {
            return false;
        }
        match fs::remove_file(self.dir.join(id)) {
            Ok(()) => {
                self.names.lock().unwrap().remove(id);
                if let Some(timeout) = &self.timeout {
                    timeout.forget(id);
                }
                true
            }
            Err(_) => {
                if let Some(timeout) = &self.timeout {
                    timeout.forget(id);
                }
                false
            }
        }
    }

    pub fn list(&self) -> io::Result<HashMap<String, String>> {
        let names = self.names.lock().unwrap();
        let mut result = HashMap::new();
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let id = entry.file_name().to_string_lossy().into_owned();
            result.insert(id.clone(), names.get(&id).cloned().unwrap_or_default());
        }
        Ok(result)
    }

    pub fn new_file(&self) -> io::Result<(String, File)> {
        for _ in 0..50 {
            let id = random_id();
            match OpenOptions::new()
                .write(true)
                .read(true)
                .create_new(true)
                .open(self.dir.join(&id))
            {
                Ok(file) => return Ok((id, file)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "unique id does not exists after tried 50 times",
        ))
    }
}

/// Adds a sliding TTL to a local store. Accessing an entry refreshes its expiry.
pub struct TimeoutFileStore {
    shared: Arc<TimeoutShared>,
    lifecycle: Arc<TimeoutLifecycle>,
}

struct TimeoutShared {
    inner: LocalFileStore,
    timeout: Duration,
    accessed: Mutex<HashMap<String, Instant>>,
}

struct TimeoutLifecycle {
    stopped: tokio::sync::watch::Sender<bool>,
    worker: Mutex<Option<mpsc::Receiver<()>>>,
}

fn start_timeout_task(
    interval: Duration,
    reap: impl Fn() + Send + Sync + 'static,
) -> Arc<TimeoutLifecycle> {
    let (stopped, mut stop_rx) = tokio::sync::watch::channel(false);
    let (done_tx, done_rx) = mpsc::channel();
    let reap = Arc::new(reap);
    crate::tokio_runtime::runtime().handle().spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                changed = stop_rx.changed() => {
                    if changed.is_err() || *stop_rx.borrow() { break; }
                }
                _ = ticker.tick() => {
                    let reap = Arc::clone(&reap);
                    if tokio::task::spawn_blocking(move || reap()).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = done_tx.send(());
    });
    Arc::new(TimeoutLifecycle {
        stopped,
        worker: Mutex::new(Some(done_rx)),
    })
}

fn stop_timeout_task(lifecycle: &TimeoutLifecycle) -> io::Result<()> {
    let _ = lifecycle.stopped.send(true);
    if let Some(worker) = lifecycle
        .worker
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
    {
        worker
            .recv()
            .map_err(|_| io::Error::other("timeout reaper task stopped unexpectedly"))?;
    }
    Ok(())
}

impl LocalTimeout {
    fn new(
        dir: PathBuf,
        names: Arc<Mutex<HashMap<String, String>>>,
        timeout: Duration,
        check_interval: Duration,
    ) -> Self {
        let accessed = Arc::new(Mutex::new(HashMap::<String, Instant>::new()));
        let worker_accessed = Arc::clone(&accessed);
        let interval = check_interval.max(Duration::from_millis(1));
        let lifecycle = start_timeout_task(interval, move || {
            reap_local_files(&dir, &names, &worker_accessed, timeout);
        });
        Self {
            accessed,
            lifecycle,
        }
    }

    fn touch(&self, id: &str) {
        self.accessed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id.to_owned(), Instant::now());
    }

    fn forget(&self, id: &str) {
        self.accessed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id);
    }
}

impl Drop for LocalTimeout {
    fn drop(&mut self) {
        let _ = stop_timeout_task(&self.lifecycle);
    }
}

fn reap_local_files(
    dir: &Path,
    names: &Mutex<HashMap<String, String>>,
    accessed: &Mutex<HashMap<String, Instant>>,
    timeout: Duration,
) -> usize {
    let now = Instant::now();
    let mut accessed = accessed.lock().unwrap_or_else(|e| e.into_inner());
    let expired: Vec<_> = accessed
        .iter()
        .filter(|(_, last_access)| now.duration_since(**last_access) > timeout)
        .map(|(id, _)| id.clone())
        .collect();
    let mut removed = 0;
    for id in expired {
        if fs::remove_file(dir.join(&id)).is_ok() {
            removed += 1;
        }
        names.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
        accessed.remove(&id);
    }
    removed
}

impl TimeoutFileStore {
    pub fn new(inner: LocalFileStore, timeout: Duration) -> Self {
        let interval = timeout
            .min(Duration::from_secs(1))
            .max(Duration::from_millis(10));
        Self::new_with_interval(inner, timeout, interval)
    }

    /// Construct a timeout store that checks for expired entries every
    /// `check_interval`, matching go-judge's ticker based TTL lifecycle.
    pub fn new_with_interval(
        inner: LocalFileStore,
        timeout: Duration,
        check_interval: Duration,
    ) -> Self {
        let shared = Arc::new(TimeoutShared {
            inner,
            timeout,
            accessed: Mutex::new(HashMap::new()),
        });
        let worker_shared = Arc::clone(&shared);
        let interval = check_interval.max(Duration::from_millis(1));
        let lifecycle = start_timeout_task(interval, move || {
            worker_shared.reap_expired();
        });
        Self { shared, lifecycle }
    }

    pub fn add(&self, name: impl Into<String>, path: impl AsRef<Path>) -> io::Result<String> {
        let id = self.shared.inner.add(name, path)?;
        self.shared
            .accessed
            .lock()
            .unwrap()
            .insert(id.clone(), Instant::now());
        Ok(id)
    }
    pub fn get(&self, id: &str) -> Option<(String, File)> {
        let found = self.shared.inner.get(id);
        if found.is_some()
            && let Some(t) = self.shared.accessed.lock().unwrap().get_mut(id)
        {
            *t = Instant::now();
        }
        found
    }
    pub fn remove(&self, id: &str) -> bool {
        let removed = self.shared.inner.remove(id);
        self.shared.accessed.lock().unwrap().remove(id);
        removed
    }
    pub fn reap_expired(&self) -> usize {
        self.shared.reap_expired()
    }

    /// Stop the expiry ticker and wait for it to exit. Repeated calls are safe.
    pub fn close(&self) -> io::Result<()> {
        stop_timeout_task(&self.lifecycle)
    }
}

impl TimeoutShared {
    fn reap_expired(&self) -> usize {
        let now = Instant::now();
        let mut accessed = self.accessed.lock().unwrap_or_else(|e| e.into_inner());
        let expired: Vec<_> = accessed
            .iter()
            .filter(|(_, t)| now.duration_since(**t) > self.timeout)
            .map(|(id, _)| id.clone())
            .collect();
        let mut removed = 0;
        for id in expired {
            if self.inner.remove(&id) {
                removed += 1;
            }
            accessed.remove(&id);
        }
        removed
    }
}

impl Drop for TimeoutFileStore {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

fn valid_id(id: &str) -> bool {
    if id.is_empty() || id == "." || id == ".." {
        return false;
    }
    let mut components = Path::new(id).components();
    matches!(
        (components.next(), components.next()),
        (Some(Component::Normal(_)), None)
    ) && !Path::new(id).is_absolute()
}
fn clean_path(p: &Path) -> PathBuf {
    p.components().collect()
}
fn random_id() -> String {
    // Use the operating system RNG through /dev/urandom on Unix; fall back to a
    // process/time mix only if the device is unavailable.
    let mut bytes = [0u8; 5];
    if File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut bytes))
        .is_err()
    {
        let n = Instant::now().elapsed().as_nanos() as u64 ^ std::process::id() as u64;
        bytes.copy_from_slice(&n.to_le_bytes()[..5]);
    }
    const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for b in bytes {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_dir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "rust-sandbox-filestore-{}-{:?}",
            std::process::id(),
            Instant::now()
        ));
        fs::create_dir_all(&p).unwrap();
        p
    }
    #[test]
    fn create_add_get_list_remove_and_reject_traversal() {
        let dir = temp_dir();
        let store = LocalFileStore::new(&dir);
        let (id, mut f) = store.new_file().unwrap();
        f.write_all(b"payload").unwrap();
        drop(f);
        assert_eq!(store.add("answer.txt", dir.join(&id)).unwrap(), id);
        let (name, mut f) = store.get(&id).unwrap();
        assert_eq!(name, "answer.txt");
        let mut s = String::new();
        std::io::Read::read_to_string(&mut f, &mut s).unwrap();
        assert_eq!(s, "payload");
        assert!(store.list().unwrap().contains_key(&id));
        assert!(store.get("../etc/passwd").is_none());
        assert!(!store.remove("../etc/passwd"));
        assert!(store.remove(&id));
        assert!(store.get(&id).is_none());
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn timeout_refreshes_and_reaps() {
        let dir = temp_dir();
        let local = LocalFileStore::new(&dir);
        let (id, _) = local.new_file().unwrap();
        let ttl = TimeoutFileStore::new_with_interval(
            local.clone(),
            Duration::from_millis(80),
            Duration::from_millis(5),
        );
        ttl.add("x", dir.join(&id)).unwrap();
        std::thread::sleep(Duration::from_millis(45));
        drop(ttl.get(&id));
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            local.get(&id).is_some(),
            "get should have refreshed the expiry"
        );
        wait_until_gone(&local, &id);
        ttl.close().unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn local_store_timeout_is_wired_to_add_get_and_remove() {
        let dir = temp_dir();
        let store =
            LocalFileStore::with_timeout(&dir, Duration::from_millis(80), Duration::from_millis(5));
        let (id, _) = store.new_file().unwrap();
        store.add("cached", dir.join(&id)).unwrap();

        std::thread::sleep(Duration::from_millis(45));
        assert!(store.get(&id).is_some(), "get should refresh the TTL");
        std::thread::sleep(Duration::from_millis(50));
        assert!(dir.join(&id).exists(), "the refreshed file should remain");
        std::thread::sleep(Duration::from_millis(50));
        assert!(store.get(&id).is_none(), "the file should expire after TTL");

        let (removed_id, _) = store.new_file().unwrap();
        store.add("removed", dir.join(&removed_id)).unwrap();
        assert!(store.remove(&removed_id));
        std::thread::sleep(Duration::from_millis(100));
        assert!(!dir.join(&removed_id).exists());

        drop(store);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn zero_local_store_timeout_disables_expiration() {
        let dir = temp_dir();
        let store = LocalFileStore::with_timeout(&dir, Duration::ZERO, Duration::ZERO);
        let (id, _) = store.new_file().unwrap();
        store.add("permanent", dir.join(&id)).unwrap();
        std::thread::sleep(Duration::from_millis(20));
        assert!(store.get(&id).is_some());
        drop(store);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn timeout_automatically_reaps_and_close_is_idempotent() {
        let dir = temp_dir();
        let local = LocalFileStore::new(&dir);
        let (id, _) = local.new_file().unwrap();
        let ttl = TimeoutFileStore::new_with_interval(
            local.clone(),
            Duration::from_millis(30),
            Duration::from_millis(3),
        );
        ttl.add("expired", dir.join(&id)).unwrap();
        wait_until_gone(&local, &id);
        ttl.close().unwrap();
        ttl.close().unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    fn wait_until_gone(store: &LocalFileStore, id: &str) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if store.get(id).is_none() {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "expired file was not reaped in time"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
