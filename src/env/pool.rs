//! Reusable environment pool corresponding to `go-judge/env/pool`.

use super::linuxcontainer::EnvError;
use std::sync::Mutex;

pub trait Environment: Send {
    fn reset(&mut self) -> Result<(), EnvError>;
    fn destroy(self: Box<Self>) -> Result<(), EnvError>;
}

pub trait EnvBuilder: Send + Sync {
    fn build(&self) -> Result<Box<dyn Environment>, EnvError>;
}

pub struct Pool {
    builder: Box<dyn EnvBuilder>,
    idle: Mutex<Vec<Box<dyn Environment>>>,
}

impl Pool {
    pub fn new(builder: Box<dyn EnvBuilder>) -> Self {
        Self {
            builder,
            idle: Mutex::new(Vec::new()),
        }
    }

    pub fn get(&self) -> Result<Box<dyn Environment>, EnvError> {
        if let Some(env) = self.idle.lock().map_err(|_| EnvError::Poisoned)?.pop() {
            return Ok(env);
        }
        self.builder.build()
    }

    /// Reset before reusing. If reset fails, destroy the environment.
    pub fn put(&self, mut env: Box<dyn Environment>) {
        if env.reset().is_err() {
            let _ = env.destroy();
            return;
        }
        if let Ok(mut idle) = self.idle.lock() {
            idle.push(env);
        } else {
            let _ = env.destroy();
        }
    }

    pub fn destroy_idle(&self) -> Result<(), EnvError> {
        let idle = std::mem::take(&mut *self.idle.lock().map_err(|_| EnvError::Poisoned)?);
        let mut first_error = None;
        for env in idle {
            if let Err(err) = env.destroy() {
                first_error.get_or_insert(err);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FakeEnv(usize, std::sync::Arc<AtomicUsize>);
    impl Environment for FakeEnv {
        fn reset(&mut self) -> Result<(), EnvError> {
            self.0 += 1;
            Ok(())
        }
        fn destroy(self: Box<Self>) -> Result<(), EnvError> {
            self.1.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    struct Builder(std::sync::Arc<AtomicUsize>);
    impl EnvBuilder for Builder {
        fn build(&self) -> Result<Box<dyn Environment>, EnvError> {
            Ok(Box::new(FakeEnv(0, self.0.clone())))
        }
    }

    #[test]
    fn returns_reset_environment_to_idle_pool() {
        let destroyed = std::sync::Arc::new(AtomicUsize::new(0));
        let pool = Pool::new(Box::new(Builder(destroyed.clone())));
        pool.put(pool.get().unwrap());
        pool.get().unwrap().destroy().unwrap();
        assert_eq!(destroyed.load(Ordering::SeqCst), 1);
    }
}
