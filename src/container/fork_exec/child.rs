use std::io::{Error, ErrorKind, Result};
use std::os::unix::process::ExitStatusExt;
use std::process::{ExitStatus, Output};

/// A process started by `Runner`. The command-building and lifecycle surface
/// mirrors `std::process::Child`; the raw Linux path owns only a PID because
/// `std::process::Child` intentionally keeps its fields private.
#[derive(Debug)]
pub struct Child {
    pub(super) process: ChildProcess,
}

#[derive(Debug)]
pub(super) enum ChildProcess {
    Raw {
        pid: libc::pid_t,
        status: Option<ExitStatus>,
    },
    Standard(std::process::Child),
}

impl Child {
    pub fn id(&self) -> u32 {
        match &self.process {
            ChildProcess::Raw { pid, .. } => *pid as u32,
            ChildProcess::Standard(child) => child.id(),
        }
    }

    pub fn kill(&mut self) -> Result<()> {
        match &mut self.process {
            ChildProcess::Raw { pid, status } => {
                if status.is_some() {
                    return Ok(());
                }
                if unsafe { libc::kill(*pid, libc::SIGKILL) } == -1 {
                    Err(Error::last_os_error())
                } else {
                    Ok(())
                }
            }
            ChildProcess::Standard(child) => child.kill(),
        }
    }

    pub fn wait(&mut self) -> Result<ExitStatus> {
        match &mut self.process {
            ChildProcess::Raw { pid, status } => {
                if let Some(status) = status {
                    return Ok(*status);
                }
                let result = wait_pid(*pid, false)?;
                *status = Some(result);
                Ok(result)
            }
            ChildProcess::Standard(child) => child.wait(),
        }
    }

    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>> {
        match &mut self.process {
            ChildProcess::Raw { pid, status } => {
                if let Some(status) = status {
                    return Ok(Some(*status));
                }
                wait_pid(*pid, true)
                    .map(|result| {
                        *status = Some(result);
                        Some(result)
                    })
                    .or_else(|error| {
                        if error.raw_os_error() == Some(libc::EAGAIN) {
                            Ok(None)
                        } else {
                            Err(error)
                        }
                    })
            }
            ChildProcess::Standard(child) => child.try_wait(),
        }
    }

    pub fn wait_with_output(mut self) -> Result<Output> {
        let status = self.wait()?;
        // Runner currently inherits all three standard streams, matching a
        // Command with its default Stdio settings.
        Ok(Output {
            status,
            stdout: Vec::new(),
            stderr: Vec::new(),
        })
    }
}

pub(super) fn wait_pid(pid: libc::pid_t, nonblocking: bool) -> Result<ExitStatus> {
    loop {
        let mut status = 0;
        let result = unsafe {
            libc::waitpid(
                pid,
                &mut status,
                if nonblocking { libc::WNOHANG } else { 0 },
            )
        };
        if result == pid {
            return Ok(ExitStatus::from_raw(status));
        }
        if nonblocking && result == 0 {
            return Err(Error::from_raw_os_error(libc::EAGAIN));
        }
        if result == -1 {
            let error = Error::last_os_error();
            if error.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
    }
}
