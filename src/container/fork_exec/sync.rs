use std::io::{Error, ErrorKind, Result};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(super) fn child_sync_with_parent(fd: i32) -> Result<()> {
    let pid = (unsafe { libc::getpid() }).to_ne_bytes();
    let mut written = 0;
    while written < pid.len() {
        // SAFETY: `pid` is a valid byte buffer for the remaining length.
        let result =
            unsafe { libc::write(fd, pid[written..].as_ptr().cast(), pid.len() - written) };
        if result == -1 {
            let error = Error::last_os_error();
            if error.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if result == 0 {
            return Err(Error::new(
                ErrorKind::WriteZero,
                "parent sync socket closed before sending child PID",
            ));
        }
        written += result as usize;
    }

    let mut acknowledgement = [0u8; 1];
    loop {
        // SAFETY: `acknowledgement` is a valid one-byte output buffer.
        let result = unsafe { libc::read(fd, acknowledgement.as_mut_ptr().cast(), 1) };
        if result == -1 {
            let error = Error::last_os_error();
            if error.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if result == 0 {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "parent sync socket closed before acknowledgement",
            ));
        }
        break;
    }
    // SAFETY: this descriptor is the child endpoint created for this
    // handshake and is no longer needed once the acknowledgement is read.
    if unsafe { libc::close(fd) } == -1 {
        return Err(Error::last_os_error());
    }
    if acknowledgement[0] != 0 {
        return Err(Error::other("parent-child sync callback failed"));
    }
    Ok(())
}

pub(super) fn sync_socket_above_stdio(socket: UnixStream) -> Result<UnixStream> {
    let fd = socket.as_raw_fd();
    if fd >= 3 {
        return Ok(socket);
    }
    // SAFETY: F_DUPFD_CLOEXEC duplicates this owned Unix socket to the first
    // descriptor at or above 3, leaving standard streams untouched.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate == -1 {
        return Err(Error::last_os_error());
    }
    drop(socket);
    // SAFETY: `duplicate` is a fresh descriptor for the same Unix socket.
    Ok(unsafe { UnixStream::from_raw_fd(duplicate) })
}

pub(super) fn spawn_parent_sync(
    socket: UnixStream,
    callback: Box<dyn FnMut(i32) -> Result<()> + Send>,
) -> Result<std::sync::mpsc::Receiver<Result<()>>> {
    socket.set_nonblocking(true)?;
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    crate::tokio_runtime::runtime().handle().spawn(async move {
        let result = match tokio::net::UnixStream::from_std(socket) {
            Ok(socket) => parent_sync_with_child(socket, callback).await,
            Err(error) => Err(error),
        };
        let _ = tx.send(result);
    });
    Ok(rx)
}

async fn parent_sync_with_child(
    mut socket: tokio::net::UnixStream,
    mut callback: Box<dyn FnMut(i32) -> Result<()> + Send>,
) -> Result<()> {
    let mut pid = [0u8; std::mem::size_of::<i32>()];
    socket.read_exact(&mut pid).await?;
    let pid = i32::from_ne_bytes(pid);
    if pid <= 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "child sync handshake supplied an invalid PID",
        ));
    }
    let result = callback(pid);
    socket.write_all(&[u8::from(result.is_err())]).await?;
    result
}
