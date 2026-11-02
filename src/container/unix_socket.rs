use nix::errno::Errno;
use nix::sys::socket::sockopt::{OobInline, PassCred};
use nix::sys::socket::{
    AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType, recvmsg,
    sendmsg, setsockopt, socketpair,
};
use std::io::{Error, ErrorKind, IoSlice, IoSliceMut, Result};
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
use std::sync::Arc;
use tokio::io::unix::AsyncFd;

pub struct Socket {
    inner: Arc<AsyncFd<OwnedFd>>,
}

impl Socket {
    pub fn as_raw_fd(&self) -> i32 {
        self.inner.get_ref().as_raw_fd()
    }

    pub fn new(fd: OwnedFd) -> Result<Socket> {
        setsockopt(&fd, PassCred, &true)?;
        setsockopt(&fd, OobInline, &true)?;

        // OwnedFd keeps the registered descriptor open and unchanged for the
        // lifetime of AsyncFd.
        Ok(Socket {
            // SAFETY: `fd` owns a valid descriptor and AsyncFd owns `fd` from
            // this point on, so its descriptor stays open and unchanged.
            inner: Arc::new(unsafe { AsyncFd::register(fd)? }),
        })
    }

    pub fn pair() -> Result<(Socket, Socket)> {
        let (tx, rx) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        )?;

        Ok((Socket::new(tx)?, Socket::new(rx)?))
    }

    pub async fn sendmsg(&self, buf: &[u8], msg: &[ControlMessage<'_>]) -> Result<usize> {
        loop {
            let mut guard = self.inner.writable().await?;

            match guard.try_io(|inner| {
                match sendmsg::<()>(
                    inner.get_ref().as_raw_fd(),
                    &[IoSlice::new(buf)],
                    msg,
                    MsgFlags::MSG_CMSG_CLOEXEC,
                    None,
                ) {
                    Ok(n) => Ok(n),
                    Err(Errno::EWOULDBLOCK) => Err(Error::from(ErrorKind::WouldBlock)),
                    Err(e) => Err(Error::from_raw_os_error(e as i32)),
                }
            }) {
                Ok(result) => {
                    let n = result?;
                    return if n == buf.len() {
                        Ok(n)
                    } else {
                        Err(Error::new(ErrorKind::WriteZero, "short seqpacket write"))
                    };
                }
                Err(_would_block) => {}
            }
        }
    }

    /// Send a packet with file descriptors attached as `SCM_RIGHTS`.
    pub async fn send_fds(&self, buf: &[u8], fds: &[BorrowedFd<'_>]) -> Result<usize> {
        let raw_fds: Vec<_> = fds.iter().map(AsRawFd::as_raw_fd).collect();
        if raw_fds.is_empty() {
            self.sendmsg(buf, &[]).await
        } else {
            self.sendmsg(buf, &[ControlMessage::ScmRights(&raw_fds)])
                .await
        }
    }

    /// Receive one packet and its ancillary data. File descriptors inside
    /// `ControlMessageOwned::ScmRights` are raw descriptors; callers must close
    /// them or convert them to `OwnedFd`.
    pub async fn recvmsg(&self, buf: &mut [u8]) -> Result<(usize, Vec<ControlMessageOwned>)> {
        // nix passes the slice length as msg_controllen; capacity alone would
        // provide zero space and make any ancillary data fail with ENOBUFS.
        let mut cmsg_buf = vec![0; 4 << 10];

        loop {
            let mut guard = self.inner.readable().await?;

            match guard.try_io(|inner| {
                match recvmsg::<()>(
                    inner.get_ref().as_raw_fd(),
                    &mut [IoSliceMut::new(buf)],
                    Some(&mut cmsg_buf),
                    MsgFlags::MSG_CMSG_CLOEXEC,
                ) {
                    Ok(val) => {
                        // Collect control data before checking truncation so any
                        // received SCM_RIGHTS descriptors are dropped on error.
                        let cmsgs: Vec<_> = match val.cmsgs() {
                            Ok(cmsgs) => cmsgs.collect(),
                            Err(error) => return Err(Error::other(error)),
                        };
                        if val
                            .flags
                            .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC)
                        {
                            close_received_rights(&cmsgs);
                            return Err(Error::new(
                                ErrorKind::InvalidData,
                                "unix socket message truncated",
                            ));
                        }
                        match val.bytes {
                            0 => Err(Error::from(ErrorKind::BrokenPipe)),
                            n => Ok((n, cmsgs)),
                        }
                    }
                    Err(Errno::EWOULDBLOCK) => Err(Error::from(ErrorKind::WouldBlock)),
                    Err(e) => Err(Error::from_raw_os_error(e as i32)),
                }
            }) {
                Ok(n) => return n,
                Err(_would_block) => {}
            }
        }
    }
}

fn close_received_rights(messages: &[ControlMessageOwned]) {
    for message in messages {
        if let ControlMessageOwned::ScmRights(fds) = message {
            for fd in fds {
                // recvmsg created these descriptors for this process; if the
                // packet is rejected they must not remain leaked.
                let _ = nix::unistd::close(*fd);
            }
        }
    }
}

impl Clone for Socket {
    fn clone(&self) -> Self {
        Socket {
            inner: self.inner.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::socket::{ControlMessage, UnixCredentials};

    #[tokio::test]
    async fn read_and_write() -> Result<()> {
        let (tx, rx) = Socket::pair()?;

        let a = tokio::spawn(async move {
            let mut buf = [0; 2];
            let ret = tx.recvmsg(&mut buf).await;
            assert_eq!(2, ret.unwrap().0);

            let ret = tx
                .sendmsg(
                    &buf,
                    &[ControlMessage::ScmCredentials(&UnixCredentials::new())],
                )
                .await;
            assert_eq!(2, ret.unwrap());
        });

        let mut buf = [0; 2];
        let ret = rx
            .sendmsg(
                &buf,
                &[ControlMessage::ScmCredentials(&UnixCredentials::new())],
            )
            .await;
        assert_eq!(2, ret.unwrap());

        let ret = rx.recvmsg(&mut buf).await;
        assert_eq!(2, ret.unwrap().0);

        a.await?;

        let ret = rx.recvmsg(&mut buf).await;
        assert_eq!(ret.unwrap_err().kind(), ErrorKind::BrokenPipe);

        Ok(())
    }

    #[tokio::test]
    async fn send_to_closed_socket() -> Result<()> {
        use nix::sys::socket::{Shutdown, shutdown};

        let (tx, rx) = Socket::pair()?;
        shutdown(rx.as_raw_fd(), Shutdown::Both).map_err(Error::other)?;
        drop(rx);
        let buf = [0; 2];
        let ret = tx
            .sendmsg(
                &buf,
                &[ControlMessage::ScmCredentials(&UnixCredentials::new())],
            )
            .await;

        assert_eq!(ret.unwrap_err().kind(), ErrorKind::BrokenPipe);

        Ok(())
    }

    #[tokio::test]
    async fn passes_owned_file_descriptors() -> Result<()> {
        use nix::unistd::{pipe, read, write};
        use std::os::fd::{AsFd, FromRawFd};

        let (tx, rx) = Socket::pair()?;
        let (read_end, write_end) = pipe().map_err(Error::other)?;
        write(&write_end, b"fd").map_err(Error::other)?;
        tx.send_fds(b"x", &[read_end.as_fd()]).await?;

        let mut payload = [0; 8];
        let (n, ancillary) = rx.recvmsg(&mut payload).await?;
        assert_eq!(&payload[..n], b"x");
        let received_raw = ancillary
            .into_iter()
            .find_map(|cmsg| match cmsg {
                ControlMessageOwned::ScmRights(mut fds) => fds.pop(),
                _ => None,
            })
            .expect("SCM_RIGHTS descriptor");
        // nix exposes received SCM_RIGHTS descriptors as raw integers.
        // Take ownership here so the descriptor is closed at the end of test.
        let received = unsafe { OwnedFd::from_raw_fd(received_raw) };
        let mut contents = [0; 2];
        assert_eq!(read(&received, &mut contents).map_err(Error::other)?, 2);
        assert_eq!(&contents, b"fd");
        Ok(())
    }

    #[tokio::test]
    async fn rejects_truncated_packet() -> Result<()> {
        let (tx, rx) = Socket::pair()?;
        tx.sendmsg(b"packet larger than destination", &[]).await?;
        let mut small = [0; 3];
        let err = rx.recvmsg(&mut small).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        Ok(())
    }
}
