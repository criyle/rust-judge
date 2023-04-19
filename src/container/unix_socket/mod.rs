use nix::errno::Errno;
use nix::sys::socket::sockopt::{OobInline, PassCred};
use nix::sys::socket::{
    recvmsg, sendmsg, setsockopt, socketpair, AddressFamily, ControlMessage, ControlMessageOwned,
    MsgFlags, SockFlag, SockType,
};
use std::io::{Error, ErrorKind, Result, IoSlice, IoSliceMut};
use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixDatagram;
use std::os::unix::prelude::FromRawFd;
use std::sync::Arc;
use tokio::io::unix::AsyncFd;

pub struct Socket {
    inner: Arc<AsyncFd<UnixDatagram>>,
}

impl Socket {
    pub fn new(fd: RawFd) -> Result<Socket> {
        setsockopt(fd, PassCred, &true)?;
        setsockopt(fd, OobInline, &true)?;

        let socket = unsafe { UnixDatagram::from_raw_fd(fd) };

        Ok(Socket {
            inner: Arc::new(AsyncFd::new(socket)?),
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
                Ok(n) => return n,
                Err(_would_block) => {}
            }
        }
    }

    pub async fn recvmsg<'a>(&self, buf: &mut [u8]) -> Result<(usize, Vec<ControlMessageOwned>)> {
        let mut cmsg_buf = Vec::with_capacity(4 << 10);

        loop {
            let mut guard = self.inner.readable().await?;

            match guard.try_io(|inner| {
                match recvmsg::<()>(
                    inner.get_ref().as_raw_fd(),
                    &mut [IoSliceMut::new(buf)],
                    Some(&mut cmsg_buf),
                    MsgFlags::MSG_CMSG_CLOEXEC,
                ) {
                    Ok(val) => Ok((val.bytes, val.cmsgs().collect())),
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

        let ret = rx.recvmsg(&mut buf).await;
        assert_eq!(0, ret.unwrap().0);

        a.await?;

        Ok(())
    }
}
