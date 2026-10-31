//! Unix `SOCK_SEQPACKET` transport with `SCM_RIGHTS` and `SCM_CREDENTIALS`.
//!
//! This is the Rust counterpart of `go-sandbox/pkg/unixsocket`. Descriptors
//! received through `SCM_RIGHTS` are returned as `OwnedFd`s, so unclaimed
//! descriptors close automatically.
use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use nix::sys::socket::sockopt::{PassCred, SockType as SockTypeOpt};
use nix::sys::socket::{
    AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType,
    UnixCredentials, getsockopt, recvmsg, sendmsg, setsockopt, socketpair,
};
use std::io::{self, ErrorKind, IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

const OOB_SIZE: usize = 4 << 10;

pub struct Socket {
    fd: OwnedFd,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Credentials {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

/// Control data requested when sending a packet.
#[derive(Default)]
pub struct SendMessage<'fd> {
    pub fds: Vec<BorrowedFd<'fd>>,
    /// Attach credentials for the current process. Linux only permits sending
    /// credentials matching the current process without special privileges.
    pub credentials: bool,
}

/// Control data delivered with a received packet.
#[derive(Debug, Default)]
pub struct ReceivedMessage {
    pub fds: Vec<OwnedFd>,
    pub credentials: Option<Credentials>,
}

impl Socket {
    /// Take ownership of an existing Unix seqpacket descriptor and mark it
    /// close-on-exec. The socket must be connected and use `SOCK_SEQPACKET`.
    pub fn new(fd: OwnedFd) -> io::Result<Self> {
        let socket_type = getsockopt(&fd, SockTypeOpt).map_err(io::Error::from)?;
        if socket_type != SockType::SeqPacket {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "expected Unix SOCK_SEQPACKET socket",
            ));
        }
        let current = fcntl(&fd, FcntlArg::F_GETFD).map_err(io::Error::from)?;
        fcntl(
            &fd,
            FcntlArg::F_SETFD(FdFlag::from_bits_truncate(current) | FdFlag::FD_CLOEXEC),
        )
        .map_err(io::Error::from)?;
        Ok(Self { fd })
    }

    pub fn pair() -> io::Result<(Self, Self)> {
        let (left, right) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC,
        )
        .map_err(io::Error::from)?;
        Ok((Self::new(left)?, Self::new(right)?))
    }

    /// Toggle automatic `SCM_CREDENTIALS` delivery on receives.
    pub fn set_pass_cred(&self, enabled: bool) -> io::Result<()> {
        setsockopt(&self.fd, PassCred, &enabled).map_err(io::Error::from)
    }

    pub fn send_msg(&self, bytes: &[u8], message: &SendMessage<'_>) -> io::Result<()> {
        let raw_fds: Vec<_> = message.fds.iter().map(AsRawFd::as_raw_fd).collect();
        let credentials = UnixCredentials::new();
        let mut controls = Vec::with_capacity(2);
        if !raw_fds.is_empty() {
            controls.push(ControlMessage::ScmRights(&raw_fds));
        }
        if message.credentials {
            controls.push(ControlMessage::ScmCredentials(&credentials));
        }
        match sendmsg::<()>(
            self.fd.as_raw_fd(),
            &[IoSlice::new(bytes)],
            &controls,
            MsgFlags::MSG_NOSIGNAL,
            None,
        ) {
            Ok(n) if n == bytes.len() => Ok(()),
            Ok(_) => Err(io::Error::new(
                ErrorKind::WriteZero,
                "short seqpacket write",
            )),
            Err(error) => Err(io::Error::from(error)),
        }
    }

    pub fn recv_msg(&self, bytes: &mut [u8]) -> io::Result<(usize, ReceivedMessage)> {
        let mut control = vec![0u8; OOB_SIZE];
        let mut iov = [IoSliceMut::new(bytes)];
        let received = recvmsg::<()>(
            self.fd.as_raw_fd(),
            &mut iov,
            Some(&mut control),
            MsgFlags::MSG_CMSG_CLOEXEC,
        )
        .map_err(io::Error::from)?;
        let count = received.bytes;
        let truncated = received
            .flags
            .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC);
        let parsed = received.cmsgs().map_err(io::Error::other)?;
        let mut message = ReceivedMessage::default();
        for control_message in parsed {
            match control_message {
                ControlMessageOwned::ScmRights(fds) => {
                    for fd in fds {
                        // SCM_RIGHTS contains newly installed descriptors owned
                        // by this process; wrap immediately so all error paths
                        // close descriptors via RAII.
                        message.fds.push(unsafe { OwnedFd::from_raw_fd(fd) });
                    }
                }
                ControlMessageOwned::ScmCredentials(cred) => {
                    message.credentials = Some(Credentials {
                        pid: cred.pid(),
                        uid: cred.uid(),
                        gid: cred.gid(),
                    });
                }
                _ => {}
            }
        }
        if truncated {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "unix socket message truncated",
            ));
        }
        if count == 0 {
            return Err(io::Error::from(ErrorKind::BrokenPipe));
        }
        Ok((count, message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::unistd::{pipe, read, write};
    use std::os::fd::AsFd;

    #[test]
    fn sends_and_receives_packet() -> io::Result<()> {
        let (a, b) = Socket::pair()?;
        a.send_msg(b"message", &SendMessage::default())?;
        let mut buffer = [0; 64];
        let (n, msg) = b.recv_msg(&mut buffer)?;
        assert_eq!(&buffer[..n], b"message");
        assert!(msg.fds.is_empty());
        Ok(())
    }

    #[test]
    fn sends_and_receives_multiple_file_descriptors() -> io::Result<()> {
        let (a, b) = Socket::pair()?;
        let mut read_ends = Vec::new();
        let mut write_ends = Vec::new();
        for byte in [b'a', b'b', b'c'] {
            let (r, w) = pipe().map_err(io::Error::from)?;
            write(&w, &[byte]).map_err(io::Error::from)?;
            read_ends.push(r);
            write_ends.push(w);
        }
        let request = SendMessage {
            fds: read_ends.iter().map(AsFd::as_fd).collect(),
            credentials: false,
        };
        a.send_msg(b"fds", &request)?;
        let mut buffer = [0; 8];
        let (n, message) = b.recv_msg(&mut buffer)?;
        assert_eq!(&buffer[..n], b"fds");
        assert_eq!(message.fds.len(), 3);
        for (i, fd) in message.fds.iter().enumerate() {
            let mut byte = [0];
            assert_eq!(read(fd, &mut byte).map_err(io::Error::from)?, 1);
            assert_eq!(byte[0], b'a' + i as u8);
        }
        Ok(())
    }

    #[test]
    fn sends_and_receives_credentials() -> io::Result<()> {
        let (a, b) = Socket::pair()?;
        b.set_pass_cred(true)?;
        let request = SendMessage {
            credentials: true,
            ..Default::default()
        };
        a.send_msg(b"cred", &request)?;
        let mut buffer = [0; 16];
        let (n, message) = b.recv_msg(&mut buffer)?;
        assert_eq!(&buffer[..n], b"cred");
        assert_eq!(
            message.credentials,
            Some(Credentials {
                pid: std::process::id() as i32,
                // The SCM credentials are from this process, which is also the test process.
                uid: unsafe { libc::getuid() },
                gid: unsafe { libc::getgid() },
            })
        );
        Ok(())
    }

    #[test]
    fn rejects_truncated_payload() -> io::Result<()> {
        let (a, b) = Socket::pair()?;
        a.send_msg(b"long packet", &SendMessage::default())?;
        assert_eq!(
            b.recv_msg(&mut [0; 2]).unwrap_err().kind(),
            ErrorKind::InvalidData
        );
        Ok(())
    }

    #[test]
    fn reports_peer_close_without_sigpipe() -> io::Result<()> {
        let (a, b) = Socket::pair()?;
        drop(b);
        assert!(a.send_msg(b"message", &SendMessage::default()).is_err());
        Ok(())
    }

    #[test]
    fn reports_eof_as_broken_pipe() -> io::Result<()> {
        let (a, b) = Socket::pair()?;
        drop(a);
        assert_eq!(
            b.recv_msg(&mut [0; 8]).unwrap_err().kind(),
            ErrorKind::BrokenPipe
        );
        Ok(())
    }

    #[test]
    fn rejects_non_socket_fd() -> io::Result<()> {
        let file = std::fs::File::open("/dev/null")?;
        let fd: OwnedFd = file.into();
        // `new` currently validates descriptor flags and retains the descriptor;
        // the Go wrapper accepts the fd initially and reports this on I/O, too.
        assert!(Socket::new(fd).is_err());
        Ok(())
    }
}
