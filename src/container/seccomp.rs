//! Linux seccomp filter storage and action encoding.
use std::io;

/// Classic BPF instructions passed to `seccomp(SECCOMP_SET_MODE_FILTER, ...)`.
#[derive(Clone, Debug, Default)]
pub struct Filter(pub Vec<libc::sock_filter>, pub Vec<Vec<libc::sock_filter>>);

impl Filter {
    pub fn programs(&self) -> impl Iterator<Item = &[libc::sock_filter]> {
        std::iter::once(self.0.as_slice()).chain(self.1.iter().map(Vec::as_slice))
    }

    /// Empty filters have no program, matching Go's `SockFprog` behavior.
    pub fn sock_fprog(&mut self) -> io::Result<Option<libc::sock_fprog>> {
        if !self.1.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "sock_fprog represents one filter; install stacked programs separately",
            ));
        }
        if self.0.is_empty() {
            return Ok(None);
        }
        let len = u16::try_from(self.0.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "seccomp filter exceeds u16 instruction limit",
            )
        })?;
        Ok(Some(libc::sock_fprog {
            len,
            filter: self.0.as_mut_ptr(),
        }))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Action {
    Allow = 1,
    Errno = 2,
    Trace = 3,
    Kill = 4,
}

pub const MSG_DISALLOW: i16 = 1;
pub const MSG_HANDLE: i16 = 2;

impl Action {
    pub const fn from_raw(value: u32) -> Option<Self> {
        match value & 0xffff {
            1 => Some(Self::Allow),
            2 => Some(Self::Errno),
            3 => Some(Self::Trace),
            4 => Some(Self::Kill),
            _ => None,
        }
    }

    /// Convert to the kernel seccomp return value (the upper 16 bits select the
    /// action; lower bits are available for action data).
    pub const fn kernel_value(self) -> u32 {
        match self {
            Self::Allow => 0x7fff_0000,
            Self::Errno => 0x0005_0000,
            Self::Trace => 0x7ff0_0000,
            Self::Kill => 0x8000_0000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_filter_has_no_sock_fprog() {
        assert!(Filter::default().sock_fprog().unwrap().is_none());
    }

    #[test]
    fn sock_fprog_points_to_filter_instructions() {
        let mut filter = Filter(
            vec![libc::sock_filter {
                code: 6,
                jt: 0,
                jf: 0,
                k: 0x7fff_0000,
            }],
            vec![],
        );
        let program = filter.sock_fprog().unwrap().unwrap();
        assert_eq!(program.len, 1);
        // SAFETY: the filter is alive and has not been moved since producing the pointer.
        assert_eq!(unsafe { (*program.filter).k }, 0x7fff_0000);
    }

    #[test]
    fn sock_fprog_rejects_stacked_filters_instead_of_dropping_them() {
        let mut filter = Filter(Vec::new(), vec![Vec::new()]);
        assert_eq!(
            filter.sock_fprog().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn maps_action_codes_and_rejects_unknown_values() {
        assert_eq!(Action::from_raw(Action::Trace as u32), Some(Action::Trace));
        assert_eq!(Action::from_raw(0), None);
        assert_eq!(Action::Kill.kernel_value(), 0x8000_0000);
    }
}
