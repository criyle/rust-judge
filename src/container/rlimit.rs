//! Resource limit descriptions equivalent to go-sandbox/pkg/rlimit.
use crate::runner::Size;
use nix::sys::resource::{Resource, rlim_t};
use std::fmt;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RLimits {
    pub cpu: u64,
    pub cpu_hard: u64,
    pub data: u64,
    pub file_size: u64,
    pub stack: u64,
    pub address_space: u64,
    pub open_file: u64,
    pub disable_core: bool,
    /// Resource IDs not represented by nix's portable `Resource` enum.
    /// Linux `setrlimit(2)` accepts these IDs directly, as Go's syscall path
    /// does.
    pub raw: Vec<RawLimit>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawLimit {
    pub resource: libc::__rlimit_resource_t,
    pub soft: u64,
    pub hard: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limit {
    pub resource: Resource,
    pub soft: rlim_t,
    pub hard: rlim_t,
}

impl RLimits {
    /// Build limits in the same stable order used by the Go implementation.
    pub fn prepare(&self) -> Vec<Limit> {
        let mut out = Vec::with_capacity(7);
        if self.cpu > 0 || self.cpu_hard > 0 {
            let soft = if self.cpu == 0 {
                self.cpu_hard
            } else {
                self.cpu
            };
            out.push(Limit {
                resource: Resource::RLIMIT_CPU,
                soft,
                hard: self.cpu_hard.max(soft),
            });
        }
        for (value, resource) in [
            (self.data, Resource::RLIMIT_DATA),
            (self.file_size, Resource::RLIMIT_FSIZE),
            (self.stack, Resource::RLIMIT_STACK),
            (self.address_space, Resource::RLIMIT_AS),
            (self.open_file, Resource::RLIMIT_NOFILE),
        ] {
            if value > 0 {
                out.push(Limit {
                    resource,
                    soft: value,
                    hard: value,
                });
            }
        }
        if self.disable_core {
            out.push(Limit {
                resource: Resource::RLIMIT_CORE,
                soft: 0,
                hard: 0,
            });
        }
        out
    }
}

impl fmt::Display for Limit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Resource::*;
        match self.resource {
            RLIMIT_CPU => write!(f, "CPU[{} s:{} s]", self.soft, self.hard),
            RLIMIT_NOFILE => write!(f, "OpenFile[{}:{}]", self.soft, self.hard),
            RLIMIT_DATA => write!(f, "Data[{}:{}]", Size(self.soft), Size(self.hard)),
            RLIMIT_FSIZE => write!(f, "File[{}:{}]", Size(self.soft), Size(self.hard)),
            RLIMIT_STACK => write!(f, "Stack[{}:{}]", Size(self.soft), Size(self.hard)),
            RLIMIT_AS => write!(f, "AddressSpace[{}:{}]", Size(self.soft), Size(self.hard)),
            RLIMIT_CORE => write!(f, "Core[{}:{}]", Size(self.soft), Size(self.hard)),
            _ => write!(f, "[{}:{}]", self.soft, self.hard),
        }
    }
}

impl fmt::Display for RLimits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RLimits[")?;
        for (index, limit) in self.prepare().iter().enumerate() {
            if index > 0 {
                f.write_str(",")?;
            }
            write!(f, "{limit}")?;
        }
        f.write_str("]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_soft_and_hard_follow_go_rules() {
        assert_eq!(
            RLimits {
                cpu_hard: 2,
                ..Default::default()
            }
            .prepare()[0],
            Limit {
                resource: Resource::RLIMIT_CPU,
                soft: 2,
                hard: 2,
            }
        );
        assert_eq!(
            RLimits {
                cpu: 3,
                cpu_hard: 2,
                ..Default::default()
            }
            .prepare()[0]
                .hard,
            3
        );
    }

    #[test]
    fn prepares_all_limits_in_order_and_formats() {
        let limits = RLimits {
            cpu: 1,
            cpu_hard: 2,
            data: 1024,
            file_size: 2048,
            stack: 4096,
            address_space: 8192,
            open_file: 16,
            disable_core: true,
            raw: Vec::new(),
        };
        assert_eq!(limits.prepare().len(), 7);
        assert_eq!(
            limits.to_string(),
            "RLimits[CPU[1 s:2 s],Data[1.0 KiB:1.0 KiB],File[2.0 KiB:2.0 KiB],Stack[4.0 KiB:4.0 KiB],AddressSpace[8.0 KiB:8.0 KiB],OpenFile[16:16],Core[0 B:0 B]]"
        );
    }

    #[test]
    fn zero_means_unspecified_except_disable_core() {
        assert!(RLimits::default().prepare().is_empty());
        assert_eq!(
            RLimits {
                disable_core: true,
                ..Default::default()
            }
            .prepare()[0]
                .resource,
            Resource::RLIMIT_CORE
        );
    }
}
