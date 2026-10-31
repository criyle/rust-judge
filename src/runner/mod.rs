//! Result and resource limit types corresponding to `go-sandbox/runner`.
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

pub mod runprog;

/// Memory quantity in bytes, bounded by `u64` like Go's `runner.Size`.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Size(pub u64);

impl Size {
    pub const fn byte(self) -> u64 {
        self.0
    }
    pub const fn kib(self) -> u64 {
        self.0 >> 10
    }
    pub const fn mib(self) -> u64 {
        self.0 >> 20
    }
    pub const fn gib(self) -> u64 {
        self.0 >> 30
    }
    pub const fn tib(self) -> u64 {
        self.0 >> 40
    }
    pub const fn pib(self) -> u64 {
        self.0 >> 50
    }
    pub const fn eib(self) -> u64 {
        self.0 >> 60
    }
}
impl fmt::Display for Size {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = self.0;
        if n < 1 << 10 {
            write!(f, "{n} B")
        } else if n < 1 << 20 {
            write!(f, "{:.1} KiB", n as f64 / (1 << 10) as f64)
        } else if n < 1 << 30 {
            write!(f, "{:.1} MiB", n as f64 / (1 << 20) as f64)
        } else {
            write!(f, "{:.1} GiB", n as f64 / (1 << 30) as f64)
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseSizeError(String);
impl fmt::Display for ParseSizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for ParseSizeError {}
impl FromStr for Size {
    type Err = ParseSizeError;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let mut s = input.trim();
        if s.is_empty() {
            return Err(ParseSizeError("empty size".into()));
        }
        if matches!(s.as_bytes().last(), Some(b'b' | b'B')) {
            s = &s[..s.len() - 1];
        }
        if s.is_empty() {
            return Err(ParseSizeError("missing size value".into()));
        }
        let (digits, shift) = match s.as_bytes().last().copied() {
            Some(b'k' | b'K') => (&s[..s.len() - 1], 10),
            Some(b'm' | b'M') => (&s[..s.len() - 1], 20),
            Some(b'g' | b'G') => (&s[..s.len() - 1], 30),
            _ => (s, 0),
        };
        if digits.is_empty() {
            return Err(ParseSizeError("missing size value".into()));
        }
        let n: u64 = digits
            .parse()
            .map_err(|e: std::num::ParseIntError| ParseSizeError(e.to_string()))?;
        n.checked_shl(shift)
            .filter(|v| (*v >> shift) == n)
            .map(Size)
            .ok_or_else(|| ParseSizeError("size overflows uint64".into()))
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(i32)]
pub enum Status {
    #[default]
    Invalid = 0,
    Normal = 1,
    TimeLimitExceeded = 2,
    MemoryLimitExceeded = 3,
    OutputLimitExceeded = 4,
    DisallowedSyscall = 5,
    Signalled = 6,
    NonzeroExitStatus = 7,
    RunnerError = 8,
}
impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Invalid => "Invalid",
            Self::Normal => "",
            Self::TimeLimitExceeded => "Time Limit Exceeded",
            Self::MemoryLimitExceeded => "Memory Limit Exceeded",
            Self::OutputLimitExceeded => "Output Limit Exceeded",
            Self::DisallowedSyscall => "Disallowed Syscall",
            Self::Signalled => "Signalled",
            Self::NonzeroExitStatus => "Nonzero Exit Status",
            Self::RunnerError => "Runner Error",
        }
    }
}
impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Limit {
    pub time_limit: Duration,
    pub memory_limit: Size,
}
impl fmt::Display for Limit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Limit[Time={:?}, Memory={}]",
            self.time_limit, self.memory_limit
        )
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResultInfo {
    pub status: Status,
    pub exit_status: i32,
    pub error: String,
    pub time: Duration,
    pub memory: Size,
    pub proc_peak: u64,
    pub setup_time: Duration,
    pub running_time: Duration,
}
impl fmt::Display for ResultInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let times = format!("{:?} {}", self.time, self.memory);
        let metrics = format!("{:?} {:?}", self.setup_time, self.running_time);
        match self.status {
            Status::Normal => write!(f, "Result[{times}][{metrics}]"),
            Status::Signalled => write!(
                f,
                "Result[Signalled({})][{times}][{metrics}]",
                self.exit_status
            ),
            Status::RunnerError => write!(
                f,
                "Result[RunnerFailed({})][{times}][{metrics}]",
                self.error
            ),
            s => write!(
                f,
                "Result[{s}({} {})][{times}][{metrics}]",
                self.error, self.exit_status
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_sizes_like_go() {
        for (text, bytes) in [
            ("12", 12),
            ("2k", 2048),
            ("2KB", 2048),
            ("3M", 3 << 20),
            ("1gB", 1 << 30),
            (" 7B ", 7),
        ] {
            assert_eq!(text.parse::<Size>().unwrap(), Size(bytes), "{text}");
        }
        assert!("".parse::<Size>().is_err());
        assert!("18446744073709551615K".parse::<Size>().is_err());
    }
    #[test]
    fn size_display_and_units() {
        assert_eq!(Size(1024).to_string(), "1.0 KiB");
        assert_eq!(Size((1 << 40) + 3).tib(), 1);
        assert_eq!(Size(0).to_string(), "0 B");
    }
    #[test]
    fn statuses_keep_go_ordinals_and_labels() {
        assert_eq!(Status::DisallowedSyscall as i32, 5);
        assert_eq!(
            Status::MemoryLimitExceeded.to_string(),
            "Memory Limit Exceeded"
        );
        assert_eq!(Status::Normal.to_string(), "");
    }
}
