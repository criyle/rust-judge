use std::ffi::{CStr, CString};
use std::io::{Error, ErrorKind, Result};
use std::os::unix::ffi::OsStrExt;

pub(super) fn insert_setgroups_denied(args: &mut Vec<CString>) {
    if args
        .iter()
        .any(|arg| arg.as_bytes() == b"--setgroups-denied")
    {
        return;
    }
    let option = CString::new("--setgroups-denied").expect("static option has no NUL");
    let insertion = args
        .iter()
        .position(|arg| arg.as_bytes() == b"--")
        .unwrap_or(args.len());
    args.insert(insertion, option);
}

/// Recognize the current non-TTY `nsenter -> chroot -> container-init` argv
/// and replace it with one helper invocation. The helper enters the saved
/// namespaces and chroots before using `Command` to spawn the workload.
pub(super) fn optimized_namespace_exec(args: &[CString]) -> Option<(CString, Vec<CString>)> {
    if args.len() < 11
        || args[0].as_bytes() != b"/usr/bin/nsenter"
        || args[1].as_bytes() != b"--target"
        || args[3].as_bytes() != b"--mount"
        || args[4].as_bytes() != b"--pid"
        || args[5].as_bytes() != b"--"
        || args[6].as_bytes() != b"/usr/sbin/chroot"
        || args[8].as_bytes() != b"/.rust-sandbox-init"
        || args[9].as_bytes() != b"--exec-direct"
    {
        return None;
    }
    let pid = args[2].to_str().ok()?;
    pid.parse::<i32>().ok()?;
    let root = args[7].as_c_str();
    let helper_path = std::path::Path::new(os_str(root)).join(".rust-sandbox-init");
    let helper = CString::new(helper_path.as_os_str().as_bytes()).ok()?;
    let mut helper_args = vec![
        CString::new("--exec-direct").ok()?,
        CString::new("--namespace-pid").ok()?,
        args[2].clone(),
        CString::new("--root").ok()?,
        root.to_owned(),
    ];
    helper_args.extend(args[10..].iter().cloned());
    Some((helper, helper_args))
}

#[repr(C)]
pub(super) struct CapUserHeader {
    pub(super) version: u32,
    pub(super) pid: i32,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CapUserData {
    pub(super) effective: u32,
    pub(super) permitted: u32,
    pub(super) inheritable: u32,
}

pub(super) fn os_str(value: &CStr) -> &std::ffi::OsStr {
    std::ffi::OsStr::from_bytes(value.to_bytes())
}

pub(super) fn parse_cpu_mask(input: &str) -> Result<Vec<u8>> {
    const CPU_SET_BYTES: usize = 128;
    let mut mask = vec![0u8; CPU_SET_BYTES];
    for item in input.split(',') {
        let (first, last) = match item.trim().split_once('-') {
            Some((first, last)) => (
                first
                    .parse::<usize>()
                    .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid CPU set range"))?,
                last.parse::<usize>()
                    .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid CPU set range"))?,
            ),
            None => {
                let cpu = item
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid CPU set ID"))?;
                (cpu, cpu)
            }
        };
        if first > last || last >= CPU_SET_BYTES * 8 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "CPU set range is out of bounds",
            ));
        }
        for cpu in first..=last {
            mask[cpu / 8] |= 1 << (cpu % 8);
        }
    }
    if mask.iter().all(|byte| *byte == 0) {
        return Err(Error::new(ErrorKind::InvalidInput, "empty CPU set"));
    }
    Ok(mask)
}
