use super::child::{Child, ChildProcess, wait_pid};
use std::ffi::CString;
use std::io::{Error, ErrorKind, Result};
use std::os::unix::ffi::OsStrExt;
use std::process::Command;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".text",
    ".global rust_judge_clone3_vfork",
    ".type rust_judge_clone3_vfork,@function",
    "rust_judge_clone3_vfork:",
    // clone3(args, size), with callback and context held in syscall-preserved
    // registers. clone3 installs the separately mapped child stack.
    "mov r8, rdx",
    "mov r9, rcx",
    "mov eax, 435",
    "syscall",
    "test rax, rax",
    "jnz 1f",
    "mov rdi, r9",
    "call r8",
    "ud2",
    "1:",
    "ret",
    ".size rust_judge_clone3_vfork, .-rust_judge_clone3_vfork",
);

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".text",
    ".global rust_judge_clone3_vfork",
    ".type rust_judge_clone3_vfork,%function",
    "rust_judge_clone3_vfork:",
    // Preserve the parent's callee-saved registers. In the child, clone3
    // switches SP to the supplied stack, so the callback uses only registers.
    "stp x19, x20, [sp, #-16]!",
    "str x30, [sp, #-16]!",
    "mov x19, x2",
    "mov x20, x3",
    "mov x8, #435",
    "svc #0",
    "cbnz x0, 1f",
    "mov x0, x20",
    "blr x19",
    "brk #0",
    "1:",
    "ldr x30, [sp], #16",
    "ldp x19, x20, [sp], #16",
    "ret",
    ".size rust_judge_clone3_vfork, .-rust_judge_clone3_vfork",
);

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
unsafe extern "C" {
    fn rust_judge_clone3_vfork(
        args: *const CloneArgs,
        size: usize,
        callback: unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
        context: *mut libc::c_void,
    ) -> libc::c_long;
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[repr(C)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

const CLONE_INTO_CGROUP: u64 = 0x0002_0000_0000;

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
struct VforkContext<'a> {
    setup: &'a mut dyn FnMut() -> Result<()>,
    exec_paths: *const *const libc::c_char,
    exec_path_count: usize,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
    cwd: *const libc::c_char,
    read_fd: libc::c_int,
    error_fd: libc::c_int,
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
extern "C" fn vfork_child(context: *mut libc::c_void) -> libc::c_int {
    let context = unsafe { &mut *context.cast::<VforkContext<'_>>() };
    unsafe { libc::close(context.read_fd) };
    if !context.cwd.is_null() && unsafe { libc::chdir(context.cwd) } == -1 {
        unsafe { child_fail(context.error_fd, *libc::__errno_location()) };
    }
    if let Err(error) = (context.setup)() {
        unsafe {
            child_fail(
                context.error_fd,
                error.raw_os_error().unwrap_or(libc::EINVAL),
            )
        };
    }
    let mut last_errno = libc::ENOENT;
    for index in 0..context.exec_path_count {
        let path = unsafe { *context.exec_paths.add(index) };
        unsafe {
            libc::syscall(libc::SYS_execve, path, context.argv, context.envp);
        }
        let errno = unsafe { *libc::__errno_location() };
        if errno == libc::EACCES {
            last_errno = errno;
            continue;
        }
        if errno == libc::ENOENT || errno == libc::ENOTDIR {
            continue;
        }
        unsafe { child_fail(context.error_fd, errno) };
    }
    unsafe { child_fail(context.error_fd, last_errno) }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
unsafe fn child_fail(fd: libc::c_int, errno: libc::c_int) -> ! {
    let value = errno;
    unsafe {
        libc::syscall(
            libc::SYS_write,
            fd,
            (&value as *const libc::c_int).cast::<libc::c_void>(),
            size_of::<libc::c_int>(),
        );
        libc::syscall(libc::SYS_exit, 127);
        core::hint::unreachable_unchecked()
    }
}

#[inline]
pub(super) fn child_errno_error() -> Error {
    Error::from_raw_os_error(unsafe { *libc::__errno_location() })
}

/// Match go-judge's current CLONE_INTO_CGROUP policy: try it only for cgroup
/// v2 on Linux 6.9 or newer. The plain clone3 vfork path remains available on
/// older kernels, and `clone3_vfork` still falls back when a syscall is denied.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(super) fn clone3_into_cgroup_available(cgroup_fd: libc::c_int) -> bool {
    static KERNEL_VERSION: OnceLock<Option<(u32, u32)>> = OnceLock::new();
    let version = *KERNEL_VERSION.get_or_init(kernel_version);
    let Some((major, minor)) = version else {
        return false;
    };
    if major < 6 || (major == 6 && minor < 9) {
        return false;
    }

    let mut filesystem = unsafe { std::mem::zeroed::<libc::statfs>() };
    if unsafe { libc::fstatfs(cgroup_fd, &mut filesystem) } == -1 {
        return false;
    }
    filesystem.f_type as u64 == libc::CGROUP2_SUPER_MAGIC as u64
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub(super) fn clone3_into_cgroup_available(_cgroup_fd: libc::c_int) -> bool {
    false
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn kernel_version() -> Option<(u32, u32)> {
    let mut uname = unsafe { std::mem::zeroed::<libc::utsname>() };
    if unsafe { libc::uname(&mut uname) } == -1 {
        return None;
    }
    let release = unsafe { std::ffi::CStr::from_ptr(uname.release.as_ptr()) }.to_bytes();
    let mut components = release.split(|byte| *byte == b'.');
    let major = parse_version_component(components.next()?)?;
    let minor = parse_version_component(components.next()?)?;
    Some((major, minor))
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn parse_version_component(component: &[u8]) -> Option<u32> {
    let digits = component
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .copied()
        .collect::<Vec<_>>();
    if digits.is_empty() {
        return None;
    }
    std::str::from_utf8(&digits).ok()?.parse().ok()
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
// This is the architecture-independent boundary called by the syscall
// trampoline. Keeping the raw clone parameters explicit makes the
// parent/child contract visible at the call site.
#[allow(clippy::too_many_arguments)]
pub(super) fn clone3_vfork(
    command: &Command,
    setup: &mut dyn FnMut() -> Result<()>,
    argv0_override: Option<&CString>,
    reserved_fd_min: libc::c_int,
    use_clone3: bool,
    cgroup_fd: Option<libc::c_int>,
    cgroup_procs_skip: &AtomicUsize,
    cgroup_procs_index: Option<usize>,
) -> Result<Child> {
    const STACK_SIZE: usize = 1024 * 1024;
    let program = CString::new(command.get_program().as_bytes())
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "NUL in program path"))?;
    let exec_paths: Vec<CString> = if program.as_bytes().contains(&b'/') {
        vec![program.clone()]
    } else {
        let configured_path = command
            .get_envs()
            .find_map(|(key, value)| (key == "PATH").then_some(value))
            .flatten()
            .map(|path| path.to_os_string())
            .or_else(|| std::env::var_os("PATH"))
            .unwrap_or_else(|| std::ffi::OsString::from("/bin:/usr/bin"));
        let mut paths = Vec::new();
        for directory in std::env::split_paths(&configured_path) {
            let candidate = if directory.as_os_str().is_empty() {
                std::path::PathBuf::from(std::ffi::OsStr::from_bytes(program.as_bytes()))
            } else {
                directory.join(std::ffi::OsStr::from_bytes(program.as_bytes()))
            };
            paths.push(
                CString::new(candidate.as_os_str().as_bytes())
                    .map_err(|_| Error::new(ErrorKind::InvalidInput, "NUL in PATH entry"))?,
            );
        }
        if paths.is_empty() {
            paths.push(program.clone());
        }
        paths
    };
    let exec_path_ptrs: Vec<_> = exec_paths.iter().map(|path| path.as_ptr()).collect();
    let mut argv = Vec::<CString>::with_capacity(command.get_args().len() + 1);
    argv.push(if let Some(argv0) = argv0_override {
        argv0.clone()
    } else {
        CString::new(command.get_program().as_bytes())
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "NUL in argv[0]"))?
    });
    for arg in command.get_args() {
        argv.push(
            CString::new(arg.as_bytes())
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "NUL in argument"))?,
        );
    }
    let mut argv_ptrs: Vec<_> = argv.iter().map(|arg| arg.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let env: Vec<CString> = command
        .get_envs()
        .map(|(key, value)| {
            let value = value.unwrap_or_else(|| std::ffi::OsStr::new(""));
            let mut bytes = Vec::with_capacity(key.as_bytes().len() + value.as_bytes().len() + 1);
            bytes.extend_from_slice(key.as_bytes());
            bytes.push(b'=');
            bytes.extend_from_slice(value.as_bytes());
            CString::new(bytes)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "NUL in environment"))
        })
        .collect::<Result<_>>()?;
    let mut env_ptrs: Vec<_> = env.iter().map(|item| item.as_ptr()).collect();
    env_ptrs.push(std::ptr::null());
    let cwd = command
        .get_current_dir()
        .map(|path| CString::new(path.as_os_str().as_bytes()))
        .transpose()
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "NUL in working directory"))?;

    let mut pipe = [-1; 2];
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } == -1 {
        return Err(Error::last_os_error());
    }
    let old_pipe = pipe;
    pipe[0] = unsafe { libc::fcntl(old_pipe[0], libc::F_DUPFD_CLOEXEC, reserved_fd_min) };
    if pipe[0] == -1 {
        let error = Error::last_os_error();
        unsafe {
            libc::close(old_pipe[0]);
            libc::close(old_pipe[1]);
        }
        return Err(error);
    }
    pipe[1] = unsafe { libc::fcntl(old_pipe[1], libc::F_DUPFD_CLOEXEC, reserved_fd_min) };
    if pipe[1] == -1 {
        let error = Error::last_os_error();
        unsafe {
            libc::close(old_pipe[0]);
            libc::close(old_pipe[1]);
            libc::close(pipe[0]);
        }
        return Err(error);
    }
    unsafe {
        libc::close(old_pipe[0]);
        libc::close(old_pipe[1]);
    }
    let mapping = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            STACK_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_STACK,
            -1,
            0,
        )
    };
    if mapping == libc::MAP_FAILED {
        unsafe {
            libc::close(pipe[0]);
            libc::close(pipe[1]);
        }
        return Err(Error::last_os_error());
    }
    let mut context = VforkContext {
        setup,
        exec_paths: exec_path_ptrs.as_ptr(),
        exec_path_count: exec_path_ptrs.len(),
        argv: argv_ptrs.as_ptr(),
        envp: env_ptrs.as_ptr(),
        cwd: cwd.as_ref().map_or(std::ptr::null(), |path| path.as_ptr()),
        read_fd: pipe[0],
        error_fd: pipe[1],
    };
    let mut args = CloneArgs {
        flags: (libc::CLONE_VM | libc::CLONE_VFORK) as u64
            | if use_clone3 && cgroup_fd.is_some() {
                CLONE_INTO_CGROUP
            } else {
                0
            },
        pidfd: 0,
        child_tid: 0,
        parent_tid: 0,
        exit_signal: libc::SIGCHLD as u64,
        stack: mapping as u64,
        stack_size: STACK_SIZE as u64,
        tls: 0,
        set_tid: 0,
        set_tid_size: 0,
        cgroup: if use_clone3 {
            cgroup_fd.unwrap_or(0) as u64
        } else {
            0
        },
    };
    let parent_errno = unsafe { *libc::__errno_location() };
    let mut using_clone3 = use_clone3;
    cgroup_procs_skip.store(
        if use_clone3 && cgroup_fd.is_some() {
            cgroup_procs_index.unwrap_or(usize::MAX)
        } else {
            usize::MAX
        },
        Ordering::Relaxed,
    );
    let mut clone_errno = 0;
    let mut pid = if using_clone3 {
        unsafe {
            rust_judge_clone3_vfork(
                &args,
                size_of::<CloneArgs>(),
                vfork_child,
                (&mut context as *mut VforkContext<'_>).cast(),
            )
        }
    } else {
        let stack_top = unsafe { mapping.cast::<u8>().add(STACK_SIZE).cast() };
        unsafe {
            let result = libc::clone(
                vfork_child,
                stack_top,
                (libc::CLONE_VM | libc::CLONE_VFORK | libc::SIGCHLD) as libc::c_int,
                (&mut context as *mut VforkContext<'_>).cast(),
            );
            if result == -1 {
                clone_errno = *libc::__errno_location();
            }
            result as libc::c_long
        }
    };
    if pid < 0 && using_clone3 {
        // An unsupported or inaccessible cgroup placement is safe to retry:
        // clone3 has not created a child when it returns an error. Retry the
        // ordinary clone3 vfork first, then the clone(2) compatibility path.
        if cgroup_fd.is_some() {
            cgroup_procs_skip.store(usize::MAX, Ordering::Relaxed);
            args.flags &= !CLONE_INTO_CGROUP;
            args.cgroup = 0;
            pid = unsafe {
                rust_judge_clone3_vfork(
                    &args,
                    size_of::<CloneArgs>(),
                    vfork_child,
                    (&mut context as *mut VforkContext<'_>).cast(),
                )
            };
        }
        if pid < 0 {
            using_clone3 = false;
            cgroup_procs_skip.store(usize::MAX, Ordering::Relaxed);
            let stack_top = unsafe { mapping.cast::<u8>().add(STACK_SIZE).cast() };
            let result = unsafe {
                libc::clone(
                    vfork_child,
                    stack_top,
                    (libc::CLONE_VM | libc::CLONE_VFORK | libc::SIGCHLD) as libc::c_int,
                    (&mut context as *mut VforkContext<'_>).cast(),
                )
            };
            if result == -1 {
                clone_errno = unsafe { *libc::__errno_location() };
            }
            pid = result as libc::c_long;
        }
    }
    // CLONE_VM also shares this thread's libc TLS. Restore errno before
    // returning to ordinary Rust code, including the successful exec case.
    unsafe {
        *libc::__errno_location() = parent_errno;
    }
    unsafe {
        libc::close(pipe[1]);
    }
    if pid < 0 {
        unsafe {
            libc::close(pipe[0]);
            libc::munmap(mapping, STACK_SIZE);
        }
        let errno = if using_clone3 {
            (-pid) as i32
        } else {
            clone_errno
        };
        return Err(Error::from_raw_os_error(errno));
    }
    let mut child_errno = 0i32;
    let mut received = 0usize;
    loop {
        let count = unsafe {
            libc::read(
                pipe[0],
                (&mut child_errno as *mut i32)
                    .cast::<u8>()
                    .add(received)
                    .cast(),
                size_of::<i32>() - received,
            )
        };
        if count == 0 {
            break;
        }
        if count == -1 {
            let error = Error::last_os_error();
            if error.kind() == ErrorKind::Interrupted {
                continue;
            }
            unsafe {
                libc::close(pipe[0]);
                libc::munmap(mapping, STACK_SIZE);
                libc::kill(pid as i32, libc::SIGKILL);
            }
            let _ = wait_pid(pid as i32, false);
            return Err(error);
        }
        received += count as usize;
        if received == size_of::<i32>() {
            break;
        }
    }
    unsafe {
        libc::close(pipe[0]);
        libc::munmap(mapping, STACK_SIZE);
    }
    if received != 0 {
        let _ = wait_pid(pid as i32, false);
        return Err(Error::from_raw_os_error(child_errno));
    }
    Ok(Child {
        process: ChildProcess::Raw {
            pid: pid as i32,
            status: None,
        },
    })
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn clone3_vfork(
    _command: &Command,
    _setup: &mut dyn FnMut() -> Result<()>,
    _argv0_override: Option<&CString>,
    _reserved_fd_min: libc::c_int,
    _use_clone3: bool,
    _cgroup_fd: Option<libc::c_int>,
    _cgroup_procs_skip: &AtomicUsize,
    _cgroup_procs_index: Option<usize>,
) -> Result<Child> {
    Err(Error::from_raw_os_error(libc::ENOSYS))
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub fn clone3_available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        let result = unsafe {
            libc::syscall(
                libc::SYS_clone3,
                std::ptr::null::<CloneArgs>(),
                size_of::<CloneArgs>(),
            )
        };
        if result >= 0 {
            // A null clone_args pointer cannot create a child; this is only a
            // feature probe and EFAULT is the expected supported-kernel result.
            false
        } else {
            matches!(
                Error::last_os_error().raw_os_error(),
                Some(libc::EFAULT) | Some(libc::EINVAL)
            )
        }
    })
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub fn clone3_available() -> bool {
    false
}
