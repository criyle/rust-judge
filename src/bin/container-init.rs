use std::process::ExitCode;

fn main() -> ExitCode {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    if unsafe { libc::getpid() } == 1
        && arguments.get(1).is_some_and(|arg| arg == "container_init")
        && !arguments.get(2).is_some_and(|arg| {
            arg == "--keepalive" || arg == "--exec-direct" || arg == "--seccomp-file"
        })
    {
        return match rust_judge::commands::go_judge_init::run() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("container-init: {error}");
                ExitCode::from(2)
            }
        };
    }
    match rust_judge::commands::container_init::run(arguments.into_iter().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("container-init: {error}");
            ExitCode::from(127)
        }
    }
}
