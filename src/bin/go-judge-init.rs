use std::process::ExitCode;

fn main() -> ExitCode {
    match rust_sandbox::commands::go_judge_init::run() {
        Ok(()) => ExitCode::from(2),
        Err(error) => {
            eprintln!("go-judge-init: {error}");
            ExitCode::from(2)
        }
    }
}
