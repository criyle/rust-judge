use std::process::ExitCode;

fn main() -> ExitCode {
    match rust_judge::commands::go_judge_init::run() {
        Ok(()) => ExitCode::from(2),
        Err(error) => {
            eprintln!("rust-judge-init: {error}");
            ExitCode::from(2)
        }
    }
}
