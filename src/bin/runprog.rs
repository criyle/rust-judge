use rust_judge::runner::runprog::{Options, cli_usage, run_container, write_result};
use rust_judge::runner::{ResultInfo, Status};
use std::fs::OpenOptions;
use std::io;

fn main() {
    let parsed = match Options::parse_cli(std::env::args_os().skip(1)) {
        Ok(Some(options)) => options,
        Ok(None) => {
            println!("{}", cli_usage());
            return;
        }
        Err(error) => {
            eprintln!("{error}\n{}", cli_usage());
            std::process::exit(2);
        }
    };
    if let Err(error) = execute(parsed) {
        eprintln!("runprog: {error}");
        std::process::exit(1);
    }
}

fn execute(mut options: Options) -> Result<(), String> {
    options
        .normalize(std::env::current_dir)
        .map_err(|error| format!("resolve work path: {error}"))?;
    let mut result_file = match options.result_output.as_str() {
        "stdout" => None,
        "stderr" => None,
        path => Some(
            OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(path)
                .map_err(|error| format!("open result output {path}: {error}"))?,
        ),
    };
    let result = match options.execution_error() {
        Ok(()) => run_container(&options).unwrap_or_else(|error| ResultInfo {
            status: Status::RunnerError,
            error: error.to_string(),
            ..Default::default()
        }),
        Err(error) => ResultInfo {
            status: Status::RunnerError,
            error,
            ..Default::default()
        },
    };
    match options.result_output.as_str() {
        "stdout" => write_result(io::stdout().lock(), &result),
        "stderr" => write_result(io::stderr().lock(), &result),
        _ => write_result(
            result_file.as_mut().expect("result file was opened"),
            &result,
        ),
    }
    .map_err(|error| format!("write result: {error}"))?;
    if result.status == Status::RunnerError {
        return Err(result.error);
    }
    Ok(())
}
