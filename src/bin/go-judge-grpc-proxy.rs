use rust_judge::commands::go_judge_grpc_proxy::{ProxyConfig, ProxyConfigError, USAGE, serve};
use std::process::ExitCode;

fn main() -> ExitCode {
    let token = std::env::var("TOKEN").unwrap_or_default();
    match ProxyConfig::parse(std::env::args(), token) {
        Err(ProxyConfigError::Help) => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("go-judge-grpc-proxy: {error}\n{USAGE}");
            ExitCode::from(2)
        }
        Ok(config) => match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => match runtime.block_on(serve(config)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("go-judge-grpc-proxy: {error}");
                    ExitCode::from(1)
                }
            },
            Err(error) => {
                eprintln!("go-judge-grpc-proxy: cannot start runtime: {error}");
                ExitCode::from(1)
            }
        },
    }
}
