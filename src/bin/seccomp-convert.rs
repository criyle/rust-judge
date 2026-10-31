fn main() {
    if let Err(error) = rust_sandbox::seccomp_convert::run_args(std::env::args_os().skip(1)) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
