use rust_judge::commands::go_judge_shell::{
    ShellConfig, ShellConfigError, ShellRequest, ShellResponse, ShellTransport, USAGE, connect,
    exec_shell_request,
};
use std::{
    io::{self, Write},
    process::ExitCode,
    sync::Arc,
};

fn main() -> ExitCode {
    let token = std::env::var("TOKEN").unwrap_or_default();
    let term = std::env::var("TERM").unwrap_or_default();
    let config = match ShellConfig::parse(std::env::args(), token, term) {
        Ok(config) => config,
        Err(ShellConfigError::Help) => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            eprintln!("go-judge-shell: {error}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("go-judge-shell: {error}");
            ExitCode::from(1)
        }
    }
}

fn run(config: ShellConfig) -> io::Result<()> {
    let transport: Arc<dyn ShellTransport> = Arc::from(connect(&config)?);
    transport
        .send(ShellRequest::Exec(exec_shell_request(&config)))
        .map_err(|e| io::Error::new(e.kind(), format!("send request: {e}")))?;
    let _raw = RawTerminal::enable(libc::STDIN_FILENO)?;
    start_stdin_pump(transport.clone());
    start_resize_pump(transport.clone());
    loop {
        match transport
            .recv()
            .map_err(|e| io::Error::new(e.kind(), format!("recv: {e}")))?
        {
            ShellResponse::Output { fd: 1, content, .. } => io::stdout().write_all(&content)?,
            ShellResponse::Output { fd: 2, content, .. } => io::stderr().write_all(&content)?,
            ShellResponse::Output { .. } => {}
            ShellResponse::Exec(response) => {
                eprintln!("finished: {response:?}");
                return Ok(());
            }
        }
    }
}

struct RawTerminal {
    fd: libc::c_int,
    old: libc::termios,
}
impl RawTerminal {
    fn enable(fd: libc::c_int) -> io::Result<Self> {
        let mut old = unsafe { std::mem::zeroed::<libc::termios>() };
        if unsafe { libc::tcgetattr(fd, &mut old) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut raw = old;
        unsafe {
            libc::cfmakeraw(&mut raw);
        }
        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &raw) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd, old })
    }
}
impl Drop for RawTerminal {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.old);
        }
    }
}

fn start_stdin_pump(transport: Arc<dyn ShellTransport>) {
    rust_judge::tokio_runtime::runtime()
        .handle()
        .spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut stdin = tokio::io::stdin();
            let mut buf = [0u8; 4096];
            let mut force_quit = false;
            loop {
                match stdin.read(&mut buf).await {
                    Ok(0) => {
                        let _ = tokio::task::spawn_blocking(move || {
                            transport.send(ShellRequest::Input {
                                index: 0,
                                fd: 0,
                                content: vec![4],
                            })
                        })
                        .await;
                        break;
                    }
                    Ok(n) => {
                        let ctrl_c = n == 1 && buf[0] == 3;
                        if ctrl_c && force_quit {
                            let transport = transport.clone();
                            let _ = tokio::task::spawn_blocking(move || {
                                transport.send(ShellRequest::Cancel)
                            })
                            .await;
                        }
                        force_quit = ctrl_c;
                        let transport = transport.clone();
                        if tokio::task::spawn_blocking(move || {
                            transport.send(ShellRequest::Input {
                                index: 0,
                                fd: 0,
                                content: buf[..n].to_vec(),
                            })
                        })
                        .await
                        .map_or(true, |result| result.is_err())
                        {
                            break;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        eprintln!("go-judge-shell: stdin: {e}");
                        break;
                    }
                }
            }
        });
}

fn start_resize_pump(transport: Arc<dyn ShellTransport>) {
    #[cfg(unix)]
    rust_judge::tokio_runtime::runtime().handle().spawn(async move {
            let Ok(mut resize) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
            else {
                return;
            };
            let Ok(mut interrupt) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()) else { return; };
            let initial = transport.clone();
            let _ = tokio::task::spawn_blocking(move || send_window_size(&*initial)).await;
            loop {
                tokio::select! {
                    value = resize.recv() => {
                        let transport = transport.clone();
                        if value.is_none() || tokio::task::spawn_blocking(move || send_window_size(&*transport)).await.map_or(true, |result| result.is_err()) { return; }
                    }
                    value = interrupt.recv() => {
                        let transport = transport.clone();
                        if value.is_none() || tokio::task::spawn_blocking(move || transport.send(ShellRequest::Input { index: 0, fd: 0, content: vec![3] })).await.map_or(true, |result| result.is_err()) { return; }
                    }
                }
            }
    });
}

#[cfg(unix)]
fn send_window_size(transport: &dyn ShellTransport) -> io::Result<()> {
    let mut size = unsafe { std::mem::zeroed::<libc::winsize>() };
    if unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut size) } != 0 {
        return Err(io::Error::last_os_error());
    }
    transport.send(ShellRequest::Resize {
        index: 0,
        fd: 0,
        rows: size.ws_row,
        cols: size.ws_col,
        x: size.ws_xpixel,
        y: size.ws_ypixel,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cli_arg_parser_keeps_shell_args() {
        let config = ShellConfig::parse(
            ["go-judge-shell", "--", "sh", "-lc", "echo ok"],
            "",
            "xterm",
        )
        .unwrap();
        assert_eq!(config.args, ["sh", "-lc", "echo ok"]);
        assert_eq!(config.execution_plan().command.args, config.args);
    }
}
