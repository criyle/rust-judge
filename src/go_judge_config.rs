//! CLI and environment configuration for the `rust-judge` server entrypoint.
//!
//! The Go server's HTTP/gRPC wiring depends on Gin, gRPC, Prometheus and the
//! full environment backend. This module translates its configuration surface
//! independently so a native server can be wired without changing the crate's
//! existing `main` binary.

use crate::runner::Size;
use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub container_init_path: String,
    pub pre_fork: i32,
    pub tmp_fs_param: String,
    pub net_share: bool,
    pub mount_conf: String,
    pub seccomp_conf: String,
    pub no_seccomp: bool,
    pub parallelism: usize,
    pub cgroup_prefix: String,
    pub container_cred_start: i32,
    pub no_fallback: bool,
    pub src_prefix: Vec<String>,
    pub dir: String,
    pub time_limit_checker_interval: Duration,
    pub extra_memory_limit: Size,
    pub output_limit: Size,
    pub copy_out_limit: Size,
    pub open_file_limit: i32,
    pub cpuset: Vec<String>,
    pub enable_cpu_rate: bool,
    pub cpu_cfs_period: Duration,
    pub file_timeout: Duration,
    pub http_addr: String,
    pub enable_grpc: bool,
    pub grpc_addr: String,
    pub monitor_addr: String,
    pub auth_token: String,
    pub grpc_msg_size: Size,
    pub enable_debug: bool,
    pub enable_metrics: bool,
    pub release: bool,
    pub silent: bool,
    pub version: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseOutcome {
    Config(Config),
    Help,
}

#[derive(Debug)]
pub struct ConfigError(pub String);
impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for ConfigError {}

impl Config {
    pub fn defaults(pid: u32, cpu_count: usize) -> Self {
        let (http_addr, grpc_addr, monitor_addr) = if pid == 1 {
            (":5050", ":5051", ":5052")
        } else {
            ("localhost:5050", "localhost:5051", "localhost:5052")
        };
        Self {
            container_init_path: String::new(),
            pre_fork: 1,
            tmp_fs_param: "size=128m,nr_inodes=4k".into(),
            net_share: false,
            mount_conf: "mount.yaml".into(),
            seccomp_conf: String::new(),
            no_seccomp: false,
            parallelism: cpu_count.max(1),
            cgroup_prefix: "gojudge".into(),
            container_cred_start: 0,
            no_fallback: false,
            src_prefix: Vec::new(),
            dir: String::new(),
            time_limit_checker_interval: Duration::from_millis(100),
            extra_memory_limit: Size(16 << 10),
            output_limit: Size(256 << 20),
            copy_out_limit: Size(256 << 20),
            open_file_limit: 256,
            cpuset: Vec::new(),
            enable_cpu_rate: false,
            cpu_cfs_period: Duration::from_millis(100),
            file_timeout: Duration::ZERO,
            http_addr: http_addr.into(),
            enable_grpc: false,
            grpc_addr: grpc_addr.into(),
            monitor_addr: monitor_addr.into(),
            auth_token: String::new(),
            grpc_msg_size: Size(64 << 20),
            enable_debug: false,
            enable_metrics: false,
            release: pid == 1,
            silent: false,
            version: false,
        }
    }

    /// Apply ES-prefixed variables, then CLI arguments. Pass arguments with or
    /// without argv[0]. CLI values override environment values, matching the
    /// Go loader order.
    pub fn parse_from<I, S>(
        args: I,
        env: &HashMap<String, String>,
        pid: u32,
        cpu_count: usize,
    ) -> Result<ParseOutcome, ConfigError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut config = Self::defaults(pid, cpu_count);
        for (key, value) in env {
            if let Some(field) = key.strip_prefix("ES_") {
                if let Some(name) = normalize_name(field) {
                    set_value(&mut config, name, value, true)?;
                }
            }
        }

        let mut tokens: Vec<String> = args.into_iter().map(Into::into).collect();
        if !tokens.is_empty() && !tokens[0].starts_with('-') {
            tokens.remove(0);
        }
        let mut index = 0;
        while index < tokens.len() {
            let token = &tokens[index];
            if token == "--" {
                break;
            }
            if token == "-h" || token == "--help" || token == "-help" {
                return Ok(ParseOutcome::Help);
            }
            if !token.starts_with('-') || token == "-" {
                break;
            }
            let raw = token.trim_start_matches('-');
            let (raw_name, inline) = raw
                .split_once('=')
                .map_or((raw, None), |(n, v)| (n, Some(v.to_string())));
            let name = normalize_name(raw_name)
                .ok_or_else(|| ConfigError(format!("unknown option: {raw_name}")))?;
            let value = if is_bool(name) {
                match inline {
                    Some(v) => v,
                    None => "true".into(),
                }
            } else if let Some(v) = inline {
                v
            } else {
                index += 1;
                tokens
                    .get(index)
                    .cloned()
                    .ok_or_else(|| ConfigError(format!("option {raw_name} requires a value")))?
            };
            set_value(&mut config, name, &value, false)?;
            index += 1;
        }
        // rust-judge is a server and accepts no positional command; the Go
        // flag package leaves trailing positional values unused as well.
        if config.parallelism == 0 {
            config.parallelism = cpu_count.max(1);
        }
        Ok(ParseOutcome::Config(config))
    }
}

pub const USAGE: &str = r#"Usage: rust-judge [options]
Starts the HTTP executor server (optional gRPC and metrics endpoints).

Options use kebab-case names; settings can also be supplied as ES_<UPPER_SNAKE_CASE> environment variables.
  --container-init-path PATH --pre-fork N --tmp-fs-param DATA --net-share
  --mount-conf PATH --seccomp-conf PATH --no-seccomp --parallelism N
  --cgroup-prefix NAME --container-cred-start UID --no-fallback
  --src-prefix DIR[,DIR...] --dir PATH --time-limit-checker-interval DURATION
  --extra-memory-limit SIZE --output-limit SIZE --copy-out-limit SIZE
  --open-file-limit N --cpuset CPUSET --enable-cpu-rate --cpu-cfs-period DURATION
  --file-timeout DURATION --http-addr ADDR --enable-grpc --grpc-addr ADDR
  --monitor-addr ADDR --auth-token TOKEN --grpc-msg-size SIZE
  --enable-debug --enable-metrics --release --silent
  --version --help
"#;

fn normalize_name(s: &str) -> Option<&'static str> {
    let compact: String = s
        .chars()
        .filter(|c| *c != '-' && *c != '_')
        .flat_map(char::to_lowercase)
        .collect();
    Some(match compact.as_str() {
        "containerinitpath" => "container_init_path",
        "prefork" => "pre_fork",
        "tmpfsparam" => "tmp_fs_param",
        "netshare" => "net_share",
        "mountconf" => "mount_conf",
        "seccompconf" => "seccomp_conf",
        "noseccomp" => "no_seccomp",
        "parallelism" => "parallelism",
        "cgroupprefix" => "cgroup_prefix",
        "containercredstart" => "container_cred_start",
        "nofallback" => "no_fallback",
        "srcprefix" => "src_prefix",
        "dir" => "dir",
        "timelimitcheckerinterval" => "time_limit_checker_interval",
        "extramemorylimit" => "extra_memory_limit",
        "outputlimit" => "output_limit",
        "copyoutlimit" => "copy_out_limit",
        "openfilelimit" => "open_file_limit",
        "cpuset" => "cpuset",
        "enablecpurate" => "enable_cpu_rate",
        "cpucfsperiod" => "cpu_cfs_period",
        "filetimeout" => "file_timeout",
        "httpaddr" => "http_addr",
        "enablegrpc" => "enable_grpc",
        "grpcaddr" => "grpc_addr",
        "monitoraddr" => "monitor_addr",
        "authtoken" => "auth_token",
        "grpcmsgsize" => "grpc_msg_size",
        "enabledebug" => "enable_debug",
        "enablemetrics" => "enable_metrics",
        "release" => "release",
        "silent" => "silent",
        "version" => "version",
        _ => return None,
    })
}

fn is_bool(name: &str) -> bool {
    matches!(
        name,
        "net_share"
            | "no_seccomp"
            | "no_fallback"
            | "enable_cpu_rate"
            | "enable_grpc"
            | "enable_debug"
            | "enable_metrics"
            | "release"
            | "silent"
            | "version"
    )
}

fn set_value(c: &mut Config, name: &str, value: &str, from_env: bool) -> Result<(), ConfigError> {
    let bad = || ConfigError(format!("invalid value for {name}: {value:?}"));
    let boolean = || match value {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Ok(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Ok(false),
        _ => Err(bad()),
    };
    let i32_value = || value.parse::<i32>().map_err(|_| bad());
    let size = || {
        value
            .parse::<Size>()
            .map_err(|e| ConfigError(e.to_string()))
    };
    let duration = || parse_duration(value).ok_or_else(bad);
    match name {
        "container_init_path" => c.container_init_path = value.into(),
        "pre_fork" => c.pre_fork = i32_value()?,
        "tmp_fs_param" => c.tmp_fs_param = value.into(),
        "net_share" => c.net_share = boolean()?,
        "mount_conf" => c.mount_conf = value.into(),
        "seccomp_conf" => c.seccomp_conf = value.into(),
        "no_seccomp" => c.no_seccomp = boolean()?,
        "parallelism" => {
            let parsed = value.parse::<i64>().map_err(|_| bad())?;
            c.parallelism = usize::try_from(parsed.max(0)).map_err(|_| bad())?;
        }
        "cgroup_prefix" => c.cgroup_prefix = value.into(),
        "container_cred_start" => c.container_cred_start = i32_value()?,
        "no_fallback" => c.no_fallback = boolean()?,
        "src_prefix" => extend_list(&mut c.src_prefix, value, from_env),
        "dir" => c.dir = value.into(),
        "time_limit_checker_interval" => c.time_limit_checker_interval = duration()?,
        "extra_memory_limit" => c.extra_memory_limit = size()?,
        "output_limit" => c.output_limit = size()?,
        "copy_out_limit" => c.copy_out_limit = size()?,
        "open_file_limit" => c.open_file_limit = i32_value()?,
        "cpuset" => extend_list(&mut c.cpuset, value, from_env),
        "enable_cpu_rate" => c.enable_cpu_rate = boolean()?,
        "cpu_cfs_period" => c.cpu_cfs_period = duration()?,
        "file_timeout" => {
            c.file_timeout = parse_file_timeout(value).ok_or_else(bad)?;
        }
        "http_addr" => c.http_addr = value.into(),
        "enable_grpc" => c.enable_grpc = boolean()?,
        "grpc_addr" => c.grpc_addr = value.into(),
        "monitor_addr" => c.monitor_addr = value.into(),
        "auth_token" => c.auth_token = value.into(),
        "grpc_msg_size" => c.grpc_msg_size = size()?,
        "enable_debug" => c.enable_debug = boolean()?,
        "enable_metrics" => c.enable_metrics = boolean()?,
        "release" => c.release = boolean()?,
        "silent" => c.silent = boolean()?,
        "version" => c.version = boolean()?,
        _ => return Err(ConfigError(format!("unknown option: {name}"))),
    }
    Ok(())
}

fn extend_list(out: &mut Vec<String>, value: &str, _from_env: bool) {
    // Go's pflag.StringSlice splits comma-separated values for both command
    // line flags and environment-backed configuration. Keep the worker CPU
    // sets as separate entries: a CLI value such as `--cpuset 0,1,2,3`
    // configures four workers pinned to one CPU each.
    out.extend(
        value
            .split(',')
            .filter(|v| !v.is_empty())
            .map(str::to_string),
    );
}

fn parse_duration(input: &str) -> Option<Duration> {
    let input = input.strip_prefix('+').unwrap_or(input);
    if input == "0" {
        return Some(Duration::ZERO);
    }
    let mut rest = input;
    let mut total = 0f64;
    while !rest.is_empty() {
        let number_end = rest.find(|c: char| !c.is_ascii_digit() && c != '.')?;
        if number_end == 0 {
            return None;
        }
        let number = rest[..number_end].parse::<f64>().ok()?;
        rest = &rest[number_end..];
        let unit_end = rest
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(rest.len());
        if unit_end == 0 {
            return None;
        }
        let unit = &rest[..unit_end];
        let scale = match unit {
            "ns" => 1e-9,
            "us" | "µs" => 1e-6,
            "ms" => 1e-3,
            "s" => 1.0,
            "m" => 60.0,
            "h" => 3600.0,
            _ => return None,
        };
        total += number * scale;
        rest = &rest[unit_end..];
    }
    if !total.is_finite() || total < 0.0 {
        return None;
    }
    Duration::try_from_secs_f64(total).ok()
}

/// Go only installs file expiration when its duration is positive, so a
/// negative timeout is accepted but has the same disabled behavior as zero.
fn parse_file_timeout(input: &str) -> Option<Duration> {
    if let Some(positive) = input.strip_prefix('-') {
        parse_duration(positive).map(|_| Duration::ZERO)
    } else {
        parse_duration(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_pid_one_addresses_match_go() {
        let config = Config::defaults(22, 8);
        assert_eq!(config.parallelism, 8);
        assert_eq!(config.http_addr, "localhost:5050");
        assert_eq!(Config::defaults(1, 4).grpc_addr, ":5051");
        assert_eq!(config.output_limit, Size(256 << 20));
    }

    #[test]
    fn env_then_cli_override_and_camel_case_flags_parse() {
        let env = HashMap::from([
            ("ES_HTTP_ADDR".into(), "0.0.0.0:80".into()),
            ("ES_SRC_PREFIX".into(), "/a,/b".into()),
        ]);
        let args = [
            "rust-judge",
            "-enableGrpc",
            "-http-addr",
            "localhost:9090",
            "-pre-fork=3",
            "-version",
        ];
        let ParseOutcome::Config(config) = Config::parse_from(args, &env, 5, 2).unwrap() else {
            panic!()
        };
        assert!(config.enable_grpc && config.version);
        assert_eq!(config.http_addr, "localhost:9090");
        assert_eq!(config.pre_fork, 3);
        assert_eq!(config.src_prefix, ["/a", "/b"]);
        assert!(USAGE.contains("--http-addr"));
    }

    #[test]
    fn comma_separated_cli_lists_match_go_string_slice_flags() {
        let ParseOutcome::Config(config) = Config::parse_from(
            ["rust-judge", "--cpuset", "0,1,2,3", "--src-prefix=/a,/b"],
            &HashMap::new(),
            5,
            2,
        )
        .unwrap() else {
            panic!()
        };
        assert_eq!(config.cpuset, ["0", "1", "2", "3"]);
        assert_eq!(config.src_prefix, ["/a", "/b"]);
    }

    #[test]
    fn nonpositive_parallelism_falls_back_to_logical_cpu_count() {
        for value in ["0", "-1"] {
            let ParseOutcome::Config(config) = Config::parse_from(
                ["rust-judge", "--parallelism", value],
                &HashMap::new(),
                5,
                6,
            )
            .unwrap() else {
                panic!();
            };
            assert_eq!(config.parallelism, 6);
        }

        let env = HashMap::from([("ES_PARALLELISM".into(), "-3".into())]);
        let ParseOutcome::Config(config) = Config::parse_from(["rust-judge"], &env, 5, 9).unwrap()
        else {
            panic!();
        };
        assert_eq!(config.parallelism, 9);
    }

    #[test]
    fn negative_file_timeout_disables_expiration_like_go() {
        let ParseOutcome::Config(config) = Config::parse_from(
            ["rust-judge", "--file-timeout", "-30s"],
            &HashMap::new(),
            5,
            1,
        )
        .unwrap() else {
            panic!();
        };
        assert_eq!(config.file_timeout, Duration::ZERO);

        let env = HashMap::from([("ES_FILE_TIMEOUT".into(), "-1m".into())]);
        let ParseOutcome::Config(config) = Config::parse_from(["rust-judge"], &env, 5, 1).unwrap()
        else {
            panic!();
        };
        assert_eq!(config.file_timeout, Duration::ZERO);
    }

    #[test]
    fn help_defaults_and_bad_values_are_reported() {
        assert_eq!(
            Config::parse_from(["rust-judge", "--help"], &HashMap::new(), 3, 1).unwrap(),
            ParseOutcome::Help
        );
        assert!(matches!(
            Config::parse_from(["rust-judge"], &HashMap::new(), 3, 1).unwrap(),
            ParseOutcome::Config(_)
        ));
        assert!(
            Config::parse_from(
                ["rust-judge", "-pre-fork", "bad", "--", "x"],
                &HashMap::new(),
                3,
                1
            )
            .is_err()
        );
        assert!(
            Config::parse_from(["rust-judge", "-unknown", "--", "x"], &HashMap::new(), 3, 1)
                .is_err()
        );
    }

    #[test]
    fn go_style_compound_duration_parser() {
        assert_eq!(parse_duration("100ms"), Some(Duration::from_millis(100)));
        assert_eq!(parse_duration("+100ms"), Some(Duration::from_millis(100)));
        assert_eq!(
            parse_duration("1m2.5s"),
            Some(Duration::from_millis(62_500))
        );
        assert_eq!(parse_duration("bad"), None);
    }
}
