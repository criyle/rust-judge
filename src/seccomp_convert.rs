//! CLI argument and conversion layer for `go-judge/cmd/seccomp-convert`.
use crate::env::seccomp_policy::{self, Error as PolicyError, MobyProfile, PolicyProfile};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_INPUT: &str = "seccomp/moby-default.json";
const DEFAULT_OUTPUT: &str = "seccomp/moby.yaml";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Options {
    pub input: PathBuf,
    pub output: PathBuf,
    /// Optional Rust-only switch for callers that also request BPF assembly.
    /// YAML is written first, so it remains available if assembly is missing.
    pub bpf_architecture: Option<String>,
    pub input_was_explicit: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            input: DEFAULT_INPUT.into(),
            output: DEFAULT_OUTPUT.into(),
            bpf_architecture: None,
            input_was_explicit: false,
        }
    }
}

impl Options {
    pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self, String> {
        let mut options = Self::default();
        let mut args = args.into_iter();
        while let Some(argument) = args.next() {
            let argument = argument
                .into_string()
                .map_err(|_| "argument is not valid UTF-8".to_string())?;
            if argument == "--" {
                break;
            }
            let (key, inline_value) = argument
                .split_once('=')
                .map_or((argument.as_str(), None), |(key, value)| (key, Some(value)));
            match key {
                "-input" | "--input" => {
                    let value = take_value(inline_value, &mut args, key)?;
                    options.input = value.into();
                    options.input_was_explicit = true;
                }
                "-output" | "--output" => {
                    options.output = take_value(inline_value, &mut args, key)?.into();
                }
                "-bpf-architecture" | "--bpf-architecture" => {
                    options.bpf_architecture = Some(take_value(inline_value, &mut args, key)?);
                }
                "-h" | "--help" => return Err(usage().into()),
                _ if key.starts_with('-') => {
                    return Err(format!("unknown flag {key}\n{}", usage()));
                }
                _ => { /* the Go command ignores positional args after flags */ }
            }
        }
        Ok(options)
    }
}

fn take_value(
    inline: Option<&str>,
    remaining: &mut impl Iterator<Item = OsString>,
    key: &str,
) -> Result<String, String> {
    let value = match inline {
        Some(value) => value.to_owned(),
        None => remaining
            .next()
            .ok_or_else(|| format!("flag {key} requires a value"))?
            .into_string()
            .map_err(|_| format!("value for {key} is not valid UTF-8"))?,
    };
    if value.is_empty() {
        return Err(format!("flag {key} requires a nonempty value"));
    }
    Ok(value)
}

pub const fn usage() -> &'static str {
    "Usage: seccomp-convert [-input profile.json] [-output policy.yaml] [-bpf-architecture arch]"
}

pub fn convert_json(input: &[u8]) -> Result<PolicyProfile, PolicyError> {
    let profile: MobyProfile =
        serde_json::from_slice(input).map_err(|error| PolicyError::Parse(error.to_string()))?;
    let syscall_tables = known_names_by_architecture(&profile);
    seccomp_policy::convert_moby(&profile, &syscall_tables)
}

fn known_names_by_architecture(profile: &MobyProfile) -> BTreeMap<String, BTreeSet<String>> {
    let targets = [
        ("x86_64", "amd64"),
        ("i386", "x86"),
        ("aarch64", "arm64"),
        ("arm", "arm"),
    ];
    let mut tables = BTreeMap::new();
    for (architecture, moby_arch) in targets {
        let mut names = BTreeSet::new();
        for group in &profile.syscalls {
            let included = group.includes.as_ref().is_none_or(|selector| {
                selector.arches.is_empty() || selector.arches.iter().any(|a| a == moby_arch)
            });
            let excluded = group
                .excludes
                .as_ref()
                .is_some_and(|selector| selector.arches.iter().any(|a| a == moby_arch));
            if included && !excluded {
                names.extend(group.names.iter().cloned());
            }
        }
        if architecture == "aarch64" && names.contains("newfstatat") {
            names.insert("fstatat".into());
        }
        tables.insert(architecture.into(), names);
    }
    tables
}

/// Read a Moby JSON profile, convert it, and write the architecture-aware YAML.
/// The generated policy file is committed before optional BPF assembly, so
/// unsupported assembly never loses the parsed/converted result.
pub fn run(options: &Options) -> Result<PolicyProfile, String> {
    let input = match fs::read(&options.input) {
        Ok(bytes) => bytes,
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                && !options.input_was_explicit
                && options.input == Path::new(DEFAULT_INPUT) =>
        {
            seccomp_policy::MOBY_DEFAULT_JSON.to_vec()
        }
        Err(error) => return Err(format!("input {}: {error}", options.input.display())),
    };
    let policy = convert_json(&input).map_err(|error| error.to_string())?;
    let yaml =
        serde_yaml::to_string(&policy).map_err(|error| format!("serialize policy: {error}"))?;
    fs::write(&options.output, yaml)
        .map_err(|error| format!("output {}: {error}", options.output.display()))?;
    if let Some(architecture) = &options.bpf_architecture {
        policy.assemble(architecture).map_err(|error| {
            format!(
                "BPF export failed; converted YAML remains at {}: {error}",
                options.output.display()
            )
        })?;
    }
    Ok(policy)
}

pub fn run_args(args: impl IntoIterator<Item = OsString>) -> Result<PolicyProfile, String> {
    run(&Options::parse(args)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn parses_go_style_input_output_flags() {
        let parsed = Options::parse([
            OsString::from("-input"),
            OsString::from("in.json"),
            OsString::from("--output=out.yaml"),
            OsString::from("ignored-position"),
        ])
        .unwrap();
        assert_eq!(parsed.input, PathBuf::from("in.json"));
        assert!(parsed.input_was_explicit);
        assert_eq!(parsed.output, PathBuf::from("out.yaml"));
    }

    #[test]
    fn rejects_missing_and_unknown_flags() {
        assert!(
            Options::parse([OsString::from("--input")])
                .unwrap_err()
                .contains("requires a value")
        );
        assert!(
            Options::parse([OsString::from("--bogus")])
                .unwrap_err()
                .contains("unknown flag")
        );
    }

    #[test]
    fn converts_profile_to_yaml_policy() {
        let input = br#"{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["read","write"],"action":"SCMP_ACT_ALLOW"}]}"#;
        let profile = convert_json(input).unwrap();
        assert_eq!(profile.default_action, "errno");
        assert!(
            profile.architectures["x86_64"]
                .syscalls
                .iter()
                .any(|rule| rule.names.contains(&"read".into()))
        );
        assert!(serde_yaml::to_string(&profile).unwrap().contains("x86_64:"));
    }

    #[test]
    fn exports_compiled_bpf_and_yaml_policy() {
        let dir = std::env::temp_dir().join(format!("seccomp-convert-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let input = dir.join("in.json");
        let output = dir.join("out.yaml");
        fs::write(
            &input,
            br#"{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[]}"#,
        )
        .unwrap();
        let options = Options {
            input,
            output: output.clone(),
            bpf_architecture: Some("x86_64".into()),
            input_was_explicit: true,
        };
        let profile = run(&options).unwrap();
        assert!(!profile.assemble("x86_64").unwrap().0.is_empty());
        let yaml = fs::read_to_string(&output).unwrap();
        assert!(yaml.contains("default_action: errno"));
        fs::remove_dir_all(dir).unwrap();
    }
}
