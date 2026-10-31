//! Go-judge's architecture-aware syscall policy and Moby profile conversion.
//!
//! The policy is kept separate from `container::seccomp::Filter`: this module
//! parses and resolves names/argument predicates, while emitting classic BPF
//! requires an architecture syscall-number table and assembler. The Go
//! runtime delegates that final step to Elastic's seccomp assembler.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;

pub const DEFAULT_PROFILE: &[u8] = include_bytes!("../../resources/seccomp/default.yaml");
pub const MOBY_DEFAULT_JSON: &[u8] = include_bytes!("../../resources/seccomp/moby-default.json");

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PolicyProfile {
    pub default_action: String,
    #[serde(default)]
    pub base: PolicySection,
    #[serde(default)]
    pub architectures: BTreeMap<String, PolicySection>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PolicySection {
    #[serde(default)]
    pub syscalls: Vec<SyscallRule>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct SyscallRule {
    #[serde(default)]
    pub names: Vec<String>,
    #[serde(default, rename = "names_with_args")]
    pub names_with_args: Vec<NamedArguments>,
    pub action: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct NamedArguments {
    pub name: String,
    #[serde(default)]
    pub arguments: Vec<Argument>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Argument {
    pub position: u32,
    pub operation: CompareOperation,
    pub value: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompareOperation {
    Equal,
    NotEqual,
    LessThan,
    LessOrEqual,
    GreaterThan,
    GreaterOrEqual,
    BitsSet,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Parse(String),
    UnknownArchitecture(String),
    UnknownSyscall { architecture: String, name: String },
    UnknownComparison(String),
    Unsupported(&'static str),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => e.fmt(f),
            Self::Parse(e) => write!(f, "invalid seccomp profile: {e}"),
            Self::UnknownArchitecture(a) => write!(
                f,
                "seccomp profile has no configuration for architecture {a:?}"
            ),
            Self::UnknownSyscall { architecture, name } => write!(
                f,
                "unknown syscall {name:?} for architecture {architecture:?}"
            ),
            Self::UnknownComparison(op) => write!(f, "unsupported seccomp comparison {op:?}"),
            Self::Unsupported(m) => write!(f, "unsupported: {m}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl<'de> Deserialize<'de> for CompareOperation {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        match name.as_str() {
            "Equal" => Ok(Self::Equal),
            "NotEqual" => Ok(Self::NotEqual),
            "LessThan" => Ok(Self::LessThan),
            "LessOrEqual" => Ok(Self::LessOrEqual),
            "GreaterThan" => Ok(Self::GreaterThan),
            "GreaterOrEqual" => Ok(Self::GreaterOrEqual),
            "BitsSet" => Ok(Self::BitsSet),
            _ => Err(serde::de::Error::custom(format!(
                "unknown operation {name}"
            ))),
        }
    }
}
impl Serialize for CompareOperation {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(match self {
            Self::Equal => "Equal",
            Self::NotEqual => "NotEqual",
            Self::LessThan => "LessThan",
            Self::LessOrEqual => "LessOrEqual",
            Self::GreaterThan => "GreaterThan",
            Self::GreaterOrEqual => "GreaterOrEqual",
            Self::BitsSet => "BitsSet",
        })
    }
}

impl PolicyProfile {
    pub fn load_default() -> Result<Self, Error> {
        Self::from_yaml(DEFAULT_PROFILE)
    }
    pub fn from_yaml(bytes: &[u8]) -> Result<Self, Error> {
        serde_yaml::from_slice(bytes).map_err(|e| Error::Parse(e.to_string()))
    }
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, Error> {
        Self::from_yaml(&std::fs::read(path)?)
    }
    /// Merge common and architecture-specific rules in the same order as Go's
    /// loader. Unknown architecture names are errors, never silently treated
    /// as an empty policy.
    pub fn rules_for_architecture(&self, architecture: &str) -> Result<Vec<SyscallRule>, Error> {
        let selected = self
            .architectures
            .get(architecture)
            .ok_or_else(|| Error::UnknownArchitecture(architecture.into()))?;
        Ok(self
            .base
            .syscalls
            .iter()
            .chain(&selected.syscalls)
            .cloned()
            .collect())
    }
    /// Validate syscall names at the same boundary as Go's seccomp assembler.
    /// The converter uses a different rule: Moby names absent from an
    /// architecture table are filtered out while generating architecture
    /// policies.
    pub fn validate_architecture(
        &self,
        architecture: &str,
        known: &BTreeSet<String>,
    ) -> Result<(), Error> {
        for rule in self.rules_for_architecture(architecture)? {
            for name in rule
                .names
                .into_iter()
                .chain(rule.names_with_args.into_iter().map(|n| n.name))
            {
                if !known.contains(&name) {
                    return Err(Error::UnknownSyscall {
                        architecture: architecture.into(),
                        name,
                    });
                }
            }
        }
        Ok(())
    }
    /// Compile policy names and argument comparisons with rust-vmm's
    /// seccompiler frontend. This uses its architecture syscall tables and
    /// verified BPF backend rather than maintaining syscall numbers or BPF
    /// instructions in this crate.
    pub fn assemble(&self, architecture: &str) -> Result<crate::container::seccomp::Filter, Error> {
        let rules = self.rules_for_architecture(architecture)?;
        let actions = rules
            .iter()
            .map(|rule| rule.action.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        if actions.len() > 1 {
            // Go's assembler evaluates groups in order, so two different-action
            // groups for the same syscall can have order-sensitive behavior.
            // Stacked kernel filters instead resolve by action precedence. We
            // only stack when the groups are provably disjoint at syscall level.
            let mut action_by_syscall = BTreeMap::<String, String>::new();
            for rule in &rules {
                let action = rule.action.to_ascii_lowercase();
                for name in rule
                    .names
                    .iter()
                    .chain(rule.names_with_args.iter().map(|n| &n.name))
                {
                    if let Some(existing) = action_by_syscall.get(name) {
                        if existing != &action {
                            return Err(Error::Unsupported(
                                "mixed seccomp actions overlap on a syscall; precedence cannot preserve Go rule order",
                            ));
                        }
                    } else {
                        action_by_syscall.insert(name.clone(), action.clone());
                    }
                }
            }

            // The base program keeps the profile's default action, but returns
            // ALLOW for every explicit rule. Additional programs return ALLOW
            // on mismatch and their action on match. Kernel precedence then
            // selects the custom action while preserving explicit ALLOW rules.
            let mut base = self.clone();
            base.base.syscalls.clear();
            base.architectures.clear();
            base.architectures.insert(
                architecture.into(),
                PolicySection {
                    syscalls: rules
                        .iter()
                        .cloned()
                        .map(|mut rule| {
                            rule.action = "allow".into();
                            rule
                        })
                        .collect(),
                },
            );
            let mut combined = base.assemble(architecture)?;
            for action in actions.into_iter().filter(|action| action != "allow") {
                let mut action_profile = self.clone();
                action_profile.default_action = "allow".into();
                action_profile.base.syscalls.clear();
                action_profile.architectures.clear();
                action_profile.architectures.insert(
                    architecture.into(),
                    PolicySection {
                        syscalls: rules
                            .iter()
                            .filter(|rule| rule.action.eq_ignore_ascii_case(&action))
                            .cloned()
                            .collect(),
                    },
                );
                let program = action_profile.assemble(architecture)?;
                if !program.0.is_empty() {
                    combined.1.push(program.0);
                }
                combined.1.extend(program.1);
            }
            return Ok(combined);
        }
        let mut filter_rules = Vec::new();
        let mut match_action: Option<String> = None;
        for rule in rules {
            if let Some(existing) = &match_action {
                if existing != &rule.action {
                    return Err(Error::Unsupported(
                        "seccompiler requires one match action per filter",
                    ));
                }
            } else {
                match_action = Some(rule.action.clone());
            }
            for name in rule.names {
                filter_rules.push(serde_json::json!({ "syscall": name }));
            }
            for named in rule.names_with_args {
                let mut alternatives = vec![Vec::<serde_json::Value>::new()];
                for arg in named.arguments {
                    if arg.position > 5 {
                        return Err(Error::Parse(format!(
                            "argument position {} exceeds seccomp's six argument slots",
                            arg.position
                        )));
                    }
                    let choices = match arg.operation {
                        CompareOperation::BitsSet => (0..64)
                            .filter_map(|bit_index| {
                                let bit = 1u64 << bit_index;
                                (arg.value & bit != 0).then(|| {
                                    serde_json::json!({
                                        "index": arg.position,
                                        "type": "qword",
                                        "op": { "masked_eq": bit },
                                        "val": bit,
                                    })
                                })
                            })
                            .collect::<Vec<_>>(),
                        operation => {
                            let op = match operation {
                                CompareOperation::Equal => "eq",
                                CompareOperation::NotEqual => "ne",
                                CompareOperation::LessThan => "lt",
                                CompareOperation::LessOrEqual => "le",
                                CompareOperation::GreaterThan => "gt",
                                CompareOperation::GreaterOrEqual => "ge",
                                CompareOperation::BitsSet => unreachable!(),
                            };
                            vec![serde_json::json!({
                                "index": arg.position,
                                "type": "qword",
                                "op": op,
                                "val": arg.value,
                            })]
                        }
                    };
                    if choices.is_empty() {
                        alternatives.clear();
                        break;
                    }
                    let count = alternatives
                        .len()
                        .checked_mul(choices.len())
                        .filter(|count| *count <= 512)
                        .ok_or(Error::Unsupported(
                            "seccomp argument alternatives exceed 512 rules",
                        ))?;
                    let mut expanded = Vec::with_capacity(count);
                    for prefix in &alternatives {
                        for choice in &choices {
                            let mut args = prefix.clone();
                            args.push(choice.clone());
                            expanded.push(args);
                        }
                    }
                    alternatives = expanded;
                }
                for args in alternatives {
                    filter_rules.push(serde_json::json!({
                        "syscall": named.name,
                        "args": args,
                    }));
                }
            }
        }
        let match_action = match_action.unwrap_or_else(|| "allow".into());
        let spec = serde_json::json!({
            "main_thread": {
                "mismatch_action": seccompiler_action(&self.default_action)?,
                "match_action": seccompiler_action(&match_action)?,
                "filter": filter_rules,
            }
        });
        let target = seccompiler::TargetArch::try_from(architecture).map_err(|e| {
            Error::Parse(format!(
                "unsupported seccomp architecture {architecture:?}: {e}"
            ))
        })?;
        let mut spec = spec;
        let programs = loop {
            let bytes = serde_json::to_vec(&spec).map_err(|e| Error::Parse(e.to_string()))?;
            match seccompiler::compile_from_json(bytes.as_slice(), target) {
                Ok(programs) => break programs,
                Err(error) => {
                    let error_text = error.to_string();
                    let Some(name) = unsupported_syscall_name(&error_text) else {
                        return Err(Error::Parse(format!(
                            "seccompiler rejected policy: {error_text}"
                        )));
                    };
                    // A name unknown to seccompiler's architecture table is
                    // omitted from the allow rules. The kernel then returns
                    // the profile's default action for it. This fails closed
                    // on newer syscalls absent from seccompiler's snapshot.
                    let list = spec["main_thread"]["filter"]
                        .as_array_mut()
                        .ok_or_else(|| Error::Parse("invalid seccompiler filter array".into()))?;
                    let before = list.len();
                    list.retain(|entry| entry["syscall"].as_str() != Some(&name));
                    if before == list.len() {
                        return Err(Error::Parse(format!(
                            "seccompiler reported unknown syscall {name:?} but no matching rule was found"
                        )));
                    }
                }
            }
        };
        let mut programs = programs;
        let program = programs.remove("main_thread").ok_or_else(|| {
            Error::Parse("seccompiler returned no main_thread BPF program".into())
        })?;
        Ok(crate::container::seccomp::Filter(
            program
                .into_iter()
                .map(|instruction| libc::sock_filter {
                    code: instruction.code,
                    jt: instruction.jt,
                    jf: instruction.jf,
                    k: instruction.k,
                })
                .collect(),
            Vec::new(),
        ))
    }
}

fn unsupported_syscall_name(error: &str) -> Option<String> {
    let prefix = "Invalid syscall name: ";
    let start = error.find(prefix)? + prefix.len();
    let rest = &error[start..];
    let end = rest.find(" for given arch:")?;
    Some(rest[..end].to_owned())
}

fn seccompiler_action(action: &str) -> Result<serde_json::Value, Error> {
    match action.to_ascii_lowercase().as_str() {
        "allow" => Ok(serde_json::json!("allow")),
        "errno" => Ok(serde_json::json!({ "errno": libc::EPERM })),
        "kill" | "kill_process" => Ok(serde_json::json!("kill_process")),
        "kill_thread" => Ok(serde_json::json!("kill_thread")),
        "trap" => Ok(serde_json::json!("trap")),
        "trace" => Ok(serde_json::json!({ "trace": 0 })),
        _ => Err(Error::Parse(format!("unknown seccomp action {action:?}"))),
    }
}

/// Mirror `env.prepareSeccomp`: forced disable wins; an empty path selects the
/// embedded go-judge profile; otherwise load the named YAML policy.
pub fn prepare_profile(config: &super::Config) -> Result<Option<PolicyProfile>, Error> {
    if config.no_seccomp {
        return Ok(None);
    }
    if config.seccomp_conf.is_empty() {
        Ok(Some(PolicyProfile::load_default()?))
    } else {
        Ok(Some(PolicyProfile::from_path(&config.seccomp_conf)?))
    }
}

pub fn native_architecture() -> Result<&'static str, Error> {
    #[cfg(target_arch = "x86_64")]
    {
        return Ok("x86_64");
    }
    #[cfg(target_arch = "x86")]
    {
        return Ok("i386");
    }
    #[cfg(target_arch = "aarch64")]
    {
        return Ok("aarch64");
    }
    #[cfg(target_arch = "arm")]
    {
        return Ok("arm");
    }
    #[allow(unreachable_code)]
    Err(Error::UnknownArchitecture(std::env::consts::ARCH.into()))
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MobyProfile {
    pub default_action: String,
    #[serde(default)]
    pub default_errno_ret: i32,
    #[serde(default)]
    pub syscalls: Vec<MobyGroup>,
}
#[derive(Clone, Debug, Deserialize)]
pub struct MobyGroup {
    #[serde(default)]
    pub names: Vec<String>,
    pub action: String,
    #[serde(default)]
    pub args: Vec<MobyArgument>,
    pub includes: Option<MobySelector>,
    pub excludes: Option<MobySelector>,
}
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MobySelector {
    #[serde(default)]
    pub caps: Vec<String>,
    #[serde(default)]
    pub arches: Vec<String>,
    #[serde(default)]
    pub min_kernel: String,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MobyArgument {
    pub index: u32,
    pub value: u64,
    pub op: String,
}

const TARGETS: [(&str, &str); 4] = [
    ("x86_64", "amd64"),
    ("i386", "x86"),
    ("aarch64", "arm64"),
    ("arm", "arm"),
];

/// Convert Moby's source JSON into the same architecture-aware policy shape
/// consumed by go-judge. `syscalls` provides each target's known syscall set;
/// unknown source names are discarded during this conversion, matching the Go
/// converter. The converter keeps policies per architecture instead of
/// factoring common groups into `base`; the resulting allow rules are
/// semantically equivalent.
pub fn convert_moby(
    profile: &MobyProfile,
    syscalls: &BTreeMap<String, BTreeSet<String>>,
) -> Result<PolicyProfile, Error> {
    let mut architectures = BTreeMap::new();
    for (target, moby_arch) in TARGETS {
        let known = syscalls
            .get(target)
            .ok_or_else(|| Error::UnknownArchitecture(target.into()))?;
        let mut rules = Vec::new();
        for group in &profile.syscalls {
            if group.action != "SCMP_ACT_ALLOW"
                || group.names.is_empty()
                || !include_group(group, moby_arch)
            {
                continue;
            }
            if group.args.is_empty() {
                let names = valid_names(&group.names, target, known);
                let names: Vec<_> = names
                    .into_iter()
                    .filter(|n| {
                        !matches!(n.as_str(), "socketcall" | "socket" | "socketpair" | "ioctl")
                    })
                    .collect();
                if !names.is_empty() {
                    rules.push(SyscallRule {
                        names,
                        action: "allow".into(),
                        ..Default::default()
                    });
                }
            } else {
                for name in valid_names(&group.names, target, known) {
                    if matches!(name.as_str(), "socket" | "socketpair") || name == "clone" {
                        continue;
                    }
                    for arg in &group.args {
                        let operation = parse_comparison(&arg.op)?;
                        rules.push(SyscallRule {
                            names_with_args: vec![NamedArguments {
                                name: name.clone(),
                                arguments: vec![Argument {
                                    position: arg.index,
                                    operation,
                                    value: arg.value,
                                }],
                            }],
                            action: "allow".into(),
                            ..Default::default()
                        });
                    }
                }
            }
        }
        for (name, family) in [("socket", 1), ("socket", 2), ("socket", 10)] {
            if known.contains(name) {
                rules.push(arg_rule(name, 0, CompareOperation::Equal, family));
            }
        }
        if known.contains("socketpair") {
            rules.push(arg_rule("socketpair", 0, CompareOperation::Equal, 1));
        }
        if known.contains("ioctl") {
            rules.push(SyscallRule {
                names_with_args: vec![NamedArguments {
                    name: "ioctl".into(),
                    arguments: vec![
                        Argument {
                            position: 1,
                            operation: CompareOperation::NotEqual,
                            value: 0x5412,
                        },
                        Argument {
                            position: 1,
                            operation: CompareOperation::NotEqual,
                            value: 0x541c,
                        },
                    ],
                }],
                action: "allow".into(),
                ..Default::default()
            });
        }
        if known.contains("socketcall") {
            rules.push(SyscallRule {
                names_with_args: vec![NamedArguments {
                    name: "socketcall".into(),
                    arguments: vec![
                        Argument {
                            position: 0,
                            operation: CompareOperation::GreaterThan,
                            value: 1,
                        },
                        Argument {
                            position: 0,
                            operation: CompareOperation::NotEqual,
                            value: 8,
                        },
                    ],
                }],
                action: "allow".into(),
                ..Default::default()
            });
        }
        if known.contains("getpgid") {
            rules.push(arg_rule("getpgid", 0, CompareOperation::Equal, 0));
        }
        for name in ["clone", "clone3", "kill", "unshare"] {
            if known.contains(name) {
                rules.push(SyscallRule {
                    names: vec![name.into()],
                    action: "allow".into(),
                    ..Default::default()
                });
            }
        }
        architectures.insert(target.into(), PolicySection { syscalls: rules });
    }
    Ok(PolicyProfile {
        default_action: "errno".into(),
        base: PolicySection::default(),
        architectures,
    })
}

pub fn load_moby_default() -> Result<MobyProfile, Error> {
    serde_json::from_slice(MOBY_DEFAULT_JSON).map_err(|e| Error::Parse(e.to_string()))
}

pub fn convert_moby_default(
    syscalls: &BTreeMap<String, BTreeSet<String>>,
) -> Result<PolicyProfile, Error> {
    convert_moby(&load_moby_default()?, syscalls)
}

fn arg_rule(name: &str, position: u32, operation: CompareOperation, value: u64) -> SyscallRule {
    SyscallRule {
        names_with_args: vec![NamedArguments {
            name: name.into(),
            arguments: vec![Argument {
                position,
                operation,
                value,
            }],
        }],
        action: "allow".into(),
        ..Default::default()
    }
}
fn parse_comparison(op: &str) -> Result<CompareOperation, Error> {
    match op {
        "SCMP_CMP_EQ" => Ok(CompareOperation::Equal),
        "SCMP_CMP_NE" => Ok(CompareOperation::NotEqual),
        "SCMP_CMP_LT" => Ok(CompareOperation::LessThan),
        "SCMP_CMP_LE" => Ok(CompareOperation::LessOrEqual),
        "SCMP_CMP_GT" => Ok(CompareOperation::GreaterThan),
        "SCMP_CMP_GE" => Ok(CompareOperation::GreaterOrEqual),
        "SCMP_CMP_MASKED_EQ" => Ok(CompareOperation::BitsSet),
        _ => Err(Error::UnknownComparison(op.into())),
    }
}
fn include_group(group: &MobyGroup, target_arch: &str) -> bool {
    if group.includes.as_ref().is_some_and(|s| !s.caps.is_empty()) {
        return false;
    }
    if group
        .excludes
        .as_ref()
        .is_some_and(|s| !s.caps.is_empty() && group.args.is_empty())
    {
        return false;
    }
    if group
        .includes
        .as_ref()
        .is_some_and(|s| !s.arches.is_empty() && !s.arches.iter().any(|a| a == target_arch))
    {
        return false;
    }
    !group
        .excludes
        .as_ref()
        .is_some_and(|s| s.arches.iter().any(|a| a == target_arch))
}
fn valid_names(names: &[String], target: &str, known: &BTreeSet<String>) -> Vec<String> {
    let denied: BTreeSet<&str> = [
        "get_robust_list",
        "process_mrelease",
        "process_vm_readv",
        "process_vm_writev",
        "ptrace",
        "execveat",
        "memfd_create",
        "memfd_secret",
        "get_thread_area",
        "modify_ldt",
        "set_thread_area",
        "mknod",
        "mknodat",
        "fanotify_mark",
        "getpgid",
        "getsid",
        "rt_sigqueueinfo",
        "rt_tgsigqueueinfo",
        "sched_setattr",
        "sched_setparam",
        "tkill",
        "io_cancel",
        "io_destroy",
        "io_getevents",
        "io_pgetevents",
        "io_setup",
        "io_submit",
        "listmount",
        "name_to_handle_at",
        "openat2",
        "statmount",
        "copy_file_range",
        "sendfile",
        "splice",
        "tee",
        "vmsplice",
        "personality",
    ]
    .into_iter()
    .collect();
    names
        .iter()
        .filter_map(|original| {
            let name = if target == "aarch64" && original == "newfstatat" {
                "fstatat"
            } else {
                original.as_str()
            };
            (known.contains(name) && !denied.contains(name)).then(|| name.to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_embedded_architecture_profile_and_preserves_unknown_names_for_validation() {
        let profile = PolicyProfile::load_default().unwrap();
        assert_eq!(profile.default_action, "errno");
        let x64 = profile.rules_for_architecture("x86_64").unwrap();
        assert!(x64.iter().any(|r| r.names.iter().any(|n| n == "read")));
        assert!(matches!(
            profile.rules_for_architecture("not-an-arch"),
            Err(Error::UnknownArchitecture(_))
        ));
        let known = BTreeSet::from(["read".to_string()]);
        assert!(matches!(
            profile.validate_architecture("x86_64", &known),
            Err(Error::UnknownSyscall { .. })
        ));
        let filter = profile.assemble("x86_64").unwrap();
        assert!(!filter.0.is_empty());
    }

    #[test]
    fn stacks_disjoint_mixed_actions_with_default_action_fallback() {
        let profile = PolicyProfile {
            default_action: "kill".into(),
            base: PolicySection {
                syscalls: vec![
                    SyscallRule {
                        names: vec!["read".into()],
                        action: "allow".into(),
                        ..Default::default()
                    },
                    SyscallRule {
                        names: vec!["write".into()],
                        action: "errno".into(),
                        ..Default::default()
                    },
                ],
            },
            architectures: BTreeMap::from([("x86_64".into(), PolicySection::default())]),
        };
        let filter = profile.assemble("x86_64").unwrap();
        assert!(!filter.0.is_empty());
        assert_eq!(filter.1.len(), 1);
    }

    #[test]
    fn rejects_cross_action_rules_for_same_syscall() {
        let profile = PolicyProfile {
            default_action: "errno".into(),
            base: PolicySection {
                syscalls: vec![
                    SyscallRule {
                        names: vec!["ioctl".into()],
                        action: "allow".into(),
                        ..Default::default()
                    },
                    SyscallRule {
                        names_with_args: vec![NamedArguments {
                            name: "ioctl".into(),
                            arguments: vec![Argument {
                                position: 1,
                                operation: CompareOperation::Equal,
                                value: 1,
                            }],
                        }],
                        action: "trap".into(),
                        ..Default::default()
                    },
                ],
            },
            architectures: BTreeMap::from([("x86_64".into(), PolicySection::default())]),
        };
        assert!(matches!(
            profile.assemble("x86_64"),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn moby_converter_filters_unknown_names_and_injects_safe_socket_conditions() {
        let profile = load_moby_default().unwrap();
        let known: BTreeSet<String> = [
            "read",
            "socket",
            "socketpair",
            "ioctl",
            "clone",
            "clone3",
            "kill",
            "unshare",
            "getpgid",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        let tables = TARGETS
            .into_iter()
            .map(|(arch, _)| (arch.into(), known.clone()))
            .collect();
        let converted = convert_moby(&profile, &tables).unwrap();
        let rules = &converted.architectures["x86_64"].syscalls;
        assert!(
            rules
                .iter()
                .any(|r| r.names.iter().any(|name| name == "read"))
        );
        assert!(!rules.iter().any(|r| r.names.iter().any(|n| n == "ptrace")));
        let sockets = rules
            .iter()
            .filter(|r| r.names_with_args.iter().any(|n| n.name == "socket"))
            .count();
        assert_eq!(sockets, 3);
        assert!(rules.iter().any(|r| {
            r.names_with_args
                .iter()
                .any(|n| n.name == "ioctl" && n.arguments.len() == 2)
        }));
    }

    #[test]
    fn unknown_moby_comparison_is_an_error() {
        assert!(matches!(
            parse_comparison("SCMP_CMP_UNKNOWN"),
            Err(Error::UnknownComparison(_))
        ));
    }

    #[test]
    fn assembles_bits_set_as_any_matching_masked_bit() {
        let profile_for = |mask| PolicyProfile {
            default_action: "errno".into(),
            base: PolicySection::default(),
            architectures: BTreeMap::from([(
                "x86_64".into(),
                PolicySection {
                    syscalls: vec![SyscallRule {
                        names: vec![],
                        names_with_args: vec![NamedArguments {
                            name: "clone".into(),
                            arguments: vec![Argument {
                                position: 0,
                                operation: CompareOperation::BitsSet,
                                value: mask,
                            }],
                        }],
                        action: "allow".into(),
                    }],
                },
            )]),
        };

        let one_bit = profile_for(0b0010).assemble("x86_64").unwrap();
        let two_bits = profile_for(0b1010).assemble("x86_64").unwrap();

        assert!(!one_bit.0.is_empty());
        assert!(
            two_bits.0.len() > one_bit.0.len(),
            "each set bit must contribute an alternative matching rule"
        );
    }

    #[test]
    fn seccomp_config_disable_and_embedded_default_match_go() {
        let disabled = super::super::Config {
            no_seccomp: true,
            ..Default::default()
        };
        assert!(prepare_profile(&disabled).unwrap().is_none());
        let enabled = super::super::Config::default();
        let profile = prepare_profile(&enabled).unwrap().unwrap();
        assert!(
            profile
                .rules_for_architecture(native_architecture().unwrap())
                .is_ok()
        );
    }
}
