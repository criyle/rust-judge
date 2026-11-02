use super::*;

pub fn discover_controller_paths(
    proc_cgroup: &str,
    mountinfo: &str,
) -> Result<ControllerPaths, EnvError> {
    let memberships = parse_memberships(proc_cgroup)?;
    let mounts = parse_mountinfo(mountinfo)?;
    let mut result = ControllerPaths::new();
    for (controller, membership) in memberships {
        if !CONTROLLERS.contains(&controller.as_str()) {
            continue;
        }
        for mount in &mounts {
            if !mount.controllers.contains(&controller) {
                continue;
            }
            let relative = membership.strip_prefix(&mount.root).map_err(|_| {
                EnvError::Backend(format!(
                    "cgroup membership {} is outside mount root {} for {controller}",
                    membership.display(),
                    mount.root.display()
                ))
            })?;
            result.insert(controller.clone(), mount.mount_point.join(relative));
            break;
        }
    }
    Ok(result)
}

/// Resolve each mounted v1 controller to its mount point without appending
/// the current process membership. go-judge creates server cgroups at the
/// configured prefix directly below each controller mount.
pub fn discover_controller_mount_paths(mountinfo: &str) -> Result<ControllerPaths, EnvError> {
    let mounts = parse_mountinfo(mountinfo)?;
    let mut result = ControllerPaths::new();
    for mount in mounts {
        for controller in mount.controllers {
            if CONTROLLERS.contains(&controller.as_str()) {
                result.insert(controller, mount.mount_point.clone());
            }
        }
    }
    Ok(result)
}

/// Create go-judge's v1 prefix, move existing prefix processes to its `api`
/// sibling, and create the `containers` sibling used by execution groups.
pub fn prepare_go_judge_hierarchy(container_roots: &ControllerPaths) -> Result<(), EnvError> {
    let mut prefix_roots = ControllerPaths::new();
    for controller in CONTROLLERS {
        if let Some(containers) = container_roots.get(controller) {
            let prefix = containers.parent().ok_or_else(|| {
                EnvError::Backend(format!(
                    "container cgroup path has no prefix: {}",
                    containers.display()
                ))
            })?;
            ensure_cgroup_root(prefix, controller == "cpuset")?;
            if controller == "cpuset" {
                initialize_cpuset(prefix)?;
            }
            prefix_roots.insert(controller.to_owned(), prefix.to_path_buf());
        }
    }
    if prefix_roots.is_empty() {
        return Err(EnvError::Unsupported(
            "no supported cgroup v1 controllers are mounted",
        ));
    }

    let prefix = CgroupV1 {
        paths: prefix_roots,
        created: Vec::new(),
        existing: true,
    };
    let mut api = prefix.new_child("api")?;
    for pid in prefix.processes()? {
        api.add_process(pid)?;
    }
    // Go creates this child after nesting API processes and uses it as the
    // parent for each per-environment cgroup.
    let _containers = prefix.new_child("containers")?;
    Ok(())
}

#[derive(Debug)]
struct CgroupMount {
    root: PathBuf,
    mount_point: PathBuf,
    controllers: BTreeSet<String>,
}

pub(super) fn parse_memberships(text: &str) -> Result<BTreeMap<String, PathBuf>, EnvError> {
    let mut memberships = BTreeMap::new();
    for line in text.lines().filter(|line| !line.is_empty()) {
        let mut fields = line.splitn(3, ':');
        let hierarchy = fields.next().unwrap_or_default();
        let controllers = fields
            .next()
            .ok_or_else(|| EnvError::Backend(format!("invalid /proc/self/cgroup entry: {line}")))?;
        let path = fields
            .next()
            .ok_or_else(|| EnvError::Backend(format!("invalid /proc/self/cgroup entry: {line}")))?;
        hierarchy.parse::<u32>().map_err(|_| {
            EnvError::Backend(format!("invalid cgroup hierarchy id in entry: {line}"))
        })?;
        if controllers.is_empty() {
            // Unified hierarchy (`0::/...`) is handled by the v2 backend.
            continue;
        }
        let path = safe_absolute_path(path)?;
        for controller in controllers.split(',') {
            if !controller.is_empty() {
                memberships.insert(controller.to_owned(), path.clone());
            }
        }
    }
    Ok(memberships)
}

fn parse_mountinfo(text: &str) -> Result<Vec<CgroupMount>, EnvError> {
    let mut mounts = Vec::new();
    for line in text.lines().filter(|line| !line.is_empty()) {
        let (left, right) = line.split_once(" - ").ok_or_else(|| {
            EnvError::Backend(format!("invalid /proc/self/mountinfo entry: {line}"))
        })?;
        let before: Vec<_> = left.split_whitespace().collect();
        let after: Vec<_> = right.split_whitespace().collect();
        if before.len() < 6 || after.len() < 3 {
            return Err(EnvError::Backend(format!(
                "incomplete /proc/self/mountinfo entry: {line}"
            )));
        }
        if after[0] != "cgroup" {
            continue;
        }
        let root = PathBuf::from(decode_mount_field(before[3])?);
        let mount_point = PathBuf::from(decode_mount_field(before[4])?);
        let mut controllers = BTreeSet::new();
        for option in before[5]
            .split(',')
            .chain(after[2].split(','))
            .chain(after[1].split(','))
        {
            if CONTROLLERS.contains(&option) {
                controllers.insert(option.to_owned());
            }
        }
        if !controllers.is_empty() {
            validate_absolute(&root)?;
            validate_absolute(&mount_point)?;
            mounts.push(CgroupMount {
                root,
                mount_point,
                controllers,
            });
        }
    }
    Ok(mounts)
}

pub(super) fn decode_mount_field(field: &str) -> Result<String, EnvError> {
    let bytes = field.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            if index + 3 >= bytes.len()
                || !bytes[index + 1..index + 4]
                    .iter()
                    .all(|byte| (b'0'..=b'7').contains(byte))
            {
                return Err(EnvError::Backend(format!(
                    "invalid escape in mountinfo field {field:?}"
                )));
            }
            let value = (bytes[index + 1] - b'0') * 64
                + (bytes[index + 2] - b'0') * 8
                + (bytes[index + 3] - b'0');
            decoded.push(value);
            index += 4;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded)
        .map_err(|_| EnvError::Backend("non-UTF-8 cgroup path in mountinfo".into()))
}

pub(super) fn safe_absolute_path(raw: &str) -> Result<PathBuf, EnvError> {
    let path = Path::new(raw);
    validate_absolute(path)?;
    Ok(path.to_path_buf())
}

pub(super) fn validate_absolute(path: &Path) -> Result<(), EnvError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(EnvError::Backend(format!(
            "invalid absolute cgroup path {}",
            path.display()
        )));
    }
    Ok(())
}

pub(super) fn safe_relative_path(raw: &str) -> Result<PathBuf, EnvError> {
    if raw.is_empty() {
        return Ok(PathBuf::new());
    }
    let path = Path::new(raw);
    if raw.contains('\0')
        || path.is_absolute()
        || raw
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(EnvError::Backend(format!(
            "invalid relative cgroup path {raw:?}"
        )));
    }
    Ok(path.to_path_buf())
}

pub(super) fn safe_leaf_prefix(prefix: &str) -> Result<String, EnvError> {
    if prefix.is_empty() {
        return Ok(String::new());
    }
    if prefix.contains('/') || prefix == "." || prefix == ".." {
        return Err(EnvError::Backend(format!(
            "invalid cgroup leaf prefix {prefix:?}"
        )));
    }
    Ok(prefix
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || "-_".contains(character) {
                character
            } else {
                '_'
            }
        })
        .take(48)
        .collect())
}

pub(super) fn remove_dirs(paths: &[PathBuf]) {
    for path in paths.iter().rev() {
        let _ = fs::remove_dir(path);
    }
}

pub(super) fn initialize_cpuset(child: &Path) -> Result<(), EnvError> {
    // The parent may itself be a newly-created intermediate cgroup with an
    // empty cpuset. Match go-sandbox's copyCgroupPropertyFromParent by
    // walking upward to the first populated value and filling each empty
    // ancestor while unwinding.
    for name in ["cpuset.cpus", "cpuset.mems"] {
        initialize_cpuset_property(child, name)?;
    }
    Ok(())
}

pub(super) fn initialize_cpuset_property(path: &Path, name: &str) -> Result<(), EnvError> {
    let property = path.join(name);
    // The kernel creates these pseudo-files with the cgroup directory. Treat
    // absent files as empty as well so filesystem fixtures can model mkdir.
    let current = fs::read_to_string(&property).unwrap_or_default();
    if !current.trim().is_empty() {
        return Ok(());
    }

    let parent = path.parent().ok_or_else(|| {
        EnvError::Backend(format!("cpuset path has no parent: {}", path.display()))
    })?;
    let parent_property = parent.join(name);
    let inherited = fs::read_to_string(&parent_property)?;
    if inherited.trim().is_empty() {
        initialize_cpuset_property(parent, name)?;
    }
    let inherited = fs::read_to_string(parent_property)?;
    fs::write(property, inherited)?;
    Ok(())
}

pub(super) fn ensure_cgroup_root(path: &Path, cpuset: bool) -> Result<(), EnvError> {
    validate_absolute(path)?;
    let mut missing = Vec::new();
    let mut current = path.to_path_buf();
    while !current.exists() {
        missing.push(current.clone());
        current = current.parent().map(Path::to_path_buf).ok_or_else(|| {
            EnvError::Backend(format!(
                "cgroup root has no existing ancestor: {}",
                path.display()
            ))
        })?;
    }
    if !current.is_dir() {
        return Err(EnvError::Backend(format!(
            "cgroup root ancestor is not a directory: {}",
            current.display()
        )));
    }
    for child in missing.into_iter().rev() {
        match fs::create_dir(&child) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        if cpuset {
            initialize_cpuset(&child)?;
        }
    }
    Ok(())
}

pub fn discover_current_controller_paths(prefix: &str) -> Result<ControllerPaths, EnvError> {
    let membership = fs::read_to_string("/proc/self/cgroup")?;
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
    Ok(CgroupV1Builder::from_proc_data(&membership, &mountinfo, prefix)?.roots)
}
