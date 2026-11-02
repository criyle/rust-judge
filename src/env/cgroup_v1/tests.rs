use super::*;

use std::sync::atomic::AtomicU64;

fn fixture_root() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "rust-sandbox-cgroup-v1-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

#[test]
fn discovers_controller_membership_from_mountinfo() {
    let cgroup =
        "2:cpu,cpuacct:/users/alice\n3:memory:/users/alice\n4:pids:/users/alice\n0::/unified";
    let mountinfo = concat!(
        "30 20 0:26 /users /sys/fs/cgroup/cpu\\040acct rw,nosuid,nodev,noexec,relatime - cgroup cgroup rw,cpu,cpuacct\n",
        "31 20 0:27 / /sys/fs/cgroup/memory rw,nosuid,nodev,noexec,relatime - cgroup cgroup rw,memory\n",
        "33 20 0:29 / /sys/fs/cgroup/unified rw - cgroup2 cgroup rw"
    );
    let paths = discover_controller_paths(cgroup, mountinfo).unwrap();
    assert_eq!(
        paths.get("cpu").unwrap(),
        &PathBuf::from("/sys/fs/cgroup/cpu acct/alice")
    );
    assert_eq!(paths.get("cpuacct"), paths.get("cpu"));
    assert_eq!(
        paths.get("memory").unwrap(),
        &PathBuf::from("/sys/fs/cgroup/memory/users/alice")
    );
    assert!(!paths.contains_key("pids"));

    let mount_roots = discover_controller_mount_paths(mountinfo).unwrap();
    assert_eq!(
        mount_roots.get("cpu").unwrap(),
        &PathBuf::from("/sys/fs/cgroup/cpu acct")
    );
    assert_eq!(
        mount_roots.get("memory").unwrap(),
        &PathBuf::from("/sys/fs/cgroup/memory")
    );
}

#[test]
fn rejects_membership_traversal_and_invalid_prefixes() {
    assert!(parse_memberships("1:memory:/../../escape").is_err());
    let builder = CgroupV1Builder::new(ControllerPaths::new());
    assert!(builder.create("../escape").is_err());
    assert!(CgroupV1Builder::from_proc_data("1:memory:/x", "", "/absolute").is_err());
}

#[test]
fn initializes_cpuset_through_empty_intermediate_ancestors() {
    let root = fixture_root();
    let middle = root.join("middle");
    let leaf = middle.join("leaf");
    fs::create_dir_all(&leaf).unwrap();
    for name in ["cpuset.cpus", "cpuset.mems"] {
        fs::write(
            root.join(name),
            if name.ends_with("cpus") {
                "0-3\n"
            } else {
                "0\n"
            },
        )
        .unwrap();
        fs::write(middle.join(name), "\n").unwrap();
        fs::write(leaf.join(name), "\n").unwrap();
    }

    initialize_cpuset(&leaf).unwrap();

    for (name, expected) in [("cpuset.cpus", "0-3\n"), ("cpuset.mems", "0\n")] {
        assert_eq!(fs::read_to_string(root.join(name)).unwrap(), expected);
        assert_eq!(fs::read_to_string(middle.join(name)).unwrap(), expected);
        assert_eq!(fs::read_to_string(leaf.join(name)).unwrap(), expected);
    }
    fs::remove_dir_all(root).unwrap();
}

fn seed_controller_files(path: &Path, controller: &str) {
    let names: &[(&str, &str)] = match controller {
        "cpu" => &[("cpu.cfs_quota_us", "-1"), ("cpu.cfs_period_us", "100000")],
        "cpuset" => &[("cpuset.cpus", ""), ("cpuset.mems", "")],
        "cpuacct" => &[("cpuacct.usage", "234000")],
        "memory" => &[
            ("memory.limit_in_bytes", "-1"),
            ("memory.usage_in_bytes", "4096"),
            ("memory.max_usage_in_bytes", "8192"),
            ("memory.memsw.max_usage_in_bytes", "12288"),
            ("memory.memsw.limit_in_bytes", "-1"),
            ("memory.stat", "cache 512\nrss 1024\n"),
        ],
        "pids" => &[("pids.max", "max")],
        _ => unreachable!(),
    };
    for (name, contents) in names {
        fs::write(path.join(name), contents).unwrap();
    }
    fs::write(path.join("cgroup.procs"), "").unwrap();
}

#[test]
fn prepares_go_judge_api_and_containers_as_v1_siblings() {
    let root = fixture_root();
    let prefix = PathBuf::from("gojudge");
    let mut container_roots = ControllerPaths::new();
    for controller in CONTROLLERS {
        let mount = root.join(controller);
        fs::create_dir_all(&mount).unwrap();
        seed_controller_files(&mount, controller);
        if controller == "cpuset" {
            fs::write(mount.join("cpuset.cpus"), "0-3\n").unwrap();
            fs::write(mount.join("cpuset.mems"), "0\n").unwrap();
        }
        let base = mount.join(&prefix);
        let api = base.join("api");
        let containers = base.join("containers");
        for path in [&base, &api, &containers] {
            fs::create_dir_all(path).unwrap();
            seed_controller_files(path, controller);
        }
        fs::write(base.join("cgroup.procs"), "101").unwrap();
        container_roots.insert(controller.to_owned(), containers);
    }

    prepare_go_judge_hierarchy(&container_roots).unwrap();

    for controller in CONTROLLERS {
        let containers = container_roots.get(controller).unwrap();
        assert!(containers.is_dir());
        assert!(containers.parent().unwrap().join("api").is_dir());
        assert_eq!(
            fs::read_to_string(containers.parent().unwrap().join("api/cgroup.procs")).unwrap(),
            "101"
        );
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn enrolls_v1_controllers_in_go_order() {
    let root = fixture_root();
    let mut paths = ControllerPaths::new();
    for controller in ["cpu", "cpuset", "cpuacct"] {
        let path = root.join(controller);
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("cgroup.procs"), "").unwrap();
        paths.insert(controller.to_owned(), path);
    }
    fs::remove_file(root.join("cpuacct/cgroup.procs")).unwrap();
    std::os::unix::fs::symlink("/dev/full", root.join("cpuacct/cgroup.procs")).unwrap();
    let mut cgroup = CgroupV1 {
        paths,
        created: Vec::new(),
        existing: true,
    };

    let error = cgroup.add_process(73).unwrap_err();

    assert!(error.to_string().contains("No space left on device"));
    assert_eq!(
        fs::read_to_string(root.join("cpu/cgroup.procs")).unwrap(),
        "73"
    );
    assert_eq!(
        fs::read_to_string(root.join("cpuset/cgroup.procs")).unwrap(),
        "73"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn creates_configures_samples_and_destroys_all_controller_groups() {
    let root = fixture_root();
    let _ = fs::remove_dir_all(&root);
    let mut roots = ControllerPaths::new();
    for controller in CONTROLLERS {
        let path = root.join(controller);
        fs::create_dir_all(&path).unwrap();
        seed_controller_files(&path, controller);
        roots.insert(controller.to_owned(), path.join("api/containers"));
    }
    fs::write(root.join("cpuset/cpuset.cpus"), "0-3\n").unwrap();
    fs::write(root.join("cpuset/cpuset.mems"), "0\n").unwrap();
    let builder = CgroupV1Builder::new(roots);
    let mut cgroup = builder.create("exec-").unwrap();
    let paths = cgroup.paths().clone();
    for (controller, path) in &paths {
        if controller != "cpuset" {
            seed_controller_files(path, controller);
        } else {
            fs::write(path.join("cgroup.procs"), "").unwrap();
        }
    }
    let membership_fds = cgroup.open_procs().unwrap();
    assert_eq!(membership_fds.len(), CONTROLLERS.len());
    for fd in membership_fds {
        fs::File::from(fd).write_all(b"99").unwrap();
    }
    for path in paths.values() {
        assert_eq!(fs::read_to_string(path.join("cgroup.procs")).unwrap(), "99");
    }
    assert_eq!(
        fs::read_to_string(paths["cpuset"].join("cpuset.cpus")).unwrap(),
        "0-3\n"
    );
    assert_eq!(
        fs::read_to_string(paths["cpuset"].join("cpuset.mems")).unwrap(),
        "0\n"
    );

    cgroup.set_cpuset("1-2").unwrap();
    cgroup.set_memory_limit(1 << 20).unwrap();
    cgroup.set_proc_limit(7).unwrap();
    cgroup
        .set_cpu_rate(500, Duration::from_millis(100))
        .unwrap();
    assert_eq!(
        fs::read_to_string(paths["cpuset"].join("cpuset.cpus")).unwrap(),
        "1-2"
    );
    assert_eq!(
        fs::read_to_string(paths["memory"].join("memory.limit_in_bytes")).unwrap(),
        "1048576"
    );
    assert_eq!(
        fs::read_to_string(paths["pids"].join("pids.max")).unwrap(),
        "7"
    );
    assert_eq!(
        fs::read_to_string(paths["cpu"].join("cpu.cfs_quota_us")).unwrap(),
        "50000"
    );
    assert_eq!(
        fs::read_to_string(paths["cpu"].join("cpu.cfs_period_us")).unwrap(),
        "100000"
    );
    assert_eq!(cgroup.cpu_usage().unwrap(), Duration::from_nanos(234000));
    assert_eq!(cgroup.current_memory().unwrap(), 4096);
    assert_eq!(cgroup.max_memory().unwrap(), 8192);
    assert!(cgroup.proc_peak().is_err());

    cgroup.set_cpuacct_usage(777).unwrap();
    cgroup.set_memory_max_usage(16384).unwrap();
    cgroup.set_memory_memsw_limit(32768).unwrap();
    cgroup.set_cpu_cfs_period(200000).unwrap();
    cgroup.set_cpu_cfs_quota(100000).unwrap();
    cgroup.set_cpuset_mems("0-1").unwrap();
    assert_eq!(cgroup.memory_memsw_max_usage().unwrap(), 12288);
    assert_eq!(cgroup.memory_stat_property("rss").unwrap(), 1024);
    assert_eq!(
        fs::read_to_string(paths["cpuacct"].join("cpuacct.usage")).unwrap(),
        "777"
    );
    assert_eq!(
        fs::read_to_string(paths["memory"].join("memory.max_usage_in_bytes")).unwrap(),
        "16384"
    );
    assert_eq!(
        fs::read_to_string(paths["memory"].join("memory.memsw.limit_in_bytes")).unwrap(),
        "32768"
    );
    assert_eq!(
        fs::read_to_string(paths["cpu"].join("cpu.cfs_period_us")).unwrap(),
        "200000"
    );
    assert_eq!(
        fs::read_to_string(paths["cpu"].join("cpu.cfs_quota_us")).unwrap(),
        "100000"
    );
    assert_eq!(
        fs::read_to_string(paths["cpuset"].join("cpuset.mems")).unwrap(),
        "0-1"
    );

    cgroup.add_process(1234).unwrap();
    for path in paths.values() {
        assert_eq!(
            fs::read_to_string(path.join("cgroup.procs")).unwrap(),
            "1234"
        );
    }
    for path in paths.values() {
        for entry in fs::read_dir(path).unwrap() {
            fs::remove_file(entry.unwrap().path()).unwrap();
        }
    }
    Box::new(cgroup).destroy().unwrap();
    for path in paths.values() {
        assert!(!path.exists());
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn supports_named_children_existing_handles_and_process_migration() {
    let root = fixture_root();
    let mut parent_paths = ControllerPaths::new();
    for controller in ["cpu", "memory"] {
        let parent_path = root.join(controller).join("parent");
        fs::create_dir_all(&parent_path).unwrap();
        seed_controller_files(&parent_path, controller);
        fs::write(parent_path.join("cgroup.procs"), "4321").unwrap();
        let child_path = parent_path.join("nested");
        fs::create_dir(&child_path).unwrap();
        seed_controller_files(&child_path, controller);
        parent_paths.insert(controller.to_owned(), parent_path);
    }

    let parent = CgroupV1 {
        paths: parent_paths.clone(),
        created: Vec::new(),
        existing: true,
    };
    let builder = CgroupV1Builder::new(parent_paths.clone());
    let opened = builder.open_existing("nested").unwrap();
    assert!(opened.existing());
    Box::new(opened).destroy().unwrap();
    assert_eq!(parent.processes().unwrap(), vec![4321]);
    let existing_child = parent.new_child("nested").unwrap();
    assert!(existing_child.existing());
    existing_child.destroy().unwrap();

    let nested = parent.nest("nested").unwrap();
    assert!(nested.existing());
    for path in parent_paths.values() {
        assert_eq!(
            fs::read_to_string(path.join("nested/cgroup.procs")).unwrap(),
            "4321"
        );
    }
    nested.destroy().unwrap();
    assert!(
        parent_paths
            .values()
            .all(|path| path.join("nested").is_dir())
    );

    let created = parent.new_child("created").unwrap();
    assert!(!created.existing());
    let created_paths: Vec<_> = parent_paths
        .values()
        .map(|path| path.join("created"))
        .collect();
    created.destroy().unwrap();
    assert!(created_paths.iter().all(|path| !path.exists()));
    assert!(parent.new_child("../escape").is_err());

    for path in parent_paths.values() {
        fs::remove_dir_all(path).unwrap();
    }
    fs::remove_dir_all(root).unwrap();
}
