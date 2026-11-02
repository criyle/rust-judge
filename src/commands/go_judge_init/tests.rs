use super::*;

use crate::container::protocol::{OpenCommand, WireCommand};

#[test]
fn rlimit_conversion_preserves_unknown_linux_resource_ids() {
    let resource = libc::RLIMIT_NPROC as i32;
    let limits = convert_rlimits(&[crate::container::protocol::ResourceLimit {
        res: resource,
        rlim: crate::container::protocol::ResourceLimitValues { cur: 7, max: 9 },
    }])
    .unwrap();
    assert_eq!(
        limits.raw,
        [crate::container::rlimit::RawLimit {
            resource: resource as libc::__rlimit_resource_t,
            soft: 7,
            hard: 9,
        }]
    );
}

#[test]
fn rlimit_conversion_preserves_all_soft_hard_pairs_and_order() {
    let limits = convert_rlimits(&[
        crate::container::protocol::ResourceLimit {
            res: libc::RLIMIT_CORE as i32,
            rlim: crate::container::protocol::ResourceLimitValues { cur: 0, max: 4096 },
        },
        crate::container::protocol::ResourceLimit {
            res: libc::RLIMIT_DATA as i32,
            rlim: crate::container::protocol::ResourceLimitValues {
                cur: 2048,
                max: 8192,
            },
        },
    ])
    .unwrap();

    assert_eq!(
        limits.raw,
        [
            crate::container::rlimit::RawLimit {
                resource: libc::RLIMIT_CORE as libc::__rlimit_resource_t,
                soft: 0,
                hard: 4096,
            },
            crate::container::rlimit::RawLimit {
                resource: libc::RLIMIT_DATA as libc::__rlimit_resource_t,
                soft: 2048,
                hard: 8192,
            },
        ]
    );
    assert!(limits.prepare().is_empty());
}

#[test]
fn init_is_noop_outside_pid_one_invocation() {
    assert_eq!(run(), Ok(()));
}

#[test]
fn opens_files_with_batch_errors_and_returns_descriptors() {
    let root = std::env::temp_dir().join(format!("rust-init-open-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let path = root.join("file");
    let commands = [
        OpenCommand {
            path: path.to_string_lossy().into_owned(),
            flag: (libc::O_CREAT | libc::O_RDWR) as i64,
            perm: 0o600,
            mkdir_all: false,
        },
        OpenCommand {
            path: root.join("missing/file").to_string_lossy().into_owned(),
            flag: libc::O_RDONLY as i64,
            perm: 0,
            mkdir_all: false,
        },
    ];
    let (reply, files) = open_files(&commands);
    assert_eq!(files.len(), 1);
    assert_eq!(reply.batch_errors.len(), 2);
    assert_eq!(reply.batch_errors[0], "");
    assert!(!reply.batch_errors[1].is_empty());
    drop(files);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn protobuf_command_and_reply_roundtrip_for_init_control() {
    let command = WireCommand {
        cmd: CommandType::Ping as i32,
        ..Default::default()
    };
    let bytes = protocol::encode_message(&command);
    let decoded: WireCommand = protocol::decode_message(&bytes).unwrap();
    assert_eq!(decoded.cmd, CommandType::Ping as i32);
    let reply = WireReply::from(&Reply::default());
    assert!(reply.error.is_none());
    assert!(reply.exec_reply.is_none());
}

#[tokio::test]
async fn seqpacket_open_command_returns_file_descriptor() {
    use crate::container::protocol::{WireOpenCommand, WireReply};

    let root = std::env::temp_dir().join(format!("rust-init-ipc-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let path = root.join("from-control");
    let (server, client) = Socket::pair().unwrap();
    let server_task = tokio::spawn(serve(server));
    let command = WireCommand {
        cmd: CommandType::Open as i32,
        open_cmd: vec![WireOpenCommand {
            path: path.to_string_lossy().into_owned(),
            flag: (libc::O_CREAT | libc::O_RDWR) as i64,
            perm: 0o600,
            mkdir_all: false,
        }],
        ..Default::default()
    };
    protocol::send_proto(&client, &command, &[]).await.unwrap();
    let (reply, frame) = protocol::recv_proto::<WireReply>(&client).await.unwrap();
    assert_eq!(reply.batch_errors, [""]);
    assert_eq!(frame.fds.len(), 1);
    assert!(path.exists());
    drop(client);
    assert!(server_task.await.unwrap().is_err());
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn idle_init_rejects_exec_sync_commands_like_go() {
    for command in [CommandType::Ok, CommandType::Kill] {
        let (server, client) = Socket::pair().unwrap();
        let server_task = tokio::spawn(serve(server));
        protocol::send_proto(
            &client,
            &WireCommand {
                cmd: command as i32,
                ..Default::default()
            },
            &[],
        )
        .await
        .unwrap();
        assert!(server_task.await.unwrap().is_err());
    }
}

#[test]
// The test exercises the custom wait4 reaper, which Clippy cannot recognize as
// reaping the `Child` returned by `Command::spawn`.
#[allow(clippy::zombie_processes)]
fn wait4_captures_final_user_cpu_time_and_peak_rss() {
    let child = std::process::Command::new("/bin/sh")
        .args(["-c", "i=0; while [ $i -lt 100000 ]; do i=$((i+1)); done"])
        .spawn()
        .unwrap();
    let mut usage = ProcessUsage::default();
    let status = loop {
        if let Some(status) = try_wait_process_usage(child.id() as i32, &mut usage).unwrap() {
            break status;
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    assert!(status.success());
    assert!(usage.user_time_ns > 0, "{usage:?}");
    assert!(usage.peak_memory_bytes > 0, "{usage:?}");
}

#[test]
fn non_pid_one_cleanup_does_not_reap_unrelated_children() {
    use std::os::unix::process::CommandExt;

    let mut workload = std::process::Command::new("/bin/sh")
        .args(["-c", "sleep 10"])
        .process_group(0)
        .spawn()
        .unwrap();
    let mut unrelated = std::process::Command::new("/bin/sh")
        .args(["-c", "sleep 0.1"])
        .spawn()
        .unwrap();
    let workload_pid = workload.id() as i32;
    let _ = unsafe { libc::kill(-workload_pid, libc::SIGKILL) };
    let _ = workload.wait();

    reap_children(workload_pid);
    assert!(unrelated.try_wait().is_ok());
    let _ = unrelated.wait();
}

#[tokio::test]
// `try_wait_process_usage` reaps this process through wait4 after pidfd wakes.
#[allow(clippy::zombie_processes)]
async fn pidfd_wakes_when_child_exits() {
    let child = std::process::Command::new("/bin/true").spawn().unwrap();
    let Some(pidfd) = open_pidfd_async(child.id() as i32) else {
        return;
    };
    tokio::time::timeout(Duration::from_secs(2), wait_pidfd_ready(&pidfd))
        .await
        .expect("pidfd readiness timed out")
        .unwrap();
    let mut usage = ProcessUsage::default();
    assert!(
        try_wait_process_usage(child.id() as i32, &mut usage)
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn exec_command_can_launch_from_received_executable_fd() {
    use crate::container::protocol::{Command as InitCommand, ExecCommand, WireReply};
    use nix::sys::socket::ControlMessage;
    use std::os::fd::AsRawFd;

    let (server, client) = Socket::pair().unwrap();
    let executable = File::open("/bin/true").unwrap();
    let command = InitCommand {
        cmd: Some(CommandType::Exec),
        exec_cmd: Some(ExecCommand {
            argv: vec!["/bin/true".into()],
            fd_exec: true,
            ..ExecCommand::default()
        }),
        ..InitCommand::default()
    };
    let fds = [executable.as_raw_fd()];
    let controls = [ControlMessage::ScmRights(&fds)];
    let config = InitConfig {
        work_dir: "/".into(),
        uid: None,
        gid: None,
        ..InitConfig::default()
    };
    let server_task = server;
    let execute_task = tokio::spawn(async move {
        let (wire, frame) = protocol::recv_proto::<WireCommand>(&server_task).await?;
        let command = InitCommand::try_from(wire)?;
        let (reply, _) = execute(&server_task, &config, command.exec_cmd, frame.fds).await?;
        send_reply(&server_task, &reply, &[], None).await
    });
    protocol::send_proto(&client, &WireCommand::from(&command), &controls)
        .await
        .unwrap();

    let (started, frame) = protocol::recv_proto::<WireReply>(&client).await.unwrap();
    assert!(started.error.is_none(), "{started:?}");
    assert!(frame.credentials.is_some());
    protocol::send_proto(
        &client,
        &WireCommand {
            cmd: CommandType::Ok as i32,
            ..Default::default()
        },
        &[],
    )
    .await
    .unwrap();
    let (finished, _) = protocol::recv_proto::<WireReply>(&client).await.unwrap();
    assert_eq!(finished.exec_reply.unwrap().status, 0);
    drop(client);
    execute_task.await.unwrap().unwrap();
}

#[test]
fn reset_removes_contents_but_keeps_tmpfs_root() {
    let root = std::env::temp_dir().join(format!("rust-init-reset-{}", std::process::id()));
    fs::create_dir_all(root.join("nested")).unwrap();
    fs::write(root.join("nested/file"), b"x").unwrap();
    let reply = reset(&[root.to_string_lossy().into_owned()]);
    assert!(reply.error.is_none());
    assert!(root.exists());
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn filesystem_plan_keeps_mount_link_and_mask_order() {
    use crate::container::{mount::Mount, protocol::SymbolicLink};

    let mounts = [Mount {
        source: "tmpfs".into(),
        target: "/tmp".into(),
        fs_type: "tmpfs".into(),
        data: "size=8m".into(),
        flags: libc::MS_NODEV,
    }];
    let links = [SymbolicLink {
        link_path: "/dev/stdout".into(),
        target: "/proc/self/fd/1".into(),
    }];
    let masks = ["/proc/kcore".to_owned()];
    let plan = filesystem_plan("/var/lib/container-root", &mounts, &links, &masks).unwrap();
    assert_eq!(plan.root.to_str().unwrap(), "/var/lib/container-root");
    assert_eq!(plan.mounts, &mounts);
    assert_eq!(plan.links, &links);
    assert_eq!(plan.mask_paths, &masks);
}

#[test]
fn filesystem_plan_rejects_missing_or_relative_root() {
    let mounts = [];
    let links = [];
    let masks = [];
    for root in ["", "root"] {
        let error = filesystem_plan(root, &mounts, &links, &masks).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}

#[test]
fn filesystem_plan_rejects_embedded_nul_before_mounting() {
    let mounts = [crate::container::mount::Mount {
        target: "/tmp\0bad".into(),
        ..Default::default()
    }];
    let error = filesystem_plan("/root", &mounts, &[], &[]).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}

#[test]
fn usage_parser_reads_user_cpu_and_kernel_peak_rss() {
    let stat = "123 (cmd with ) chars) S 0 0 0 0 0 0 0 0 0 0 1234 5678 0";
    assert_eq!(process_user_ticks(stat), Some(1234));
    let status = "Name:\tcmd\nVmPeak:\t9000 kB\nVmHWM:\t12 kB\n";
    assert_eq!(process_vm_hwm_bytes(status), Some(12 * 1024));
    assert_eq!(process_vm_hwm_bytes("Name:\tcmd\n"), None);
}
