//! Container command/reply model and Rust-native protobuf IPC.
//!
//! Messages use Prost length-delimited protobuf over the Tokio Unix
//! `SOCK_SEQPACKET` transport. File descriptors travel as ancillary data on
//! the first packet. This is an intentional wire format change from Go gob.
use super::mount::Mount;
use super::seccomp::Filter;
use nix::sys::socket::{ControlMessage, ControlMessageOwned, UnixCredentials};
use prost::{Enumeration, Message};
use std::io::{self, ErrorKind};
use std::os::fd::{FromRawFd, OwnedFd};

pub const BUFFER_SIZE: usize = 32 << 10;
pub const CHUNK_BYTE: u8 = 0;
pub const CHUNK_HEADER_SIZE: usize = 2;
pub const CHUNK_PAYLOAD_SIZE: usize = BUFFER_SIZE - CHUNK_HEADER_SIZE;
pub const CHUNK_PARTIAL: u8 = 0;
pub const CHUNK_COMPLETE: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Enumeration)]
#[repr(i32)]
pub enum CommandType {
    Ping = 1,
    Open = 2,
    Delete = 3,
    Reset = 4,
    Exec = 5,
    Ok = 6,
    Kill = 7,
    Configure = 8,
    Symlink = 9,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OpenCommand {
    pub path: String,
    pub flag: i64,
    pub perm: u32,
    pub mkdir_all: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DeleteCommand {
    pub path: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SymbolicLink {
    pub link_path: String,
    pub target: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResourceLimit {
    pub res: i32,
    pub rlim: ResourceLimitValues,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResourceLimitValues {
    pub cur: u64,
    pub max: u64,
}

#[derive(Clone, Debug, Default)]
pub struct ExecCommand {
    pub argv: Vec<String>,
    pub env: Vec<String>,
    pub rlimits: Vec<ResourceLimit>,
    pub seccomp: Filter,
    pub fd_exec: bool,
    pub fd_cgroup: bool,
    pub ctty: bool,
    pub sync_after: bool,
    pub cpu_set: String,
    pub cgroup_fd_count: u32,
}

#[derive(Clone, Debug, Default)]
pub struct ContainerConfig {
    pub work_dir: String,
    pub host_name: String,
    pub domain_name: String,
    pub container_root: String,
    pub mounts: Vec<Mount>,
    pub symbolic_links: Vec<SymbolicLink>,
    pub mask_paths: Vec<String>,
    pub init_command: Vec<String>,
    pub container_uid: i32,
    pub container_gid: i32,
    pub cred: bool,
    pub unshare_cgroup: bool,
    pub seccomp: Filter,
}

#[derive(Clone, Debug, Default)]
pub struct ConfigureCommand {
    pub conf: ContainerConfig,
}

#[derive(Clone, Debug, Default)]
pub struct Command {
    pub delete_cmd: Option<DeleteCommand>,
    pub exec_cmd: Option<ExecCommand>,
    pub conf_cmd: Option<ConfigureCommand>,
    pub open_cmd: Vec<OpenCommand>,
    pub symlink_cmd: Vec<SymbolicLink>,
    pub cmd: Option<CommandType>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ErrorReply {
    pub errno: Option<i32>,
    pub message: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExecReply {
    pub exit_status: i32,
    pub status: i32,
    /// User CPU time in nanoseconds, as sent by Go's `time.Duration`.
    pub time_ns: i64,
    pub memory_bytes: u64,
    pub exit_time_ns: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Reply {
    pub error: Option<ErrorReply>,
    pub exec_reply: Option<ExecReply>,
    pub batch_errors: Vec<String>,
}

/// Protobuf representation of the Go container command/reply structs.
/// These fields intentionally use Rust/Prost semantics instead of gob tags.
#[derive(Clone, PartialEq, Message)]
pub struct WireCommand {
    #[prost(enumeration = "CommandType", tag = "1")]
    pub cmd: i32,
    #[prost(message, optional, tag = "2")]
    pub delete_cmd: Option<WireDeleteCommand>,
    #[prost(message, optional, tag = "3")]
    pub exec_cmd: Option<WireExecCommand>,
    #[prost(message, optional, tag = "4")]
    pub conf_cmd: Option<WireConfigureCommand>,
    #[prost(message, repeated, tag = "5")]
    pub open_cmd: Vec<WireOpenCommand>,
    #[prost(message, repeated, tag = "6")]
    pub symlink_cmd: Vec<WireSymbolicLink>,
}

#[derive(Clone, PartialEq, Message)]
pub struct WireOpenCommand {
    #[prost(string, tag = "1")]
    pub path: String,
    #[prost(int64, tag = "2")]
    pub flag: i64,
    #[prost(uint32, tag = "3")]
    pub perm: u32,
    #[prost(bool, tag = "4")]
    pub mkdir_all: bool,
}
#[derive(Clone, PartialEq, Message)]
pub struct WireDeleteCommand {
    #[prost(string, tag = "1")]
    pub path: String,
}
#[derive(Clone, PartialEq, Message)]
pub struct WireSymbolicLink {
    #[prost(string, tag = "1")]
    pub link_path: String,
    #[prost(string, tag = "2")]
    pub target: String,
}
#[derive(Clone, PartialEq, Message)]
pub struct WireResourceLimit {
    #[prost(int32, tag = "1")]
    pub res: i32,
    #[prost(message, optional, tag = "2")]
    pub rlim: Option<WireResourceLimitValues>,
}
#[derive(Clone, PartialEq, Message)]
pub struct WireResourceLimitValues {
    #[prost(uint64, tag = "1")]
    pub cur: u64,
    #[prost(uint64, tag = "2")]
    pub max: u64,
}
#[derive(Clone, PartialEq, Message)]
pub struct WireFilterInstruction {
    #[prost(uint32, tag = "1")]
    pub code: u32,
    #[prost(uint32, tag = "2")]
    pub jt: u32,
    #[prost(uint32, tag = "3")]
    pub jf: u32,
    #[prost(uint32, tag = "4")]
    pub k: u32,
}
#[derive(Clone, PartialEq, Message)]
pub struct WireSeccompProgram {
    #[prost(message, repeated, tag = "1")]
    pub instructions: Vec<WireFilterInstruction>,
}
#[derive(Clone, PartialEq, Message)]
pub struct WireExecCommand {
    #[prost(string, repeated, tag = "1")]
    pub argv: Vec<String>,
    #[prost(string, repeated, tag = "2")]
    pub env: Vec<String>,
    #[prost(message, repeated, tag = "3")]
    pub rlimits: Vec<WireResourceLimit>,
    #[prost(message, repeated, tag = "4")]
    pub seccomp: Vec<WireFilterInstruction>,
    #[prost(bool, tag = "5")]
    pub fd_exec: bool,
    #[prost(bool, tag = "6")]
    pub fd_cgroup: bool,
    #[prost(bool, tag = "7")]
    pub ctty: bool,
    #[prost(bool, tag = "8")]
    pub sync_after: bool,
    #[prost(message, repeated, tag = "9")]
    pub seccomp_programs: Vec<WireSeccompProgram>,
    #[prost(string, tag = "10")]
    pub cpu_set: String,
    #[prost(uint32, tag = "11")]
    pub cgroup_fd_count: u32,
}
#[derive(Clone, PartialEq, Message)]
pub struct WireConfigureCommand {
    #[prost(message, optional, tag = "1")]
    pub conf: Option<WireContainerConfig>,
}
#[derive(Clone, PartialEq, Message)]
pub struct WireContainerConfig {
    #[prost(string, tag = "1")]
    pub work_dir: String,
    #[prost(string, tag = "2")]
    pub host_name: String,
    #[prost(string, tag = "3")]
    pub domain_name: String,
    #[prost(string, tag = "4")]
    pub container_root: String,
    #[prost(message, repeated, tag = "5")]
    pub mounts: Vec<WireMount>,
    #[prost(message, repeated, tag = "6")]
    pub symbolic_links: Vec<WireSymbolicLink>,
    #[prost(string, repeated, tag = "7")]
    pub mask_paths: Vec<String>,
    #[prost(string, repeated, tag = "8")]
    pub init_command: Vec<String>,
    #[prost(int32, tag = "9")]
    pub container_uid: i32,
    #[prost(int32, tag = "10")]
    pub container_gid: i32,
    #[prost(bool, tag = "11")]
    pub cred: bool,
    #[prost(bool, tag = "12")]
    pub unshare_cgroup: bool,
    #[prost(message, repeated, tag = "13")]
    pub seccomp: Vec<WireFilterInstruction>,
    #[prost(message, repeated, tag = "14")]
    pub seccomp_programs: Vec<WireSeccompProgram>,
}
#[derive(Clone, PartialEq, Message)]
pub struct WireMount {
    #[prost(string, tag = "1")]
    pub source: String,
    #[prost(string, tag = "2")]
    pub target: String,
    #[prost(string, tag = "3")]
    pub fs_type: String,
    #[prost(string, tag = "4")]
    pub data: String,
    #[prost(uint64, tag = "5")]
    pub flags: u64,
}
#[derive(Clone, PartialEq, Message)]
pub struct WireReply {
    #[prost(message, optional, tag = "1")]
    pub error: Option<WireErrorReply>,
    #[prost(message, optional, tag = "2")]
    pub exec_reply: Option<WireExecReply>,
    #[prost(string, repeated, tag = "3")]
    pub batch_errors: Vec<String>,
}
#[derive(Clone, PartialEq, Message)]
pub struct WireErrorReply {
    #[prost(int32, optional, tag = "1")]
    pub errno: Option<i32>,
    #[prost(string, tag = "2")]
    pub message: String,
}
#[derive(Clone, PartialEq, Message)]
pub struct WireExecReply {
    #[prost(int32, tag = "1")]
    pub exit_status: i32,
    #[prost(int32, tag = "2")]
    pub status: i32,
    #[prost(int64, tag = "3")]
    pub time_ns: i64,
    #[prost(uint64, tag = "4")]
    pub memory_bytes: u64,
    #[prost(uint64, tag = "5")]
    pub exit_time_ns: u64,
}

fn encode_filter(filter: &Filter) -> Vec<WireFilterInstruction> {
    encode_program(&filter.0)
}

fn encode_program(program: &[libc::sock_filter]) -> Vec<WireFilterInstruction> {
    program
        .iter()
        .map(|f| WireFilterInstruction {
            code: f.code as u32,
            jt: f.jt as u32,
            jf: f.jf as u32,
            k: f.k,
        })
        .collect()
}

fn encode_additional_filters(filter: &Filter) -> Vec<WireSeccompProgram> {
    filter
        .1
        .iter()
        .map(|program| WireSeccompProgram {
            instructions: encode_program(program),
        })
        .collect()
}

fn decode_filter_programs(
    primary: Vec<WireFilterInstruction>,
    additional: Vec<WireSeccompProgram>,
) -> io::Result<Filter> {
    let mut filter = decode_filter(primary)?;
    for program in additional {
        filter.1.push(decode_filter(program.instructions)?.0);
    }
    Ok(filter)
}

impl From<&Command> for WireCommand {
    fn from(command: &Command) -> Self {
        Self {
            cmd: command.cmd.map_or(0, |c| c as i32),
            delete_cmd: command.delete_cmd.as_ref().map(|v| WireDeleteCommand {
                path: v.path.clone(),
            }),
            exec_cmd: command.exec_cmd.as_ref().map(|v| WireExecCommand {
                argv: v.argv.clone(),
                env: v.env.clone(),
                rlimits: v
                    .rlimits
                    .iter()
                    .map(|r| WireResourceLimit {
                        res: r.res,
                        rlim: Some(WireResourceLimitValues {
                            cur: r.rlim.cur,
                            max: r.rlim.max,
                        }),
                    })
                    .collect(),
                seccomp: encode_filter(&v.seccomp),
                seccomp_programs: encode_additional_filters(&v.seccomp),
                fd_exec: v.fd_exec,
                fd_cgroup: v.fd_cgroup,
                ctty: v.ctty,
                sync_after: v.sync_after,
                cpu_set: v.cpu_set.clone(),
                cgroup_fd_count: v.cgroup_fd_count,
            }),
            conf_cmd: command.conf_cmd.as_ref().map(|v| WireConfigureCommand {
                conf: Some(WireContainerConfig {
                    work_dir: v.conf.work_dir.clone(),
                    host_name: v.conf.host_name.clone(),
                    domain_name: v.conf.domain_name.clone(),
                    container_root: v.conf.container_root.clone(),
                    mounts: v
                        .conf
                        .mounts
                        .iter()
                        .map(|m| WireMount {
                            source: m.source.clone(),
                            target: m.target.clone(),
                            fs_type: m.fs_type.clone(),
                            data: m.data.clone(),
                            flags: m.flags,
                        })
                        .collect(),
                    symbolic_links: v
                        .conf
                        .symbolic_links
                        .iter()
                        .map(|l| WireSymbolicLink {
                            link_path: l.link_path.clone(),
                            target: l.target.clone(),
                        })
                        .collect(),
                    mask_paths: v.conf.mask_paths.clone(),
                    init_command: v.conf.init_command.clone(),
                    container_uid: v.conf.container_uid,
                    container_gid: v.conf.container_gid,
                    cred: v.conf.cred,
                    unshare_cgroup: v.conf.unshare_cgroup,
                    seccomp: encode_filter(&v.conf.seccomp),
                    seccomp_programs: encode_additional_filters(&v.conf.seccomp),
                }),
            }),
            open_cmd: command
                .open_cmd
                .iter()
                .map(|v| WireOpenCommand {
                    path: v.path.clone(),
                    flag: v.flag,
                    perm: v.perm,
                    mkdir_all: v.mkdir_all,
                })
                .collect(),
            symlink_cmd: command
                .symlink_cmd
                .iter()
                .map(|v| WireSymbolicLink {
                    link_path: v.link_path.clone(),
                    target: v.target.clone(),
                })
                .collect(),
        }
    }
}

impl From<&Reply> for WireReply {
    fn from(reply: &Reply) -> Self {
        Self {
            error: reply.error.as_ref().map(|e| WireErrorReply {
                errno: e.errno,
                message: e.message.clone(),
            }),
            exec_reply: reply.exec_reply.as_ref().map(|e| WireExecReply {
                exit_status: e.exit_status,
                status: e.status,
                time_ns: e.time_ns,
                memory_bytes: e.memory_bytes,
                exit_time_ns: e.exit_time_ns,
            }),
            batch_errors: reply.batch_errors.clone(),
        }
    }
}

impl TryFrom<WireCommand> for Command {
    type Error = io::Error;

    fn try_from(wire: WireCommand) -> io::Result<Self> {
        let cmd = CommandType::try_from(wire.cmd)
            .map_err(|_| invalid(format!("unknown container command type {}", wire.cmd)))?;
        let delete_cmd = wire.delete_cmd.map(|v| DeleteCommand { path: v.path });
        let exec_cmd = wire
            .exec_cmd
            .map(|v| -> io::Result<ExecCommand> {
                Ok(ExecCommand {
                    argv: v.argv,
                    env: v.env,
                    rlimits: v
                        .rlimits
                        .into_iter()
                        .map(|r| ResourceLimit {
                            res: r.res,
                            rlim: r.rlim.map_or(ResourceLimitValues { cur: 0, max: 0 }, |r| {
                                ResourceLimitValues {
                                    cur: r.cur,
                                    max: r.max,
                                }
                            }),
                        })
                        .collect(),
                    seccomp: decode_filter_programs(v.seccomp, v.seccomp_programs)?,
                    fd_exec: v.fd_exec,
                    fd_cgroup: v.fd_cgroup,
                    ctty: v.ctty,
                    sync_after: v.sync_after,
                    cpu_set: v.cpu_set,
                    cgroup_fd_count: v.cgroup_fd_count,
                })
            })
            .transpose()?;
        let conf_cmd = wire
            .conf_cmd
            .map(|v| -> io::Result<ConfigureCommand> {
                let v = v.conf.unwrap_or_default();
                Ok(ConfigureCommand {
                    conf: ContainerConfig {
                        work_dir: v.work_dir,
                        host_name: v.host_name,
                        domain_name: v.domain_name,
                        container_root: v.container_root,
                        mounts: v
                            .mounts
                            .into_iter()
                            .map(|m| Mount {
                                source: m.source,
                                target: m.target,
                                fs_type: m.fs_type,
                                data: m.data,
                                flags: m.flags,
                            })
                            .collect(),
                        symbolic_links: v
                            .symbolic_links
                            .into_iter()
                            .map(|l| SymbolicLink {
                                link_path: l.link_path,
                                target: l.target,
                            })
                            .collect(),
                        mask_paths: v.mask_paths,
                        init_command: v.init_command,
                        container_uid: v.container_uid,
                        container_gid: v.container_gid,
                        cred: v.cred,
                        unshare_cgroup: v.unshare_cgroup,
                        seccomp: decode_filter_programs(v.seccomp, v.seccomp_programs)?,
                    },
                })
            })
            .transpose()?;
        Ok(Self {
            delete_cmd,
            exec_cmd,
            conf_cmd,
            open_cmd: wire
                .open_cmd
                .into_iter()
                .map(|v| OpenCommand {
                    path: v.path,
                    flag: v.flag,
                    perm: v.perm,
                    mkdir_all: v.mkdir_all,
                })
                .collect(),
            symlink_cmd: wire
                .symlink_cmd
                .into_iter()
                .map(|v| SymbolicLink {
                    link_path: v.link_path,
                    target: v.target,
                })
                .collect(),
            cmd: Some(cmd),
        })
    }
}

impl From<WireReply> for Reply {
    fn from(wire: WireReply) -> Self {
        Self {
            error: wire.error.map(|e| ErrorReply {
                errno: e.errno,
                message: e.message,
            }),
            exec_reply: wire.exec_reply.map(|e| ExecReply {
                exit_status: e.exit_status,
                status: e.status,
                time_ns: e.time_ns,
                memory_bytes: e.memory_bytes,
                exit_time_ns: e.exit_time_ns,
            }),
            batch_errors: wire.batch_errors,
        }
    }
}

fn decode_filter(instructions: Vec<WireFilterInstruction>) -> io::Result<Filter> {
    instructions
        .into_iter()
        .map(|f| {
            Ok(libc::sock_filter {
                code: u16::try_from(f.code).map_err(|_| invalid("BPF code exceeds u16"))?,
                jt: u8::try_from(f.jt).map_err(|_| invalid("BPF jt exceeds u8"))?,
                jf: u8::try_from(f.jf).map_err(|_| invalid("BPF jf exceeds u8"))?,
                k: f.k,
            })
        })
        .collect::<io::Result<Vec<_>>>()
        .map(|program| Filter(program, Vec::new()))
}

/// Encode one message with Prost's standard length-delimited protobuf framing.
pub fn encode_message(message: &impl Message) -> Vec<u8> {
    message.encode_length_delimited_to_vec()
}

/// Decode exactly one length-delimited protobuf message, rejecting trailing bytes.
pub fn decode_message<M: Message + Default>(bytes: &[u8]) -> io::Result<M> {
    let mut input = bytes;
    let message = M::decode_length_delimited(&mut input).map_err(|e| invalid(e.to_string()))?;
    if !input.is_empty() {
        return Err(invalid("trailing bytes after protobuf message"));
    }
    Ok(message)
}

pub async fn send_proto<M: Message>(
    socket: &super::unix_socket::Socket,
    message: &M,
    control: &[ControlMessage<'_>],
) -> io::Result<()> {
    send_framed(socket, &encode_message(message), control).await
}

pub async fn recv_proto<M: Message + Default>(
    socket: &super::unix_socket::Socket,
) -> io::Result<(M, ReceivedFrame)> {
    let frame = recv_framed(socket).await?;
    let message = decode_message(&frame.payload)?;
    Ok((message, frame))
}

/// The control data is attached to the first datagram only, even for a
/// multi-datagram payload. FDs are owned and close automatically.
#[derive(Debug, Default)]
pub struct ReceivedFrame {
    pub payload: Vec<u8>,
    pub fds: Vec<OwnedFd>,
    pub credentials: Option<UnixCredentials>,
}

/// Return packet datagrams using go-sandbox's `[0, flag, payload]` framing.
/// Messages of at most 32 KiB are passed through unmodified.
pub fn encode_packets(payload: &[u8]) -> Vec<Vec<u8>> {
    if payload.len() <= BUFFER_SIZE {
        return vec![payload.to_vec()];
    }
    payload
        .chunks(CHUNK_PAYLOAD_SIZE)
        .enumerate()
        .map(|(index, part)| {
            let final_chunk = (index + 1) * CHUNK_PAYLOAD_SIZE >= payload.len();
            let mut packet = Vec::with_capacity(CHUNK_HEADER_SIZE + part.len());
            packet.push(CHUNK_BYTE);
            packet.push(if final_chunk {
                CHUNK_COMPLETE
            } else {
                CHUNK_PARTIAL
            });
            packet.extend_from_slice(part);
            packet
        })
        .collect()
}

/// Decode datagrams from one logical Go container message.
pub fn decode_packets(packets: &[Vec<u8>]) -> io::Result<Vec<u8>> {
    let Some(first) = packets.first() else {
        return Err(invalid("no packet received"));
    };
    if first.len() < CHUNK_HEADER_SIZE || first[0] != CHUNK_BYTE {
        if packets.len() != 1 {
            return Err(invalid("unexpected extra packet after unchunked message"));
        }
        if first.len() > BUFFER_SIZE {
            return Err(invalid("packet exceeds receive buffer"));
        }
        return Ok(first.clone());
    }
    let mut payload = Vec::new();
    for (index, packet) in packets.iter().enumerate() {
        if packet.len() < CHUNK_HEADER_SIZE || packet[0] != CHUNK_BYTE {
            return Err(invalid(format!("expected chunk packet at index {index}")));
        }
        if packet.len() > BUFFER_SIZE {
            return Err(invalid("chunk exceeds receive buffer"));
        }
        let complete = match packet[1] {
            CHUNK_PARTIAL => false,
            CHUNK_COMPLETE => true,
            flag => return Err(invalid(format!("invalid chunk flag {flag}"))),
        };
        if complete != (index + 1 == packets.len()) {
            return Err(invalid(if complete {
                "data follows complete chunk"
            } else {
                "incomplete chunk sequence"
            }));
        }
        payload.extend_from_slice(&packet[CHUNK_HEADER_SIZE..]);
    }
    Ok(payload)
}

/// Send length-delimited protobuf payload bytes using the bounded seqpacket framing.
pub async fn send_framed(
    socket: &super::unix_socket::Socket,
    payload: &[u8],
    first_packet_control: &[ControlMessage<'_>],
) -> io::Result<()> {
    for (index, packet) in encode_packets(payload).iter().enumerate() {
        let control = if index == 0 {
            first_packet_control
        } else {
            &[]
        };
        socket.sendmsg(packet, control).await?;
    }
    Ok(())
}

/// Receive and reassemble one logical message. Any file descriptors on a later
/// chunk are closed and rejected because Go's protocol only carries them once.
pub async fn recv_framed(socket: &super::unix_socket::Socket) -> io::Result<ReceivedFrame> {
    let mut buffer = vec![0; BUFFER_SIZE];
    let (n, control) = socket.recvmsg(&mut buffer).await?;
    let mut frame = ReceivedFrame::default();
    take_control(control, &mut frame)?;
    let first = &buffer[..n];
    if first.len() < CHUNK_HEADER_SIZE || first[0] != CHUNK_BYTE {
        frame.payload.extend_from_slice(first);
        return Ok(frame);
    }
    let flag = validate_chunk(first, 0, &mut frame.payload)?;
    let mut complete = flag == CHUNK_COMPLETE;
    let mut index = 1;
    while !complete {
        let (n, control) = socket
            .recvmsg(&mut buffer)
            .await
            .map_err(|e| io::Error::new(e.kind(), format!("recv msg: chunk: {e}")))?;
        let mut later = ReceivedFrame::default();
        take_control(control, &mut later)?;
        if !later.fds.is_empty() {
            return Err(invalid("unexpected FDs in chunk"));
        }
        let packet = &buffer[..n];
        let flag = validate_chunk(packet, index, &mut frame.payload)?;
        complete = flag == CHUNK_COMPLETE;
        index += 1;
    }
    Ok(frame)
}

fn take_control(control: Vec<ControlMessageOwned>, frame: &mut ReceivedFrame) -> io::Result<()> {
    for message in control {
        match message {
            ControlMessageOwned::ScmRights(fds) => {
                for fd in fds {
                    // SAFETY: SCM_RIGHTS returned a newly installed descriptor.
                    frame.fds.push(unsafe { OwnedFd::from_raw_fd(fd) });
                }
            }
            ControlMessageOwned::ScmCredentials(cred) => frame.credentials = Some(cred),
            _ => {}
        }
    }
    Ok(())
}

fn validate_chunk(packet: &[u8], index: usize, payload: &mut Vec<u8>) -> io::Result<u8> {
    if packet.len() < CHUNK_HEADER_SIZE || packet[0] != CHUNK_BYTE {
        return Err(invalid(format!("expected chunk packet at index {index}")));
    }
    if packet.len() > BUFFER_SIZE {
        return Err(invalid("chunk exceeds receive buffer"));
    }
    if !matches!(packet[1], CHUNK_PARTIAL | CHUNK_COMPLETE) {
        return Err(invalid(format!("invalid chunk flag {}", packet[1])));
    }
    payload.extend_from_slice(&packet[CHUNK_HEADER_SIZE..]);
    Ok(packet[1])
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::socket::ControlMessage;
    use nix::unistd::{pipe, read, write};
    use std::io::ErrorKind;
    use std::os::fd::AsRawFd;

    #[test]
    fn small_packet_is_unmodified() {
        let payload = encode_message(&WireReply::default());
        let packets = encode_packets(&payload);
        assert_eq!(packets.as_slice(), std::slice::from_ref(&payload));
        assert_eq!(decode_packets(&packets).unwrap(), payload);
    }

    #[test]
    fn command_fields_roundtrip_through_prost_wire_messages() {
        let command = Command {
            cmd: Some(CommandType::Exec),
            exec_cmd: Some(ExecCommand {
                argv: vec!["/bin/cat".into()],
                env: vec!["A=B".into()],
                rlimits: vec![ResourceLimit {
                    res: libc::RLIMIT_NOFILE as i32,
                    rlim: ResourceLimitValues { cur: 128, max: 128 },
                }],
                seccomp: Filter(
                    vec![libc::sock_filter {
                        code: 6,
                        jt: 0,
                        jf: 0,
                        k: 0x7fff_0000,
                    }],
                    vec![vec![libc::sock_filter {
                        code: 6,
                        jt: 0,
                        jf: 0,
                        k: 0x0005_0001,
                    }]],
                ),
                fd_exec: true,
                fd_cgroup: false,
                ctty: true,
                sync_after: false,
                cpu_set: String::new(),
                cgroup_fd_count: 0,
            }),
            open_cmd: vec![OpenCommand {
                path: "/w/input".into(),
                flag: libc::O_RDONLY as i64,
                perm: 0o644,
                mkdir_all: true,
            }],
            ..Default::default()
        };
        let wire = WireCommand::from(&command);
        let payload = encode_message(&wire);
        assert_eq!(&payload[..1], &[payload.len() as u8 - 1]);
        let decoded: WireCommand = decode_message(&payload).unwrap();
        assert_eq!(decoded, wire);
        let decoded = Command::try_from(decoded).unwrap();
        assert_eq!(decoded.cmd, Some(CommandType::Exec));
        assert_eq!(decoded.exec_cmd.as_ref().unwrap().argv, ["/bin/cat"]);
        assert_eq!(decoded.exec_cmd.as_ref().unwrap().rlimits[0].rlim.max, 128);
        assert_eq!(
            decoded.exec_cmd.as_ref().unwrap().seccomp.0[0].k,
            0x7fff_0000
        );
        assert_eq!(
            decoded.exec_cmd.as_ref().unwrap().seccomp.1[0][0].k,
            0x0005_0001
        );
        assert_eq!(decoded.open_cmd[0].path, "/w/input");
    }

    #[test]
    fn configure_preserves_cgroup_namespace_setting() {
        let command = Command {
            cmd: Some(CommandType::Configure),
            conf_cmd: Some(ConfigureCommand {
                conf: ContainerConfig {
                    unshare_cgroup: true,
                    ..Default::default()
                },
            }),
            ..Default::default()
        };
        let wire = WireCommand::from(&command);
        let decoded =
            Command::try_from(decode_message::<WireCommand>(&encode_message(&wire)).unwrap())
                .unwrap();
        assert!(decoded.conf_cmd.unwrap().conf.unshare_cgroup);
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut bytes = encode_message(&WireReply::default());
        bytes.push(0);
        assert_eq!(
            decode_message::<WireReply>(&bytes).err().unwrap().kind(),
            ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn typed_ipc_roundtrip_is_protobuf_and_keeps_file_descriptors() -> io::Result<()> {
        let (tx, rx) = super::super::unix_socket::Socket::pair()?;
        let (read_end, write_end) = pipe().map_err(io::Error::other)?;
        write(&write_end, b"protobuf fd").map_err(io::Error::other)?;
        let raw_fd = [read_end.as_raw_fd()];
        let control = [ControlMessage::ScmRights(&raw_fd)];
        let reply = WireReply {
            error: Some(WireErrorReply {
                errno: Some(libc::ENOENT),
                message: "not found".into(),
            }),
            batch_errors: vec!["a".into(), "b".into()],
            ..Default::default()
        };
        let receive = tokio::spawn(async move { recv_proto::<WireReply>(&rx).await });
        send_proto(&tx, &reply, &control).await?;
        let (decoded, frame) = receive.await.map_err(io::Error::other)??;
        assert_eq!(decoded, reply);
        assert_eq!(frame.fds.len(), 1);
        let mut received = [0; 11];
        assert_eq!(
            read(&frame.fds[0], &mut received).map_err(io::Error::other)?,
            11
        );
        assert_eq!(&received, b"protobuf fd");
        Ok(())
    }

    #[tokio::test]
    async fn typed_large_protobuf_messages_use_bounded_packets() -> io::Result<()> {
        let (tx, rx) = super::super::unix_socket::Socket::pair()?;
        let reply = WireReply {
            batch_errors: (0..1200)
                .map(|i| format!("error-{i}-{}", "x".repeat(80)))
                .collect(),
            ..Default::default()
        };
        assert!(encode_message(&reply).len() > BUFFER_SIZE);
        let receive = tokio::spawn(async move { recv_proto::<WireReply>(&rx).await });
        send_proto(&tx, &reply, &[]).await?;
        let (decoded, frame) = receive.await.map_err(io::Error::other)??;
        assert_eq!(decoded, reply);
        assert!(frame.fds.is_empty());
        Ok(())
    }

    #[test]
    fn large_packet_matches_go_chunk_envelope_and_roundtrips() {
        let payload = vec![42; BUFFER_SIZE * 2 + 17];
        let packets = encode_packets(&payload);
        assert_eq!(packets.len(), 3);
        assert_eq!(&packets[0][..2], &[CHUNK_BYTE, CHUNK_PARTIAL]);
        assert_eq!(&packets[1][..2], &[CHUNK_BYTE, CHUNK_PARTIAL]);
        assert_eq!(&packets[2][..2], &[CHUNK_BYTE, CHUNK_COMPLETE]);
        assert!(packets.iter().all(|packet| packet.len() <= BUFFER_SIZE));
        assert_eq!(decode_packets(&packets).unwrap(), payload);
    }

    #[test]
    fn rejects_incomplete_or_invalid_chunk_sequences() {
        assert_eq!(
            decode_packets(&[]).unwrap_err().kind(),
            ErrorKind::InvalidData
        );
        assert!(decode_packets(&[vec![CHUNK_BYTE, CHUNK_PARTIAL, 1]]).is_err());
        assert!(decode_packets(&[vec![CHUNK_BYTE, 9, 1]]).is_err());
        assert!(decode_packets(&[vec![CHUNK_BYTE, CHUNK_COMPLETE, 1], vec![2]]).is_err());
    }

    #[tokio::test]
    async fn async_transport_keeps_fds_on_first_chunk_only() -> io::Result<()> {
        let (tx, rx) = super::super::unix_socket::Socket::pair()?;
        let (read_end, write_end) = pipe().map_err(io::Error::other)?;
        write(&write_end, b"z").map_err(io::Error::other)?;
        let payload = vec![7u8; BUFFER_SIZE + 100];
        let raw_fd = [read_end.as_raw_fd()];
        let control = [ControlMessage::ScmRights(&raw_fd)];
        let recv = tokio::spawn(async move { recv_framed(&rx).await });
        send_framed(&tx, &payload, &control).await?;
        let frame = recv.await.map_err(io::Error::other)??;
        assert_eq!(frame.payload, payload);
        assert_eq!(frame.fds.len(), 1);
        let mut byte = [0];
        assert_eq!(read(&frame.fds[0], &mut byte).map_err(io::Error::other)?, 1);
        assert_eq!(byte, [b'z']);
        Ok(())
    }

    #[test]
    fn command_values_match_go_constants() {
        assert_eq!(CommandType::Ping as i8, 1);
        assert_eq!(CommandType::Symlink as i8, 9);
    }
}
