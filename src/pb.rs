//! Protobuf wire types for the schemas in `go-judge/pb`.
//!
//! Tags and scalar encodings match the source `.proto` files. RPC client/server stubs
//! and ProtoJSON's custom enum/base64 formatting are intentionally not included.
use prost::{Enumeration, Message, Oneof};
use std::collections::HashMap;

#[derive(Clone, PartialEq, Message)]
pub struct Empty {}

#[derive(Clone, PartialEq, Message)]
pub struct Request {
    #[prost(string, tag = "1")]
    pub request_id: String,
    #[prost(message, repeated, tag = "2")]
    pub cmd: Vec<request::CmdType>,
    #[prost(message, repeated, tag = "3")]
    pub pipe_mapping: Vec<request::PipeMap>,
}
pub mod request {
    use super::*;
    #[derive(Clone, PartialEq, Message)]
    pub struct LocalFile {
        #[prost(string, tag = "1")]
        pub src: String,
    }
    #[derive(Clone, PartialEq, Message)]
    pub struct MemoryFile {
        #[prost(bytes = "vec", tag = "1")]
        pub content: Vec<u8>,
    }
    #[derive(Clone, PartialEq, Message)]
    pub struct CachedFile {
        #[prost(string, tag = "1")]
        pub file_id: String,
    }
    #[derive(Clone, PartialEq, Message)]
    pub struct PipeCollector {
        #[prost(string, tag = "1")]
        pub name: String,
        #[prost(int64, tag = "2")]
        pub max: i64,
        #[prost(bool, tag = "3")]
        pub pipe: bool,
    }
    #[derive(Clone, PartialEq, Message)]
    pub struct File {
        #[prost(oneof = "file::Kind", tags = "1,2,3,4,5,6")]
        pub kind: Option<file::Kind>,
    }
    pub mod file {
        use super::*;
        #[derive(Clone, PartialEq, Oneof)]
        pub enum Kind {
            #[prost(message, tag = "1")]
            Local(LocalFile),
            #[prost(message, tag = "2")]
            Memory(MemoryFile),
            #[prost(message, tag = "3")]
            Cached(CachedFile),
            #[prost(message, tag = "4")]
            Pipe(PipeCollector),
            #[prost(message, tag = "5")]
            StreamIn(Empty),
            #[prost(message, tag = "6")]
            StreamOut(Empty),
        }
    }
    #[derive(Clone, PartialEq, Message)]
    pub struct CmdCopyOutFile {
        #[prost(string, tag = "1")]
        pub name: String,
        #[prost(bool, tag = "2")]
        pub optional: bool,
    }
    #[derive(Clone, PartialEq, Message)]
    pub struct CmdType {
        #[prost(string, repeated, tag = "1")]
        pub args: Vec<String>,
        #[prost(string, repeated, tag = "2")]
        pub env: Vec<String>,
        #[prost(message, repeated, tag = "3")]
        pub files: Vec<File>,
        #[prost(uint64, tag = "4")]
        pub cpu_time_limit: u64,
        #[prost(uint64, tag = "5")]
        pub clock_time_limit: u64,
        #[prost(uint64, tag = "6")]
        pub memory_limit: u64,
        #[prost(uint64, tag = "7")]
        pub proc_limit: u64,
        #[prost(map = "string,message", tag = "8")]
        pub copy_in: HashMap<String, File>,
        #[prost(message, repeated, tag = "9")]
        pub copy_out: Vec<CmdCopyOutFile>,
        #[prost(message, repeated, tag = "10")]
        pub copy_out_cached: Vec<CmdCopyOutFile>,
        #[prost(string, tag = "11")]
        pub copy_out_dir: String,
        #[prost(uint64, tag = "12")]
        pub stack_limit: u64,
        #[prost(bool, tag = "13")]
        pub tty: bool,
        #[prost(uint64, tag = "14")]
        pub copy_out_max: u64,
        #[prost(uint64, tag = "15")]
        pub cpu_rate_limit: u64,
        #[prost(bool, tag = "16")]
        pub data_segment_limit: bool,
        #[prost(string, tag = "17")]
        pub cpu_set_limit: String,
        #[prost(map = "string,string", tag = "18")]
        pub symlinks: HashMap<String, String>,
        #[prost(bool, tag = "19")]
        pub address_space_limit: bool,
        #[prost(bool, tag = "20")]
        pub copy_out_truncate: bool,
    }
    #[derive(Clone, PartialEq, Message)]
    pub struct PipeMap {
        #[prost(message, optional, tag = "1")]
        pub r#in: Option<PipeIndex>,
        #[prost(message, optional, tag = "2")]
        pub out: Option<PipeIndex>,
        #[prost(bool, tag = "3")]
        pub proxy: bool,
        #[prost(string, tag = "4")]
        pub name: String,
        #[prost(uint64, tag = "5")]
        pub max: u64,
        #[prost(bool, tag = "6")]
        pub disable_zero_copy: bool,
    }
    #[derive(Clone, PartialEq, Message)]
    pub struct PipeIndex {
        #[prost(int32, tag = "1")]
        pub index: i32,
        #[prost(int32, tag = "2")]
        pub fd: i32,
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct Response {
    #[prost(string, tag = "1")]
    pub request_id: String,
    #[prost(message, repeated, tag = "2")]
    pub results: Vec<response::Result>,
    #[prost(string, tag = "3")]
    pub error: String,
}
pub mod response {
    use super::*;
    #[derive(Clone, PartialEq, Message)]
    pub struct FileError {
        #[prost(string, tag = "1")]
        pub name: String,
        #[prost(enumeration = "file_error::ErrorType", tag = "2")]
        pub r#type: i32,
        #[prost(string, tag = "3")]
        pub message: String,
    }
    pub mod file_error {
        use super::*;
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Enumeration)]
        #[repr(i32)]
        pub enum ErrorType {
            CopyInOpenFile = 0,
            CopyInCreateFile = 1,
            CopyInCopyContent = 2,
            CopyOutOpen = 3,
            CopyOutNotRegularFile = 4,
            CopyOutSizeExceeded = 5,
            CopyOutCreateFile = 6,
            CopyOutCopyContent = 7,
            CollectSizeExceeded = 8,
            Symlink = 9,
        }
    }
    #[derive(Clone, PartialEq, Message)]
    pub struct Result {
        #[prost(enumeration = "result::StatusType", tag = "1")]
        pub status: i32,
        #[prost(int32, tag = "2")]
        pub exit_status: i32,
        #[prost(string, tag = "3")]
        pub error: String,
        #[prost(uint64, tag = "4")]
        pub time: u64,
        #[prost(uint64, tag = "5")]
        pub memory: u64,
        #[prost(map = "string,bytes", tag = "6")]
        pub files: HashMap<String, Vec<u8>>,
        #[prost(map = "string,string", tag = "7")]
        pub file_ids: HashMap<String, String>,
        #[prost(uint64, tag = "8")]
        pub run_time: u64,
        #[prost(message, repeated, tag = "9")]
        pub file_error: Vec<FileError>,
        #[prost(uint64, tag = "10")]
        pub proc_peak: u64,
    }
    pub mod result {
        use super::*;
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Enumeration)]
        #[repr(i32)]
        pub enum StatusType {
            Invalid = 0,
            Accepted = 1,
            WrongAnswer = 2,
            PartiallyCorrect = 3,
            MemoryLimitExceeded = 4,
            TimeLimitExceeded = 5,
            OutputLimitExceeded = 6,
            FileError = 7,
            NonZeroExitStatus = 8,
            Signalled = 9,
            DangerousSyscall = 10,
            JudgementFailed = 11,
            InvalidInteraction = 12,
            InternalError = 13,
        }
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct FileId {
    #[prost(string, tag = "1")]
    pub file_id: String,
}
#[derive(Clone, PartialEq, Message)]
pub struct FileContent {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(bytes = "vec", tag = "2")]
    pub content: Vec<u8>,
}
#[derive(Clone, PartialEq, Message)]
pub struct FileListType {
    #[prost(map = "string,string", tag = "1")]
    pub file_ids: HashMap<String, String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct StreamRequest {
    #[prost(oneof = "stream_request::Kind", tags = "1,2,3,4")]
    pub kind: Option<stream_request::Kind>,
}
pub mod stream_request {
    use super::*;
    #[derive(Clone, PartialEq, Message)]
    pub struct Input {
        #[prost(uint32, tag = "1")]
        pub index: u32,
        #[prost(bytes = "vec", tag = "2")]
        pub content: Vec<u8>,
        #[prost(uint32, tag = "3")]
        pub fd: u32,
    }
    #[derive(Clone, PartialEq, Message)]
    pub struct Resize {
        #[prost(uint32, tag = "1")]
        pub index: u32,
        #[prost(uint32, tag = "2")]
        pub rows: u32,
        #[prost(uint32, tag = "3")]
        pub cols: u32,
        #[prost(uint32, tag = "4")]
        pub x: u32,
        #[prost(uint32, tag = "5")]
        pub y: u32,
        #[prost(uint32, tag = "6")]
        pub fd: u32,
    }
    #[derive(Clone, PartialEq, Oneof)]
    pub enum Kind {
        #[prost(message, tag = "1")]
        ExecRequest(Request),
        #[prost(message, tag = "2")]
        ExecInput(Input),
        #[prost(message, tag = "3")]
        ExecResize(Resize),
        #[prost(message, tag = "4")]
        ExecCancel(Empty),
    }
}
#[derive(Clone, PartialEq, Message)]
pub struct StreamResponse {
    #[prost(oneof = "stream_response::Kind", tags = "1,2")]
    pub kind: Option<stream_response::Kind>,
}
pub mod stream_response {
    use super::*;
    #[derive(Clone, PartialEq, Message)]
    pub struct Output {
        #[prost(uint32, tag = "1")]
        pub index: u32,
        #[prost(bytes = "vec", tag = "2")]
        pub content: Vec<u8>,
        #[prost(uint32, tag = "3")]
        pub fd: u32,
    }
    #[derive(Clone, PartialEq, Oneof)]
    pub enum Kind {
        #[prost(message, tag = "1")]
        ExecResponse(Response),
        #[prost(message, tag = "2")]
        ExecOutput(Output),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn request_oneof_and_high_number_fields_have_expected_wire_tags() {
        let request = Request {
            request_id: "r".into(),
            cmd: vec![request::CmdType {
                tty: true,
                stack_limit: 99,
                copy_out_truncate: true,
                ..Default::default()
            }],
            ..Default::default()
        };
        let bytes = request.encode_to_vec();
        let decoded = Request::decode(bytes.as_slice()).unwrap();
        assert_eq!(decoded, request);
        assert!(bytes.windows(2).any(|w| w == [0x68, 0x01])); // tty field 13
        assert!(bytes.windows(2).any(|w| w == [0xa0, 0x01])); // copyOutTruncate field 20 key (value follows)
    }
    #[test]
    fn response_maps_enums_and_unsigned_counters_roundtrip() {
        let value = Response {
            results: vec![response::Result {
                status: response::result::StatusType::Accepted as i32,
                time: u64::MAX,
                files: HashMap::from([("out".into(), vec![0, 255])]),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(
            Response::decode(value.encode_to_vec().as_slice()).unwrap(),
            value
        );
    }
    #[test]
    fn stream_messages_keep_proto_field_numbers() {
        let msg = StreamRequest {
            kind: Some(stream_request::Kind::ExecInput(stream_request::Input {
                index: 2,
                fd: 4,
                content: b"x".to_vec(),
            })),
        };
        let bytes = msg.encode_to_vec();
        assert_eq!(StreamRequest::decode(bytes.as_slice()).unwrap(), msg);
        let out = stream_response::Output {
            index: 1,
            fd: 2,
            content: vec![3],
        };
        let wire = out.encode_to_vec();
        assert!(wire.contains(&0x18)); // output fd is tag 3, not tag 2
    }
}
