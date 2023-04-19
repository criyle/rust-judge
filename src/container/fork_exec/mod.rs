use std::ffi::CString;
use std::io::Result;

pub struct Runner {
    pub args: Vec<CString>,
    pub env: Vec<CString>,
    // rlimit
    pub work_dir: CString,

    pub pivot_root: Option<CString>,
    pub host_name: Option<CString>,
    pub domain_name: Option<CString>,

    pub sync_fn: Option<Box<dyn FnMut() -> Result<()> + Send + Sync>>,

    pub clone_flags: i32,
    pub credential: Option<Credential>,
    pub uid_map: Option<Vec<IdMap>>,
    pub gid_map: Option<Vec<IdMap>>,
    pub gid_map_enable_set_groups: bool,

    pub no_new_privs: bool,
    pub drop_caps: bool,
    pub unshare_cgroup_after_sync: bool,
    pub control_tty: bool,
}

pub struct IdMap {
    pub container_id: u32,
    pub host_id: u32,
    pub size: u32,
}

pub struct Credential {
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
    pub no_set_groups: bool,
}

fn test() {}
