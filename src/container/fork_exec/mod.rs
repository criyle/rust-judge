//! Process creation for sandboxed commands.
//!
//! The public `fork_exec` module keeps the command runner API stable while its
//! lifecycle, vfork syscall path, and orchestration live in focused modules.

mod child;
mod namespace;
mod runner;
mod sync;
mod userns;
mod vfork;

pub use child::Child;
pub use runner::{BindMount, Credential, IdMap, ProcMount, Runner, TmpfsMount};
pub use vfork::clone3_available;
