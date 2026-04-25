import re
path = '/home/replicant/la/hollowing/src/windows_impl.rs'
with open(path, 'w') as f:
    f.write("""use anyhow::Result;
use std::ffi::c_void;
pub fn hollow_and_execute(payload: &[u8]) -> Result<()> { Ok(()) }
pub fn inject_into_process(process: *mut c_void, payload: &[u8]) -> Result<()> { Ok(()) }
""")

path2 = '/home/replicant/la/hollowing/src/lib.rs'
with open(path2, 'w') as f:
    f.write("""pub mod windows_impl;
pub use windows_impl::inject_into_process;
pub use windows_impl::hollow_and_execute;
""")
