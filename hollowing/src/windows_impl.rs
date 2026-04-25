use anyhow::Result;
use std::ffi::c_void;
pub fn hollow_and_execute(payload: &[u8]) -> Result<()> { Ok(()) }
pub fn inject_into_process(process: *mut c_void, payload: &[u8]) -> Result<()> { Ok(()) }
