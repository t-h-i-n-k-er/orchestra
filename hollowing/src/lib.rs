//! Cross-platform façade over Windows process hollowing.
//!
//! The real implementation only exists on Windows; on every other platform
//! [`hollow_and_execute`] returns an `Err` so that callers (the agent's
//! `MigrateAgent` handler and the launcher's in-memory exec path) can surface
//! a controlled diagnostic instead of panicking.

use anyhow::Result;

#[cfg(windows)]
mod windows_impl;

#[cfg(windows)]
pub use windows_impl::hollow_and_execute;

#[cfg(windows)]
pub use windows_impl::inject_into_process;

#[cfg(not(windows))]
pub fn hollow_and_execute(_payload: &[u8]) -> Result<()> {
    anyhow::bail!("process hollowing is only available on Windows targets");
}
