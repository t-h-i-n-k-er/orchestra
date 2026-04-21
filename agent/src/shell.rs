//! Interactive shell session management.

use anyhow::Result;
use portable_pty::{ChildKiller, CommandBuilder, NativePtySystem, PtySize, PtySystem};
use std::io::{Read, Write};

pub struct ShellSession {
    writer: Box<dyn Write + Send>,
    reader: Box<dyn Read + Send>,
    child_killer: Option<Box<dyn ChildKiller + Send + Sync>>,
}

impl ShellSession {
    pub fn new() -> Result<Self> {
        let pty_system = NativePtySystem::default();
        let pair = pty_system.openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })?;

        let cmd = if cfg!(windows) {
            CommandBuilder::new("cmd.exe")
        } else {
            CommandBuilder::new("/bin/sh")
        };

        let child = pair.slave.spawn_command(cmd)?;
        let child_killer = Some(child.clone_killer());

        Ok(Self {
            writer: pair.master.take_writer()?,
            reader: pair.master.try_clone_reader()?,
            child_killer,
        })
    }

    pub fn write_input(&mut self, data: &[u8]) -> Result<()> {
        self.writer.write_all(data)?;
        Ok(())
    }

    pub fn try_read_output(&mut self) -> Vec<u8> {
        let mut buf = Vec::new();
        // This will not block.
        self.reader.read_to_end(&mut buf).ok();
        buf
    }
}

impl Drop for ShellSession {
    fn drop(&mut self) {
        if let Some(mut killer) = self.child_killer.take() {
            killer.kill().ok();
        }
    }
}
